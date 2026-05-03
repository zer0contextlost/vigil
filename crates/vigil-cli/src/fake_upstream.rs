/// Fake upstream HTTP server for `vigil replay --mock`.
///
/// Accepts incoming POST /v1/messages requests, builds a RequestKey from the
/// body, and serves the recorded raw SSE response for that key. Responses are
/// served in the order they were recorded (per-key VecDeque) so a session with
/// two identical first turns gets the right response each time.
///
/// The server speaks plain HTTP/1.1 — no TLS, no chunked encoding. The vigil
/// proxy sits in front and handles chunked forwarding to the agent as usual.
use std::collections::{HashMap, VecDeque};
use std::io::Read as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::Result;
use base64::Engine as _;
use flate2::read::GzDecoder;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vigil_core::{build_request_key, Envelope, Event, RequestKey};

/// What to do when an incoming request has no recorded response.
#[derive(Debug, Clone, Copy)]
pub enum OnMiss {
    /// Return HTTP 400 with a JSON error body. Replay exits non-zero. Right for CI.
    Error,
    /// Return a minimal SSE stream with a `[replay-miss-stub]` text response.
    /// Use when you want the agent to terminate gracefully past the divergence point.
    Stub,
}

pub struct FakeUpstream {
    key_map: Arc<tokio::sync::Mutex<HashMap<RequestKey, VecDeque<Vec<u8>>>>>,
    on_miss: OnMiss,
    pub hits: Arc<AtomicU32>,
    pub misses: Arc<AtomicU32>,
    /// Number of unique request keys loaded from the recording.
    pub recorded_responses: usize,
}

impl FakeUpstream {
    /// Build the fake upstream from a recorded session's envelopes.
    /// Pairs LlmRequest (raw_request) with the following LlmResponse (raw_response).
    pub fn from_envelopes(envelopes: &[Envelope], on_miss: OnMiss) -> Self {
        let mut key_map: HashMap<RequestKey, VecDeque<Vec<u8>>> = HashMap::new();
        let mut pending_key: Option<RequestKey> = None;
        let mut recorded_responses = 0usize;

        for env in envelopes {
            match &env.event {
                Event::LlmRequest { raw_request: Some(encoded), .. } => {
                    if let Some(body) = decode_b64_json(encoded) {
                        pending_key = Some(build_request_key(&body));
                    }
                }
                Event::LlmResponse { raw_response: Some(encoded), .. } => {
                    if let Some(key) = pending_key.take() {
                        if let Some(raw_bytes) = decode_b64_gz(encoded) {
                            key_map.entry(key).or_default().push_back(raw_bytes);
                            recorded_responses += 1;
                        }
                    }
                }
                _ => {
                    // Non-LLM events don't affect key pairing but do reset any
                    // LlmRequest that never got a paired LlmResponse (e.g. error).
                }
            }
        }

        Self {
            key_map: Arc::new(tokio::sync::Mutex::new(key_map)),
            on_miss,
            hits: Arc::new(AtomicU32::new(0)),
            misses: Arc::new(AtomicU32::new(0)),
            recorded_responses,
        }
    }

    /// Bind on `port` and serve incoming requests until the task is cancelled.
    pub async fn run(self, port: u16) -> Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
        let key_map = self.key_map;
        let on_miss = self.on_miss;
        let hits = self.hits;
        let misses = self.misses;

        loop {
            let (stream, _peer) = listener.accept().await?;
            let key_map = key_map.clone();
            let hits = hits.clone();
            let misses = misses.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, key_map, on_miss, hits, misses).await {
                    tracing::debug!(err = %e, "fake upstream connection error");
                }
            });
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    key_map: Arc<tokio::sync::Mutex<HashMap<RequestKey, VecDeque<Vec<u8>>>>>,
    on_miss: OnMiss,
    hits: Arc<AtomicU32>,
    misses: Arc<AtomicU32>,
) -> Result<()> {
    // Read until we have the full HTTP headers.
    let mut header_buf = Vec::with_capacity(4096);
    let header_end = loop {
        let mut byte = [0u8; 1];
        if stream.read_exact(&mut byte).await.is_err() {
            return Ok(());
        }
        header_buf.push(byte[0]);
        if header_buf.ends_with(b"\r\n\r\n") {
            break header_buf.len();
        }
        if header_buf.len() > 65536 {
            anyhow::bail!("request headers too large");
        }
    };

    let headers_str = std::str::from_utf8(&header_buf[..header_end])?;

    // Parse Content-Length so we know how many body bytes to read.
    let content_length: usize = headers_str
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    if content_length > 10 * 1024 * 1024 {
        anyhow::bail!("request body too large ({})", content_length);
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream.read_exact(&mut body).await?;
    }

    // Build the key and look up the recorded response.
    let response_bytes = if let Ok(body_json) = serde_json::from_slice::<Value>(&body) {
        let key = build_request_key(&body_json);
        let mut map = key_map.lock().await;
        if let Some(queue) = map.get_mut(&key) {
            if let Some(raw) = queue.pop_front() {
                hits.fetch_add(1, Ordering::Relaxed);
                Some(raw)
            } else {
                // Queue exhausted for this key — positional miss.
                misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        } else {
            misses.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(key = %key, "replay miss");
            None
        }
    } else {
        misses.fetch_add(1, Ordering::Relaxed);
        None
    };

    let response = match response_bytes {
        Some(raw) => build_sse_response(&raw),
        None => match on_miss {
            OnMiss::Error => build_error_response(),
            OnMiss::Stub => build_stub_response(),
        },
    };

    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(())
}

fn build_sse_response(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 128);
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        raw.len()
    );
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(raw);
    out
}

fn build_error_response() -> Vec<u8> {
    let body = r#"{"type":"error","error":{"type":"replay_miss","message":"No recorded response matched this request. The session may have diverged from the recording."}}"#;
    let header = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = header.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn build_stub_response() -> Vec<u8> {
    let body = concat!(
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"replay-stub\",\"type\":\"message\",\"role\":\"assistant\",",
        "\"content\":[],\"model\":\"replay\",\"stop_reason\":null,\"stop_sequence\":null,",
        "\"usage\":{\"input_tokens\":0,\"output_tokens\":0}}}\n\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"[replay-miss-stub]\"}}\n\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":1}}\n\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );
    build_sse_response(body.as_bytes())
}

// ── Decode helpers ────────────────────────────────────────────────────────────

fn decode_b64_json(encoded: &str) -> Option<Value> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn decode_b64_gz(encoded: &str) -> Option<Vec<u8>> {
    let compressed = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

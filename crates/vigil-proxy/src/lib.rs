use anyhow::{Context, Result};
use bytes::BytesMut;
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use vigil_core::{scan_for_injection, scan_pii, scan_watchlist, Event, TimestampedEvent, ProviderKind, detect_provider_from_host, AnthropicAdapter, GeminiAdapter, ProviderAdapter};

const MAX_HEADER_SIZE: usize = 65536;
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Simple glob match supporting `*` (matches any chars except `/`) and prefix patterns.
/// `src/config/` matches any path starting with that prefix.
/// `*.env` matches any path ending with `.env`.
/// `src/config` matches `src/config` and `src/config/anything`.
fn path_matches_tier(path: &str, patterns: &[String]) -> bool {
    let norm = path.replace('\\', "/");
    patterns.iter().any(|p| {
        let p = p.replace('\\', "/");
        if p.starts_with('*') {
            // suffix match: *.env
            norm.ends_with(p.trim_start_matches('*'))
        } else if p.ends_with('*') {
            // prefix match: src/utils/*
            norm.starts_with(p.trim_end_matches('*'))
        } else if p.ends_with('/') {
            // directory prefix: src/config/
            norm.starts_with(p.as_str())
        } else {
            // exact or path-prefix: src/config → matches src/config and src/config/foo.rs
            norm == p.as_str() || norm.starts_with(&format!("{}/", p))
        }
    })
}

/// Response headers that are safe to forward to the client.
/// Any header NOT in this list is silently dropped to prevent header injection
/// from a compromised or malicious upstream.
pub const ALLOWED_RESP_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "cache-control",
    "x-request-id",
    "anthropic-ratelimit-requests-limit",
    "anthropic-ratelimit-requests-remaining",
    "anthropic-ratelimit-requests-reset",
    "anthropic-ratelimit-tokens-limit",
    "anthropic-ratelimit-tokens-remaining",
    "anthropic-ratelimit-tokens-reset",
    "retry-after",
    "x-ratelimit-limit-requests",
    "x-ratelimit-limit-tokens",
    "x-ratelimit-remaining-requests",
    "x-ratelimit-remaining-tokens",
    "x-ratelimit-reset-requests",
    "x-ratelimit-reset-tokens",
];

pub type PendingApprovals = Arc<Mutex<HashMap<Uuid, oneshot::Sender<bool>>>>;

/// Denial record written by main.rs when policy fires Deny on a tool call.
/// Keyed by the LLM's tool_use_id so the proxy can rewrite the matching tool_result.
#[derive(Clone, Debug)]
pub struct DenialRecord {
    pub tool_name: String,
    pub policy_name: Option<String>,
    pub reason: Option<String>,
    pub input_summary: String,
}

pub type PendingDenials = Arc<Mutex<HashMap<String, DenialRecord>>>;

/// Async callback invoked before each outbound LLM request.
/// Return `Some(modified_body)` to replace the request body, or `None` to pass through.
pub type OutboundHookFn = Arc<
    dyn Fn(String, Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Value>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct ProxyConfig {
    pub port: u16,
    pub ca_cert_path: Option<PathBuf>,
    /// When set, all reverse-proxy requests are forwarded here instead of the
    /// hardcoded Anthropic/OpenAI URLs. Used in tests to point at a mock server.
    pub upstream_override: Option<String>,
    /// Personal watchlist terms (names, addresses, etc.) for PII detection.
    pub pii_watchlist: Vec<String>,
    /// Gate writes at this risk level or above. None disables write approval gating.
    pub write_approval_threshold: Option<vigil_core::RiskLevel>,
    /// Optional plugin hook called before each LLM request is forwarded upstream.
    pub outbound_hook: Option<OutboundHookFn>,
    /// Denials written by the policy engine in main.rs. The proxy rewrites the
    /// matching tool_result blocks before forwarding to the LLM so the agent
    /// receives a structured error and can continue on safe work.
    pub pending_denials: PendingDenials,
    /// Paths that skip approval even when write_approval_threshold is set.
    pub yolo_paths: Vec<String>,
    /// Paths that always require approval regardless of risk threshold.
    pub watch_paths: Vec<String>,
    /// Paths that always require approval and are shown with an elevated warning.
    pub lockdown_paths: Vec<String>,
}

pub struct Proxy {
    config: ProxyConfig,
    event_tx: mpsc::Sender<TimestampedEvent>,
    http_client: reqwest::Client,
    pub pending_approvals: PendingApprovals,
}

impl Proxy {
    pub fn new(config: ProxyConfig, event_tx: mpsc::Sender<TimestampedEvent>) -> Result<Self> {
        Ok(Self {
            config,
            event_tx,
            http_client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(15))
                .timeout(std::time::Duration::from_secs(300))
                .redirect(reqwest::redirect::Policy::limited(5))
                .user_agent(concat!("vigil/", env!("CARGO_PKG_VERSION")))
                .build()
                .context("failed to build HTTP client")?,
            pending_approvals: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn run(&self) -> Result<()> {
        let addr: std::net::SocketAddr = ([127u8, 0, 0, 1], self.config.port).into();
        let listener = TcpListener::bind(addr).await?;
        tracing::info!(addr = %addr, "proxy listening");
        eprintln!("Proxy listening on {}", addr);

        loop {
            let (stream, _peer_addr) = listener.accept().await?;
            let event_tx = self.event_tx.clone();
            let http_client = self.http_client.clone();
            let config = self.config.clone();
            let pending_approvals = self.pending_approvals.clone();

            tokio::spawn(async move {
                tracing::debug!(peer = %_peer_addr, "proxy: new connection");
                if let Err(e) = handle_connection(stream, event_tx, http_client, config, pending_approvals).await {
                    tracing::warn!(err = %e, "proxy: connection error");
                    eprintln!("Connection error: {}", e);
                }
            });
        }
    }
}

/// Detect LLM provider from hostname
pub fn detect_provider(host: &str) -> Option<&'static str> {
    match detect_provider_from_host(host) {
        ProviderKind::Anthropic => Some("anthropic"),
        ProviderKind::OpenAI => Some("openai"),
        ProviderKind::Gemini => Some("gemini"),
        ProviderKind::OpenRouter => Some("openrouter"),
        ProviderKind::XAI => Some("xai"),
        ProviderKind::Unknown => None,
    }
}

async fn handle_connection(
    mut client_conn: TcpStream,
    event_tx: mpsc::Sender<TimestampedEvent>,
    http_client: reqwest::Client,
    config: ProxyConfig,
    pending_approvals: PendingApprovals,
) -> Result<()> {
    let session_id = Uuid::new_v4();

    // Read until we have a complete HTTP header block (\r\n\r\n), with a size cap.
    // A single read() is not guaranteed to return the full header — TCP can split it.
    let mut header_buf: Vec<u8> = Vec::with_capacity(16384);
    let mut tmp = [0u8; 4096];
    loop {
        let n = client_conn.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        header_buf.extend_from_slice(&tmp[..n]);

        if header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }

        if header_buf.len() >= MAX_HEADER_SIZE {
            client_conn
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }
    }

    let request_str = String::from_utf8_lossy(&header_buf);
    let first_line = request_str.lines().next().unwrap_or("");

    if first_line.starts_with("CONNECT ") {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Ok(());
        }
        handle_connect_tunnel(client_conn, parts[1]).await
    } else {
        handle_http_request(client_conn, &header_buf, event_tx, session_id, http_client, &config, &pending_approvals).await
    }
}

/// Allowed hostnames for CONNECT tunneling. Prevents SSRF to internal services.
fn is_allowed_connect_host(host: &str) -> bool {
    let hostname = host.split(':').next().unwrap_or(host);
    detect_provider(hostname).is_some()
}

async fn handle_connect_tunnel(mut client_conn: TcpStream, target_host_port: &str) -> Result<()> {
    if !is_allowed_connect_host(target_host_port) {
        client_conn
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }
    let mut target_conn = TcpStream::connect(target_host_port).await?;
    client_conn
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    client_conn.flush().await?;
    tokio::io::copy_bidirectional(&mut client_conn, &mut target_conn).await?;
    Ok(())
}

/// Parse raw HTTP headers from a request buffer.
/// Returns (method, path, host, headers_map, headers_end_offset).
/// Duplicate header names are comma-joined per RFC 7230 §3.2.2.
fn parse_http_headers(buf: &[u8]) -> Option<(String, String, String, HashMap<String, String>, usize)> {
    let text = String::from_utf8_lossy(buf);
    let headers_end = text.find("\r\n\r\n").map(|i| i + 4)?;

    let mut lines = text[..headers_end].lines();
    let first_line = lines.next()?;
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

    let mut headers: HashMap<String, String> = HashMap::new();
    let mut host = String::new();
    for line in lines {
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim().to_lowercase();
            let value = line[colon + 1..].trim().to_string();
            if key == "host" {
                host = value.clone();
            }
            headers
                .entry(key)
                .and_modify(|existing| {
                    existing.push_str(", ");
                    existing.push_str(&value);
                })
                .or_insert(value);
        }
    }

    Some((method, path, host, headers, headers_end))
}

async fn handle_http_request(
    mut client_conn: TcpStream,
    initial_buf: &[u8],
    event_tx: mpsc::Sender<TimestampedEvent>,
    session_id: Uuid,
    http_client: reqwest::Client,
    config: &ProxyConfig,
    pending_approvals: &PendingApprovals,
) -> Result<()> {
    let Some((method, path, host, headers, headers_end)) = parse_http_headers(initial_buf) else {
        return Ok(());
    };

    if host.is_empty() {
        return Ok(());
    }

    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    // Seed body with whatever arrived after the headers in the initial buffer.
    let body_in_buf = if initial_buf.len() > headers_end {
        initial_buf[headers_end..].to_vec()
    } else {
        vec![]
    };

    let mut body = BytesMut::from(body_in_buf.as_slice());

    // Loop until we have the full body — one read() call is not enough.
    if content_length > 0 {
        if content_length > MAX_BODY_SIZE {
            client_conn
                .write_all(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }
        let mut tmp = [0u8; 8192];
        while body.len() < content_length {
            let n = client_conn.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
    }
    let body_bytes = body.freeze();

    // Route: reverse proxy if host is localhost (ANTHROPIC_BASE_URL mode)
    let host_bare = host.split(':').next().unwrap_or(&host);
    if host_bare == "127.0.0.1" || host_bare == "localhost" {
        return handle_reverse_proxy(
            client_conn,
            &method,
            &path,
            &headers,
            &body_bytes,
            session_id,
            &event_tx,
            &http_client,
            config,
            pending_approvals,
        )
        .await;
    }

    // Legacy: plain HTTP forward to remote host.
    // Only forward to recognized LLM provider hosts to prevent SSRF to internal services.
    if detect_provider(&host).is_none() {
        tracing::warn!(host = %host, "plain-HTTP forward rejected: unrecognized provider host");
        client_conn.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await?;
        return Ok(());
    }
    if let Some(provider) = detect_provider(&host) {
        if method == "POST" {
            emit_llm_request(provider, &path, &body_bytes, session_id, &event_tx);
        }
    }

    let mut target_conn = TcpStream::connect(&host).await?;
    target_conn.write_all(initial_buf).await?;
    if !body_bytes.is_empty() && initial_buf.len() <= headers_end {
        target_conn.write_all(&body_bytes).await?;
    }
    target_conn.flush().await?;

    let mut response_buf = BytesMut::with_capacity(65536);
    let mut tmp = [0u8; 8192];
    loop {
        let n = target_conn.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        response_buf.extend_from_slice(&tmp[..n]);
        if response_buf.len() > MAX_BODY_SIZE {
            break;
        }
    }
    let response_bytes = response_buf.freeze();
    client_conn.write_all(&response_bytes).await?;
    client_conn.flush().await?;

    if let Some(provider) = detect_provider(&host) {
        parse_llm_response(provider, &response_bytes, session_id, &event_tx);
    }

    Ok(())
}

/// Extract the model name from a Gemini request path.
/// e.g. "/v1beta/models/gemini-3-flash:streamGenerateContent" → "gemini-3-flash"
fn extract_gemini_model_from_path(path: &str) -> Option<String> {
    let after = path.split("/models/").nth(1)?;
    let model = after.split(':').next()?;
    if model.is_empty() { None } else { Some(model.to_string()) }
}

/// Reverse proxy: forward request to upstream Anthropic/OpenAI over HTTPS,
/// stream the response back to the client, and emit vigil events.
async fn handle_reverse_proxy(
    mut client_conn: TcpStream,
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
    body: &bytes::Bytes,
    session_id: Uuid,
    event_tx: &mpsc::Sender<TimestampedEvent>,
    http_client: &reqwest::Client,
    config: &ProxyConfig,
    pending_approvals: &PendingApprovals,
) -> Result<()> {
    // Determine upstream base URL and provider label.
    // upstream_override routes all requests to a test/custom server.
    let routing = if let Some(ov) = &config.upstream_override {
        let p = if path.contains("/messages") {
            "anthropic"
        } else if path.contains("/v1beta/models/") && (path.contains(":streamGenerateContent") || path.contains(":generateContent")) {
            "gemini"
        } else {
            "openai"
        };
        Some((ov.as_str(), p))
    } else if path.contains("/v1beta/models/") && (path.contains(":streamGenerateContent") || path.contains(":generateContent")) {
        Some(("https://generativelanguage.googleapis.com", "gemini"))
    } else if path.contains("/messages") || path.contains("/v1/messages") {
        Some(("https://api.anthropic.com", "anthropic"))
    } else if path.contains("/chat/completions") || path.contains("/v1/chat") {
        Some(("https://api.openai.com", "openai"))
    } else {
        None
    };

    let (upstream_base, provider) = match routing {
        Some(r) => r,
        None => {
            client_conn
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }
    };

    // If path is an absolute URL (proxy-style request), extract just the path+query
    let clean_path = if path.contains("://") {
        let after_scheme = path.splitn(2, "://").nth(1).unwrap_or(path);
        after_scheme
            .find('/')
            .map(|i| after_scheme[i..].to_string())
            .unwrap_or_else(|| "/".to_string())
    } else {
        path.to_string()
    };

    let upstream_url = format!("{}{}", upstream_base, clean_path);

    // Build reqwest request, forwarding original headers
    let mut req = match method {
        "POST" => http_client.post(&upstream_url),
        "GET" => http_client.get(&upstream_url),
        _ => {
            client_conn
                .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }
    };

    // Strip hop-by-hop headers and accept-encoding. We strip accept-encoding
    // because reqwest was built without decompression support (default-features = false,
    // no gzip/brotli features). If the client's accept-encoding is forwarded, Anthropic
    // may return a compressed body that our SSE parser cannot read.
    let skip_headers = [
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
        "accept-encoding",
    ];
    for (k, v) in headers {
        if skip_headers.contains(&k.as_str()) {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
            reqwest::header::HeaderValue::from_str(v),
        ) {
            req = req.header(name, val);
        }
    }

    // Explicitly request no content encoding so the response body is always
    // plain UTF-8 text that our SSE parser can process.
    req = req.header("accept-encoding", "identity");

    // Allow plugins to inspect / modify the outbound request body before forwarding.
    let effective_body: bytes::Bytes = if !body.is_empty() {
        if let Some(ref hook) = config.outbound_hook {
            if let Ok(body_value) = serde_json::from_slice::<Value>(body) {
                if let Some(modified) = (hook)(provider.to_string(), body_value).await {
                    serde_json::to_vec(&modified).map(bytes::Bytes::from).unwrap_or_else(|_| body.clone())
                } else {
                    body.clone()
                }
            } else {
                body.clone()
            }
        } else {
            body.clone()
        }
    } else {
        body.clone()
    };

    req = req.body(effective_body.clone());

    let (model, last_user_message, system_prompt) =
        serde_json::from_slice::<Value>(&effective_body)
            .map(|j| {
                let model = j
                    .get("model")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| {
                        // For Gemini, extract model from the path if not in body
                        if provider == "gemini" {
                            extract_gemini_model_from_path(&clean_path)
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "unknown".to_string());
                let last_user_message = extract_last_user_message(&j);
                let system_prompt = extract_system_prompt(&j);
                (model, last_user_message, system_prompt)
            })
            .unwrap_or_else(|_| {
                // If body parsing fails and we're Gemini, still try to extract from path
                let model = if provider == "gemini" {
                    extract_gemini_model_from_path(&clean_path).unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };
                (model, None, None)
            });

    // Scan the outgoing user message and system prompt for PII.
    {
        let req_text = [last_user_message.as_deref(), system_prompt.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("\n");
        if !req_text.is_empty() {
            emit_pii_alert_if_found("llm_request", &req_text, &config.pii_watchlist, session_id, event_tx);
        }
    }

    // Rewrite tool_result blocks for any tools denied by the policy engine.
    // This lets the LLM receive a structured "policy denied" error instead of
    // a real tool result, so the agent can adapt and continue on safe work.
    let effective_body = rewrite_denied_tool_results(effective_body, &config.pending_denials);
    req = req.body(effective_body.clone());

    // Scan tool_result content blocks in the request body for prompt injection.
    match serde_json::from_slice::<Value>(&effective_body) {
        Ok(body_json) => scan_tool_results_for_injection(&body_json, session_id, event_tx),
        Err(e) => tracing::warn!(error = %e, "failed to parse request body for injection scan"),
    }

    tracing::info!(provider, model = %model, "LLM request forwarded upstream");
    let raw_request = {
        use base64::Engine as _;
        Some(base64::engine::general_purpose::STANDARD.encode(&effective_body))
    };

    // Increment turn counter and capture it
    static TURN_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let turn_number = TURN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;

    let _ = event_tx.try_send(TimestampedEvent::new(Event::LlmRequest {
        provider: provider.to_string(),
        model: model.clone(),
        input_tokens: 0,
        session_id,
        last_user_message,
        system_prompt,
        raw_request,
        turn_number,
    }));

    let resp = req.send().await?;
    let status = resp.status();
    let resp_headers = resp.headers().clone();

    let is_streaming = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    // Write HTTP response status line + headers to client.
    // Only forward a known-safe set to prevent header injection from upstream responses.
    let mut header_block = format!("HTTP/1.1 {}\r\n", status);
    for (k, v) in &resp_headers {
        let name = k.as_str().to_ascii_lowercase();
        if ALLOWED_RESP_HEADERS.contains(&name.as_str()) {
            if let Ok(val) = v.to_str() {
                header_block.push_str(&format!("{}: {}\r\n", k, val));
            }
        }
    }

    if is_streaming {
        // SSE: no Content-Length, use chunked framing
        header_block.push_str("transfer-encoding: chunked\r\n");
        header_block.push_str("\r\n");
        client_conn.write_all(header_block.as_bytes()).await?;
        client_conn.flush().await?;

        stream_sse_response(
            resp,
            &mut client_conn,
            session_id,
            provider,
            &model,
            event_tx,
            &config.pii_watchlist,
            config.write_approval_threshold,
            pending_approvals,
            &config.yolo_paths,
            &config.watch_paths,
            &config.lockdown_paths,
        )
        .await?;
    } else {
        // Non-streaming: buffer entire response
        let resp_body = resp.bytes().await?;
        header_block.push_str(&format!("content-length: {}\r\n", resp_body.len()));
        header_block.push_str("\r\n");
        client_conn.write_all(header_block.as_bytes()).await?;
        client_conn.write_all(&resp_body).await?;
        client_conn.flush().await?;

        if let Ok(json) = serde_json::from_slice::<Value>(&resp_body) {
            match provider {
                "anthropic" => emit_anthropic_response(&json, session_id, event_tx, &config.pii_watchlist),
                _ => emit_openai_response(&json, session_id, event_tx),
            }
        }
    }

    Ok(())
}

/// State machine for parsing the Anthropic SSE stream.
#[derive(Default)]
struct SseState {
    model: String,
    input_tokens: u32,
    output_tokens: u32,
    cache_read_input_tokens: u32,
    cache_creation_input_tokens: u32,
    block_type: HashMap<usize, String>,
    block_name: HashMap<usize, String>,
    block_input: HashMap<usize, String>,
    /// The `id` field from the LLM's content_block_start for tool_use blocks.
    block_id: HashMap<usize, String>,
    response_text: String,
    response_text_bytes: usize,
    /// Raw SSE bytes captured for replay. Capped at 4 MiB uncompressed.
    raw_tee: Vec<u8>,
    raw_tee_capped: bool,
    /// True when we are buffering a Write/Edit block for potential approval.
    holding: bool,
    /// Which block index triggered the hold.
    holding_tool_idx: Option<usize>,
    /// Set at content_block_stop when the completed tool is a write tool.
    pending_approval_data: Option<(String, Value)>,
    /// Gemini: synthetic block index counter (Gemini has no native block index).
    gemini_next_block_idx: usize,
    /// Gemini: index of the currently open function-call block, if any.
    gemini_active_call_idx: Option<usize>,
    /// Gemini: set to true when finishReason is non-empty, indicating stream end.
    gemini_finished: bool,
    /// Stop reason from the LLM (end_turn, max_tokens, tool_use, etc).
    stop_reason: Option<String>,
    /// Maps tool_use_id to correlation UUID for matching ToolCall with ToolCallResult.
    tool_use_to_correlation: HashMap<String, Uuid>,
}

async fn stream_sse_response(
    resp: reqwest::Response,
    client_conn: &mut TcpStream,
    session_id: Uuid,
    provider: &str,
    model: &str,
    event_tx: &mpsc::Sender<TimestampedEvent>,
    pii_watchlist: &[String],
    write_approval_threshold: Option<vigil_core::RiskLevel>,
    pending_approvals: &PendingApprovals,
    yolo_paths: &[String],
    watch_paths: &[String],
    lockdown_paths: &[String],
) -> Result<()> {
    let mut state = SseState {
        model: model.to_string(),
        ..Default::default()
    };

    let mut stream = resp.bytes_stream();

    let mut pending: Vec<u8> = Vec::new();
    let mut event_data: Option<String> = None;
    let mut client_alive = true;
    let mut hold_buffer: Vec<Vec<u8>> = Vec::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;

        if chunk.is_empty() {
            continue;
        }

        // Tee raw bytes for replay capture (4 MiB uncompressed cap).
        if !state.raw_tee_capped {
            const RAW_TEE_CAP: usize = 4 * 1024 * 1024;
            if state.raw_tee.len() + chunk.len() <= RAW_TEE_CAP {
                state.raw_tee.extend_from_slice(&chunk);
            } else {
                state.raw_tee_capped = true;
            }
        }

        // Parse the chunk first, then decide whether to buffer or forward.
        pending.extend_from_slice(&chunk);
        loop {
            match pending.iter().position(|&b| b == b'\n') {
                None => break,
                Some(newline_pos) => {
                    let line_end = if newline_pos > 0 && pending[newline_pos - 1] == b'\r' {
                        newline_pos - 1
                    } else {
                        newline_pos
                    };
                    let line_bytes = pending[..line_end].to_vec();
                    pending.drain(..newline_pos + 1);

                    if line_bytes.is_empty() {
                        if let Some(data) = event_data.take() {
                            if data != "[DONE]" && !data.is_empty() {
                                if let Ok(event_json) = serde_json::from_str::<Value>(&data) {
                                    match provider {
                                        "openai" | "openrouter" => process_openai_sse_event(
                                            &event_json,
                                            &mut state,
                                            session_id,
                                            event_tx,
                                            pii_watchlist,
                                        ),
                                        "gemini" => process_gemini_sse_event(
                                            &event_json,
                                            &mut state,
                                            session_id,
                                            event_tx,
                                            pii_watchlist,
                                        ),
                                        _ => process_sse_event(
                                            &event_json,
                                            &mut state,
                                            session_id,
                                            provider,
                                            event_tx,
                                            pii_watchlist,
                                        ),
                                    }
                                }
                            }
                        }
                    } else if let Ok(line) = std::str::from_utf8(&line_bytes) {
                        if let Some(data) = line.strip_prefix("data: ") {
                            event_data = Some(data.to_string());
                        }
                    }
                }
            }
        }

        // After parsing, decide: buffer or forward.
        if state.holding && write_approval_threshold.is_some() && client_alive {
            hold_buffer.push(chunk.to_vec());
        } else if client_alive {
            let frame_header = format!("{:x}\r\n", chunk.len());
            let write_result = async {
                client_conn.write_all(frame_header.as_bytes()).await?;
                client_conn.write_all(&chunk).await?;
                client_conn.write_all(b"\r\n").await?;
                client_conn.flush().await
            }
            .await;
            if let Err(e) = write_result {
                tracing::warn!(err = %e, "client disconnected mid-stream; continuing for telemetry");
                client_alive = false;
            }
        }

        // Check if a Write/Edit block just completed.
        if let Some((tool_name, input)) = state.pending_approval_data.take() {
            let path_str = input.get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Reject paths that escape the working directory to prevent path traversal.
            let safe_path = std::env::current_dir().ok().and_then(|cwd| {
                let p = std::path::Path::new(&path_str);
                let abs = if p.is_absolute() { p.to_path_buf() } else { cwd.join(p) };
                abs.canonicalize().ok().filter(|canon| canon.starts_with(&cwd))
            });
            if safe_path.is_none() && !path_str.is_empty() {
                tracing::warn!(path = %path_str, "write approval: path rejected (outside cwd or invalid)");
                // Skip approval — treat as no content to diff
            }
            let before = safe_path.as_ref()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .unwrap_or_default();

            let after = if tool_name.eq_ignore_ascii_case("Write") || tool_name.eq_ignore_ascii_case("NotebookEdit") {
                input.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string()
            } else if tool_name.eq_ignore_ascii_case("Edit") {
                let old = input.get("old_string").and_then(|v| v.as_str()).unwrap_or("");
                let new = input.get("new_string").and_then(|v| v.as_str()).unwrap_or("");
                before.replacen(old, new, 1)
            } else {
                // MultiEdit or unknown — use new_string from first edit if available
                input.get("edits")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|e| e.get("new_string"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };

            let risk = vigil_core::score_write(&path_str, &before, &after);

            // Apply path trust tiers: yolo skips approval, watch/lockdown force it.
            let in_yolo     = path_matches_tier(&path_str, yolo_paths);
            let in_watch    = path_matches_tier(&path_str, watch_paths);
            let in_lockdown = path_matches_tier(&path_str, lockdown_paths);

            let needs_approval = if in_yolo {
                false
            } else if in_lockdown || in_watch {
                true
            } else {
                write_approval_threshold.map(|t| risk.level >= t).unwrap_or(false)
            };

            if needs_approval {
                let approval_id = Uuid::new_v4();
                let (approval_tx, approval_rx) = oneshot::channel::<bool>();
                {
                    let mut map = pending_approvals.lock().unwrap();
                    map.insert(approval_id, approval_tx);
                }
                // Use send (not try_send) so the approval request is guaranteed to reach the TUI.
                // If the channel is closed the approval gate must reject — never silently proceed.
                if event_tx.send(TimestampedEvent::new(Event::WriteApprovalRequired {
                    path: path_str.clone(),
                    before: before.clone(),
                    after: after.clone(),
                    risk_level: format!("{:?}", risk.level),
                    reasons: risk.reasons.clone(),
                    session_id,
                    approval_id,
                    is_lockdown: in_lockdown,
                })).await.is_err() {
                    tracing::error!(approval_id = %approval_id, "approval event channel closed — rejecting write");
                    hold_buffer.clear();
                    state.holding = false;
                    state.holding_tool_idx = None;
                    continue;
                }

                // Wait for user decision (with 5-minute timeout).
                let approved = match tokio::time::timeout(
                    tokio::time::Duration::from_secs(300),
                    approval_rx,
                ).await {
                    Ok(Ok(decision)) => decision,
                    Ok(Err(_)) => {
                        tracing::error!(approval_id = %approval_id, "approval channel dropped — rejecting write");
                        false
                    }
                    Err(_) => {
                        tracing::warn!(approval_id = %approval_id, "approval timeout (300s) — rejecting write");
                        false
                    }
                };

                if approved {
                    // Flush the hold buffer and resume.
                    if client_alive {
                        for buffered_chunk in &hold_buffer {
                            let frame_header = format!("{:x}\r\n", buffered_chunk.len());
                            let _ = client_conn.write_all(frame_header.as_bytes()).await;
                            let _ = client_conn.write_all(buffered_chunk).await;
                            let _ = client_conn.write_all(b"\r\n").await;
                        }
                        let _ = client_conn.flush().await;
                    }
                    hold_buffer.clear();
                    state.holding = false;
                    state.holding_tool_idx = None;
                } else {
                    // Rejected: send HTTP 403 with context so the agent can adapt.
                    if client_alive {
                        let reason = if in_lockdown {
                            format!("Write rejected by vigil: '{}' is in a lockdown zone — edit a safer path or ask for approval", path_str)
                        } else if in_watch {
                            format!("Write rejected by vigil: '{}' is in a watched zone", path_str)
                        } else {
                            format!("Write rejected by vigil: '{}' ({:?} risk)", path_str, risk.level)
                        };
                        let resp_str = format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
                            reason.len()
                        );
                        let _ = client_conn.write_all(resp_str.as_bytes()).await;
                        let _ = client_conn.write_all(reason.as_bytes()).await;
                        let _ = client_conn.flush().await;
                    }
                    hold_buffer.clear();
                    return Ok(());
                }
            } else {
                // Below threshold — flush buffer immediately, continue streaming.
                if client_alive {
                    for buffered_chunk in &hold_buffer {
                        let frame_header = format!("{:x}\r\n", buffered_chunk.len());
                        let _ = client_conn.write_all(frame_header.as_bytes()).await;
                        let _ = client_conn.write_all(buffered_chunk).await;
                        let _ = client_conn.write_all(b"\r\n").await;
                    }
                    let _ = client_conn.flush().await;
                }
                hold_buffer.clear();
                state.holding = false;
                state.holding_tool_idx = None;
            }
        }
    }

    // Chunked terminator — best effort, client may already be gone
    if client_alive {
        let _ = client_conn.write_all(b"0\r\n\r\n").await;
        let _ = client_conn.flush().await;
    }

    if state.output_tokens > 0 || state.input_tokens > 0 || state.gemini_finished {
        let cost = cost_usd_with_cache(&state.model, state.input_tokens, state.output_tokens, state.cache_read_input_tokens, state.cache_creation_input_tokens);
        tracing::info!(
            model = %state.model,
            input_tokens = state.input_tokens,
            output_tokens = state.output_tokens,
            cost_usd = cost,
            "LLM response received"
        );
        let response_text = if state.response_text.is_empty() {
            None
        } else {
            Some(state.response_text.clone())
        };
        if let Some(text) = &response_text {
            emit_pii_alert_if_found("llm_response", text, pii_watchlist, session_id, event_tx);
        }
        let raw_response = if !state.raw_tee.is_empty() && !state.raw_tee_capped {
            use base64::Engine as _;
            use flate2::{write::GzEncoder, Compression};
            use std::io::Write as _;
            let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
            enc.write_all(&state.raw_tee)
                .and_then(|_| enc.finish())
                .ok()
                .map(|compressed| base64::engine::general_purpose::STANDARD.encode(&compressed))
        } else {
            None
        };
        let _ = event_tx.try_send(TimestampedEvent::new(Event::LlmResponse {
            provider: provider.to_string(),
            model: state.model.clone(),
            input_tokens: state.input_tokens,
            output_tokens: state.output_tokens,
            cost_usd: cost,
            session_id,
            response_text,
            cache_read_input_tokens: state.cache_read_input_tokens,
            cache_creation_input_tokens: state.cache_creation_input_tokens,
            raw_response,
            stop_reason: state.stop_reason.clone(),
        }));
    }

    Ok(())
}

fn process_sse_event(
    event_json: &Value,
    state: &mut SseState,
    session_id: Uuid,
    provider: &str,
    event_tx: &mpsc::Sender<TimestampedEvent>,
    pii_watchlist: &[String],
) {
    let event_type = event_json.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match event_type {
        "message_start" => {
            if let Some(msg) = event_json.get("message") {
                if let Some(model) = msg.get("model").and_then(|v| v.as_str()) {
                    state.model = model.to_string();
                }
                if let Some(usage) = msg.get("usage") {
                    state.input_tokens = usage
                        .get("input_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    state.cache_read_input_tokens = usage
                        .get("cache_read_input_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    state.cache_creation_input_tokens = usage
                        .get("cache_creation_input_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                }
            }
        }
        "content_block_start" => {
            let idx = event_json
                .get("index")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            if let Some(block) = event_json.get("content_block") {
                let bt = block
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if bt == "tool_use" {
                    let name = block
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let id = block
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if AnthropicAdapter.write_tools().iter().any(|t| name.eq_ignore_ascii_case(t)) {
                        state.holding = true;
                        state.holding_tool_idx = Some(idx);
                    }
                    state.block_name.insert(idx, name);
                    state.block_input.insert(idx, String::new());
                    if !id.is_empty() {
                        state.block_id.insert(idx, id);
                    }
                }
                state.block_type.insert(idx, bt);
            }
        }
        "content_block_delta" => {
            let idx = event_json
                .get("index")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            if let Some(delta) = event_json.get("delta") {
                let delta_type = delta.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if delta_type == "input_json_delta" {
                    if let Some(partial) = delta.get("partial_json").and_then(|v| v.as_str()) {
                        state.block_input.entry(idx).or_default().push_str(partial);
                    }
                } else if delta_type == "text_delta" {
                    if let Some(text) = delta.get("text").and_then(|v| v.as_str()) {
                        const MAX_RESPONSE_TEXT: usize = 1024 * 1024; // 1 MB cap
                        if state.response_text_bytes + text.len() <= MAX_RESPONSE_TEXT {
                            state.response_text.push_str(text);
                            state.response_text_bytes += text.len();
                        }
                    }
                }
            }
        }
        "content_block_stop" => {
            let idx = event_json
                .get("index")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            if state.block_type.get(&idx).map(|s| s == "tool_use").unwrap_or(false) {
                let tool_name = state
                    .block_name
                    .remove(&idx)
                    .unwrap_or_else(|| "unknown".to_string());
                let input_str = state.block_input.remove(&idx).unwrap_or_default();
                let input: Value = match serde_json::from_str(&input_str) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to parse tool_use input JSON, using empty object");
                        json!({})
                    }
                };
                let tool_use_id = state.block_id.remove(&idx);
                tracing::info!(tool = %tool_name, "tool call detected in stream");
                emit_pii_alert_if_found(&tool_name, &input.to_string(), pii_watchlist, session_id, event_tx);
                emit_fs_events_for_tool(&tool_name, &input, session_id, event_tx);
                if AnthropicAdapter.write_tools().iter().any(|t| tool_name.eq_ignore_ascii_case(t)) {
                    state.pending_approval_data = Some((tool_name.clone(), input.clone()));
                }

                // Generate correlation_id and store it for matching with ToolCallResult
                let correlation_id = Some(Uuid::new_v4());
                if let Some(ref id) = tool_use_id {
                    if let Some(corr_id) = correlation_id {
                        state.tool_use_to_correlation.insert(id.clone(), corr_id);
                    }
                }

                let _ = event_tx.try_send(TimestampedEvent::new(Event::ToolCall {
                    agent: "claude".to_string(),
                    tool_name,
                    input,
                    session_id,
                    tool_use_id,
                    correlation_id,
                }));
            }
            state.block_type.remove(&idx);
        }
        "message_delta" => {
            if let Some(usage) = event_json.get("usage") {
                state.output_tokens = usage
                    .get("output_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
            }
        }
        _ => {}
    }

    let _ = provider;
}

fn process_openai_sse_event(
    event_json: &Value,
    state: &mut SseState,
    session_id: Uuid,
    event_tx: &mpsc::Sender<TimestampedEvent>,
    pii_watchlist: &[String],
) {
    if let Some(model) = event_json.get("model").and_then(|v| v.as_str()) {
        if !model.is_empty() {
            state.model = model.to_string();
        }
    }

    if let Some(content) = event_json
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|choice| choice.get("delta"))
        .and_then(|delta| delta.get("content"))
        .and_then(|c| c.as_str())
    {
        const MAX_RESPONSE_TEXT: usize = 1024 * 1024;
        if state.response_text_bytes + content.len() <= MAX_RESPONSE_TEXT {
            state.response_text.push_str(content);
            state.response_text_bytes += content.len();
        }
    }

    if let Some(choices) = event_json.get("choices").and_then(|c| c.as_array()) {
        for choice in choices {
            if let Some(delta) = choice.get("delta") {
                if let Some(tool_calls) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                    for tc in tool_calls {
                        let idx = tc.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                        if let Some(func) = tc.get("function") {
                            if let Some(name) = func.get("name").and_then(|v| v.as_str()) {
                                if !name.is_empty() {
                                    state.block_name.insert(idx, name.to_string());
                                    state.block_input.insert(idx, String::new());
                                    state.block_type.insert(idx, "tool_use".to_string());
                                }
                            }
                            if let Some(args) = func.get("arguments").and_then(|v| v.as_str()) {
                                state.block_input.entry(idx).or_default().push_str(args);
                            }
                        }
                    }
                }
                if choice.get("finish_reason").and_then(|v| v.as_str()) == Some("tool_calls") {
                    for (idx, tool_name) in state.block_name.clone() {
                        let input_str = state.block_input.remove(&idx).unwrap_or_default();
                        let input: Value = serde_json::from_str(&input_str).unwrap_or(json!({}));
                        emit_pii_alert_if_found(&tool_name, &input.to_string(), pii_watchlist, session_id, event_tx);
                        emit_fs_events_for_tool(&tool_name, &input, session_id, event_tx);

                        // Generate correlation_id for OpenAI (no tool_use_id, so we use index as string key)
                        let correlation_id = Some(Uuid::new_v4());
                        let tool_use_id = Some(format!("openai_{}", idx));
                        if let Some(corr_id) = correlation_id {
                            state.tool_use_to_correlation.insert(tool_use_id.clone().unwrap_or_default(), corr_id);
                        }

                        let _ = event_tx.try_send(TimestampedEvent::new(Event::ToolCall {
                            agent: "openai".to_string(),
                            tool_name,
                            input,
                            session_id,
                            tool_use_id,
                            correlation_id,
                        }));
                    }
                    state.block_name.clear();
                    state.block_type.clear();
                }
            }
        }
    }

    if let Some(usage) = event_json.get("usage") {
        if let Some(pt) = usage.get("prompt_tokens").and_then(|v| v.as_u64()) {
            state.input_tokens = pt as u32;
        }
        if let Some(ct) = usage.get("completion_tokens").and_then(|v| v.as_u64()) {
            state.output_tokens = ct as u32;
        }
    }
}

fn process_gemini_sse_event(
    event_json: &Value,
    state: &mut SseState,
    session_id: Uuid,
    event_tx: &mpsc::Sender<TimestampedEvent>,
    pii_watchlist: &[String],
) {
    // Token counts: last-write-wins; only present on final chunk.
    if let Some(usage) = event_json.get("usageMetadata") {
        if let Some(pt) = usage.get("promptTokenCount").and_then(|v| v.as_u64()) {
            state.input_tokens = pt as u32;
        }
        if let Some(ct) = usage.get("candidatesTokenCount").and_then(|v| v.as_u64()) {
            state.output_tokens = ct as u32;
        }
    }

    let candidate = match event_json
        .get("candidates")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
    {
        Some(c) => c,
        None => return,
    };

    if let Some(parts) = candidate
        .get("content")
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
    {
        for part in parts {
            // Skip thinking/reasoning text (Gemini 2.5+ chain-of-thought).
            if part.get("thought").and_then(|v| v.as_bool()) == Some(true) {
                continue;
            }

            // Text part.
            if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                const MAX_RESPONSE_TEXT: usize = 1024 * 1024;
                if state.response_text_bytes + text.len() <= MAX_RESPONSE_TEXT {
                    state.response_text.push_str(text);
                    state.response_text_bytes += text.len();
                }
                continue;
            }

            // Function call part.
            if let Some(fc) = part.get("functionCall") {
                let idx = match state.gemini_active_call_idx {
                    Some(i) => i,
                    None => {
                        let i = state.gemini_next_block_idx;
                        state.gemini_next_block_idx += 1;
                        state.gemini_active_call_idx = Some(i);
                        let name = fc
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        state.block_name.insert(i, name);
                        state.block_type.insert(i, "tool_use".to_string());
                        state.block_input.insert(i, String::new());
                        i
                    }
                };

                // partialArgs is a streaming delta (concat); args is a snapshot (overwrite).
                if let Some(partial) = fc.get("partialArgs").and_then(|v| v.as_str()) {
                    state.block_input.entry(idx).or_default().push_str(partial);
                } else if let Some(args) = fc.get("args") {
                    let s = serde_json::to_string(args).unwrap_or_default();
                    state.block_input.insert(idx, s);
                }

                let will_continue = fc
                    .get("willContinue")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !will_continue {
                    flush_gemini_call(state, idx, session_id, event_tx, pii_watchlist);
                    state.gemini_active_call_idx = None;
                }
            }
        }
    }

    // End-of-stream signal.
    if let Some(reason) = candidate.get("finishReason").and_then(|v| v.as_str()) {
        if !reason.is_empty() {
            // Defensive flush: close any still-open call.
            if let Some(idx) = state.gemini_active_call_idx.take() {
                flush_gemini_call(state, idx, session_id, event_tx, pii_watchlist);
            }
            state.gemini_finished = true;
        }
    }
}

fn flush_gemini_call(
    state: &mut SseState,
    idx: usize,
    session_id: Uuid,
    event_tx: &mpsc::Sender<TimestampedEvent>,
    pii_watchlist: &[String],
) {
    let raw_name = state.block_name.remove(&idx).unwrap_or_else(|| "unknown".to_string());
    let input_str = state.block_input.remove(&idx).unwrap_or_default();
    let input: Value = serde_json::from_str(&input_str).unwrap_or(json!({}));
    state.block_type.remove(&idx);

    // Canonicalize Gemini tool names so downstream pipeline (fs-events, drift, exfil)
    // sees the same names it expects from Claude Code ("Write", "Edit", "Read", etc.).
    let tool_name = GeminiAdapter.canonical_tool_name(&raw_name).to_string();

    emit_pii_alert_if_found(&tool_name, &input.to_string(), pii_watchlist, session_id, event_tx);
    emit_fs_events_for_tool(&tool_name, &input, session_id, event_tx);

    // Write-approval gate: set hold if this is a write tool.
    // NOTE: unlike Anthropic, the current SSE chunk has already been forwarded
    // by the time we detect the tool name here. Subsequent chunks are held.
    if GeminiAdapter.write_tools().iter().any(|t| raw_name.eq_ignore_ascii_case(t)) {
        state.pending_approval_data = Some((tool_name.clone(), input.clone()));
        state.holding = true;
        state.holding_tool_idx = Some(idx);
    }

    // Generate correlation_id for Gemini tool calls
    let correlation_id = Some(Uuid::new_v4());

    let _ = event_tx.try_send(TimestampedEvent::new(Event::ToolCall {
        agent: "gemini".to_string(),
        tool_name,
        input,
        session_id,
        tool_use_id: None,
        correlation_id,
    }));
}

fn emit_pii_alert_if_found(
    source: &str,
    text: &str,
    watchlist: &[String],
    session_id: Uuid,
    event_tx: &mpsc::Sender<TimestampedEvent>,
) {
    let mut hits = scan_pii(text);
    hits.extend(scan_watchlist(text, watchlist));
    if hits.is_empty() {
        return;
    }
    let kinds: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        hits.iter()
            .filter(|h| seen.insert(h.kind.clone()))
            .map(|h| h.kind.clone())
            .collect()
    };
    tracing::warn!(source = source, ?kinds, "PII detected");
    let _ = event_tx.try_send(TimestampedEvent::new(Event::PiiAlert {
        source: source.to_string(),
        kinds,
        session_id,
    }));
}

/// Rewrite `tool_result` content blocks whose `tool_use_id` is in `pending_denials`.
/// Returns the (possibly modified) body. Removes matched entries from the map.
/// The rewritten content tells the LLM the tool was denied by policy so it can
/// continue on safe work rather than waiting for a result that will never arrive.
fn rewrite_denied_tool_results(body: bytes::Bytes, pending_denials: &PendingDenials) -> bytes::Bytes {
    let mut denials = pending_denials.lock().unwrap();
    if denials.is_empty() {
        return body;
    }
    let mut json: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return body,
    };
    let messages = match json.get_mut("messages").and_then(|v| v.as_array_mut()) {
        Some(m) => m,
        None => return body,
    };
    let mut rewrote = false;
    for msg in messages.iter_mut() {
        if msg.get("role").and_then(|r| r.as_str()) != Some("user") {
            continue;
        }
        let content = match msg.get_mut("content").and_then(|v| v.as_array_mut()) {
            Some(c) => c,
            None => continue,
        };
        for block in content.iter_mut() {
            if block.get("type").and_then(|t| t.as_str()) != Some("tool_result") {
                continue;
            }
            let id = match block.get("tool_use_id").and_then(|v| v.as_str()) {
                Some(id) => id.to_string(),
                None => continue,
            };
            if let Some(denial) = denials.remove(&id) {
                let msg = format!(
                    "vigil policy denial: {}\nPolicy: {}\nAttempted tool: {}\nAttempted input: {}\n\
                     This operation was blocked. You may continue with other safe work.",
                    denial.reason.as_deref().unwrap_or("operation not permitted"),
                    denial.policy_name.as_deref().unwrap_or("unnamed-policy"),
                    denial.tool_name,
                    denial.input_summary,
                );
                *block = json!({
                    "type": "tool_result",
                    "tool_use_id": id,
                    "is_error": true,
                    "content": msg,
                });
                rewrote = true;
                tracing::info!(tool_use_id = %id, tool = %denial.tool_name, "injected policy denial into tool_result");
            }
        }
    }
    if rewrote {
        match serde_json::to_vec(&json) {
            Ok(b) => bytes::Bytes::from(b),
            Err(_) => body,
        }
    } else {
        body
    }
}

/// Scan all `tool_result` content blocks in an outbound request body for prompt
/// injection patterns. For each finding, emit a `PromptInjectionAlert` event.
fn scan_tool_results_for_injection(
    body: &Value,
    session_id: Uuid,
    event_tx: &mpsc::Sender<TimestampedEvent>,
) {
    let messages = match body.get("messages").and_then(|v| v.as_array()) {
        Some(m) => m,
        None => return,
    };
    for msg in messages {
        if msg.get("role").and_then(|r| r.as_str()) != Some("user") {
            continue;
        }
        let content = match msg.get("content").and_then(|v| v.as_array()) {
            Some(c) => c,
            None => continue,
        };
        for block in content {
            if block.get("type").and_then(|t| t.as_str()) != Some("tool_result") {
                continue;
            }
            // tool_use_id is the name proxy for tool results; fall back to "unknown"
            let tool_name = block
                .get("tool_use_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            // Content may be a plain string or an array of text blocks
            let texts: Vec<String> = match block.get("content") {
                Some(Value::String(s)) => vec![s.clone()],
                Some(Value::Array(blocks)) => blocks
                    .iter()
                    .filter_map(|b| {
                        if b.get("type").and_then(|t| t.as_str()) == Some("text") {
                            b.get("text").and_then(|t| t.as_str()).map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                    .collect(),
                _ => continue,
            };

            for text in &texts {
                if text.is_empty() {
                    continue;
                }
                let findings = scan_for_injection(text);
                if findings.is_empty() {
                    continue;
                }
                let f = &findings[0];
                tracing::warn!(
                    tool_name = %tool_name,
                    category = f.category,
                    "prompt injection pattern detected in tool result"
                );
                let _ = event_tx.try_send(TimestampedEvent::new(Event::PromptInjectionAlert {
                    session_id,
                    tool_name: tool_name.clone(),
                    category: f.category.to_string(),
                    snippet: f.snippet.clone(),
                }));
            }
        }
    }
}

/// Compute diff statistics from before/after strings using the similar crate.
fn compute_diff_stats(before: &str, after: &str) -> (u32, u32, u32) {
    use similar::TextDiff;

    let diff = TextDiff::from_lines(before, after);
    let mut lines_added = 0u32;
    let mut lines_removed = 0u32;
    let mut hunk_count = 0u32;
    let mut in_hunk = false;

    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Delete => {
                lines_removed += 1;
                if !in_hunk {
                    hunk_count += 1;
                    in_hunk = true;
                }
            }
            similar::ChangeTag::Insert => {
                lines_added += 1;
                if !in_hunk {
                    hunk_count += 1;
                    in_hunk = true;
                }
            }
            similar::ChangeTag::Equal => {
                in_hunk = false;
            }
        }
    }

    (lines_added, lines_removed, hunk_count)
}

/// Derive FsRead / FsWrite events from a tool call's name and input JSON,
/// and send them immediately after the ToolCall event.
fn emit_fs_events_for_tool(
    tool_name: &str,
    input: &Value,
    session_id: Uuid,
    event_tx: &mpsc::Sender<TimestampedEvent>,
) {
    let path = |key: &str| -> Option<String> {
        input.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
    };

    let evt = match tool_name {
        "Read" => path("file_path").map(|p| Event::FsRead { path: p, session_id }),

        "Write" => match path("file_path") {
            None => return,
            Some(p) => {
                let bytes = input
                    .get("content")
                    .and_then(|v| v.as_str())
                    .map(|s| s.len() as u64)
                    .unwrap_or(0);
                Some(Event::FsWrite { path: p, bytes, session_id, lines_added: 0, lines_removed: 0, hunk_count: 0 })
            }
        }

        "Edit" | "MultiEdit" => {
            match path("file_path") {
                None => return,
                Some(p) => {
                    // For Edit, try to extract before/after from the edit edits array
                    let before = input
                        .get("edits")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|e| e.get("old_string"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    let after = input
                        .get("edits")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|e| e.get("new_string"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    let (lines_added, lines_removed, hunk_count) = if !before.is_empty() || !after.is_empty() {
                        compute_diff_stats(before, after)
                    } else {
                        (0, 0, 0)
                    };

                    Some(Event::FsWrite { path: p, bytes: 0, session_id, lines_added, lines_removed, hunk_count })
                }
            }
        }

        "NotebookEdit" => path("notebook_path").map(|p| Event::FsWrite { path: p, bytes: 0, session_id, lines_added: 0, lines_removed: 0, hunk_count: 0 }),

        "Glob" | "Grep" => path("pattern")
            .or_else(|| path("path"))
            .map(|p| Event::FsRead { path: p, session_id }),

        _ => return,
    };

    if let Some(e) = evt {
        let _ = event_tx.try_send(TimestampedEvent::new(e));
    }
}

/// Extract the text of the last user message from a request body.
fn extract_last_user_message(body: &Value) -> Option<String> {
    let messages = body.get("messages")?.as_array()?;
    let last_user = messages
        .iter()
        .rev()
        .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))?;
    content_to_text(last_user.get("content")?)
}

/// Extract the system prompt text from a request body.
fn extract_system_prompt(body: &Value) -> Option<String> {
    content_to_text(body.get("system")?)
}

/// Convert an Anthropic content field (string or array of blocks) to plain text.
fn content_to_text(content: &Value) -> Option<String> {
    match content {
        Value::String(s) => Some(s.clone()),
        Value::Array(blocks) => {
            let text: String = blocks
                .iter()
                .filter_map(|b| {
                    if b.get("type").and_then(|t| t.as_str()) == Some("text") {
                        b.get("text").and_then(|t| t.as_str()).map(|s| s.to_string())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            if text.is_empty() { None } else { Some(text) }
        }
        _ => None,
    }
}

fn emit_llm_request(
    provider: &str,
    path: &str,
    body: &[u8],
    session_id: Uuid,
    event_tx: &mpsc::Sender<TimestampedEvent>,
) {
    if body.is_empty() {
        return;
    }
    if let Ok(json) = serde_json::from_slice::<Value>(body) {
        let model = json
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        if (provider == "anthropic" && path.contains("/messages"))
            || ((provider == "openai" || provider == "openrouter")
                && path.contains("/chat/completions"))
        {
            let last_user_message = extract_last_user_message(&json);
            let system_prompt = extract_system_prompt(&json);
            let raw_request = {
                use base64::Engine as _;
                Some(base64::engine::general_purpose::STANDARD.encode(json.to_string()))
            };

            // Increment turn counter for non-streaming responses
            static TURN_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let turn_number = TURN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;

            let _ = event_tx.try_send(TimestampedEvent::new(Event::LlmRequest {
                provider: provider.to_string(),
                model,
                input_tokens: 0,
                session_id,
                last_user_message,
                system_prompt,
                raw_request,
                turn_number,
            }));
        }
    }
}

fn parse_llm_response(
    provider: &str,
    body: &[u8],
    session_id: Uuid,
    event_tx: &mpsc::Sender<TimestampedEvent>,
) {
    // Strip HTTP response headers to find JSON body
    let text = String::from_utf8_lossy(body);
    let body_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let json_bytes = &body[body_start..];
    if json_bytes.is_empty() {
        return;
    }
    if let Ok(json) = serde_json::from_slice::<Value>(json_bytes) {
        match provider {
            "anthropic" => emit_anthropic_response(&json, session_id, event_tx, &[]),
            _ => emit_openai_response(&json, session_id, event_tx),
        }
    }
}

fn emit_anthropic_response(
    json: &Value,
    session_id: Uuid,
    event_tx: &mpsc::Sender<TimestampedEvent>,
    pii_watchlist: &[String],
) {
    let model = json
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let input_tokens = json
        .get("usage")
        .and_then(|u| u.get("input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let output_tokens = json
        .get("usage")
        .and_then(|u| u.get("output_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let cache_read_input_tokens = json
        .get("usage")
        .and_then(|u| u.get("cache_read_input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let cache_creation_input_tokens = json
        .get("usage")
        .and_then(|u| u.get("cache_creation_input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let cost = cost_usd_with_cache(&model, input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens);
    tracing::info!(model = %model, input_tokens, output_tokens, "non-streaming LLM response parsed");

    let response_text = json
        .get("content")
        .and_then(|c| c.as_array())
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| {
                    if b.get("type").and_then(|t| t.as_str()) == Some("text") {
                        b.get("text").and_then(|t| t.as_str()).map(|s| s.to_string())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|s| !s.is_empty());

    if let Some(text) = &response_text {
        emit_pii_alert_if_found("llm_response", text, pii_watchlist, session_id, event_tx);
    }

    let stop_reason = json
        .get("stop_reason")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let _ = event_tx.try_send(TimestampedEvent::new(Event::LlmResponse {
        provider: "anthropic".to_string(),
        model: model.clone(),
        input_tokens,
        output_tokens,
        cost_usd: cost,
        session_id,
        response_text,
        cache_read_input_tokens,
        cache_creation_input_tokens,
        raw_response: None,
        stop_reason,
    }));

    if let Some(content) = json.get("content").and_then(|v| v.as_array()) {
        for item in content {
            if item.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                if let Some(tool_name) = item.get("name").and_then(|v| v.as_str()) {
                    let input = item.get("input").cloned().unwrap_or(json!({}));
                    let tool_use_id = item.get("id").and_then(|v| v.as_str()).map(|s| s.to_string());

                    // Generate correlation_id for non-streaming response
                    let correlation_id = Some(Uuid::new_v4());

                    emit_pii_alert_if_found(tool_name, &input.to_string(), pii_watchlist, session_id, event_tx);
                    emit_fs_events_for_tool(tool_name, &input, session_id, event_tx);
                    let _ = event_tx.try_send(TimestampedEvent::new(Event::ToolCall {
                        agent: "claude".to_string(),
                        tool_name: tool_name.to_string(),
                        input,
                        session_id,
                        tool_use_id,
                        correlation_id,
                    }));
                }
            }
        }
    }
}

fn emit_openai_response(
    json: &Value,
    session_id: Uuid,
    event_tx: &mpsc::Sender<TimestampedEvent>,
) {
    let model = json
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let input_tokens = json
        .get("usage")
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let output_tokens = json
        .get("usage")
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let cost = cost_usd(&model, input_tokens, output_tokens);

    let response_text = json
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|choices| choices.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    let stop_reason = json
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|choices| choices.first())
        .and_then(|c| c.get("finish_reason"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let _ = event_tx.try_send(TimestampedEvent::new(Event::LlmResponse {
        provider: "openai".to_string(),
        model,
        input_tokens,
        output_tokens,
        cost_usd: cost,
        session_id,
        response_text,
        cache_read_input_tokens: 0,
        cache_creation_input_tokens: 0,
        raw_response: None,
        stop_reason,
    }));

    if let Some(choices) = json.get("choices").and_then(|v| v.as_array()) {
        for choice in choices {
            if let Some(message) = choice.get("message") {
                if let Some(tool_calls) = message.get("tool_calls").and_then(|v| v.as_array()) {
                    for tc in tool_calls {
                        if let Some(function) = tc.get("function") {
                            if let Some(tool_name) = function.get("name").and_then(|v| v.as_str()) {
                                let input = function
                                    .get("arguments")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
                                    .unwrap_or(json!({}));

                                // Generate correlation_id for non-streaming response
                                let correlation_id = Some(Uuid::new_v4());

                                let _ = event_tx.try_send(TimestampedEvent::new(Event::ToolCall {
                                    agent: "openai".to_string(),
                                    tool_name: tool_name.to_string(),
                                    input,
                                    session_id,
                                    tool_use_id: None,
                                    correlation_id,
                                }));
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn cost_usd(model: &str, input_tokens: u32, output_tokens: u32) -> f64 {
    let (input_cost, output_cost) = vigil_core::pricing::PricingTable::global().lookup(model);
    (input_tokens as f64 / 1_000_000.0) * input_cost
        + (output_tokens as f64 / 1_000_000.0) * output_cost
}

pub fn cost_usd_with_cache(model: &str, input_tokens: u32, output_tokens: u32, cache_read: u32, cache_creation: u32) -> f64 {
    let (input_cost, output_cost) = vigil_core::pricing::PricingTable::global().lookup(model);
    (input_tokens as f64 / 1_000_000.0) * input_cost
        + (output_tokens as f64 / 1_000_000.0) * output_cost
        + (cache_read as f64 / 1_000_000.0) * input_cost * 0.1
        + (cache_creation as f64 / 1_000_000.0) * input_cost * 1.25
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_gemini_model_from_path() {
        assert_eq!(
            extract_gemini_model_from_path("/v1beta/models/gemini-3-flash:streamGenerateContent"),
            Some("gemini-3-flash".to_string())
        );
        assert_eq!(
            extract_gemini_model_from_path("/v1beta/models/gemini-2.5-flash-lite:generateContent"),
            Some("gemini-2.5-flash-lite".to_string())
        );
        assert_eq!(extract_gemini_model_from_path("/v1/messages"), None);
        assert_eq!(extract_gemini_model_from_path(""), None);
    }

    #[test]
    fn test_detect_provider_anthropic() {
        assert_eq!(detect_provider("api.anthropic.com"), Some("anthropic"));
    }

    #[test]
    fn test_detect_provider_openai() {
        assert_eq!(detect_provider("api.openai.com"), Some("openai"));
    }

    #[test]
    fn test_detect_provider_unknown() {
        assert_eq!(detect_provider("unknown.com"), None);
    }

    #[test]
    fn test_cost_usd_claude_sonnet() {
        let cost = cost_usd("claude-sonnet-4-6-20251201", 1_000_000, 1_000_000);
        assert_eq!(cost, 18.0);
    }

    #[test]
    fn test_cost_usd_gpt4o() {
        let cost = cost_usd("gpt-4o", 1_000_000, 1_000_000);
        assert_eq!(cost, 12.50);
    }

    #[test]
    fn test_is_allowed_connect_host_blocks_ssh() {
        assert!(!is_allowed_connect_host("127.0.0.1:22"));
    }

    #[test]
    fn test_is_allowed_connect_host_allows_anthropic() {
        assert!(is_allowed_connect_host("api.anthropic.com:443"));
    }

    #[test]
    fn test_parse_http_headers_joins_duplicates() {
        let raw = b"POST /v1/messages HTTP/1.1\r\nHost: localhost\r\nanthropic-beta: feat-a\r\nanthropic-beta: feat-b\r\n\r\n";
        let (_, _, _, headers, _) = parse_http_headers(raw).unwrap();
        assert_eq!(headers.get("anthropic-beta").unwrap(), "feat-a, feat-b");
    }

    #[test]
    fn test_parse_http_headers_single_value_unchanged() {
        let raw = b"POST /v1/messages HTTP/1.1\r\nHost: localhost\r\nx-api-key: sk-123\r\n\r\n";
        let (_, _, _, headers, _) = parse_http_headers(raw).unwrap();
        assert_eq!(headers.get("x-api-key").unwrap(), "sk-123");
    }

    #[test]
    fn test_response_header_allowlist_blocks_injected_headers() {
        // Simulate what an upstream could send to try to inject headers.
        // build_allowed_response_headers should only pass safe headers through.
        let dangerous = [
            "set-cookie",
            "x-custom-injected",
            "location",
            "www-authenticate",
            "proxy-authenticate",
        ];
        for h in &dangerous {
            assert!(
                !ALLOWED_RESP_HEADERS.contains(h),
                "dangerous header '{}' must not be in the allowlist",
                h
            );
        }
    }

    #[test]
    fn test_response_header_allowlist_passes_safe_headers() {
        let safe = ["content-type", "cache-control", "x-request-id", "retry-after"];
        for h in &safe {
            assert!(
                ALLOWED_RESP_HEADERS.contains(h),
                "safe header '{}' should be in the allowlist",
                h
            );
        }
    }

    // ── Gemini SSE state machine tests ─────────────────────────────────────

    fn make_gemini_text_chunk(text: &str) -> Value {
        json!({
            "candidates": [{
                "content": {"parts": [{"text": text}], "role": "model"}
            }]
        })
    }

    fn make_gemini_tool_chunk(name: &str, args: Value, will_continue: bool) -> Value {
        json!({
            "candidates": [{
                "content": {
                    "parts": [{"functionCall": {"name": name, "args": args, "willContinue": will_continue}}],
                    "role": "model"
                }
            }]
        })
    }

    fn make_gemini_final_chunk(finish_reason: &str, prompt_tokens: u32, candidate_tokens: u32) -> Value {
        json!({
            "candidates": [{"content": {"parts": [], "role": "model"}, "finishReason": finish_reason}],
            "usageMetadata": {"promptTokenCount": prompt_tokens, "candidatesTokenCount": candidate_tokens}
        })
    }

    #[test]
    fn gemini_text_accumulates_in_response_text() {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let mut state = SseState { model: "gemini-3-flash".to_string(), ..Default::default() };
        let sid = Uuid::new_v4();
        process_gemini_sse_event(&make_gemini_text_chunk("hello "), &mut state, sid, &tx, &[]);
        process_gemini_sse_event(&make_gemini_text_chunk("world"), &mut state, sid, &tx, &[]);
        assert_eq!(state.response_text, "hello world");
    }

    #[test]
    fn gemini_token_counts_extracted_from_final_chunk() {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let mut state = SseState { model: "gemini-3-flash".to_string(), ..Default::default() };
        let sid = Uuid::new_v4();
        process_gemini_sse_event(&make_gemini_text_chunk("hello"), &mut state, sid, &tx, &[]);
        process_gemini_sse_event(&make_gemini_final_chunk("STOP", 10, 5), &mut state, sid, &tx, &[]);
        assert_eq!(state.input_tokens, 10);
        assert_eq!(state.output_tokens, 5);
        assert!(state.gemini_finished);
    }

    #[test]
    fn gemini_tool_call_emits_event() {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let mut state = SseState { model: "gemini-3-flash".to_string(), ..Default::default() };
        let sid = Uuid::new_v4();
        let chunk = make_gemini_tool_chunk("read_file", json!({"path": "/foo.rs"}), false);
        process_gemini_sse_event(&chunk, &mut state, sid, &tx, &[]);
        drop(tx);
        // Should have emitted a ToolCall event with canonical name "Read"
        let mut events = vec![];
        let mut rx = rx;
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        assert!(events.iter().any(|e| matches!(&e.event, Event::ToolCall { tool_name, .. } if tool_name == "Read")));
    }

    #[test]
    fn gemini_tool_call_canonical_write_file_sets_hold() {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let mut state = SseState { model: "gemini-3-flash".to_string(), ..Default::default() };
        let sid = Uuid::new_v4();
        let chunk = make_gemini_tool_chunk("write_file", json!({"path": "/out.rs", "content": "fn main(){}"}), false);
        process_gemini_sse_event(&chunk, &mut state, sid, &tx, &[]);
        assert!(state.holding, "write_file should set state.holding");
        assert!(state.pending_approval_data.is_some());
    }

    #[test]
    fn gemini_safety_finish_sets_gemini_finished_with_zero_tokens() {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let mut state = SseState { model: "gemini-3-flash".to_string(), ..Default::default() };
        let sid = Uuid::new_v4();
        process_gemini_sse_event(&make_gemini_final_chunk("SAFETY", 0, 0), &mut state, sid, &tx, &[]);
        assert!(state.gemini_finished);
        assert_eq!(state.input_tokens, 0);
    }

    #[test]
    fn gemini_thought_parts_not_added_to_response_text() {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let mut state = SseState { model: "gemini-2.5-flash".to_string(), ..Default::default() };
        let sid = Uuid::new_v4();
        let chunk = json!({
            "candidates": [{"content": {"parts": [
                {"thought": true, "text": "reasoning..."},
                {"text": "answer"}
            ], "role": "model"}}]
        });
        process_gemini_sse_event(&chunk, &mut state, sid, &tx, &[]);
        assert_eq!(state.response_text, "answer");
        assert!(!state.response_text.contains("reasoning"));
    }

    #[test]
    fn gemini_two_sequential_tool_calls_get_distinct_indices() {
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let mut state = SseState { model: "gemini-3-flash".to_string(), ..Default::default() };
        let sid = Uuid::new_v4();
        let c1 = make_gemini_tool_chunk("read_file",  json!({"path": "/a.rs"}), false);
        let c2 = make_gemini_tool_chunk("write_file", json!({"path": "/b.rs", "content": "x"}), false);
        process_gemini_sse_event(&c1, &mut state, sid, &tx, &[]);
        process_gemini_sse_event(&c2, &mut state, sid, &tx, &[]);
        assert_eq!(state.gemini_next_block_idx, 2);
        assert!(state.gemini_active_call_idx.is_none());
    }

    #[test]
    fn turn_number_increments_per_llm_request() {
        // Verify that turn_number increases monotonically for successive LlmRequest events.
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let sid = Uuid::new_v4();

        let req1 = Event::LlmRequest {
            provider: "anthropic".into(),
            model: "claude".into(),
            input_tokens: 0,
            session_id: sid,
            last_user_message: None,
            system_prompt: None,
            raw_request: None,
            turn_number: 1,
        };

        let req2 = Event::LlmRequest {
            provider: "anthropic".into(),
            model: "claude".into(),
            input_tokens: 0,
            session_id: sid,
            last_user_message: None,
            system_prompt: None,
            raw_request: None,
            turn_number: 2,
        };

        let _ = tx.try_send(TimestampedEvent::new(req1));
        let _ = tx.try_send(TimestampedEvent::new(req2));
        drop(tx);

        let mut events = vec![];
        while let Ok(ev) = rx.try_recv() {
            if let Event::LlmRequest { turn_number, .. } = &ev.event {
                events.push(*turn_number);
            }
        }

        assert_eq!(events.len(), 2);
        assert_eq!(events[0], 1);
        assert_eq!(events[1], 2);
    }

    #[test]
    fn tool_call_correlation_id_matches_result() {
        // Verify that a ToolCall event has the same correlation_id as its paired ToolCallResult.
        let correlation_id = Uuid::new_v4();
        let sid = Uuid::new_v4();

        let tool_call = Event::ToolCall {
            agent: "claude".into(),
            tool_name: "Read".into(),
            input: json!({"file_path": "/test.rs"}),
            session_id: sid,
            tool_use_id: Some("id_1".into()),
            correlation_id: Some(correlation_id),
        };

        let tool_result = Event::ToolCallResult {
            agent: "claude".into(),
            tool_name: "Read".into(),
            blocked: false,
            session_id: sid,
            correlation_id: Some(correlation_id),
            duration_ms: Some(100),
            is_error: false,
        };

        if let Event::ToolCall { correlation_id: call_corr, .. } = &tool_call {
            if let Event::ToolCallResult { correlation_id: result_corr, .. } = &tool_result {
                assert_eq!(call_corr, result_corr, "ToolCall and ToolCallResult must have matching correlation_id");
            }
        }
    }

    #[test]
    fn tool_call_result_is_error_true_when_flagged() {
        // Verify that is_error flag is properly captured in ToolCallResult.
        let sid = Uuid::new_v4();

        let error_result = Event::ToolCallResult {
            agent: "claude".into(),
            tool_name: "Bash".into(),
            blocked: false,
            session_id: sid,
            correlation_id: None,
            duration_ms: Some(50),
            is_error: true,  // Error case
        };

        if let Event::ToolCallResult { is_error, .. } = &error_result {
            assert!(*is_error, "is_error should be true for error results");
        }

        let success_result = Event::ToolCallResult {
            agent: "claude".into(),
            tool_name: "Bash".into(),
            blocked: false,
            session_id: sid,
            correlation_id: None,
            duration_ms: Some(50),
            is_error: false,  // Success case
        };

        if let Event::ToolCallResult { is_error, .. } = &success_result {
            assert!(!*is_error, "is_error should be false for successful results");
        }
    }

    #[test]
    fn fswrite_hunk_count_from_diff() {
        // Verify that hunk_count is computed correctly from a before/after diff.
        let before = "line 1\nline 2\nline 3\n";
        let after = "line 1\nmodified line 2\nline 3\nnew line 4\n";

        let (lines_added, lines_removed, hunk_count) = compute_diff_stats(before, after);

        // before has 3 lines, after has 4 lines
        // Diff should show: 1 deletion (line 2), 1 insertion (modified line 2), 1 insertion (new line 4)
        // That's 2 lines added (modified + new), 1 line removed
        assert_eq!(lines_removed, 1, "should have 1 line removed");
        assert_eq!(lines_added, 2, "should have 2 lines added");
        assert!(hunk_count > 0, "should have at least 1 hunk");
    }

    #[test]
    fn stop_reason_captured_from_llm() {
        // Verify that stop_reason is properly captured from LLM responses.
        let sid = Uuid::new_v4();

        let resp_with_stop_reason = Event::LlmResponse {
            provider: "anthropic".into(),
            model: "claude".into(),
            input_tokens: 10,
            output_tokens: 20,
            cost_usd: 0.001,
            session_id: sid,
            response_text: None,
            cache_read_input_tokens: 0,
            cache_creation_input_tokens: 0,
            raw_response: None,
            stop_reason: Some("end_turn".into()),
        };

        if let Event::LlmResponse { stop_reason, .. } = &resp_with_stop_reason {
            assert_eq!(
                stop_reason.as_ref().map(|s| s.as_str()),
                Some("end_turn"),
                "stop_reason should be captured"
            );
        }

        let resp_without_stop_reason = Event::LlmResponse {
            provider: "openai".into(),
            model: "gpt-4o".into(),
            input_tokens: 10,
            output_tokens: 20,
            cost_usd: 0.01,
            session_id: sid,
            response_text: None,
            cache_read_input_tokens: 0,
            cache_creation_input_tokens: 0,
            raw_response: None,
            stop_reason: None,
        };

        if let Event::LlmResponse { stop_reason, .. } = &resp_without_stop_reason {
            assert!(stop_reason.is_none(), "stop_reason can be None");
        }
    }
}

#[cfg(test)]
mod integration {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{sleep, Duration};
    use vigil_core::Event;

    // Starts a mock HTTP server. Every accepted connection is handled in a spawned
    // task: the raw request bytes are captured, then `response` is written back.
    // Returns (bound address, shared list of captured raw requests).
    async fn mock_server(response: Vec<u8>) -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(vec![]));
        let cap2 = captured.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = listener.accept().await else { return };
                let resp = response.clone();
                let cap = cap2.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let n = conn.read(&mut buf).await.unwrap_or(0);
                    cap.lock().unwrap().push(buf[..n].to_vec());
                    let _ = conn.write_all(&resp).await;
                    let _ = conn.flush().await;
                });
            }
        });

        (addr, captured)
    }

    // Spawns a proxy with handle_connection called directly so we can bind to port 0
    // and discover the actual address. Returns (proxy addr, event receiver).
    async fn spawn_proxy(
        upstream: Option<SocketAddr>,
    ) -> (SocketAddr, mpsc::Receiver<TimestampedEvent>) {
        let (event_tx, event_rx) = mpsc::channel(256);
        let upstream_override = upstream.map(|a| format!("http://{}", a));
        let config = ProxyConfig {
            port: 0,
            ca_cert_path: None,
            upstream_override,
            pii_watchlist: vec![],
            write_approval_threshold: None,
            outbound_hook: None,
            pending_denials: Arc::new(Mutex::new(HashMap::new())),
            yolo_paths: vec![],
            watch_paths: vec![],
            lockdown_paths: vec![],
        };
        let http_client = reqwest::Client::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let tx = event_tx.clone();
                let client = http_client.clone();
                let cfg = config.clone();
                let approvals: PendingApprovals = Arc::new(Mutex::new(HashMap::new()));
                tokio::spawn(async move {
                    let _ = handle_connection(stream, tx, client, cfg, approvals).await;
                });
            }
        });

        (addr, event_rx)
    }

    // Build a raw HTTP request as bytes.
    fn make_request(method: &str, path: &str, extra_headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut req = format!("{} {} HTTP/1.1\r\nhost: 127.0.0.1\r\n", method, path);
        for (k, v) in extra_headers {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
        if !body.is_empty() {
            req.push_str(&format!("content-length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");
        let mut bytes = req.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    // Parse the HTTP status code from the first line of a raw response.
    fn status(resp: &[u8]) -> u16 {
        std::str::from_utf8(resp)
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .unwrap_or("0")
            .parse()
            .unwrap_or(0)
    }

    // Build a minimal valid JSON HTTP response.
    fn json_resp(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    // Send raw bytes to the proxy and read back the full response.
    async fn round_trip(proxy_addr: SocketAddr, req: &[u8]) -> Vec<u8> {
        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();
        conn.write_all(req).await.unwrap();
        conn.flush().await.unwrap();
        let mut resp = vec![0u8; 32768];
        let n = conn.read(&mut resp).await.unwrap_or(0);
        resp.truncate(n);
        resp
    }

    #[tokio::test]
    async fn non_streaming_round_trip() {
        let upstream_body = r#"{"id":"msg_1","model":"claude-sonnet-4-6","usage":{"input_tokens":10,"output_tokens":5},"content":[]}"#;
        let (mock_addr, captured) = mock_server(json_resp(upstream_body)).await;
        let (proxy_addr, _rx) = spawn_proxy(Some(mock_addr)).await;

        let req = make_request("POST", "/v1/messages", &[], b"{}");
        let resp = round_trip(proxy_addr, &req).await;

        assert_eq!(status(&resp), 200, "expected 200, got: {}", String::from_utf8_lossy(&resp));
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains(r#""id":"msg_1""#));
        assert_eq!(captured.lock().unwrap().len(), 1, "mock should have received one request");
    }

    #[tokio::test]
    async fn split_header_read() {
        // Verify the header read loop handles TCP segmentation — headers arrive in two writes.
        let (mock_addr, _) = mock_server(json_resp("{}")).await;
        let (proxy_addr, _rx) = spawn_proxy(Some(mock_addr)).await;

        let full = make_request("POST", "/v1/messages", &[], b"{}");
        // Split after the first line so the header block definitely arrives in two reads.
        let split = full.iter().position(|&b| b == b'\n').unwrap() + 1;

        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();
        conn.write_all(&full[..split]).await.unwrap();
        conn.flush().await.unwrap();
        sleep(Duration::from_millis(10)).await;
        conn.write_all(&full[split..]).await.unwrap();
        conn.flush().await.unwrap();

        let mut resp = vec![0u8; 4096];
        let n = conn.read(&mut resp).await.unwrap();
        assert_eq!(status(&resp[..n]), 200);
    }

    #[tokio::test]
    async fn split_body_read() {
        // Verify the body read loop handles a body arriving in two TCP writes.
        let body = b"{\"model\":\"claude-sonnet-4-6\",\"messages\":[]}";
        let (mock_addr, captured) = mock_server(json_resp("{}")).await;
        let (proxy_addr, _rx) = spawn_proxy(Some(mock_addr)).await;

        let header_block = format!(
            "POST /v1/messages HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );

        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();
        conn.write_all(header_block.as_bytes()).await.unwrap();
        conn.flush().await.unwrap();
        sleep(Duration::from_millis(10)).await;
        let half = body.len() / 2;
        conn.write_all(&body[..half]).await.unwrap();
        conn.flush().await.unwrap();
        sleep(Duration::from_millis(10)).await;
        conn.write_all(&body[half..]).await.unwrap();
        conn.flush().await.unwrap();

        let mut resp = vec![0u8; 4096];
        let n = conn.read(&mut resp).await.unwrap();
        assert_eq!(status(&resp[..n]), 200);

        // Give the mock a moment to record the request, then verify it got the complete body.
        sleep(Duration::from_millis(20)).await;
        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let req_text = String::from_utf8_lossy(&reqs[0]);
        assert!(req_text.contains(r#""messages":[]"#), "mock should have received the complete body");
    }

    #[tokio::test]
    async fn duplicate_headers_joined() {
        // Two anthropic-beta lines should be comma-joined before forwarding.
        let (mock_addr, captured) = mock_server(json_resp("{}")).await;
        let (proxy_addr, _rx) = spawn_proxy(Some(mock_addr)).await;

        let raw = b"POST /v1/messages HTTP/1.1\r\nhost: 127.0.0.1\r\nanthropic-beta: feat-a\r\nanthropic-beta: feat-b\r\ncontent-length: 2\r\n\r\n{}";
        let resp = round_trip(proxy_addr, raw).await;
        assert_eq!(status(&resp), 200);

        sleep(Duration::from_millis(20)).await;
        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let req_text = String::from_utf8_lossy(&reqs[0]).to_lowercase();
        assert!(
            req_text.contains("anthropic-beta: feat-a, feat-b")
                || req_text.contains("anthropic-beta: feat-b, feat-a"),
            "expected joined anthropic-beta header, forwarded request was:\n{}",
            req_text
        );
    }

    #[tokio::test]
    async fn oversized_body_rejected() {
        // Content-Length larger than MAX_BODY_SIZE should produce a 413.
        let (proxy_addr, _rx) = spawn_proxy(None).await;
        let raw = format!(
            "POST /v1/messages HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: {}\r\n\r\n{{}}",
            MAX_BODY_SIZE + 1
        );
        let resp = round_trip(proxy_addr, raw.as_bytes()).await;
        assert_eq!(status(&resp), 413);
    }

    #[tokio::test]
    async fn oversized_headers_rejected() {
        // More than MAX_HEADER_SIZE bytes without \r\n\r\n should produce a 431.
        let (proxy_addr, _rx) = spawn_proxy(None).await;
        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();
        // All 'x' bytes — no \r\n\r\n — guaranteed to hit the header size cap.
        let junk = vec![b'x'; MAX_HEADER_SIZE + 512];
        conn.write_all(&junk).await.unwrap();
        conn.flush().await.unwrap();

        let mut resp = vec![0u8; 512];
        let n = conn.read(&mut resp).await.unwrap_or(0);
        // Either 431 or the connection closed are both acceptable responses to garbage input.
        if n > 0 {
            assert_eq!(status(&resp[..n]), 431, "got: {}", String::from_utf8_lossy(&resp[..n]));
        }
    }

    #[tokio::test]
    async fn unknown_method_rejected() {
        // Methods other than GET/POST should return 405.
        let (mock_addr, _) = mock_server(json_resp("{}")).await;
        let (proxy_addr, _rx) = spawn_proxy(Some(mock_addr)).await;

        let raw = b"DELETE /v1/messages HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\n\r\n";
        let resp = round_trip(proxy_addr, raw).await;
        assert_eq!(status(&resp), 405);
    }

    #[tokio::test]
    async fn connect_to_blocked_host_rejected() {
        // CONNECT to a non-LLM host should be refused with 403.
        let (proxy_addr, _rx) = spawn_proxy(None).await;

        let raw = b"CONNECT 127.0.0.1:22 HTTP/1.1\r\nhost: 127.0.0.1:22\r\n\r\n";
        let resp = round_trip(proxy_addr, raw).await;
        assert_eq!(status(&resp), 403);
    }

    #[tokio::test]
    async fn hop_by_hop_headers_stripped() {
        // proxy-authorization must not be forwarded to the upstream.
        let (mock_addr, captured) = mock_server(json_resp("{}")).await;
        let (proxy_addr, _rx) = spawn_proxy(Some(mock_addr)).await;

        let raw = b"POST /v1/messages HTTP/1.1\r\nhost: 127.0.0.1\r\nproxy-authorization: Basic abc123\r\ncontent-length: 2\r\n\r\n{}";
        let resp = round_trip(proxy_addr, raw).await;
        assert_eq!(status(&resp), 200);

        sleep(Duration::from_millis(20)).await;
        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let req_text = String::from_utf8_lossy(&reqs[0]).to_lowercase();
        assert!(
            !req_text.contains("proxy-authorization"),
            "proxy-authorization should have been stripped, but got:\n{}",
            req_text
        );
    }

    #[tokio::test]
    async fn events_emitted_for_non_streaming_response() {
        // A successful non-streaming response should emit LlmRequest and LlmResponse events.
        let upstream_body = r#"{"id":"msg_1","type":"message","model":"claude-sonnet-4-6","usage":{"input_tokens":10,"output_tokens":5},"content":[]}"#;
        let (mock_addr, _) = mock_server(json_resp(upstream_body)).await;
        let (proxy_addr, mut event_rx) = spawn_proxy(Some(mock_addr)).await;

        let req = make_request("POST", "/v1/messages", &[], b"{}");
        round_trip(proxy_addr, &req).await;

        sleep(Duration::from_millis(50)).await;
        let mut events = vec![];
        while let Ok(ev) = event_rx.try_recv() {
            events.push(ev);
        }

        assert!(
            events.iter().any(|e| matches!(e.event, Event::LlmRequest { .. })),
            "expected LlmRequest event"
        );
        assert!(
            events.iter().any(|e| matches!(e.event, Event::LlmResponse { .. })),
            "expected LlmResponse event"
        );
    }

    #[tokio::test]
    async fn sse_streaming_forwarded() {
        // The proxy should forward SSE chunks as HTTP chunked encoding and emit a
        // LlmResponse event after the stream ends.
        let sse_body = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":5}}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\n",
            "data: [DONE]\n\n",
        );
        let mock_resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n{}",
            sse_body
        )
        .into_bytes();

        let (mock_addr, _) = mock_server(mock_resp).await;
        let (proxy_addr, mut event_rx) = spawn_proxy(Some(mock_addr)).await;

        let req = make_request("POST", "/v1/messages", &[], b"{}");
        let resp = round_trip(proxy_addr, &req).await;
        let resp_text = String::from_utf8_lossy(&resp);

        assert_eq!(status(&resp), 200);
        assert!(
            resp_text.to_lowercase().contains("transfer-encoding: chunked"),
            "expected chunked encoding in response headers"
        );
        assert!(resp_text.contains("message_start"), "expected SSE data in body");

        sleep(Duration::from_millis(50)).await;
        let mut events = vec![];
        while let Ok(ev) = event_rx.try_recv() {
            events.push(ev);
        }
        assert!(
            events.iter().any(|e| matches!(e.event, Event::LlmResponse { .. })),
            "expected LlmResponse event after SSE stream"
        );
    }
}

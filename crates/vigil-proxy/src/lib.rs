use anyhow::Result;
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
use vigil_core::{scan_for_injection, scan_pii, scan_watchlist, Event, TimestampedEvent, ProviderKind, detect_provider_from_host, AnthropicAdapter, ProviderAdapter};

const MAX_HEADER_SIZE: usize = 65536;
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

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
}

pub struct Proxy {
    config: ProxyConfig,
    event_tx: mpsc::Sender<TimestampedEvent>,
    http_client: reqwest::Client,
    pub pending_approvals: PendingApprovals,
}

impl Proxy {
    pub fn new(config: ProxyConfig, event_tx: mpsc::Sender<TimestampedEvent>) -> Self {
        Self {
            config,
            event_tx,
            http_client: {
                // Honor system proxy env vars (http_proxy, https_proxy, no_proxy) by default.
                // vigil forwards to api.anthropic.com; a corporate proxy may be required.
                reqwest::Client::builder()
                    .connect_timeout(std::time::Duration::from_secs(15))
                    .timeout(std::time::Duration::from_secs(300))
                    .redirect(reqwest::redirect::Policy::limited(5))
                    .user_agent(concat!("vigil/", env!("CARGO_PKG_VERSION")))
                    .build()
                    .expect("failed to build HTTP client")
            },
            pending_approvals: Arc::new(Mutex::new(HashMap::new())),
        }
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

    // Legacy: plain HTTP forward to remote host
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
        let p = if path.contains("/messages") { "anthropic" } else { "openai" };
        Some((ov.as_str(), p))
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
                    .unwrap_or("unknown")
                    .to_string();
                let last_user_message = extract_last_user_message(&j);
                let system_prompt = extract_system_prompt(&j);
                (model, last_user_message, system_prompt)
            })
            .unwrap_or_else(|_| ("unknown".to_string(), None, None));

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
    if let Ok(body_json) = serde_json::from_slice::<Value>(&effective_body) {
        scan_tool_results_for_injection(&body_json, session_id, event_tx);
    }

    tracing::info!(provider, model = %model, "LLM request forwarded upstream");
    let _ = event_tx.try_send(TimestampedEvent::new(Event::LlmRequest {
        provider: provider.to_string(),
        model: model.clone(),
        input_tokens: 0,
        session_id,
        last_user_message,
        system_prompt,
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
    /// True when we are buffering a Write/Edit block for potential approval.
    holding: bool,
    /// Which block index triggered the hold.
    holding_tool_idx: Option<usize>,
    /// Set at content_block_stop when the completed tool is a write tool.
    pending_approval_data: Option<(String, Value)>,
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

            let needs_approval = write_approval_threshold
                .map(|t| risk.level >= t)
                .unwrap_or(false);

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
                    // Rejected: send HTTP 403 and close.
                    if client_alive {
                        let body = b"Write rejected by vigil";
                        let resp_str = format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = client_conn.write_all(resp_str.as_bytes()).await;
                        let _ = client_conn.write_all(body).await;
                        let _ = client_conn.flush().await;
                    }
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

    if state.output_tokens > 0 || state.input_tokens > 0 {
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
                let input: Value = serde_json::from_str(&input_str).unwrap_or(json!({}));
                let tool_use_id = state.block_id.remove(&idx);
                tracing::info!(tool = %tool_name, "tool call detected in stream");
                emit_pii_alert_if_found(&tool_name, &input.to_string(), pii_watchlist, session_id, event_tx);
                emit_fs_events_for_tool(&tool_name, &input, session_id, event_tx);
                if AnthropicAdapter.write_tools().iter().any(|t| tool_name.eq_ignore_ascii_case(t)) {
                    state.pending_approval_data = Some((tool_name.clone(), input.clone()));
                }
                let _ = event_tx.try_send(TimestampedEvent::new(Event::ToolCall {
                    agent: "claude".to_string(),
                    tool_name,
                    input,
                    session_id,
                    tool_use_id,
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
                        let _ = event_tx.try_send(TimestampedEvent::new(Event::ToolCall {
                            agent: "openai".to_string(),
                            tool_name,
                            input,
                            session_id,
                            tool_use_id: None,
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
                Some(Event::FsWrite { path: p, bytes, session_id })
            }
        }

        "Edit" | "MultiEdit" => path("file_path").map(|p| Event::FsWrite { path: p, bytes: 0, session_id }),

        "NotebookEdit" => path("notebook_path").map(|p| Event::FsWrite { path: p, bytes: 0, session_id }),

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
            let _ = event_tx.try_send(TimestampedEvent::new(Event::LlmRequest {
                provider: provider.to_string(),
                model,
                input_tokens: 0,
                session_id,
                last_user_message,
                system_prompt,
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
    }));

    if let Some(content) = json.get("content").and_then(|v| v.as_array()) {
        for item in content {
            if item.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                if let Some(tool_name) = item.get("name").and_then(|v| v.as_str()) {
                    let input = item.get("input").cloned().unwrap_or(json!({}));
                    let tool_use_id = item.get("id").and_then(|v| v.as_str()).map(|s| s.to_string());
                    emit_pii_alert_if_found(tool_name, &input.to_string(), pii_watchlist, session_id, event_tx);
                    emit_fs_events_for_tool(tool_name, &input, session_id, event_tx);
                    let _ = event_tx.try_send(TimestampedEvent::new(Event::ToolCall {
                        agent: "claude".to_string(),
                        tool_name: tool_name.to_string(),
                        input,
                        session_id,
                        tool_use_id,
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
                                let _ = event_tx.try_send(TimestampedEvent::new(Event::ToolCall {
                                    agent: "openai".to_string(),
                                    tool_name: tool_name.to_string(),
                                    input,
                                    session_id,
                                    tool_use_id: None,
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

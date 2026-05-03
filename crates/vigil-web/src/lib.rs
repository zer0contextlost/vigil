use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response, sse::{Event as SseEvent, KeepAlive, Sse}},
    routing::{get, post},
};
use futures::stream::{self, Stream};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, net::SocketAddr};
use tokio::sync::broadcast;
use vigil_core::{TimestampedEvent, list_active};
use vigil_proxy::PendingApprovals;

#[derive(RustEmbed)]
#[folder = "assets/"]
struct Assets;

#[derive(Clone)]
pub struct DashboardState {
    event_tx: broadcast::Sender<TimestampedEvent>,
    pending_approvals: PendingApprovals,
    token: String,
    port: u16,
}

pub async fn run_dashboard(
    addr: SocketAddr,
    event_tx: broadcast::Sender<TimestampedEvent>,
    pending_approvals: PendingApprovals,
) -> anyhow::Result<()> {
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    println!("Dashboard: http://127.0.0.1:{}/?token={}", addr.port(), token);

    let state = DashboardState { event_tx, pending_approvals, token, port: addr.port() };

    let static_routes = Router::new()
        .route("/", get(serve_index))
        .route("/style.css", get(serve_css))
        .route("/app.js", get(serve_js));

    let api_routes = Router::new()
        .route("/api/sessions", get(api_sessions))
        .route("/api/sessions/{id}", get(api_session_detail))
        .route("/api/events", get(api_events))
        .route("/api/sessions/{id}/events", get(api_session_events))
        .route("/api/approvals", get(api_approvals_list))
        .route("/api/approvals/{id}", post(api_approval_submit))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let app = Router::new()
        .merge(static_routes)
        .merge(api_routes)
        .with_state(state)
        .layer(middleware::from_fn(security_headers_middleware));

    tracing::info!(%addr, "vigil dashboard listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    h.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    h.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'",
        ),
    );
    resp
}

async fn require_auth(
    State(state): State<DashboardState>,
    req: Request,
    next: Next,
) -> Response {
    // DNS rebinding mitigation: reject requests with missing or invalid Host header.
    let allowed_hosts = [
        format!("127.0.0.1:{}", state.port),
        format!("localhost:{}", state.port),
    ];
    let host_ok = req.headers().get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| allowed_hosts.iter().any(|a| a == h))
        .unwrap_or(false);
    if !host_ok {
        return (StatusCode::FORBIDDEN, "forbidden host").into_response();
    }

    if !check_token(&req, &state.token) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }

    next.run(req).await
}

fn constant_eq(a: &str, b: &str) -> bool {
    // Timing-safe comparison: accumulate XOR over all bytes to prevent timing attacks.
    // Token length (64 hex chars) is not secret, so the early-exit on length mismatch is fine.
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn check_token(req: &Request, expected: &str) -> bool {
    // Authorization: Bearer <token>
    if let Some(auth) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(val) = auth.to_str() {
            if let Some(t) = val.strip_prefix("Bearer ") {
                if constant_eq(t, expected) {
                    return true;
                }
            }
        }
    }
    // ?token=<token> (EventSource can't set custom headers)
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some(t) = pair.strip_prefix("token=") {
                if constant_eq(t, expected) {
                    return true;
                }
            }
        }
    }
    false
}

async fn serve_index() -> impl IntoResponse {
    serve_asset("index.html", "text/html; charset=utf-8")
}

async fn serve_css() -> impl IntoResponse {
    serve_asset("style.css", "text/css")
}

async fn serve_js() -> impl IntoResponse {
    serve_asset("app.js", "application/javascript")
}

fn serve_asset(path: &str, content_type: &'static str) -> Response {
    match Assets::get(path) {
        Some(content) => (
            [(header::CONTENT_TYPE, content_type)],
            content.data.to_vec(),
        ).into_response(),
        None => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionEntry {
    id: String,
    name: Option<String>,
    agent: String,
    status: String,
    started_at: String,
    cost_usd: f64,
    burn_rate_per_min: f64,
    last_event: String,
    tokens: u32,
    needs_attention: bool,
}

async fn api_sessions() -> impl IntoResponse {
    let json = tokio::task::spawn_blocking(build_sessions_json).await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "spawn_blocking panicked in build_sessions_json");
            "[]".to_string()
        });
    ([(header::CONTENT_TYPE, "application/json")], json)
}

fn build_sessions_json() -> String {
    let active = list_active();
    let mut entries: Vec<SessionEntry> = Vec::new();

    for s in &active {
        entries.push(SessionEntry {
            id: s.session_id.to_string(),
            name: s.name.clone(),
            agent: s.agent.clone(),
            status: "live".to_string(),
            started_at: s.started_at.to_rfc3339(),
            cost_usd: s.session_cost_usd,
            burn_rate_per_min: s.burn_rate_per_min,
            last_event: s.last_event.clone(),
            tokens: s.session_tokens,
            needs_attention: s.needs_attention,
        });
    }

    let active_ids: std::collections::HashSet<_> = active.iter()
        .map(|s| s.session_id)
        .collect();

    if let Ok(summaries) = vigil_core::session::Session::list_all() {
        for s in summaries.iter().take(50) {
            if active_ids.contains(&s.id) {
                continue;
            }
            entries.push(SessionEntry {
                id: s.id.to_string(),
                name: s.name.clone(),
                agent: s.agent.clone(),
                status: "completed".to_string(),
                started_at: s.started_at.to_rfc3339(),
                cost_usd: s.total_cost_usd,
                burn_rate_per_min: 0.0,
                last_event: if s.ended_at.is_some() { "Session ended".to_string() } else { "".to_string() },
                tokens: s.total_input_tokens.saturating_add(s.total_output_tokens),
                needs_attention: false,
            });
        }
    }

    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
}

#[derive(Debug, Serialize)]
struct SessionDetail {
    id: String,
    name: Option<String>,
    agent: String,
    status: String,
    started_at: String,
    ended_at: Option<String>,
    cost_usd: f64,
    total_input_tokens: u32,
    total_output_tokens: u32,
    policy_violations: u32,
    event_count: usize,    // total events in session
    events_offset: usize,  // index of first returned event
    events: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
struct DetailQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

async fn api_session_detail(
    Path(id): Path<String>,
    Query(query): Query<DetailQuery>,
) -> impl IntoResponse {
    let Ok(uuid) = uuid::Uuid::parse_str(&id) else {
        return (StatusCode::BAD_REQUEST, [(header::CONTENT_TYPE, "application/json")], "\"invalid uuid\"".to_string());
    };

    let result = tokio::task::spawn_blocking(move || {
        build_session_detail_json(&uuid, query.limit, query.offset)
    }).await;
    let (status, json) = match result {
        Ok(Some(json)) => (StatusCode::OK, json),
        Ok(None) => (StatusCode::NOT_FOUND, "\"not found\"".to_string()),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "\"error\"".to_string()),
    };
    (status, [(header::CONTENT_TYPE, "application/json")], json)
}

fn build_session_detail_json(
    uuid: &uuid::Uuid,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Option<String> {
    let meta = vigil_core::store::SessionStore::load_meta(uuid).ok()?;
    let envelopes = vigil_core::store::SessionStore::load_envelopes(uuid).unwrap_or_default();

    let total = envelopes.len();
    let limit = limit.unwrap_or(200).min(2000);
    // Default: tail — show the last `limit` events unless caller specifies offset
    let offset = offset.unwrap_or_else(|| total.saturating_sub(limit));
    let offset = offset.min(total);

    let events: Vec<serde_json::Value> = envelopes[offset..]
        .iter()
        .take(limit)
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect();

    let detail = SessionDetail {
        id: meta.session_id.to_string(),
        name: meta.name.clone(),
        agent: meta.agent.clone(),
        status: if meta.ended_at.is_some() { "completed".to_string() } else { "live".to_string() },
        started_at: meta.started_at.to_rfc3339(),
        ended_at: meta.ended_at.map(|t| t.to_rfc3339()),
        cost_usd: meta.total_cost_usd,
        total_input_tokens: meta.total_input_tokens,
        total_output_tokens: meta.total_output_tokens,
        policy_violations: meta.policy_violations,
        event_count: total,
        events_offset: offset,
        events,
    };
    serde_json::to_string(&detail).ok()
}

async fn api_session_events(
    Path(id): Path<String>,
    State(state): State<DashboardState>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = state.event_tx.subscribe();
    let filter_id = id;

    let stream = stream::unfold((rx, filter_id), |(mut rx, fid)| async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if event.session_id.to_string() == fid {
                        if let Ok(json) = serde_json::to_string(&event) {
                            let sse_event = SseEvent::default()
                                .event(event_type_name(&event))
                                .data(json);
                            return Some((Ok(sse_event), (rx, fid)));
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return None,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn api_events(State(state): State<DashboardState>) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = state.event_tx.subscribe();

    let stream = stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        let sse_event = SseEvent::default()
                            .event(event_type_name(&event))
                            .data(json);
                        return Some((Ok(sse_event), rx));
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return None,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn event_type_name(event: &TimestampedEvent) -> &'static str {
    use vigil_core::Event;
    match &event.event {
        Event::LlmRequest { .. } => "LlmRequest",
        Event::LlmResponse { .. } => "LlmResponse",
        Event::ToolCall { .. } => "ToolCall",
        Event::ToolCallResult { .. } => "ToolCallResult",
        Event::FsWrite { .. } => "FsWrite",
        Event::FsRead { .. } => "FsRead",
        Event::BurnRateAlert { .. } => "BurnRateAlert",
        Event::LoopAlert { .. } => "LoopAlert",
        Event::DriftAlert { .. } => "DriftAlert",
        Event::ExfilAlert { .. } => "ExfilAlert",
        Event::PromptInjectionAlert { .. } => "PromptInjectionAlert",
        Event::WriteApprovalRequired { .. } => "WriteApprovalRequired",
        Event::WriteApprovalDecision { .. } => "WriteApprovalDecision",
        Event::PiiAlert { .. } => "PiiAlert",
        Event::ToolTimeout { .. } => "ToolTimeout",
        Event::CostAlert { .. } => "CostAlert",
        Event::SessionDurationAlert { .. } => "SessionDurationAlert",
        Event::SubAgentSpawned { .. } => "SubAgentSpawned",
        Event::ProcessSpawn { .. } => "ProcessSpawn",
        Event::McpCall { .. } => "McpCall",
    }
}

#[derive(Debug, Serialize)]
struct PendingApprovalEntry {
    id: String,
}

async fn api_approvals_list(State(state): State<DashboardState>) -> Response {
    let map = match state.pending_approvals.lock() {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(error = %e, "pending_approvals mutex poisoned");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let ids: Vec<PendingApprovalEntry> = map.keys()
        .map(|id| PendingApprovalEntry { id: id.to_string() })
        .collect();
    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&ids).unwrap_or_else(|_| "[]".to_string()),
    ).into_response()
}

#[derive(Debug, Deserialize)]
struct ApprovalBody {
    approved: bool,
}

async fn api_approval_submit(
    Path(id): Path<String>,
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(body): Json<ApprovalBody>,
) -> Response {
    // Origin check: belt-and-suspenders on top of the Bearer token
    if let Some(origin) = headers.get("Origin") {
        let ok = [
            format!("http://127.0.0.1:{}", state.port),
            format!("http://localhost:{}", state.port),
        ];
        if let Ok(o) = origin.to_str() {
            if !ok.iter().any(|a| a == o) {
                return (StatusCode::FORBIDDEN, "forbidden origin").into_response();
            }
        }
    }

    let Ok(uuid) = uuid::Uuid::parse_str(&id) else {
        return (StatusCode::BAD_REQUEST, "invalid uuid").into_response();
    };
    let sender = match state.pending_approvals.lock() {
        Ok(mut m) => m.remove(&uuid),
        Err(e) => {
            tracing::error!(error = %e, "pending_approvals mutex poisoned");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    match sender {
        Some(tx) => {
            let _ = tx.send(body.approved);
            (StatusCode::OK, if body.approved { "approved" } else { "rejected" }).into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    fn test_state() -> (DashboardState, broadcast::Sender<TimestampedEvent>) {
        let (tx, _) = broadcast::channel(16);
        let approvals: PendingApprovals = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let token = "test-token-abc123".to_string();
        let state = DashboardState { event_tx: tx.clone(), pending_approvals: approvals, token, port: 9999 };
        (state, tx)
    }

    fn test_app(state: DashboardState) -> axum::Router {
        let static_routes = Router::new()
            .route("/", get(serve_index))
            .route("/style.css", get(serve_css))
            .route("/app.js", get(serve_js));

        let api_routes = Router::new()
            .route("/api/sessions", get(api_sessions))
            .route("/api/events", get(api_events))
            .route("/api/approvals", get(api_approvals_list))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

        Router::new()
            .merge(static_routes)
            .merge(api_routes)
            .with_state(state)
            .layer(middleware::from_fn(security_headers_middleware))
    }

    #[tokio::test]
    async fn api_requires_token() {
        let (state, _) = test_state();
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::get("/api/sessions")
                    .header("Host", "127.0.0.1:9999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_accepts_bearer_token() {
        let (state, _) = test_state();
        let token = state.token.clone();
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::get("/api/sessions")
                    .header("Authorization", format!("Bearer {}", token))
                    .header("Host", "127.0.0.1:9999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_accepts_query_token() {
        let (state, _) = test_state();
        let token = state.token.clone();
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::get(format!("/api/sessions?token={}", token))
                    .header("Host", "127.0.0.1:9999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn static_assets_no_token_required() {
        let (state, _) = test_state();
        let app = test_app(state);

        let resp = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn security_headers_present() {
        let (state, _) = test_state();
        let app = test_app(state);

        let resp = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.headers().get("X-Frame-Options").unwrap(), "DENY");
        assert_eq!(resp.headers().get("X-Content-Type-Options").unwrap(), "nosniff");
        assert!(resp.headers().contains_key("Content-Security-Policy"));
    }

    #[tokio::test]
    async fn wrong_host_rejected() {
        let (state, _) = test_state();
        let token = state.token.clone();
        let app = test_app(state);

        let resp = app
            .oneshot(
                Request::get("/api/sessions")
                    .header("Authorization", format!("Bearer {}", token))
                    .header("Host", "evil.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn sse_endpoint_returns_event_stream_content_type() {
        use vigil_core::{Event, TimestampedEvent};

        let (state, tx) = test_state();
        let token = state.token.clone();
        let app = test_app(state);

        let session_id = uuid::Uuid::new_v4();
        let _ = tx.send(TimestampedEvent::new(Event::FsRead {
            path: "/tmp/test".to_string(),
            session_id,
        }));

        let resp = app
            .oneshot(
                Request::get(format!("/api/events?token={}", token))
                    .header("Host", "127.0.0.1:9999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap().to_str().unwrap(),
            "text/event-stream"
        );
    }
}

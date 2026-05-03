use axum::{
    Router,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response, sse::{Event as SseEvent, KeepAlive, Sse}},
    routing::get,
};
use futures::stream::{self, Stream};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, net::SocketAddr};
use tokio::sync::broadcast;
use vigil_core::{TimestampedEvent, list_active};

#[derive(RustEmbed)]
#[folder = "assets/"]
struct Assets;

#[derive(Clone)]
pub struct DashboardState {
    event_tx: broadcast::Sender<TimestampedEvent>,
}

pub async fn run_dashboard(
    addr: SocketAddr,
    event_tx: broadcast::Sender<TimestampedEvent>,
) -> anyhow::Result<()> {
    let state = DashboardState { event_tx };
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/style.css", get(serve_css))
        .route("/app.js", get(serve_js))
        .route("/api/sessions", get(api_sessions))
        .route("/api/sessions/{id}", get(api_session_detail))
        .route("/api/events", get(api_events))
        .route("/api/sessions/{id}/events", get(api_session_events))
        .with_state(state);

    tracing::info!(%addr, "vigil dashboard listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
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

    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string()),
    )
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
    event_count: usize,
    events: Vec<serde_json::Value>,
}

async fn api_session_detail(Path(id): Path<String>) -> impl IntoResponse {
    let Ok(uuid) = uuid::Uuid::parse_str(&id) else {
        return (StatusCode::BAD_REQUEST, [(header::CONTENT_TYPE, "application/json")], "\"invalid uuid\"".to_string());
    };

    let envelopes = vigil_core::store::SessionStore::load_envelopes(&uuid).unwrap_or_default();
    let meta = vigil_core::store::SessionStore::load_meta(&uuid).ok();

    let events: Vec<serde_json::Value> = envelopes.iter()
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect();

    let detail = if let Some(m) = meta {
        SessionDetail {
            id: m.session_id.to_string(),
            name: m.name.clone(),
            agent: m.agent.clone(),
            status: if m.ended_at.is_some() { "completed".to_string() } else { "live".to_string() },
            started_at: m.started_at.to_rfc3339(),
            ended_at: m.ended_at.map(|t| t.to_rfc3339()),
            cost_usd: m.total_cost_usd,
            total_input_tokens: m.total_input_tokens,
            total_output_tokens: m.total_output_tokens,
            policy_violations: m.policy_violations,
            event_count: events.len(),
            events,
        }
    } else {
        return (StatusCode::NOT_FOUND, [(header::CONTENT_TYPE, "application/json")], "\"not found\"".to_string());
    };

    let json = serde_json::to_string(&detail).unwrap_or_else(|_| "{}".to_string());
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], json)
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
                            let sse_event = SseEvent::default().event("vigil").data(json);
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
                            .event("vigil")
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

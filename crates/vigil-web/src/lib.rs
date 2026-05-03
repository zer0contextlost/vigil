use axum::{
    Router,
    extract::State,
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
        .route("/api/events", get(api_events))
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

use serde_json::{json, Value};
use std::collections::HashSet;

/// Fire-and-forget webhook notifier. Spawns a tokio task per alert.
#[derive(Debug, Clone)]
pub struct WebhookNotifier {
    url: String,
    allowed_labels: HashSet<String>,
}

impl WebhookNotifier {
    pub fn new(url: String, webhook_events: Vec<String>) -> Self {
        Self {
            url,
            allowed_labels: webhook_events.into_iter().map(|s| s.to_uppercase()).collect(),
        }
    }

    /// Returns true if this label should be forwarded.
    pub fn should_notify(&self, label: &str) -> bool {
        self.allowed_labels.is_empty() || self.allowed_labels.contains(&label.to_uppercase())
    }

    /// Spawn a background task to POST the payload. Never blocks the caller.
    pub fn send(&self, label: &str, session_id: &str, detail: Value) {
        if !self.should_notify(label) {
            return;
        }
        let url = self.url.clone();
        let payload = json!({
            "vigil_alert": label,
            "session_id": session_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "detail": detail,
        });
        tokio::spawn(async move {
            for attempt in 0..3u32 {
                match reqwest::Client::new().post(&url).json(&payload).send().await {
                    Ok(r) if r.status().is_success() => break,
                    Ok(r) => {
                        tracing::warn!(status = %r.status(), attempt, "webhook non-2xx");
                    }
                    Err(e) => {
                        tracing::warn!(err = %e, attempt, "webhook send error");
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(2u64.pow(attempt))).await;
            }
        });
    }
}

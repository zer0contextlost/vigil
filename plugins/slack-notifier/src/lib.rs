//! vigil-slack-notifier — post alerts to a Slack webhook.
//!
//! Set SLACK_WEBHOOK_URL to your Slack incoming webhook URL.
//! Set SLACK_VIGIL_EVENTS to a comma-separated list of labels to forward
//! (default: BURN,LOOP,EXFL,DENY). Leave empty to receive all alerts.

use vigil_plugin::{async_trait, declare_plugin, AlertLabel, PluginContext, Value, VigilPlugin};

pub struct SlackNotifier {
    webhook_url: Option<String>,
    filter: Vec<String>,
}

impl SlackNotifier {
    fn new() -> Self {
        let webhook_url = std::env::var("SLACK_WEBHOOK_URL").ok();
        let filter = std::env::var("SLACK_VIGIL_EVENTS")
            .unwrap_or_else(|_| "BURN,LOOP,EXFL,DENY".to_string())
            .split(',')
            .map(|s| s.trim().to_uppercase())
            .filter(|s| !s.is_empty())
            .collect();
        Self { webhook_url, filter }
    }
}

#[async_trait]
impl VigilPlugin for SlackNotifier {
    fn name(&self) -> &str { "slack-notifier" }

    async fn on_session_start(&self, ctx: &PluginContext) {
        let Some(ref url) = self.webhook_url else { return };
        let url = url.clone();
        let sid = ctx.session_id.to_string();
        tokio::spawn(async move {
            let body = serde_json::json!({
                "text": format!(":eyes: vigil session started `{}`", &sid[..8])
            });
            let _ = reqwest_post(&url, &body).await;
        });
    }

    async fn on_session_end(&self, ctx: &PluginContext) {
        let Some(ref url) = self.webhook_url else { return };
        let url = url.clone();
        let sid = ctx.session_id.to_string();
        tokio::spawn(async move {
            let body = serde_json::json!({
                "text": format!(":checkered_flag: vigil session ended `{}`", &sid[..8])
            });
            let _ = reqwest_post(&url, &body).await;
        });
    }

    async fn on_alert(&self, ctx: &PluginContext, label: AlertLabel, detail: &Value) {
        let Some(ref url) = self.webhook_url else { return };
        let code = label.code().to_string();
        if !self.filter.is_empty() && !self.filter.contains(&code) { return; }
        let url = url.clone();
        let sid = ctx.session_id.to_string();
        let text = format!(":rotating_light: `{}` in session `{}` — {}", code, &sid[..8], detail);
        tokio::spawn(async move {
            let body = serde_json::json!({ "text": text });
            let _ = reqwest_post(&url, &body).await;
        });
    }
}

async fn reqwest_post(url: &str, body: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    client.post(url).json(body).send().await?;
    Ok(())
}

declare_plugin!(SlackNotifier::new());

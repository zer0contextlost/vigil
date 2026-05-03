//! vigil-otel-exporter — send vigil events as OpenTelemetry log records.
//!
//! Posts OTLP/HTTP JSON to an OpenTelemetry collector.
//! Set OTEL_EXPORTER_OTLP_ENDPOINT (default: http://localhost:4318).
//! Set OTEL_SERVICE_NAME (default: vigil).

use vigil_plugin::{async_trait, declare_plugin, AlertLabel, Envelope, PluginContext, Value, VigilPlugin};
use std::sync::Mutex;

pub struct OtelExporter {
    endpoint: String,
    service_name: String,
    session_start_ns: Mutex<u64>,
}

impl OtelExporter {
    fn new() -> Self {
        let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:4318".to_string());
        let service_name = std::env::var("OTEL_SERVICE_NAME")
            .unwrap_or_else(|_| "vigil".to_string());
        Self { endpoint, service_name, session_start_ns: Mutex::new(0) }
    }

    fn now_ns() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    async fn send_log(&self, body: serde_json::Value) {
        let url = format!("{}/v1/logs", self.endpoint);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        let _ = client.post(&url).json(&body).send().await;
    }
}

#[async_trait]
impl VigilPlugin for OtelExporter {
    fn name(&self) -> &str { "otel-exporter" }

    async fn on_session_start(&self, ctx: &PluginContext) {
        let now = Self::now_ns();
        if let Ok(mut g) = self.session_start_ns.lock() { *g = now; }
        let body = otlp_log_record(
            &self.service_name,
            ctx.session_id.to_string(),
            now, "INFO",
            "session_start",
            serde_json::json!({"session_id": ctx.session_id.to_string()}),
        );
        self.send_log(body).await;
    }

    async fn on_session_end(&self, ctx: &PluginContext) {
        let start = self.session_start_ns.lock().ok().map(|g| *g).unwrap_or(0);
        let now = Self::now_ns();
        let duration_ms = if start > 0 { (now - start) / 1_000_000 } else { 0 };
        let body = otlp_log_record(
            &self.service_name,
            ctx.session_id.to_string(),
            now, "INFO",
            "session_end",
            serde_json::json!({"session_id": ctx.session_id.to_string(), "duration_ms": duration_ms}),
        );
        self.send_log(body).await;
    }

    async fn on_alert(&self, ctx: &PluginContext, label: AlertLabel, detail: &Value) {
        let body = otlp_log_record(
            &self.service_name,
            ctx.session_id.to_string(),
            Self::now_ns(), "WARN",
            label.code(),
            detail.clone(),
        );
        self.send_log(body).await;
    }

    async fn on_event(&self, ctx: &PluginContext, envelope: &Envelope) {
        let event_type = format!("{:?}", envelope.event).split('{').next().unwrap_or("Event").trim().to_string();
        let body = otlp_log_record(
            &self.service_name,
            ctx.session_id.to_string(),
            Self::now_ns(), "DEBUG",
            &event_type,
            serde_json::to_value(&envelope.event).unwrap_or_default(),
        );
        self.send_log(body).await;
    }
}

fn otlp_log_record(service: &str, session_id: String, time_ns: u64, severity: &str, body: &str, attrs: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "resourceLogs": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": service}}]},
            "scopeLogs": [{
                "logRecords": [{
                    "timeUnixNano": time_ns.to_string(),
                    "severityText": severity,
                    "body": {"stringValue": body},
                    "attributes": [
                        {"key": "session_id", "value": {"stringValue": session_id}},
                        {"key": "detail", "value": {"stringValue": attrs.to_string()}},
                    ]
                }]
            }]
        }]
    })
}

declare_plugin!(OtelExporter::new());

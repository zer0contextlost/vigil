use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use vigil_plugin::{declare_plugin, Envelope, PluginContext, PluginDecision, Value, VigilPlugin};

/// Writes every alert to a NDJSON log file and optionally blocks tool calls
/// whose names match patterns listed in VIGIL_BLOCK_TOOLS (comma-separated).
///
/// Configuration via environment variables (read at startup):
///   VIGIL_ALERT_LOG   — path to log file (default: ~/.vigil/alerts.ndjson)
///   VIGIL_BLOCK_TOOLS — comma-separated tool name substrings to deny
///                       e.g. "Bash,WebSearch"
pub struct AlertLogger {
    file: Mutex<File>,
    block_patterns: Vec<String>,
}

impl AlertLogger {
    fn new() -> Self {
        let log_path = std::env::var("VIGIL_ALERT_LOG").unwrap_or_else(|_| {
            let home = if cfg!(target_os = "windows") {
                std::env::var("USERPROFILE").unwrap_or_default()
            } else {
                std::env::var("HOME").unwrap_or_default()
            };
            format!("{}/.vigil/alerts.ndjson", home)
        });

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap_or_else(|e| panic!("alert-logger: cannot open {}: {}", log_path, e));

        let block_patterns = std::env::var("VIGIL_BLOCK_TOOLS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase)
            .collect();

        Self { file: Mutex::new(file), block_patterns }
    }

    fn write_line(&self, record: &serde_json::Value) {
        if let Ok(line) = serde_json::to_string(record) {
            if let Ok(mut f) = self.file.lock() {
                let _ = writeln!(f, "{}", line);
            }
        }
    }
}

impl VigilPlugin for AlertLogger {
    fn name(&self) -> &str { "alert-logger" }

    fn on_alert(&self, ctx: &PluginContext, label: &str, detail: &Value) {
        let record = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "type": "alert",
            "label": label,
            "session_id": ctx.session_id,
            "detail": detail,
        });
        self.write_line(&record);
    }

    fn on_event(&self, _ctx: &PluginContext, _envelope: &Envelope) {
        // Intentionally left as no-op — alerts are the interesting signal.
        // Override this if you want every event logged.
    }

    fn on_tool_call(&self, _ctx: &PluginContext, tool_name: &str, _input: &Value) -> PluginDecision {
        if self.block_patterns.is_empty() {
            return PluginDecision::Allow;
        }
        let lower = tool_name.to_lowercase();
        for pattern in &self.block_patterns {
            if lower.contains(pattern.as_str()) {
                return PluginDecision::Deny(format!(
                    "alert-logger: '{}' matches blocked pattern '{}'",
                    tool_name, pattern
                ));
            }
        }
        PluginDecision::Allow
    }
}

declare_plugin!(AlertLogger::new());

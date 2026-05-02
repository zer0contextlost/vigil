# vigil plugin system

vigil exposes a stable Rust trait (`VigilPlugin`) that lets you receive every
event and alert from a running session without forking vigil itself.

## How it works

`vigil-core` (a library crate) exports two types:

```rust
pub trait VigilPlugin: Send + Sync {
    fn on_event(&self, envelope: &Envelope) {}
    fn on_alert(&self, label: &str, session_id: &str, detail: &serde_json::Value) {}
}

pub struct PluginHost { … }
impl PluginHost {
    pub fn add(&mut self, plugin: Box<dyn VigilPlugin>);
}
```

`PluginHost` fans out to all registered plugins. vigil-cli calls
`dispatch_event` for every filtered event and `dispatch_alert` for every alert
before forwarding them to the TUI.

## Alert labels

| Label  | Trigger |
|--------|---------|
| BURN   | Burn-rate threshold exceeded |
| LOOP   | Repeated identical tool call detected |
| EXFL   | Credential exfiltration attempt |
| DENY   | Policy blocked a tool call |
| COST   | Soft cost alert threshold crossed |
| DURA   | Session duration limit reached |
| TOUT   | Tool call hung with no LLM response |
| WAPPR  | Write approval required (manual approval gate) |
| PII    | PII detected in traffic (from proxy scanner) |

## Writing a plugin

Add `vigil-core` to your `Cargo.toml`:

```toml
[dependencies]
vigil-core = { git = "https://github.com/zer0contextlost/vigil" }
```

Implement the trait. Both methods have default no-op bodies; implement only
what you need:

```rust
use vigil_core::{VigilPlugin, Envelope};
use serde_json::Value;

pub struct SlackNotifier {
    webhook_url: String,
}

impl VigilPlugin for SlackNotifier {
    fn on_alert(&self, label: &str, session_id: &str, detail: &Value) {
        let url = self.webhook_url.clone();
        let text = format!("[vigil {}] session {} — {}", label, &session_id[..8], detail);
        tokio::spawn(async move {
            let _ = reqwest::Client::new()
                .post(&url)
                .json(&serde_json::json!({ "text": text }))
                .send()
                .await;
        });
    }
}
```

## Registering your plugin

vigil-cli's internal `run_agent_with_plugins` function accepts a `PluginHost`.
The simplest integration is a thin wrapper binary:

```rust
use vigil_core::PluginHost;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut host = PluginHost::new();
    host.add(Box::new(SlackNotifier {
        webhook_url: std::env::var("SLACK_WEBHOOK")?,
    }));

    // parse your own args, then call vigil-cli's entry point
    vigil_cli::run_agent_with_plugins(
        8877, None, None,
        vec!["claude".into()],
        vec![],
        None, None,
        host,
    ).await
}
```

Add vigil-cli as a library dependency in your `Cargo.toml`:

```toml
[dependencies]
vigil-cli = { git = "https://github.com/zer0contextlost/vigil", package = "vigil" }
```

## Threading contract

`on_event` and `on_alert` are called from within an async tokio task. Your
implementation must not block. If you need to do I/O (HTTP calls, disk writes,
database inserts), spawn a `tokio::task` or send to a channel you own.

## Example: structured logging plugin

```rust
use vigil_core::{VigilPlugin, Envelope};
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

pub struct NdjsonLogger {
    file: Mutex<std::fs::File>,
}

impl NdjsonLogger {
    pub fn new(path: &str) -> Self {
        let file = OpenOptions::new().create(true).append(true).open(path).unwrap();
        Self { file: Mutex::new(file) }
    }
}

impl VigilPlugin for NdjsonLogger {
    fn on_event(&self, envelope: &Envelope) {
        if let Ok(line) = serde_json::to_string(envelope) {
            if let Ok(mut f) = self.file.lock() {
                let _ = writeln!(f, "{}", line);
            }
        }
    }
}
```

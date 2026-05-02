# vigil plugin system

vigil exposes a stable Rust trait (`VigilPlugin`) that lets you receive every event and alert from a running session without forking vigil itself.

## How it works

`vigil-core` exports two types:

```rust
pub trait VigilPlugin: Send + Sync {
    fn on_event(&self, envelope: &Envelope) {}
    fn on_alert(&self, label: &str, session_id: &str, detail: &serde_json::Value) {}
}

pub struct PluginHost { … }
impl PluginHost {
    pub fn add(&mut self, plugin: Box<dyn VigilPlugin>);
    pub fn load_from_file(&mut self, path: &Path) -> anyhow::Result<()>;
}
```

`PluginHost` fans out to all registered plugins. vigil-cli calls `dispatch_event` for every filtered event and `dispatch_alert` for every alert before forwarding them to the TUI.

## Alert labels

| Label  | Trigger |
|--------|---------|
| `BURN` | Rolling $/min burn-rate exceeded threshold |
| `LOOP` | Same tool+input repeated N times |
| `EXFL` | Credential exfiltration attempt detected |
| `DENY` | Policy blocked a tool call |
| `COST` | Soft cost alert threshold crossed |
| `DURA` | Session duration limit reached |
| `TOUT` | Tool call hung with no LLM response |
| `WAPPR`| Write approval required |
| `PII`  | PII detected in traffic |

## Loading plugins

### Auto-load (recommended)

Drop your compiled shared library in `~/.vigil/plugins/`. vigil scans this directory on every `vigil run` and loads any `.dll` (Windows), `.so` (Linux), or `.dylib` (macOS) file it finds.

```bash
vigil plugins dir    # prints the auto-load directory
vigil plugins list   # shows what's currently in it
```

### Explicit load

```bash
vigil run --plugin ./my-plugin.dll -- claude
vigil run --plugin ./a.dll --plugin ./b.dll -- claude
```

### Compatibility note

Plugin and host must be compiled with the same Rust toolchain and `vigil-core` version. The `dyn VigilPlugin` vtable layout is not stable across compiler versions. Pin both to the same `vigil-core` git revision.

## Writing a dynamic plugin

Compile your plugin as a `cdylib` crate and export `vigil_plugin_create`:

**`Cargo.toml`**

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
vigil-core = { git = "https://github.com/zer0contextlost/vigil" }
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
```

**`src/lib.rs`**

```rust
use vigil_core::{Envelope, VigilPlugin};
use serde_json::Value;

struct SlackNotifier {
    webhook_url: String,
}

impl VigilPlugin for SlackNotifier {
    fn on_alert(&self, label: &str, session_id: &str, detail: &Value) {
        let url = self.webhook_url.clone();
        let text = format!("[vigil {}] {} — {}", label, &session_id[..8], detail);
        tokio::spawn(async move {
            let _ = reqwest::Client::new()
                .post(&url)
                .json(&serde_json::json!({ "text": text }))
                .send()
                .await;
        });
    }
}

/// vigil calls this function to create your plugin.
/// Return a heap-allocated Box<dyn VigilPlugin> wrapped in another Box.
#[no_mangle]
pub extern "C" fn vigil_plugin_create() -> *mut Box<dyn VigilPlugin> {
    let plugin: Box<dyn VigilPlugin> = Box::new(SlackNotifier {
        webhook_url: std::env::var("SLACK_WEBHOOK").unwrap_or_default(),
    });
    Box::into_raw(Box::new(plugin))
}
```

Build with `cargo build --release` and copy the resulting `.dll`/`.so`/`.dylib` to `~/.vigil/plugins/`.

## Writing an in-process plugin (wrapper binary)

For tighter integration — custom CLI flags, combining with your own config — write a thin wrapper binary that calls vigil's `run_agent_with_plugins`:

**`Cargo.toml`**

```toml
[dependencies]
vigil-core = { git = "https://github.com/zer0contextlost/vigil" }
vigil-cli  = { git = "https://github.com/zer0contextlost/vigil", package = "vigil" }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

**`src/main.rs`**

```rust
use vigil_core::PluginHost;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut host = PluginHost::new();
    host.add(Box::new(MyPlugin::new()));

    vigil_cli::run_agent_with_plugins(
        8877,                    // port
        None,                    // policy file
        None,                    // log file
        vec!["claude".into()],   // agent argv
        vec![],                  // PII watchlist terms
        None,                    // vigil.toml config
        None,                    // config path string
        host,
        None,                    // session name
    ).await
}
```

## Threading contract

`on_event` and `on_alert` are called from within an async tokio task. Implementations must not block. Spawn a `tokio::task` or send to a channel you own for any I/O.

## Example: structured NDJSON logger

```rust
use vigil_core::{Envelope, VigilPlugin};
use std::sync::Mutex;

pub struct NdjsonLogger {
    file: Mutex<std::fs::File>,
}

impl NdjsonLogger {
    pub fn new(path: &str) -> Self {
        let file = std::fs::OpenOptions::new()
            .create(true).append(true).open(path).unwrap();
        Self { file: Mutex::new(file) }
    }
}

impl VigilPlugin for NdjsonLogger {
    fn on_event(&self, envelope: &Envelope) {
        if let Ok(line) = serde_json::to_string(envelope) {
            if let Ok(mut f) = self.file.lock() {
                let _ = std::io::Write::write_fmt(&mut *f, format_args!("{}\n", line));
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn vigil_plugin_create() -> *mut Box<dyn VigilPlugin> {
    let plugin: Box<dyn VigilPlugin> = Box::new(NdjsonLogger::new("/tmp/vigil-extra.ndjson"));
    Box::into_raw(Box::new(plugin))
}
```

# vigil plugin system

vigil exposes a stable Rust trait (`VigilPlugin`) that lets you observe every event, react to every alert, and block tool calls — all without forking vigil itself.

## How it works

`vigil-core` exports the trait, context, and decision types:

```rust
pub struct PluginContext {
    pub session_id: uuid::Uuid,
    pub config_dir: PathBuf,      // ~/.vigil/plugins/<plugin-name>/
    pub host_version: &'static str,
}

pub enum PluginDecision {
    Allow,
    Deny(String),   // reason shown to the agent (HTTP 403) and logged as DENY
}

pub enum AlertLabel {
    BurnRate, Loop, Exfil, Deny, Cost, Duration, Timeout, WriteApproval, Pii,
    // label.code() returns the short string, e.g. BurnRate → "BURN"
}

pub trait VigilPlugin: Send + Sync {
    fn name(&self) -> &str { "unnamed" }
    async fn on_event(&self, ctx: &PluginContext, envelope: &Envelope) {}
    async fn on_alert(&self, ctx: &PluginContext, label: AlertLabel, detail: &serde_json::Value) {}
    async fn on_tool_call(&self, ctx: &PluginContext, tool_name: &str, input: &serde_json::Value) -> PluginDecision {
        PluginDecision::Allow
    }
}

pub struct PluginHost { … }
impl PluginHost {
    pub fn add(&mut self, plugin: Box<dyn VigilPlugin>);
    pub fn load_from_file(&mut self, path: &Path) -> anyhow::Result<()>;
}
```

`PluginHost` fans out to all registered plugins. `on_event` and `on_alert` are passive observers. `on_tool_call` is called after the built-in policy engine allows a tool call — the first plugin to return `Deny` blocks it, firing a DENY alert identical to a policy deny.

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
vigil plugins check ./my-plugin.dll  # validate ABI/rustc without loading
```

### Explicit load

```bash
vigil run --plugin ./my-plugin.dll -- claude
vigil run --plugin ./a.dll --plugin ./b.dll -- claude
```

### Compatibility

Plugin and host must be compiled with the same Rust toolchain and `vigil-core` version. The `dyn VigilPlugin` vtable layout is not stable across compiler versions. Use `vigil-plugin` (the SDK crate) and the `declare_plugin!` macro — it embeds ABI and rustc version metadata so vigil can detect mismatches before instantiation and give you a clear error instead of undefined behavior.

## Writing a dynamic plugin

Add `vigil-plugin` as your only vigil dependency — it re-exports everything you need and provides the `declare_plugin!` macro that handles all C-ABI boilerplate.

**`Cargo.toml`**

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
vigil-plugin = { git = "https://github.com/zer0contextlost/vigil", tag = "v0.2.1" }
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
```

**`src/lib.rs`**

```rust
use vigil_plugin::{async_trait, declare_plugin, AlertLabel, Envelope, PluginContext, PluginDecision, Value, VigilPlugin};

struct SlackNotifier {
    webhook_url: String,
}

#[async_trait]
impl VigilPlugin for SlackNotifier {
    fn name(&self) -> &str { "slack-notifier" }

    async fn on_alert(&self, ctx: &PluginContext, label: AlertLabel, detail: &Value) {
        let url = self.webhook_url.clone();
        let sid = ctx.session_id.to_string();
        let text = format!("[vigil {}] {} — {}", label.code(), &sid[..8], detail);
        tokio::spawn(async move {
            let _ = reqwest::Client::new()
                .post(&url)
                .json(&serde_json::json!({ "text": text }))
                .send()
                .await;
        });
    }
}

declare_plugin!(SlackNotifier {
    webhook_url: std::env::var("SLACK_WEBHOOK").unwrap_or_default(),
});
```

Build with `cargo build --release` and copy the resulting `.dll`/`.so`/`.dylib` to `~/.vigil/plugins/`.

`declare_plugin!` generates three C-ABI exports (exporting ABI version 3) that vigil checks before instantiation:

- `vigil_plugin_create` — constructs your plugin
- `vigil_plugin_abi_version` — returns the ABI version the plugin was built against
- `vigil_plugin_rustc_version` — returns the rustc version string baked in at compile time

If the ABI or rustc version doesn't match the running vigil binary, load is refused with a message like:

```
ABI mismatch loading my-plugin.dll: plugin ABI v1, host ABI v2.
Rebuild your plugin against vigil-plugin v0.3.0.
```

or:

```
rustc mismatch loading my-plugin.dll: plugin built with rustc 1.83.0, host built with rustc 1.84.0.
Rebuild both with the same toolchain.
```

## Writing an in-process plugin (wrapper binary)

For tighter integration — custom CLI flags, combining with your own config — write a thin wrapper binary that calls vigil's `run_agent_with_plugins`:

**`Cargo.toml`**

```toml
[dependencies]
vigil-core = { git = "https://github.com/zer0contextlost/vigil", tag = "v0.2.0" }
vigil-cli  = { git = "https://github.com/zer0contextlost/vigil", tag = "v0.2.0", package = "vigil" }
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

All methods (`on_event`, `on_alert`, `on_tool_call`) are async. Do not block — spawn tasks or send to channels for any I/O.

## Example: structured NDJSON logger

```rust
use vigil_plugin::{async_trait, declare_plugin, Envelope, PluginContext, VigilPlugin};
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

#[async_trait]
impl VigilPlugin for NdjsonLogger {
    fn name(&self) -> &str { "ndjson-logger" }

    async fn on_event(&self, _ctx: &PluginContext, envelope: &Envelope) {
        if let Ok(line) = serde_json::to_string(envelope) {
            if let Ok(mut f) = self.file.lock() {
                let _ = std::io::Write::write_fmt(&mut *f, format_args!("{}\n", line));
            }
        }
    }
}

declare_plugin!(NdjsonLogger::new("/tmp/vigil-extra.ndjson"));
```

## Low-level FFI (advanced)

If you can't use `vigil-plugin` (e.g. you're writing bindings for another language), you must export these three C symbols manually:

```rust
#[no_mangle]
pub extern "C" fn vigil_plugin_create() -> *mut Box<dyn VigilPlugin> {
    let plugin: Box<dyn VigilPlugin> = Box::new(MyPlugin::new());
    Box::into_raw(Box::new(plugin))
}

#[no_mangle]
pub extern "C" fn vigil_plugin_abi_version() -> u32 {
    3  // must match vigil_core::ABI_VERSION
}

#[no_mangle]
pub extern "C" fn vigil_plugin_rustc_version() -> *const std::os::raw::c_char {
    b"rustc 1.XX.0 (HASH DATE)\0".as_ptr() as *const _
}
```

If `vigil_plugin_abi_version` or `vigil_plugin_rustc_version` are absent, vigil skips those checks and attempts to load anyway (backward compatibility with plugins built before v0.2.0).

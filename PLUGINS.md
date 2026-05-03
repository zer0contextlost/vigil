# vigil plugin system

vigil exposes a stable Rust trait (`VigilPlugin`) that lets you observe every event, react to every alert, block tool calls, and modify outbound requests — all without forking vigil itself.

## What plugins can do

Five hooks are available. All are async; override only the ones you need.

| Hook | When it fires | Can block? |
|------|--------------|------------|
| `on_session_start(ctx)` | Once, before any events are dispatched | No |
| `on_session_end(ctx)` | Once, on clean exit or TUI quit | No |
| `on_event(ctx, envelope)` | Every event that passes the policy filter | No |
| `on_alert(ctx, label, detail)` | Every time vigil fires an alert | No |
| `on_tool_call(ctx, tool_name, input)` | Every tool call the built-in policy engine allows | Yes — return `Deny(reason)` |
| `on_outbound_request(ctx, provider, body)` | Every LLM request before forwarding | Yes — return `Some(modified_body)` |

`on_tool_call` is evaluated after the built-in policy engine allows a call. The first plugin to return `Deny` blocks it; the agent receives HTTP 403 and a `DENY` alert fires. `on_outbound_request` lets you modify the request body; the first `Some(value)` returned wins.

## Alert label codes

| Code | Variant | Trigger |
|------|---------|---------|
| `BURN` | `BurnRate` | Rolling $/min exceeded `max_burn_rate_usd_per_min` |
| `DRFT` | `Drift` | Drift signal fired (acceleration, stall, or self-contradiction) |
| `EXFL` | `Exfil` | Fingerprinted secret appeared in an outbound request or shell command |
| `DENY` | `Deny` | Policy or plugin blocked a tool call |
| `LOOP` | `Loop` | Same tool+input repeated N times |
| `WAPPR` | `WriteApproval` | Write approval required; risky diff gated on human approval |
| `TOUT` | `Timeout` | No LLM response after a tool call within the configured window |
| `COST` | `Cost` | Soft cost alert: session spend crossed `cost_alert_usd` |
| `DURA` | `Duration` | Session exceeded `max_session_duration_mins` |
| `PII` | `Pii` | PII detected in traffic |
| `PINJ` | `PromptInjection` | Prompt injection detected in a tool result |

## AlertDetail variants

The `detail: &Value` passed to `on_alert` can be deserialized into a typed struct using `label.parse_detail(detail)`. Fields for each variant:

`alert::BurnRate` — `rate_per_min_usd: f64`, `projected_total_usd: f64`

`alert::Drift` — `signal: String` (one of `OutputTokenAcceleration`, `ProgressStall`, `SelfContradiction`), `details: String`

`alert::Exfil` — `source: String`, `matches: Vec<String>` (redacted snippets)

`alert::Deny` — `tool_name: String`, `policy: Option<String>`, `reason: Option<String>`

`alert::Loop` — `tool_name: String`, `repeat_count: u32`

`alert::WriteApproval` — `path: String`, `risk: String`

`alert::Timeout` — `tool_name: String`, `elapsed_secs: u64`

`alert::Cost` — `threshold_usd: f64`, `session_cost_usd: f64`

`alert::Duration` — `elapsed_mins: u64`

`alert::Pii` — `kind: String`, `snippet: String`

`alert::PromptInjection` — `tool_name: String`, `category: String` (one of `instruction-override`, `system-tag`, `hidden-unicode`, `base64-payload`), `snippet: String`

## PluginContext fields

Every hook receives `ctx: &PluginContext`:

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | `uuid::Uuid` | Current session UUID |
| `config_dir` | `PathBuf` | Per-plugin data directory: `~/.vigil/plugins/<plugin-name>/`. Created on first dispatch if missing |
| `host_version` | `&'static str` | Version string of the running vigil binary |

Note: `config_dir` is automatically scoped per plugin — two plugins with different names get different directories even though they share the same base context.

## Scaffold and install

```bash
# Scaffold a new plugin crate
vigil plugins new my-plugin --template alert

# Available templates: alert, gatekeeper, logger, blank
vigil plugins new my-plugin --template gatekeeper

# Build it
cd my-plugin
cargo build --release

# Install to the auto-load directory
vigil plugins install ./target/release/my_plugin.dll   # Windows
vigil plugins install ./target/release/libmy_plugin.so # Linux

# Validate without installing
vigil plugins check ./target/release/my_plugin.dll

# Show the auto-load directory
vigil plugins dir

# List installed plugins
vigil plugins list
```

Auto-load directory: `~/.vigil/plugins/`. vigil scans it on every `vigil run` and loads any `.dll` (Windows), `.so` (Linux), or `.dylib` (macOS).

One-off load without installing:

```bash
vigil run --plugin ./my-plugin.dll --plugin ./other.dll -- claude
```

## Full example: webhook notifier for PINJ alerts

**`Cargo.toml`**

```toml
[package]
name = "vigil-pinj-notifier"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
vigil-plugin = { git = "https://github.com/zer0contextlost/vigil", tag = "v0.4.0" }
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde_json = "1"
```

**`src/lib.rs`**

```rust
use vigil_plugin::{
    async_trait, declare_plugin, AlertLabel, PluginContext, PluginDecision, Value, VigilPlugin,
};

struct PinjNotifier {
    webhook_url: String,
}

#[async_trait]
impl VigilPlugin for PinjNotifier {
    fn name(&self) -> &str { "pinj-notifier" }

    async fn on_alert(&self, ctx: &PluginContext, label: AlertLabel, detail: &Value) {
        // Only act on prompt injection alerts
        if label != AlertLabel::PromptInjection {
            return;
        }

        let url = self.webhook_url.clone();
        let sid = ctx.session_id.to_string();
        let text = format!(
            "[vigil PINJ] session {} — {}",
            &sid[..8],
            detail.get("category").and_then(|v| v.as_str()).unwrap_or("unknown")
        );

        tokio::spawn(async move {
            let _ = reqwest::Client::new()
                .post(&url)
                .json(&serde_json::json!({ "text": text }))
                .send()
                .await;
        });
    }

    async fn on_tool_call(
        &self,
        _ctx: &PluginContext,
        _tool_name: &str,
        _input: &Value,
    ) -> PluginDecision {
        PluginDecision::Allow
    }
}

declare_plugin!(PinjNotifier {
    webhook_url: std::env::var("WEBHOOK_URL").unwrap_or_default(),
});
```

Build and install:

```bash
cargo build --release
vigil plugins install ./target/release/vigil_pinj_notifier.dll
```

Set `WEBHOOK_URL` in your environment before running `vigil run`.

## ABI versioning

The current ABI version is **4**. It is embedded in every plugin compiled with `declare_plugin!` via the `vigil_plugin_abi_version` C export. vigil checks this before instantiation and refuses to load a mismatched plugin with a clear error:

```
ABI mismatch in my-plugin.dll: plugin ABI v3, host ABI v4.
Rebuild against vigil-plugin v0.4.0.
```

rustc version is also checked:

```
rustc mismatch in my-plugin.dll: plugin built with rustc 1.83.0, host built with rustc 1.84.0.
Rebuild both with the same toolchain.
```

Whenever `ABI_VERSION` bumps you must rebuild all plugins against the new `vigil-plugin` SDK crate. There is no backward compatibility for ABI mismatches — vtable layout is not stable across compiler versions. In-process plugins (added via `PluginHost::add`) are unaffected.

## Threading contract

All hook methods are async. Do not block synchronously — spawn tasks or send to channels for any I/O. The PluginHost fans out to all registered plugins sequentially; long blocking in one plugin delays all subsequent ones.

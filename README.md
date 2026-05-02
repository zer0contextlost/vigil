# vigil

Runtime observability and policy enforcement for AI coding agents.

vigil intercepts every LLM API call your AI coding agent makes, shows a live ratatui dashboard, records tamper-evident NDJSON session files, and enforces budget, policy, and safety rules in real time. Works with Claude Code, Codex, Cursor, Aider, and Gemini CLI.

## Install

```bash
git clone https://github.com/zer0contextlost/vigil
cd vigil
cargo install --path crates/vigil-cli
```

## Quick start

```bash
# Run Claude Code under vigil
vigil run -- claude

# Name a session for easy reference later
vigil run --name auth-refactor -- claude

# With a config file (budget limits, policies, webhooks)
vigil run --config vigil.toml -- claude

# Load a plugin from a shared library
vigil run --plugin ./my-plugin.dll -- claude
```

## Session commands

```bash
# Browse sessions in a full TUI (arrow keys / j·k, Enter to replay, d to delete)
vigil browse

# Text table of all sessions
vigil sessions

# Tag a session with a human-readable name (UUID or existing name both work)
vigil tag <session-id> my-label
vigil tag my-label  better-label

# Replay a session in the TUI
vigil replay <session-id-or-name>

# Replay a session prefix, then continue live
vigil fork <session-id> --prefix-events 20 -- claude

# Show all currently running vigil sessions on this machine
vigil ps
```

## Integrity and export

```bash
# Verify hash chain + ed25519 signature
vigil verify <session-id>

# Legacy audit (hash chain + ULID order + meta count)
vigil audit <session-id>

# Export session to NDJSON with PII redacted
vigil export <session-id>
vigil export <session-id> --output redacted.ndjson
```

`vigil verify` exits 0 (PASS) or 1 (FAIL) — suitable for CI.

## What vigil records

| Event | What it captures |
|-------|-----------------|
| `REQ / RES` | Every model call: provider, model, tokens, cost (including cache tokens) |
| `TOOL` | Tool calls before execution — inspectable and blockable |
| `DENY / OK` | Policy decisions on tool calls |
| `READ / WRIT` | File reads and writes inferred from tool call parameters |
| `PROC` | Child processes spawned by the agent |
| `MCP` | MCP server tool calls via vigil-mcp-shim |
| `PII!` | PII detections (regex + custom watchlist) |
| `BURN` | Burn-rate alarm: $/min exceeded threshold |
| `LOOP` | Loop detection: same tool+input repeated N times |
| `WAPPR` | Write approval required: risky diff gated on human approval |
| `EXFL` | Credential exfiltration: secret from a file read appeared in outbound request |
| `COST` | Soft cost alert: session spend crossed a warning threshold |
| `DURA` | Session duration alert: session has been running longer than configured limit |
| `TOUT` | Tool timeout: no LLM response after a tool call for N seconds |

## Configuration (vigil.toml)

```toml
[proxy]
port = 8877

# Shell command substrings to block (case-sensitive). Default list shown.
# Set to [] to disable all blocking.
blocked_commands = ["rm -rf", "dd if=", "mkfs", ":(){ :|:& };:"]

# Gate writes at this risk level or above. Low / Medium / High.
write_approval_threshold = "High"

# Alert if a tool call gets no LLM response within this many seconds.
tool_timeout_secs = 600

# Optionally kill the agent process after this many seconds of tool silence.
# tool_timeout_kill_secs = 900

[session]
store_raw = true

[pii]
watchlist_file = "~/.vigil/watchlist.txt"

[budget]
max_cost_usd = 5.00
max_tokens = 500000
allowed_hours = "09:00-18:00"      # overnight: "22:00-06:00"
max_burn_rate_usd_per_min = 0.50   # alert when rolling $/min exceeds this
loop_detect_threshold = 5          # alert when same tool+input repeats N times
cost_alert_usd = 1.00              # soft warning before hard limit
max_session_duration_mins = 60     # alert after this many minutes

[notify]
webhook = "https://hooks.slack.com/services/..."
# Which alert labels trigger the webhook. Omit to receive all.
webhook_events = ["BURN", "EXFL", "DENY", "LOOP"]

[[policies]]
name = "block-bash"
action = "Deny"
[policies.matcher]
type = "ToolCall"
tool_name_pattern = "Bash"
```

Pass with `vigil run --config vigil.toml -- <agent>`.

## Policy enforcement

Policies are evaluated in order; first match wins. Actions: `Deny`, `Confirm`, `LogOnly`.

```yaml
policies:
  - name: block-writes-outside-project
    matcher:
      type: FsWriteOutside
      root: "."
    action: Deny

  - name: no-env-reads
    matcher:
      type: FsPath
      path_pattern: ".env"
    action: LogOnly

  - name: token-budget
    matcher:
      type: TokenBudget
      max_tokens: 1000000
    action: LogOnly
```

See `POLICY_ENGINE.md` for all matcher types and hardcoded safety floors.

## Budget enforcement

When any hard limit is hit the agent session is stopped:

```toml
[budget]
max_cost_usd = 5.00           # stop if session cost exceeds $5
max_tokens = 500000           # stop if total tokens exceed 500k
allowed_hours = "09:00-18:00" # only allow runs during business hours
```

Soft alerts (`cost_alert_usd`, `max_session_duration_mins`) fire once as TUI events and webhook calls without stopping the session.

## Diff-gated write approval

```toml
[proxy]
write_approval_threshold = "High"   # Low / Medium / High
```

vigil buffers the SSE stream at any Write/Edit/MultiEdit/NotebookEdit call, scores the diff, and if risk meets the threshold shows a full-screen before/after diff overlay. Press `y` to approve or `n` to reject (agent receives HTTP 403). 5-minute timeout auto-rejects.

Risk scoring: crown-jewels paths (`.env`, auth, migration, payment, private keys) → High; >40% lines deleted → High; >10 lines deleted → Medium; file >500 lines → Medium.

## PII detection

Two mechanisms run on every LLM request/response and tool call:

Regex patterns cover: email, US phone, SSN, credit card (Luhn-validated), AWS access key, GitHub PAT, JWT, public IPv4, URLs with PII query params.

Custom watchlist: place one term per line in `~/.vigil/watchlist.txt` (or `--pii-watchlist <file>`). Terms are matched as literal case-insensitive substrings — not regex. Matched terms are never echoed in logs or TUI; only the label `[watchlist term]` is shown.

## Credential exfiltration detection

vigil fingerprints secrets (API keys, tokens, `.env` values) from files the agent reads via SHA-256. If a fingerprint later appears in an outbound LLM request or shell command, an `EXFL` event fires with a redacted match.

## Webhook notifications

```toml
[notify]
webhook = "https://hooks.example.com/vigil"
webhook_events = ["BURN", "EXFL", "DENY", "LOOP", "COST", "DURA", "TOUT"]
```

vigil POSTs JSON to the webhook on each matching alert. Retries up to 3 times with exponential backoff. Payload:

```json
{ "label": "BURN", "session_id": "...", "detail": { "rate_per_min_usd": 0.82, ... } }
```

## Plugin system

Drop a compiled shared library in `~/.vigil/plugins/` to auto-load it on every `vigil run`. See [PLUGINS.md](PLUGINS.md) for authoring instructions and examples.

```bash
vigil plugins list   # list plugins in ~/.vigil/plugins/
vigil plugins dir    # print the auto-load directory path
vigil run --plugin ./extra.dll -- claude   # load a specific plugin once
```

Plugins implement the `VigilPlugin` trait from the `vigil-plugin` SDK crate:

```rust
use vigil_plugin::{declare_plugin, Envelope, PluginContext, PluginDecision, Value, VigilPlugin};

struct MyPlugin;
impl VigilPlugin for MyPlugin {
    fn name(&self) -> &str { "my-plugin" }

    fn on_alert(&self, ctx: &PluginContext, label: &str, detail: &Value) {
        // fires on BURN, LOOP, EXFL, DENY, COST, DURA, TOUT, WAPPR, PII
    }

    fn on_tool_call(&self, _ctx: &PluginContext, tool_name: &str, _input: &Value) -> PluginDecision {
        // called after policy allows — return Deny to block
        PluginDecision::Allow
    }
}
declare_plugin!(MyPlugin);
```

A ready-to-use `alert-logger` plugin ships in `plugins/alert-logger/`. It writes every alert to `~/.vigil/alerts.ndjson` and can block tool calls by name via `VIGIL_BLOCK_TOOLS=Bash,WebSearch`.

## Session integrity

Every envelope is SHA-256 chained. On clean exit the chain-root hash is signed with a per-session ed25519 key and stored in the `.meta.json` sidecar.

```bash
vigil verify <session-id>
# vigil verify: abc-123...
# Events:     42
# Hash chain: OK
# Signature:  OK
# PASS
```

Sessions created before signing was added report `Signature: SKIP`.

## Pricing

Model pricing is loaded from `~/.vigil/pricing.toml` if present, otherwise built-in defaults apply. To override:

```toml
[[model]]
pattern = "claude-sonnet-4"
input_per_million = 3.0
output_per_million = 15.0
```

Patterns match as case-insensitive substrings. Put more-specific patterns first.

## MCP shim

To intercept MCP server tool calls, replace your MCP server command with `vigil-mcp-shim`:

```bash
vigil-mcp-shim --session-id <uuid> --ndjson ~/.vigil/sessions/<uuid>.ndjson <real-server> [args]
```

All `tools/call` requests are PII-scanned and logged as `McpCall` events.

## Architecture

Six Rust crates:

| Crate | Role |
|-------|------|
| `vigil-cli` | Binary, CLI args, agent spawning, TUI orchestration, budget enforcement, plugin loading |
| `vigil-proxy` | HTTP reverse proxy, SSE parser (Anthropic + OpenAI formats), write-approval gate |
| `vigil-core` | Event types, Envelope/hash chain, SessionStore, ed25519 signing, VigilConfig, BudgetEnforcer, PricingTable, PolicyEngine, PII scanner, PluginHost |
| `vigil-tui` | ratatui dashboard, session browser, replay |
| `vigil-watch` | Process tree monitor (sysinfo) — no-op on Windows |
| `vigil-mcp` | vigil-mcp-shim binary for stdio JSON-RPC MCP servers |

Traffic interception works by setting `ANTHROPIC_BASE_URL=http://127.0.0.1:8877` in the agent's environment. The proxy forwards to the real API over TLS.

## License

MIT

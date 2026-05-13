# vigil

**v0.8.0** — Runtime observability and policy enforcement for AI coding agents.

vigil intercepts every LLM API call your AI coding agent makes, shows a live ratatui TUI, serves a browser dashboard, records tamper-evident NDJSON session files, and enforces budget, policy, and safety rules in real time. Works with Claude Code, Cursor, Aider, Codex, Gemini CLI, and any agent that respects `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, or `GOOGLE_GEMINI_BASE_URL`.

## Quick start

```bash
git clone https://github.com/zer0contextlost/vigil
cd vigil
cargo install --path crates/vigil-cli

# Run Claude Code under vigil
vigil run -- claude

# Name a session
vigil run --name auth-refactor -- claude

# With a config file
vigil run --config vigil.toml -- claude
```

For IDEs that can't be launched by vigil (Cursor, etc.), use `vigil proxy` instead:

```bash
vigil proxy --port 8877 --config vigil.toml
```

Then point your IDE at `http://127.0.0.1:8877`. Cursor: Settings → Models → BYOK → set Override OpenAI Base URL to `http://127.0.0.1:8877/v1`.

For Gemini CLI, set the base URL environment variable before running:

```bash
vigil proxy --port 8877 --config vigil.toml
export GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8877
gemini
```

vigil auto-detects Gemini requests by path pattern and routes them to `https://generativelanguage.googleapis.com`. The write-approval gate, PII scanner, policy engine, and all other vigil features work identically for Gemini traffic.

## Architecture

| Crate | Role |
|-------|------|
| `vigil-cli` | Binary entrypoint; CLI parsing, agent spawning, TUI orchestration, budget enforcement, plugin loading |
| `vigil-core` | Event types, Envelope/hash chain, SessionStore, ed25519 signing, VigilConfig, BudgetEnforcer, PricingTable, PolicyEngine, PII scanner, PluginHost, drift/exfil/injection detection |
| `vigil-proxy` | HTTP reverse proxy, SSE parser (Anthropic + OpenAI + Gemini formats), write-approval gate |
| `vigil-tui` | ratatui dashboard, session browser, replay viewer |
| `vigil-web` | Browser dashboard (axum + rust-embed) — sessions table, event timeline, write-approval UI, SSE live updates, JSON/HTML export |
| `vigil-watch` | Process tree monitor (sysinfo) — tracks child processes spawned by the agent |
| `vigil-mcp` | MCP server mode (`vigil mcp`) and `vigil-mcp-shim` proxy binary for stdio JSON-RPC MCP servers |
| `vigil-plugin` | Plugin SDK — `VigilPlugin` trait, `declare_plugin!` macro, ABI versioning |

Traffic interception works by setting `ANTHROPIC_BASE_URL=http://127.0.0.1:8877` (Claude Code / Anthropic), `OPENAI_BASE_URL=http://127.0.0.1:8877/v1` (Cursor / OpenAI-compatible), or `GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8877` (Gemini CLI) in the agent's environment. The proxy forwards to the real API over TLS.

## CLI commands

### Session management

| Command | Description |
|---------|-------------|
| `vigil run [--port N] [--config F] [--name LABEL] [--plugin P] -- <agent>` | Run an agent under observation |
| `vigil proxy [--port N] [--config F] [--name LABEL] [--plugin P]` | Start proxy and TUI without spawning an agent |
| `vigil ps` | Show all currently active vigil sessions on this machine |
| `vigil status [--recent N]` | One-line-per-session status dump (live + last N completed); scriptable |
| `vigil sessions` | Print a text table of all recorded sessions (ID, name, agent, cost, tokens, violations) |
| `vigil browse [--speed N]` | Interactive TUI session browser (arrow keys / j·k, Enter to replay, d to delete) |
| `vigil replay <session-id> [--speed N]` | Replay a session in the TUI; `--speed 2.0` plays back at 2× real time |
| `vigil replay <session-id> --mock [--on-miss error\|stub]` | Replay against a fake upstream — no real API calls, cost-free regression testing |
| `vigil fork <session-id> [--prefix-events N] -- <agent>` | Replay a session prefix, then continue live |
| `vigil tag <session-id> <name>` | Assign a human-readable label to a session |
| `vigil clear [-y]` | Delete all session files (prompts for confirmation unless `-y`) |
| `vigil prune [--older-than N]` | Delete session files older than N days (default 30) |
| `vigil repair-meta [--dry-run]` | Recompute `.meta.json` stats from NDJSON event logs; use after upgrades to backfill historical sessions |
| `vigil export <session-id> [--output FILE]` | Export session to NDJSON with PII redacted |
| `vigil export --all [--output-dir DIR]` | Export all sessions to a directory |
| `vigil diff <session-a> <session-b> [--brief]` | Compare tool-call sequences of two sessions |
| `vigil cost-report [--days N] [--branch NAME]` | Show cost breakdown by branch and day |

### Analysis

| Command | Description |
|---------|-------------|
| `vigil report <id> [--json] [--html] [--html-fragment]` | Generate session audit report with hygiene scorecard (9 signals, scorecard_version 2). `<id>` accepts full UUID, prefix, or session name |
| `vigil verify <id>` | Verify hash chain and ed25519 signature; exits 0 (PASS) or 1 (FAIL) |
| `vigil audit <id>` | Hash chain audit: ULID order, meta count, chain integrity |
| `vigil diff <id-a> <id-b> [--brief]` | Compare tool-call sequences of two sessions |

### Plugins

| Command | Description |
|---------|-------------|
| `vigil plugins new <name> [--template alert\|gatekeeper\|logger\|blank]` | Scaffold a new plugin crate |
| `vigil plugins install <path>` | Copy a compiled plugin to the auto-load directory |
| `vigil plugins list` | List plugins in `~/.vigil/plugins/` |
| `vigil plugins check <path>` | Validate ABI/rustc compatibility without installing |
| `vigil plugins dir` | Print the auto-load directory path |

### Other

| Command | Description |
|---------|-------------|
| `vigil init [--output FILE] [--force]` | Initialize a policy file and `vigil.toml` for this project; exits 1 if files already exist without `--force` |
| `vigil pricing [--write [--force]]` | Show the current effective pricing table. `--write` dumps defaults to `~/.vigil/pricing.toml` |
| `vigil mcp` | Start vigil as an MCP server (JSON-RPC over stdio) |

## vigil.toml reference

Pass with `vigil run --config vigil.toml -- <agent>`.

### [proxy]

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | `u16` | `8877` | Proxy listen port |
| `dashboard_port` | `u16` | — | Bind the browser dashboard on `127.0.0.1:<port>`. Omit to disable. Example: `8878` |
| `blocked_commands` | `[string]` | `["rm -rf", "dd if=", "mkfs", ":(){ :\|:& };:"]` | Bash command substrings to block (case-sensitive substring match) |
| `write_approval_threshold` | `string` | — | Gate writes at this risk level or above: `"Low"`, `"Medium"`, or `"High"`. Omit to disable |
| `tool_timeout_secs` | `u64` | — | Emit a TOUT alert if no LLM response follows a tool call within N seconds |
| `tool_timeout_kill_secs` | `u64` | — | Kill the agent process after N seconds of tool silence (must be ≥ `tool_timeout_secs`) |

### [web]

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | `u16` | — | Bind the browser dashboard on `127.0.0.1:<port>`. Omit to disable. Access via the printed URL which includes a one-time bearer token |

The dashboard is always bound to `127.0.0.1` — never exposed to the network. It shows a live sessions table, per-session event timelines, write-approval banners, and supports column sorting, status filtering, and JSON/HTML session export.

### [approval]

File trust tiers that override `write_approval_threshold` on a per-path basis. Globs support prefix (`src/*`), suffix (`*.env`), and directory (`src/config/`) patterns.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `yolo_paths` | `[string]` | `[]` | Skip write approval for these paths entirely |
| `watch_paths` | `[string]` | `[]` | Always require write approval for these paths, regardless of risk score |
| `lockdown_paths` | `[string]` | `[]` | Same as `watch_paths` but shows an elevated ⚠ LOCKDOWN ZONE banner and includes the zone name in the agent's 403 rejection body so it can self-correct |

Example:

```toml
[approval]
yolo_paths   = ["tests/", "*.md", "docs/"]
watch_paths  = ["src/"]
lockdown_paths = [".env", "src/config/", "*.pem", "*.key"]
```

### [session]

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `store_raw` | `bool` | — | Whether to store raw request/response bodies in session files |
| `sessions_dir` | `path` | `~/.vigil/sessions/` | Override the session storage directory |

### [pii]

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `watchlist_file` | `path` | — | File with one literal term per line for custom PII matching |

### [budget]

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_cost_usd` | `f64` | — | Hard stop if session cost exceeds this amount |
| `max_tokens` | `u32` | — | Hard stop if total tokens exceed this count |
| `allowed_hours` | `string` | — | Allow runs only during this window, format `"HH:MM-HH:MM"` local time |
| `max_burn_rate_usd_per_min` | `f64` | — | Fire BURN alert when rolling $/min exceeds this |
| `loop_detect_threshold` | `u32` | — | Fire LOOP alert when the same tool+input repeats N times |
| `cost_alert_usd` | `f64` | — | Fire soft COST alert (no stop) at this spend level |
| `max_session_duration_mins` | `u64` | — | Fire DURA alert after this many minutes |
| `max_sub_agent_depth` | `u32` | — | Deny Task tool calls when count exceeds this value (fires TASK/SubAgentSpawned) |

### [notify]

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `webhook` | `string` | — | HTTP endpoint to POST alert events to (3 retries, exponential backoff) |
| `webhook_events` | `[string]` | all alerts | Alert codes to forward. Valid: `BURN`, `TOUT`, `EXFL`, `LOOP`, `WAPPR`, `COST`, `DURA`, `DENY`, `DRFT`, `PINJ`, `PII` |

### [report]

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `turn_to_first_write_warn` | `u32` | `5` | Turns before first FsWrite to show WATCH verdict |
| `turn_to_first_write_flag` | `u32` | `15` | Turns before first FsWrite to show FLAG verdict |
| `input_growth_warn_multiplier` | `f64` | `1.5` | Input token growth multiplier (last third vs first third) to warn |
| `input_growth_flag_multiplier` | `f64` | `2.0` | Input token growth multiplier to flag |
| `reread_warn_count` | `u32` | `2` | Paths read more than this many times to warn |
| `reread_flag_count` | `u32` | `3` | Paths read more than this many times to flag |

### [window]

Auto-position the vigil TUI and agent windows at launch. All fields optional — omit to keep current behavior (no repositioning). Values are in pixels.

| Field | Type | Description |
|-------|------|-------------|
| `tui_x` | `i32` | vigil TUI window X position |
| `tui_y` | `i32` | vigil TUI window Y position |
| `tui_width` | `u32` | vigil TUI window width |
| `tui_height` | `u32` | vigil TUI window height |
| `agent_x` | `i32` | Agent window X position |
| `agent_y` | `i32` | Agent window Y position |
| `agent_width` | `u32` | Agent window width |
| `agent_height` | `u32` | Agent window height |

Example split-screen layout (1920×1080 monitor):

```toml
[window]
tui_x = 0
tui_y = 0
tui_width = 960
tui_height = 1080
agent_x = 960
agent_y = 0
agent_width = 960
agent_height = 1080
```

Linux: requires `xterm` (agent window) and optionally `wmctrl` (vigil window). Windows: uses native `CreateProcessW` and `SetWindowPos`.

### [drift]

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `baseline_turns` | `usize` | `5` | Number of early LlmResponse events used to build the output-token baseline |
| `window_turns` | `usize` | `5` | Rolling window size for the recent average |
| `acceleration_multiplier` | `f64` | `3.0` | Window average must exceed baseline by this multiplier to fire |
| `acceleration_min_tokens` | `u32` | `200` | Minimum window average tokens before acceleration check applies |
| `stall_threshold` | `usize` | `5` | Consecutive LlmRequests without FsWrite or novel FsRead before ProgressStall fires |
| `debounce_events` | `u32` | `25` | Events to suppress the same drift signal after it fires |

### [[policies]]

Policies are evaluated in order; first match wins. Actions: `Deny`, `Confirm`, `LogOnly`.

```toml
[[policies]]
name = "block-bash"
action = "Deny"
[policies.matcher]
type = "ToolCall"
tool_name_pattern = "Bash"

[[policies]]
name = "no-env-reads"
action = "LogOnly"
[policies.matcher]
type = "FsPath"
path_pattern = ".env"
```

## Alert types

| Code | Trigger |
|------|---------|
| `BURN` | Rolling $/min burn-rate exceeded `max_burn_rate_usd_per_min` |
| `DRFT` | Drift signal fired: output token acceleration, progress stall, or self-contradiction |
| `EXFL` | Credential exfiltration: a fingerprinted secret appeared in an outbound request |
| `DENY` | Policy or plugin blocked a tool call |
| `LOOP` | Same tool+input repeated N times |
| `WAPPR` | Write approval required: risky diff gated on human approval |
| `TOUT` | Tool timeout: no LLM response after a tool call within the configured window |
| `COST` | Soft cost alert: session spend crossed `cost_alert_usd` |
| `DURA` | Session duration alert: session exceeded `max_session_duration_mins` |
| `PII` | PII detected in traffic (regex patterns or custom watchlist) |
| `PINJ` | Prompt injection detected in a tool result |
| `TASK` | Sub-agent spawned: Task tool call count exceeded `max_sub_agent_depth` |

## Security features

**Policy engine** — policies in `vigil.toml` match tool calls by name, input pattern, path, or sub-agent depth. Actions: `Deny` (HTTP 403 to agent), `Confirm` (human approval), `LogOnly`.

**Write approval** — at `write_approval_threshold`, vigil buffers SSE streams at Write/Edit/MultiEdit/NotebookEdit calls, scores the diff, and shows a full-screen before/after overlay. Press `y` to approve or `n` to reject. 5-minute timeout auto-rejects. Risk scoring: crown-jewels paths (`.env`, auth, migration, payment, private keys) → High; >40% lines deleted → High; >10 lines deleted → Medium; file >500 lines → Medium.

**PII and secrets detection** — runs on every LLM request/response and tool call. Personal data patterns: email, US phone, SSN, credit card (Luhn-validated), public IPv4, URLs with PII query params. Secret patterns (trufflehog-quality coverage): Anthropic, OpenAI (`sk-` and `sk-proj-`), GitHub PAT/Actions/OAuth/refresh tokens, AWS access key, Google API key and OAuth token, Stripe secret/publishable/restricted keys, Slack bot/user/app tokens, npm token, SendGrid, Mailgun, HuggingFace, Twilio account SID, Cloudflare API token, Databricks token, PEM private key header, JWT, and a generic `api_key = <value>` context pattern. Custom watchlist terms are matched as case-insensitive substrings; matched terms are never echoed in logs or snippets.

**Prompt injection (PINJ)** — scans tool results for instruction-override phrases, hidden system tags, suspicious Unicode (bidi/zero-width), and large base64 blobs. Fires `PINJ` alert with the category and a snippet.

**Exfil detection** — fingerprints secrets (API keys, tokens, `.env` values) from file reads via SHA-256. If a fingerprint appears in an outbound request or shell command, `EXFL` fires. Bash commands are also scanned for curl/wget/netcat/scp/dns exfiltration patterns.

**Drift detection** — three signals: `OutputTokenAcceleration` (rolling token average exceeds baseline by multiplier), `ProgressStall` (N consecutive LLM requests with no file activity), `SelfContradiction` (response negates a path or tool the session has demonstrably used).

**Session signing** — every envelope is SHA-256 chained. On clean exit the chain-root hash is signed with a per-session ed25519 key and stored in the `.meta.json` sidecar. `vigil verify` checks both chain and signature, exits 0 on PASS.

## Plugin system

Drop a compiled shared library in `~/.vigil/plugins/` to auto-load it on every `vigil run`. See [PLUGINS.md](PLUGINS.md) for authoring instructions and full examples.

```bash
vigil plugins new my-plugin --template alert
vigil plugins install ./my-plugin.dll
vigil run --plugin ./extra.dll -- claude   # one-off load
```

Plugins implement the `VigilPlugin` trait from `vigil-plugin` and can observe events, react to alerts, block tool calls, and modify outbound requests.

## MCP server

`vigil mcp` starts vigil as a self-contained MCP server over stdio (JSON-RPC 2.0). Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vigil": {
      "command": "vigil",
      "args": ["mcp"]
    }
  }
}
```

Five tools are available to the AI assistant:

| Tool | Description |
|------|-------------|
| `vigil_status` | Active session count and proxy status |
| `vigil_sessions` | List recent sessions with cost, name, and timestamp. Accepts optional `limit` integer |
| `vigil_policy_check` | Check whether a named tool call would be allowed or require confirmation. Requires `tool_name` string |
| `vigil_report` | Generate an audit report for a session. Accepts `session_id` (UUID) and optional `format: "json"` for structured output |
| `vigil_diff` | Diff two sessions' tool-call sequences. Accepts `session_a` and `session_b` UUIDs |

The `vigil-mcp-shim` binary is also available as a transparent proxy for wrapping existing MCP servers, logging their `tools/call` events as `McpCall` events in a vigil session.

## Pricing

Model pricing is loaded from `~/.vigil/pricing.toml` if present, otherwise built-in defaults apply. Use `vigil pricing` to inspect the active table and `vigil pricing --write` to seed the file with defaults for local overrides.

```toml
[[model]]
pattern = "claude-sonnet-4"
input_per_million = 3.0
output_per_million = 15.0
```

Patterns match as case-insensitive substrings. Put more-specific patterns first. Built-in defaults include entries for Claude, GPT, and Gemini models; Gemini entries are ordered so `gemini-2.5-flash-lite` appears before `gemini-2.5-flash` to prevent the shorter pattern matching the longer model name.

## vigil-slack plugin

A ready-to-use Slack notification plugin is maintained as a separate crate at `github.com/zer0contextlost/vigil-slack`. It is not part of the vigil workspace.

## License

MIT

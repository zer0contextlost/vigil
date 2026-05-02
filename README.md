# vigil

Runtime observability and policy enforcement for AI coding agents.

vigil intercepts every LLM API call your AI coding agent makes, shows a live ratatui dashboard, and records tamper-evident NDJSON session files. Works with Claude Code, Codex, Cursor, Aider, and Gemini CLI.

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

# With a config file (budget limits, PII watchlist, policies)
vigil run --config vigil.toml -- claude

# List recorded sessions
vigil sessions

# Show all currently running vigil sessions
vigil ps

# Replay a session in the TUI
vigil replay <session-uuid>

# Fork a session: replay N events as context, then go live
vigil fork <session-uuid> --prefix-events 10 -- claude

# Verify a session's hash chain integrity
vigil audit <session-uuid>
```

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
| `WAPPR` | Write approval required: agent wants to write a risky file |
| `EXFL` | Credential exfiltration: secret from a file read appeared in outbound LLM request |

## Configuration (vigil.toml)

```toml
[proxy]
port = 8877

[session]
store_raw = true

[pii]
watchlist_file = "~/.vigil/watchlist.txt"

[budget]
max_cost_usd = 5.00
max_tokens = 500000
allowed_hours = "09:00-18:00"

[[policies]]
name = "block-bash"
action = "Deny"
[policies.matcher]
type = "ToolCall"
tool_name_pattern = "Bash"
```

Pass with `vigil run --config vigil.toml -- <agent>`.

## Policy enforcement

Policies are evaluated in order; first match wins. Supported actions: `Deny`, `Confirm`, `LogOnly`.

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

See `example-policy.yaml` for all matcher types. See `POLICY_ENGINE.md` for hardcoded safety floors and engine details.

## Budget enforcement

When any budget limit is hit, the agent session is stopped and the TUI drains remaining events:

```toml
[budget]
max_cost_usd = 5.00          # stop if session cost exceeds $5
max_tokens = 500000          # stop if total tokens exceed 500k
allowed_hours = "09:00-18:00" # only allow runs during business hours
```

Overnight windows work too: `"22:00-06:00"`.

## PII detection

Two mechanisms run on every LLM request/response and tool call:

Regex patterns: email, US phone, SSN, credit card, AWS key, GitHub PAT, JWT, public IPv4, URLs with PII params. Custom terms: case-insensitive substring match against a watchlist file. Both emit `PiiAlert` events with partial redaction before storage.

## Pricing

Model pricing is loaded from `~/.vigil/pricing.toml` if present, otherwise built-in defaults are used. To override:

```toml
[[model]]
pattern = "claude-sonnet-4"
input_per_million = 3.0
output_per_million = 15.0
```

Patterns are matched as case-insensitive substrings. Put more-specific patterns first.

## MCP shim

To intercept MCP server tool calls, replace your MCP server command with `vigil-mcp-shim`:

```bash
vigil-mcp-shim --session-id <uuid> --ndjson ~/.vigil/sessions/<uuid>.ndjson <real-server> [args]
```

All `tools/call` requests are PII-scanned and logged as `McpCall` events.

## Audit

`vigil audit <session-uuid>` verifies the integrity of a recorded session:

```
vigil audit: 3f2a1b4c-...
Events:     42
Hash chain: OK
ULID order: OK
Meta count: OK

PASS
```

Exits with code 0 (PASS) or 1 (FAIL). Suitable for CI use.

## Burn-rate alarms and loop detection

```toml
[budget]
max_burn_rate_usd_per_min = 0.50   # alert when spending exceeds this rate
loop_detect_threshold = 5          # alert when same tool+input repeats N times
```

A `BURN` event fires with a projected session total whenever the rolling $/min rate exceeds the limit. A `LOOP` event fires when the same tool+input hash is seen N times in a session.

## Diff-gated write approval

```toml
[proxy]
write_approval_threshold = "High"   # Low / Medium / High
```

When set, vigil buffers the SSE stream at any Write/Edit/MultiEdit/NotebookEdit tool call, scores the diff, and if risk meets the threshold shows a full-screen TUI overlay with before/after diff. Press `y` to approve or `n` to reject (agent receives HTTP 403). 5-minute timeout auto-rejects.

Risk scoring: crown jewels paths (`.env`, `auth`, `migration`, `payment`, private keys) → High; >40% lines deleted → High; >10 lines deleted → Medium; file >500 lines → Medium.

## Credential exfiltration detection

vigil fingerprints secrets (API keys, tokens, `.env` values) from files the agent reads. If a fingerprint later appears in an outbound LLM request or shell command, an `EXFL` event fires with a redacted match.

No credentials are stored — only SHA-256 hashes. Redacted matches show the first 4 characters followed by `***`.

## Multi-session dashboard

```bash
vigil ps
```

Shows all currently running vigil sessions on this machine with per-session burn rate, token count, cost, and attention flags. Uses `~/.vigil/active/` lock files with PID verification to detect stale entries.

## Architecture

Six Rust crates:

| Crate | Role |
|-------|------|
| vigil-cli | Binary, CLI args, agent spawning, TUI orchestration, budget enforcement |
| vigil-proxy | HTTP reverse proxy, SSE parser (Anthropic + OpenAI formats), event emission |
| vigil-core | Event types, Envelope/hash chain, SessionStore, VigilConfig, BudgetEnforcer, PricingTable, PolicyEngine, PII scanner |
| vigil-tui | ratatui dashboard, App state, replay |
| vigil-watch | Process tree monitor (sysinfo-based) |
| vigil-mcp | vigil-mcp-shim binary: intercepts stdio JSON-RPC MCP servers |

Traffic interception works by setting `ANTHROPIC_BASE_URL=http://127.0.0.1:8877` in the agent's environment. The proxy forwards to the real API over TLS.

## License

MIT

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

# Replay a session in the TUI
vigil replay <session-uuid>

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

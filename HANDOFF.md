# Vigil — Handoff Notes

## What vigil does

Vigil is a runtime observability tool for AI coding agents. It intercepts the agent's LLM API calls via an HTTP reverse proxy, shows a live ratatui TUI with every request/response and token count, and saves append-only NDJSON session files for audit and replay.

```
vigil run -- claude -p "your prompt"
vigil run --config vigil.toml -- claude -p "your prompt"
vigil sessions
vigil replay <session-uuid>
```

After the agent finishes, the TUI shows `[DONE -- q to exit]`. Press q to exit.

## Crate layout

| Crate | Purpose |
|---|---|
| vigil-cli | Binary entrypoint, CLI args, agent spawning, TUI orchestration, budget enforcement |
| vigil-proxy | HTTP reverse proxy, SSE parser (Anthropic + OpenAI), event emission |
| vigil-core | Event, Envelope, SessionStore, VigilConfig, BudgetEnforcer, ProviderKind, Scanner, PolicyEngine |
| vigil-tui | ratatui dashboard, App state, replay |
| vigil-watch | Filesystem/process watcher (no-op on Windows) |
| vigil-mcp | vigil-mcp-shim binary: intercepts stdio JSON-RPC MCP tool servers |

## How traffic interception works

The proxy is a plain HTTP server on port 8877 (configurable). The agent is launched with `ANTHROPIC_BASE_URL=http://127.0.0.1:8877` in its environment. Claude Code sends plain HTTP to the proxy. The proxy forwards to `https://api.anthropic.com` (or `https://api.openai.com` etc.) via reqwest with TLS. The response is streamed back as chunked HTTP/1.1.

The proxy always sets `accept-encoding: identity` on upstream requests. If this is missing, Anthropic returns gzip-compressed SSE and the parser sees binary garbage.

## Supported providers

`vigil_core::provider::detect_provider_from_host()` returns a `ProviderKind` enum:
Anthropic, OpenAI, Gemini, OpenRouter, XAI, Unknown.

The proxy dispatches to `process_sse_event()` (Anthropic format) or `process_openai_sse_event()` (OpenAI `choices[0].delta` format) based on the detected provider. Non-streaming responses call `emit_anthropic_response()` or `emit_openai_response()`.

## Session lifecycle

Events flow: `proxy task → raw_tx → filter task (policy + budget eval) → filtered_tx → TUI`.

The TUI's `App::push_event` calls `store.append(event)` to write each event as a JSON line to `~/.vigil/sessions/<uuid>.ndjson`. A sidecar `<uuid>.meta.json` is atomically updated on each flush.

The `Envelope` struct wraps every `Event` with: ULID event_id (sortable), session_id (Uuid), schema_version (u8), SHA-256 hash-chain over previous envelope, and turn_id.

`TimestampedEvent` is a type alias for `Envelope` (backward compat).

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
allowed_hours = "09:00-18:00"   # or "22:00-06:00" for overnight

[[policies]]
name = "block-bash"
action = "Deny"
[policies.matcher]
type = "ToolCall"
tool_name_pattern = "Bash"
```

Pass with `vigil run --config vigil.toml -- <agent>`.

## Budget enforcement

`vigil_core::budget::BudgetEnforcer` is created from `VigilConfig.budget` and checked after every `LlmResponse` event in the filter task. When any limit is exceeded the filter task breaks, printing `[BUDGET] ...` to stderr and letting the TUI drain.

## MCP shim

`vigil-mcp-shim` is a transparent stdio proxy for MCP servers:

```
vigil-mcp-shim --session-id <uuid> --ndjson ~/.vigil/sessions/<uuid>.ndjson <real-server-command> [args]
```

Configure your MCP client (Claude Desktop, etc.) to use `vigil-mcp-shim <real-server> [args]` as the server command. All `tools/call` requests are intercepted, PII-scanned, and logged as `McpCall` events to the NDJSON file. Falls back to stderr if `--ndjson` is not given.

## TUI layout

Three-panel layout: header (3 lines) + horizontal split [event list 65% | stats sidebar 35%] (55%) + detail pane (44%) + help bar (1 line).

Header shows: status badge (LIVE/DONE/REPLAY), session ID (first 8 chars), agent name, scroll position, config file path when `--config` is used.

Event type labels: REQ, RES, TOOL, DENY, OK, READ, WRIT, PROC, MCP, PII! (4-char fixed-width).

Tab toggles focus to the detail pane for scrolling. Up/Down/PgUp/PgDn/Home/End navigate. q or Esc quits.

## Replay

`vigil replay <uuid>` tries NDJSON format first (new sessions), replaying with timestamp-paced delays (each event delayed by its original elapsed time, capped at 500ms). Falls back to old JSON `Session.load()` for pre-Phase-1 sessions.

## PII detection

Two mechanisms on every LLM request/response and tool call:
- `scan_pii()`: regex patterns for email, US phone, SSN (Luhn-validated), credit card, AWS key, GitHub PAT, JWT, public IPv4, URLs with PII params.
- `scan_watchlist()`: case-insensitive substring match against custom terms from `--pii-watchlist` file.

Both emit `PiiAlert` events with `source` (tool name or "llm_request"/"llm_response") and `kinds` list. Snippets are partially redacted before storage.

## Audit

`vigil audit <session-uuid>` verifies the integrity of a recorded NDJSON session:

Hash chain: re-computes each envelope's SHA-256 hash and checks the next envelope's `prev_hash` field matches. Reports first break position if any.

ULID order: checks that ULID strings are non-decreasing (lexicographic order = time order for Crockford base32).

Meta count: loads the `.meta.json` sidecar and checks `event_count` matches actual envelope count.

Exits with code 0 (PASS) or 1 (FAIL). Suitable for CI use.

## Pricing

`vigil_core::PricingTable` is the single authoritative source of per-model pricing. On startup it tries to load `~/.vigil/pricing.toml`. If the file is missing or unparseable it falls back to built-in defaults.

To override pricing, create `~/.vigil/pricing.toml`:

```toml
[[model]]
pattern = "claude-opus-4"
input_per_million = 15.0
output_per_million = 75.0

[[model]]
pattern = "claude-sonnet-4"
input_per_million = 3.0
output_per_million = 15.0
```

Entries are matched by case-insensitive substring. Put more-specific patterns first (e.g. `gpt-4o-mini` before `gpt-4o`).

## Known gaps

**Windows-only proxy mode.** `vigil-watch` is a stub on Windows; FsRead/FsWrite/ProcessSpawn events never appear for file-system activity.

## Running tests

```
cargo test --workspace
```

20 integration tests in vigil-proxy cover: chunked reads, SSE streaming, non-streaming round-trips, header handling, SSRF blocking, oversized request rejection, event emission.

## Reinstalling after code changes

```
cargo install --path F:\projects\vigil\crates\vigil-cli --force
```

## GitHub

Repo: `zer0contextlost/vigil` (private). Branches: `main` (stable), `dev` (working). Workflow: commit dev → PR to main → QA agent reviews → merge.

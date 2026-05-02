# Vigil — Handoff Notes

## What vigil does

Vigil is a runtime observability tool for AI coding agents. It intercepts the agent's LLM API calls via an HTTP reverse proxy, shows a live ratatui TUI with every request/response and token count, and saves full session JSON files for later review.

Run it like this:

```
vigil run --log-file session.log -- claude -p "your prompt"
```

After the agent finishes, the TUI shows `[DONE -- q to exit]`. Press q to save the session and print the cost summary.

## Crate layout

| Crate | Purpose |
|---|---|
| vigil-cli | Binary entrypoint, CLI args, agent spawning, TUI orchestration |
| vigil-proxy | HTTP reverse proxy, SSE parser, event emission |
| vigil-core | Shared types: Event, TimestampedEvent, Session, PolicyEngine |
| vigil-tui | ratatui dashboard, App state |
| vigil-watch | Filesystem/process watcher (no-op on Windows) |
| vigil-mcp | MCP shim stub |

## How traffic interception works

The proxy is a plain HTTP server on port 8877. The agent process is launched with `ANTHROPIC_BASE_URL=http://127.0.0.1:8877` in its environment. Claude Code sends unencrypted HTTP to the proxy. The proxy forwards to `https://api.anthropic.com` using reqwest (which handles TLS). The response is streamed back as chunked HTTP/1.1 to the agent.

Important: the proxy builds reqwest with `default-features = false` (no gzip/brotli). The upstream request always sets `accept-encoding: identity` to prevent Anthropic from compressing responses. If this header is ever missing, Anthropic will return gzip-compressed SSE and the parser will see binary garbage and emit zero tokens.

## SSE parsing

`stream_sse_response` in `vigil-proxy/src/lib.rs` accumulates raw bytes in a `Vec<u8>` buffer, finds newline boundaries byte-by-byte (handles both `\n` and `\r\n`), and dispatches JSON payloads on blank lines. It calls `process_sse_event` which updates an `SseState` struct, tracking `input_tokens` from `message_start` and `output_tokens` from `message_delta`. After the stream ends it emits one `LlmResponse` event with both counts.

## Session lifecycle

Events flow: `proxy task → raw_tx channel → filter task (policy eval) → filtered_tx channel → TUI`. The TUI's `App::push_event` updates session stats (input/output tokens, cost, violations) and calls `session.record(event)` so every event is persisted. On exit, `app.session.save()` writes the JSON to `~/.vigil/sessions/<uuid>.json`.

## Shutdown sequence

When the agent process exits, vigil waits 1500ms (grace period for in-flight SSE streams to emit their final LlmResponse), then aborts the filter task. Aborting the filter closes `filtered_tx`, which causes the TUI's event receiver to return `None`. The TUI sets `agent_done = true` and stays open showing `[DONE — q to exit]`. The user presses q, the TUI exits, and the session is saved.

## TUI layout

The TUI (`vigil-tui/src/lib.rs`) uses a three-panel layout:

The top 3 lines are a header bar with an inverted status badge (LIVE / DONE / REPLAY), session ID, agent name, and a tail/position indicator. Below that the screen splits 55% / 44% vertically between the main area and the detail pane, with a 1-line help bar at the bottom.

The main area splits 65% / 35% horizontally. The left panel is the scrollable event list; the right panel is the stats sidebar. The stats sidebar shows: session ID (first 8 chars), agent name, total cost in green, input/output token counts with thousands separators, then a per-type event breakdown that only shows non-zero rows (req, res, tool, result, blocked, fsread, fswrite, spawn, mcp), then violations and PII alert counts in red if non-zero.

Event rows use 4-character fixed-width type labels: REQ (cyan dim), RES (cyan), TOOL (yellow), DENY (red bold), OK (green dim), READ (gray), WRIT (magenta), PROC (yellow dim), MCP (cyan dim), PII! (red bold).

The detail pane shows full event content for the selected row. Tab toggles focus to the detail pane for scrolling; Tab again or Esc returns to the list.

`App` now carries an `EventCounts` struct with per-type counts that are updated in `push_event` alongside the session stats. The `fmt_num` helper adds thousands separators to token counts.

## PII detection

Two mechanisms run independently on every LLM request, LLM response, and tool call input.

`scan_pii` in `vigil-core/src/pii.rs` applies regex patterns for: email, US phone, SSN, credit card (with Luhn validation), AWS access key, GitHub PAT, JWT, public IPv4, and URLs containing PII parameter names. This runs automatically with no configuration.

`scan_watchlist` does case-insensitive substring matching against a list of custom terms loaded from a file passed via `--pii-watchlist`. Use this for names, internal project codes, or any sensitive string that doesn't fit a standard pattern. The watchlist is optional; omitting it does not disable the regex patterns.

Both emit `PiiAlert` events with a `source` field (tool name, `llm_request`, or `llm_response`) and a `kinds` list of what was found. Matched snippets are partially redacted (last N chars kept) before being stored.

## Known gaps

**Cache token accounting.** The Anthropic `message_start` event includes `cache_read_input_tokens` and `cache_creation_input_tokens` separately from `input_tokens`. Vigil currently only records `input_tokens` (the non-cached count). Cache read tokens are priced at ~10% of regular input tokens. For heavy Claude Code sessions where the system prompt is always cached, the recorded cost will be understated.

**Hardcoded pricing.** `cost_usd()` in `vigil-proxy/src/lib.rs` uses hardcoded per-million-token prices. These will drift as Anthropic adjusts pricing.

**Windows-only proxy mode.** `vigil-watch` is a stub on Windows. File reads, file writes, and process spawns never appear in the event log. Full observability requires Linux or macOS.

**Session replay.** The `vigil replay <session-id>` command exists and loads events, but replays them all at once with no timestamp pacing. It works for reviewing events but doesn't feel like a real replay.

## Running tests

```
cargo test -p vigil-proxy
```

20 integration tests cover: chunked header/body reads, SSE streaming, non-streaming round-trip, duplicate header joining, hop-by-hop header stripping, SSRF blocking, oversized request rejection, and event emission.

## Reinstalling after code changes

```
cargo install --path F:\projects\vigil\crates\vigil-cli --force
```

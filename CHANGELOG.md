# Changelog

All notable changes to vigil are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.7.2] - 2026-05-03

### Added
- Session detail pagination — default loads last 200 events; "Load N earlier events" button fetches the full history without blocking the reactor
- Keyboard navigation in sessions table: j/k or arrow keys to move, Enter to open, Escape to go back, / to focus search
- Global session filter — search box above the table filters by session name, agent, or ID prefix in real time
- MCP `vigil_report` tool — agent can call `vigil report <session_id>` on itself via Claude Desktop or Cursor; supports `format: "json"` for structured output
- MCP `vigil_diff` tool — agent can diff two sessions to detect regression after CLAUDE.md or policy edits

## [0.7.1] - 2026-05-03

### Security
- Dashboard API requires bearer token authentication — vigil prints `Dashboard: http://127.0.0.1:PORT/?token=...` on startup; all `/api/*` routes return 401 without a valid `Authorization: Bearer <token>` header or `?token=` query param
- Host header validation on all API routes blocks DNS rebinding attacks
- Origin check on `POST /api/approvals/:id` as belt-and-suspenders CSRF guard
- `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy` headers on all responses

### Added
- `[web]` config section with `port` field — supersedes `[proxy] dashboard_port` (which still works as fallback)
- 7 integration tests for vigil-web: token enforcement, Bearer auth, query-param token, static asset exemption, security headers, Host rejection, SSE content-type
- SSE events now carry the specific event type name (`LlmRequest`, `FsWrite`, etc.) instead of the generic `"vigil"` event name

### Fixed
- `api_sessions` and `api_session_detail` now use `tokio::task::spawn_blocking` so filesystem I/O never blocks the async reactor or stalls the SSE broadcast
- Dashboard no longer accumulates cost/tokens client-side; server snapshot is authoritative (eliminates visible jitter on 30s poll)
- `needs_attention` flag is now cleared when a `WriteApprovalDecision` event arrives
- Relative times in the sessions table tick every 30 seconds instead of freezing

## [0.7.0] - 2026-05-03

### Added
- `vigil-web` crate — embedded single-binary browser dashboard served from `[proxy] dashboard_port` in `vigil.toml`; bind address is always `127.0.0.1` (never exposed to the network)
- Sessions list view — live table of active and completed sessions with cost, token count, burn rate, and attention indicator; auto-refreshes every 30 seconds and updates in real time via SSE
- Session detail view — click any session row to load full event timeline with per-event type formatting (tool calls, writes, alerts, approvals)
- `GET /api/events` SSE stream — broadcasts all `TimestampedEvent` values for the global event feed
- `GET /api/sessions/:id/events` SSE stream — filtered per-session event stream
- `GET /api/sessions` — merged list of live (`list_active()`) and completed (`Session::list_all()`) sessions
- `GET /api/sessions/:id` — full session detail with envelopes loaded from `SessionStore`
- `GET /api/approvals` + `POST /api/approvals/:id` — write approval banner: lists pending approvals and accepts approve/reject decisions from the browser
- Event fan-out refactored from `mpsc` to `tokio::sync::broadcast::channel` so both the TUI and the web dashboard can subscribe to the same event stream simultaneously

---

## [0.6.1] - 2026-05-03

### Added
- `vigil report <session-id>` — session audit report with five sections (headline, hygiene scorecard, alert timeline, files touched, tool heatmap) and three output formats (`--json`, `--html`, `--html-fragment`); scorecard grades 8 independent signals (input token growth, re-read rate, tool retry/thrash, turn-to-first-write, policy friction, sub-agent fan-out, late-session alert clustering, write approval rejection rate)
- `[report]` config section in `vigil.toml` — configurable scorecard thresholds
- `[window]` config section in `vigil.toml` — auto-position vigil TUI and agent windows at launch (pixel coordinates, all optional); Windows uses `SetWindowPos`; Linux uses xterm geometry flags + `wmctrl`
- Session report data model enrichment: `turn_number` on `LlmRequest`, `stop_reason` on `LlmResponse`, `correlation_id` linking `ToolCall` to `ToolCallResult`, `duration_ms` and `is_error` on `ToolCallResult`, `lines_added`/`lines_removed`/`hunk_count` on `FsWrite`
- Linux install script (`install-linux.sh`) — one-shot installer for Ubuntu/Debian covering build toolchain, Rust, Claude Code, xterm, wmctrl, and vigil itself
- Linux terminal window support — agent spawned in new xterm/alacritty/kitty window on Unix so vigil TUI and agent TUI don't share the same console

### Fixed
- Linux build: `mod win_console` was missing `#[cfg(windows)]` gate
- Linux build: `mod fake_upstream` was incorrectly gated to `#[cfg(windows)]` — replay mock now works on all platforms
- Linux build: spurious `mut` on `child` in non-windows spawn path

---

## [0.6.0] - 2026-05-03

### Added
- Gemini CLI adapter — vigil now intercepts and observes Google Gemini API traffic in addition to Anthropic and OpenAI; set `GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8877` to route Gemini CLI through the proxy
- `GeminiAdapter` in `vigil-core::provider` — implements `ProviderAdapter` with write-approval tool list (write_file, replace) and canonical tool name mappings to vigil's internal names (write_file→Write, replace→Edit, read_file→Read, glob→Glob, grep_search→Grep, run_shell_command→Bash)
- Gemini routing in `vigil-proxy` — detects `/v1beta/models/…:streamGenerateContent` path pattern and routes to `https://generativelanguage.googleapis.com`; model name extracted from URL path since Gemini does not include it in the request body
- `process_gemini_sse_event()` SSE state machine — handles text parts, `functionCall` with `partialArgs` (delta concat) vs `args` (snapshot overwrite), `willContinue`, `finishReason`, `usageMetadata`, and SAFETY terminations with zero tokens
- `flush_gemini_call()` — canonicalizes Gemini tool names, runs PII scan, triggers write-approval gate, emits `ToolCall` event
- Built-in pricing entries for `gemini-2.5-flash`, `gemini-2.5-flash-lite`, `gemini-3-flash`, `gemini-3.1-pro`; ordered most-specific first to avoid substring matching collision

---

## [0.5.0] - 2026-05-03

### Added
- `vigil replay <session-id> --mock` — runs a mock proxy that serves recorded LLM responses to a live agent instead of calling the real Anthropic API; enables cost-free regression testing of CLAUDE.md and policy rules
- `raw_response: Option<String>` on `LlmResponse` events — full upstream SSE wire bytes, gzip+base64-encoded, capped at 4 MiB; the load-bearing prerequisite for replay
- `raw_request: Option<String>` on `LlmRequest` events — full outbound JSON body, base64-encoded; enables content-based cache key matching in replay
- `vigil-core::replay` module — `build_request_key()` builds a structural digest of a request body stable across CLAUDE.md edits, tool result content drift, UUID/timestamp noise, and assistant text changes; 15 unit tests
- Fake upstream HTTP server (`fake_upstream.rs`) — minimal HTTP/1.1 server backed by a per-key `VecDeque<Vec<u8>>`; positional replay within each key; `--on-miss error|stub` control
- `run_proxy_mode` now accepts `upstream_override: Option<String>` parameter for injection of any alternate upstream

---

## [0.4.0] - 2026-05-03

### Added
- `vigil mcp` — MCP server over stdio (JSON-RPC 2.0); exposes `vigil_status`, `vigil_sessions`, `vigil_policy_check` tools to Claude Desktop, Cursor, and any MCP-aware client
- Prompt injection detection (`PINJ` alert) — scans `tool_result` content for instruction-override phrases, system tags, bidi/zero-width Unicode, large base64 payloads
- `vigil diff <a> <b>` — LCS-based colored diff of tool-call sequences between two sessions; `--brief` flag for changed-only view
- Network exfil bash command scanner — detects curl-pipe, wget-post, netcat-send, base64-pipe, ssh-exfil, dns-exfil patterns in Bash tool inputs; 12 unit tests
- Sub-agent depth limiting — `SubAgentDepth` policy matcher, `budget.max_sub_agent_depth` config, `SubAgentSpawned` event; detects and optionally denies Task tool spawning
- `vigil cost-report [--days N] [--branch name]` — aggregate session cost by date and git branch from `.meta.json` files
- Git notes cost attribution — on session finish, writes `vigil-cost` trailer to the git commit the session ran against (best-effort)
- Claude Desktop env-var hint in `vigil proxy` mode — checks `HKCU\Environment` for `ANTHROPIC_BASE_URL` and surfaces `setx` instructions
- `ProviderAdapter` trait (`AnthropicAdapter`, `OpenAiAdapter`) in `vigil-core` — replaces hardcoded `WRITE_TOOLS` constant, foundation for future Gemini support
- Boring denials — policy `Deny` now injects a typed `is_error: true` tool_result back to the LLM so the agent receives a structured refusal message and continues on safe work; `tool_use_id` tracked through the full SSE stream
- `DESIGN_NOTES.md` — architectural decisions documented to prevent future relitigating

### Changed
- `vigil-mcp` upgraded from non-functional stub to working MCP server
- README and PLUGINS.md fully rewritten for v0.4.0 accuracy
- Policy denials no longer silently drop — they record into `PendingDenials` and rewrite the outbound request

---

## [0.3.0] - 2026-05-03

### Added
- Drift detection — `DriftDetector` with three signals: `OutputTokenAcceleration`, `ProgressStall`, `SelfContradiction`; configurable via `[drift]` section in `vigil.toml`; fires `DRFT` alert
- Session auto-naming — Twitch-style adjective-noun pairs (e.g. `frozen-raven`) generated at session creation
- `vigil clear [-y]` — wipe all sessions with confirmation prompt and failure reporting
- `vigil export --all [--output-dir]` — bulk export all sessions as redacted JSON with per-session error isolation
- `DRFT` alert label in plugin ABI; `AlertDetail::Drift` typed struct
- TUI: drift alert counter in sidebar, session name in header and session row

### Changed
- `vigil ps` shows session name column instead of raw UUID
- Security: OOM cap on SelfContradiction input (64 KiB), whole-word tool-name matching, silent-failure fixes in `vigil clear` and export
- vigil-slack standalone cdylib plugin added (separate crate)

---

## [0.2.0] - 2026-05-02

### Added
- Webhook notifier — fire-and-forget HTTP POST on alert events with 3-retry backoff
- `CostAlert` — soft single-fire warning at `budget.cost_alert_usd`
- `SessionDurationAlert` — fires after `budget.max_session_duration_mins`
- `ToolTimeout` — hung tool detection with optional agent kill via `proxy.tool_timeout_kill_secs`
- Plugin system — `VigilPlugin` async trait, `PluginHost` fan-out, `vigil plugins new/install/list/check/dir`
- Plugin ABI v3: `async_trait`, `AlertLabel` typed enum, `AlertDetail` typed variants
- Plugin ABI v4: `on_session_start`, `on_session_end`, `on_outbound_request` hooks; `SessionMeta` git context
- `vigil proxy` mode — proxy-only without spawning agent, for Cursor/IDEs
- `vigil browse` — ratatui session browser with replay, j/k navigation, detail pane
- `vigil fork` — replay session prefix then go live against real LLM
- `vigil tag` — rename sessions
- `vigil verify` — ed25519 chain-root signature verification
- `vigil export --redacted` — NDJSON export with PII replaced
- Session signing — ed25519 + SHA-256 hash chain, `SessionStore` generates per-session key
- Git context capture at session start (developer, repo, branch, commit)
- Dynamic plugin loading — `vigil run --plugin <path>`
- ProcessSpawn exfil detection, reqwest client hardening
- `vigil sessions` — list all recorded sessions with cost

### Fixed
- SSRF bypass via mixed-case hostname (critical)
- Response header injection — replaced forwarding with explicit allowlist
- Write-approval path traversal — canonicalized + cwd-scoped
- Watchlist PII echo in logs/TUI
- Tool timeout not disarmed on ToolCallResult
- `allowed_hours` inclusive upper bound
- Write approval `try_send` → `send().await`
- Fork command port collision — scans 8877–8897

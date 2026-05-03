# Changelog

All notable changes to vigil are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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

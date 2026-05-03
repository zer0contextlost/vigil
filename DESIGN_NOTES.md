# vigil design notes

Architectural decisions documented here so future contributors don't relitigate them.

## Why no HTTPS MITM for Claude Desktop

The original plan was to MITM Claude Desktop's HTTPS traffic the same way vigil intercepts CLI agent traffic. Three problems ruled it out:

First, the blast radius of certificate cleanup. Injecting a root CA into the system trust store affects every application on the machine. If vigil crashes or is force-killed before removing the cert, the machine is left with a rogue CA. Corporate AV and EDR tools commonly flag or block this operation entirely.

Second, system proxy persistence. Setting `HTTPS_PROXY` or the Windows system proxy at the OS level can stick across reboots if the process dies before restoring it. An agent-spawned vigil dying mid-session would leave all HTTPS traffic routed to a dead port.

Third, Claude Desktop routes most of its traffic through Anthropic's relay infrastructure, not directly to `api.anthropic.com`. MITM would require unpinning certificates in the Electron app, which changes across releases.

The MCP server mode (`vigil mcp`) solves all of this: vigil speaks JSON-RPC 2.0 over stdio, Claude Desktop calls it as a registered MCP server, and no certificate or proxy manipulation is needed.

## Why ProviderAdapter trait

Early versions hardcoded the list of write-capable tools (`str_replace_editor`, `write_file`, etc.) for the Anthropic Claude Code toolset. When Cursor support was added, the same list was wrong. Two problems followed: false-positive write approvals on Cursor's tool names, and missed approvals on tools vigil didn't know about.

The `ProviderAdapter` trait was introduced to let each provider declare its own write tool list and SSE parsing logic. `AnthropicAdapter` and a pass-through OpenAI adapter ship in `vigil-core`. Future Gemini or OpenAI-native adapters implement the same trait without touching the proxy core.

The proxy selects the adapter based on the incoming request path (`/v1/messages` → Anthropic, `/v1/chat/completions` → OpenAI).

## Why sub-agent depth is a counter not a stack

vigil does not have access to the LLM's internal call stack. When an agent uses the Claude Code `Task` tool to spawn a sub-agent, vigil sees a `ToolCall` event with `tool_name = "Task"` but has no way to know when that sub-agent's turn ends and the parent's resumes — all traffic flows through the same proxy connection.

The practical approximation is a per-session `Task` call counter. When the count exceeds `max_sub_agent_depth`, vigil denies the next Task call. This prevents runaway recursive agent spawning without requiring call-stack visibility. The counter never decrements; it is a total-calls limit, not a concurrent-depth limit. Documenting this prevents confusion when contributors expect stack semantics.

## Why drift debounce fires before check

The `DriftDetector` calls `tick_debounce()` at the top of `check()`, before any signal evaluation. This means `debounce_events = N` produces the pattern: fire, suppress N-1 times, re-fire on the Nth event.

With `debounce_events = 3`: fire (debounce set to 3), first event (3→2, suppressed), second event (2→1, suppressed), third event (1→0, fires again).

The alternative — ticking after the check — would suppress N events before re-firing, which is less intuitive when configuring the value. The current behavior means "re-fire every N events" which maps directly to what operators want: "don't spam me more than once per N turns."

## Why session signing uses ed25519 + hash chain

vigil is designed for single-developer or small-team use without a central server. Traditional audit log approaches (append-only database, WORM storage, remote signing service) require infrastructure. vigil's design goal is zero infrastructure beyond the binary.

The hash chain ensures that any tampering with an event in the middle of a session file is detectable: each envelope's SHA-256 includes the previous envelope's hash, so a modified event breaks all subsequent hashes. Ed25519 signing of the chain root at session end prevents wholesale replacement of the chain. The signing key is generated per-session and stored in the `.meta.json` sidecar alongside the public key, so verification is self-contained.

Sessions created before signing was introduced report `Signature: SKIP` from `vigil verify` rather than FAIL, preserving backward compatibility.

## Gemini adapter status — deferred to v0.5

The `ProviderAdapter` trait is the intended extension point. The environment variable `GOOGLE_GEMINI_BASE_URL` is reserved for the Gemini adapter (analogous to `ANTHROPIC_BASE_URL`).

The main implementation cost is SSE streaming format: Gemini's server-sent events use a different envelope structure than Anthropic's. The token counting and cost fields also differ. Implementing `GeminiAdapter` requires a new SSE parser and a pricing table entry. The proxy routing logic (path-based adapter selection) will need a third branch.

This work was deferred to v0.5 to avoid destabilizing the proxy core before the Anthropic and OpenAI paths are fully hardened.

## Replay against mocked LLM — deferred to v0.5

The goal is a `vigil replay --mock` mode where the proxy pattern-matches incoming requests against a recorded session and replays the recorded responses instead of forwarding to the real API. This enables deterministic re-runs for debugging and cost-free regression testing.

The precursor feature is `vigil fork`, which already replays a session prefix and then goes live. The mock mode would replace the "go live" step with a fake upstream that serves recorded responses.

Design sketch: a `FakeUpstream` struct holds the recorded `LlmResponse` events indexed by a hash of the request's messages array. On a cache hit it returns the recorded SSE stream; on a miss it returns a configurable fallback (error or empty response). The `Proxy` struct already accepts an upstream URL, so `FakeUpstream` would bind on a localhost port and set that as the upstream for the session.

This was deferred because the request-matching heuristic is non-trivial: prompts often include timestamps or session IDs that change between runs, making exact-match unreliable. A fuzzy-match strategy needs more design work before it can ship reliably.

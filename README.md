# vigil

Runtime observability and policy enforcement for AI coding agents.

vigil sees and gates every tool call, file write, and API request your AI coding agent makes — across Claude Code, Codex, Cursor, Aider, and Gemini CLI.

## Demo

![vigil demo](demo/demo.gif)

*vigil catching a destructive shell command in real time. The BLOCKED event fires before the command executes.*

> **Record your own:** see [demo/README.md](demo/README.md)

## Install

```bash
# Via cargo
cargo install --git https://github.com/vigil-dev/vigil vigil

# Or clone and build
git clone https://github.com/vigil-dev/vigil
cd vigil
cargo install --path crates/vigil-cli
```

After install, `vigil` is available in your PATH.

## Quick Start

```bash
vigil run -- claude
```

This starts vigil with a proxy on port 8877, spawns your Claude Code agent, and shows a live dashboard of all its activity.

## What vigil monitors

| Event | What it catches |
|-------|----------------|
| `LLM_REQ/RES` | Every model call: provider, model, tokens, cost |
| `TOOL` | Tool calls before execution — inspectable and blockable |
| `BLOCKED` | Tool calls stopped by policy |
| `FSREAD/WRITE` | File reads and writes by the agent process |
| `SPAWN` | Child processes spawned by the agent |
| `MCP` | MCP server tool calls (via vigil-mcp-shim) |

## Policy Configuration

Create a `.agent-sentinel.yaml` file to define policies:

```yaml
policies:
  - name: "Block file deletion"
    action: DENY
    matcher:
      type: ToolCall
      tool_name_pattern: "^(rm|delete).*"

  - name: "Confirm before shell"
    action: CONFIRM
    matcher:
      type: ToolCall
      tool_name_pattern: "^(bash|sh|cmd)$"

  - name: "Log all LLM requests"
    action: LOGONLY
    matcher:
      type: AnyLlmRequest

  - name: "Token budget"
    action: DENY
    matcher:
      type: TokenBudget
      max_tokens: 100000
```

Pass it with:

```bash
vigil run --policy .agent-sentinel.yaml -- claude
```

## Architecture

vigil consists of five Rust crates:

- **vigil-core** — Event types, policy engine, session model
- **vigil-proxy** — HTTPS MITM proxy for observing LLM API calls
- **vigil-mcp** — MCP protocol shim for intercepting tool calls
- **vigil-tui** — ratatui-based dashboard showing live activity
- **vigil-cli** — Command-line interface and session orchestrator

The proxy runs on a configurable port and intercepts HTTPS traffic to known LLM providers. The MCP shim spawns the real MCP server as a child process and pipes JSON-RPC messages through, logging all tool invocations. The TUI shows a scrollable event log with cost tracking and policy decision markers.

## Status

Early development. v0.1 focus: HTTPS proxy + process supervisor + TUI dashboard. No kernel/eBPF needed.

## License

MIT

# Vigil Policy Engine

## Overview

The policy engine is a fast, in-process evaluator that runs on every event (LLM request, tool call, file operation, etc.) and returns an action: **Allow**, **Deny**, **Confirm**, or **LogOnly**.

All policy evaluation happens in sub-10ms with pre-compiled regex patterns to avoid runtime overhead.

## Architecture

### Hardcoded Safety Floor

Certain patterns are **always** blocked, regardless of policy configuration. These are non-bypassable guards:

- `rm -rf` — recursive delete
- `dd if=` — disk operations
- `mkfs` — filesystem creation
- `:(){ :|:& };:` — fork bomb
- `curl ... | sh` — pipe to shell download/execute
- `wget ... | sh` — pipe to shell download/execute

These patterns are checked first in the `evaluate()` method and immediately return **Deny** with reason "destructive shell pattern blocked" or "pipe-to-shell pattern blocked".

### Policy Matchers

Policies are defined in YAML and loaded at startup. The engine tries each policy in order; the **first match wins**.

#### ToolCall

```yaml
matcher:
  type: ToolCall
  tool_name_pattern: "bash"
action: DENY
```

Matches any tool call where the tool name contains the pattern (case-insensitive substring).

#### FsWriteOutside

```yaml
matcher:
  type: FsWriteOutside
  root: "/home/user/project"
action: DENY
```

Matches file writes (FsWrite events) to paths that do NOT start with the root prefix.

#### FsPath

```yaml
matcher:
  type: FsPath
  path_pattern: ".env"
action: DENY
```

Matches FsRead or FsWrite events where the path contains the pattern (case-insensitive).

#### NetworkDomain

```yaml
matcher:
  type: NetworkDomain
  deny_unless_in: ["openai", "anthropic"]
action: DENY
```

Matches LlmRequest events where the provider is NOT in the allowlist. Currently checks the `provider` field; to support raw domains in HTTP events, extend to check URL hosts.

#### TokenBudget

```yaml
matcher:
  type: TokenBudget
  max_tokens: 1000000
action: LOGONLY
```

Matches when the session total tokens (tracked across all LlmRequest events) exceeds the threshold.

#### AnyLlmRequest

```yaml
matcher:
  type: AnyLlmRequest
action: LOGONLY
```

Matches any LlmRequest event. Useful as a catch-all for logging.

#### ToolCallInput

```yaml
matcher:
  type: ToolCallInput
  tool_name_pattern: "http_request"
  input_field: "url"
  value_pattern: "localhost"
action: DENY
```

Matches ToolCall events where:
1. Tool name contains `tool_name_pattern`
2. Input JSON has a field named `input_field` (string value)
3. That field's value contains `value_pattern`

All patterns use case-insensitive substring matching (compiled as regex with `(?i)` flag and escaped).

## Integration in vigil-cli

When `vigil run --policy <file>` is invoked:

1. **PolicyEngine** is loaded from the YAML file in `run_agent()`
2. **Two channels** are created:
   - `raw_tx` — raw events from proxy/watcher
   - `filtered_tx` — events after policy filtering
3. **Policy filter task** runs in a separate tokio task:
   - Receives events from `raw_tx`
   - Tracks session token count (cumulative from LlmRequest events)
   - Calls `engine.evaluate(event, session_tokens)`
   - Routes based on decision:
     - **Deny**: Print `[POLICY DENY] ...` to stderr, send ToolCallResult with `blocked=true`, skip original event
     - **LogOnly**: Forward event as-is
     - **Allow** or **Confirm**: Forward event as-is
4. **TUI** receives events from `filtered_tx` instead of direct proxy/watcher output

## YAML Format

```yaml
policies:
  - name: human-readable-name
    matcher:
      type: ToolCall  # or FsWriteOutside, FsPath, NetworkDomain, TokenBudget, AnyLlmRequest, ToolCallInput
      # Fields depend on type
    action: DENY      # or ALLOW, CONFIRM, LOGONLY
```

**Actions** are case-sensitive (UPPERCASE in YAML).

## Example Policy File

See `example-policy.yaml` in the root for a reference configuration.

## Performance

- Regex patterns are pre-compiled in `PolicyEngine::new()` — O(1) at eval time
- Each policy check is a pattern match on the relevant event fields
- Token budgets are O(1) cumulative additions
- Destructive shell pattern detection is a quick string contains check

Target: sub-10ms per event evaluation.

## Design Notes

1. **First-match-wins**: Policies are evaluated in order. Place the most specific/expensive rules first if performance matters.
2. **No regex at eval time**: All patterns compile once during `PolicyEngine::new()`.
3. **Hardcoded floor first**: Destructive shell patterns are checked before any policy, guaranteeing they can never be bypassed.
4. **Prefix matching for FsWriteOutside**: Uses simple string prefix check for now. Can be upgraded to canonicalize paths if needed.
5. **Provider-based domain matching**: Currently checks `Event::LlmRequest.provider`. To support raw HTTP domain filtering, add an HTTP matcher variant.

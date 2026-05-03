use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    LlmRequest {
        provider: String,
        model: String,
        #[serde(default)]
        input_tokens: u32,
        session_id: Uuid,
        /// Last user message extracted from the messages array.
        /// None for requests we couldn't parse (e.g. empty body).
        #[serde(default)]
        last_user_message: Option<String>,
        /// System prompt, if present in the request.
        #[serde(default)]
        system_prompt: Option<String>,
    },
    LlmResponse {
        provider: String,
        model: String,
        #[serde(default)]
        input_tokens: u32,
        output_tokens: u32,
        cost_usd: f64,
        session_id: Uuid,
        /// Full assistant text accumulated from SSE text_delta events.
        #[serde(default)]
        response_text: Option<String>,
        #[serde(default)]
        cache_read_input_tokens: u32,
        #[serde(default)]
        cache_creation_input_tokens: u32,
    },
    ToolCall {
        agent: String,
        tool_name: String,
        input: Value,
        session_id: Uuid,
        /// The `id` field from the LLM's tool_use block. Used to inject a
        /// structured denial message into the next tool_result if policy denies.
        #[serde(default)]
        tool_use_id: Option<String>,
    },
    ToolCallResult {
        agent: String,
        tool_name: String,
        blocked: bool,
        session_id: Uuid,
    },
    FsRead {
        path: String,
        session_id: Uuid,
    },
    FsWrite {
        path: String,
        bytes: u64,
        session_id: Uuid,
    },
    ProcessSpawn {
        command: String,
        args: Vec<String>,
        session_id: Uuid,
    },
    McpCall {
        server: String,
        method: String,
        params: Value,
        session_id: Uuid,
    },
    PiiAlert {
        /// Where the PII was found: tool name, "llm_request", or "llm_response"
        source: String,
        /// Human-readable list of what was found, e.g. ["email", "phone"]
        kinds: Vec<String>,
        session_id: Uuid,
    },
    BurnRateAlert {
        rate_per_min_usd: f64,
        projected_total_usd: f64,
        session_cost_usd: f64,
        session_id: Uuid,
    },
    LoopAlert {
        tool_name: String,
        repeat_count: u32,
        session_id: Uuid,
    },
    /// Emitted by the proxy when a Write/Edit tool call exceeds the risk threshold.
    /// The filter task forwards this to the TUI which shows a diff preview and waits for approval.
    WriteApprovalRequired {
        #[serde(default)]
        path: String,
        #[serde(default)]
        before: String,
        #[serde(default)]
        after: String,
        /// "Low" / "Medium" / "High" as string to keep Event serde simple.
        #[serde(default)]
        risk_level: String,
        #[serde(default)]
        reasons: Vec<String>,
        session_id: Uuid,
        /// Proxy sets this to a unique ID so the TUI can send the decision back on the right channel.
        approval_id: Uuid,
    },
    /// Emitted by the filter task after the user approves or rejects a pending write.
    WriteApprovalDecision {
        approval_id: Uuid,
        approved: bool,
        session_id: Uuid,
    },
    /// Emitted when a credential fingerprinted from a file read is detected in an
    /// outbound LLM request or shell tool call.
    ExfilAlert {
        /// Partially-redacted matched credential snippets (e.g. "sk-a***")
        matches: Vec<String>,
        /// "llm_request" or the tool name (e.g. "Bash")
        source: String,
        session_id: Uuid,
    },
    /// Emitted when a tool call has been running longer than tool_timeout_secs
    /// with no follow-up LlmRequest from the agent.
    ToolTimeout {
        tool_name: String,
        elapsed_secs: u64,
        session_id: Uuid,
    },
    /// Soft cost warning fired once when session cost crosses cost_alert_usd.
    CostAlert {
        threshold_usd: f64,
        session_cost_usd: f64,
        session_id: Uuid,
    },
    /// Fired once when session wall-clock duration exceeds max_session_duration_mins.
    SessionDurationAlert {
        elapsed_mins: u64,
        session_id: Uuid,
    },
    /// Emitted by the filter task when DriftDetector observes a behavioural drift signal
    /// (output-token runaway, progress stall, or self-contradiction).
    DriftAlert {
        signal: crate::drift::DriftSignal,
        details: String,
        session_id: Uuid,
    },
    /// Emitted when a Task tool call is observed, incrementing the session-level
    /// sub-agent depth counter. Depth is the total Task invocation count so far
    /// (not a true call-stack depth — vigil doesn't track returns).
    SubAgentSpawned {
        session_id: Uuid,
        depth: u32,
        tool_name: String,
    },
    /// Emitted when a tool_result content block contains a known indirect prompt
    /// injection pattern (instruction override, system tag, bidi Unicode, etc.).
    PromptInjectionAlert {
        session_id: Uuid,
        tool_name: String,
        category: String,
        snippet: String,
    },
}

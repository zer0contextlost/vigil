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
}

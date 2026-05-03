use std::fmt;

/// Normalizes provider-specific request/response formats into vigil's internal event model.
pub trait ProviderAdapter: Send + Sync {
    /// List of tool names that perform filesystem writes (used for write-approval gating).
    fn write_tools(&self) -> &[&'static str];

    /// List of tool names that perform filesystem reads (used for drift stall detection).
    fn read_tools(&self) -> &[&'static str];

    /// Map a provider tool name to a vigil-canonical name (e.g. "write_file" → "Write").
    /// Returns the original name unchanged if no mapping exists.
    fn canonical_tool_name<'a>(&self, name: &'a str) -> &'a str {
        name
    }
}

pub struct AnthropicAdapter;

impl ProviderAdapter for AnthropicAdapter {
    fn write_tools(&self) -> &[&'static str] {
        &["Write", "Edit", "MultiEdit", "NotebookEdit", "create_file", "str_replace_editor"]
    }
    fn read_tools(&self) -> &[&'static str] {
        &["Read", "Glob", "Grep", "LS", "Bash"]
    }
}

pub struct OpenAiAdapter;

impl ProviderAdapter for OpenAiAdapter {
    fn write_tools(&self) -> &[&'static str] {
        &["create_file", "str_replace_editor", "insert_edit_into_file"]
    }
    fn read_tools(&self) -> &[&'static str] {
        &["read_file", "run_terminal_cmd"]
    }
}

pub struct GeminiAdapter;

impl ProviderAdapter for GeminiAdapter {
    fn write_tools(&self) -> &[&'static str] {
        &["write_file", "replace"]
    }
    fn read_tools(&self) -> &[&'static str] {
        &["read_file", "glob", "grep_search", "list_directory"]
    }
    fn canonical_tool_name<'a>(&self, name: &'a str) -> &'a str {
        match name {
            "write_file"        => "Write",
            "replace"           => "Edit",
            "read_file"         => "Read",
            "list_directory"    => "LS",
            "glob"              => "Glob",
            "grep_search"       => "Grep",
            "run_shell_command" => "Bash",
            _                   => name,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProviderKind {
    Anthropic,
    OpenAI,
    Gemini,
    OpenRouter,
    XAI,
    Unknown,
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProviderKind::Anthropic => write!(f, "anthropic"),
            ProviderKind::OpenAI => write!(f, "openai"),
            ProviderKind::Gemini => write!(f, "gemini"),
            ProviderKind::OpenRouter => write!(f, "openrouter"),
            ProviderKind::XAI => write!(f, "xai"),
            ProviderKind::Unknown => write!(f, "unknown"),
        }
    }
}

pub fn detect_provider_from_host(host: &str) -> ProviderKind {
    let h = host.to_ascii_lowercase();
    if h.contains("api.anthropic.com") {
        ProviderKind::Anthropic
    } else if h.contains("api.openai.com") {
        ProviderKind::OpenAI
    } else if h.contains("generativelanguage.googleapis.com") {
        ProviderKind::Gemini
    } else if h.contains("openrouter.ai") {
        ProviderKind::OpenRouter
    } else if h.contains("api.x.ai") {
        ProviderKind::XAI
    } else {
        ProviderKind::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_provider_lowercase() {
        assert_eq!(detect_provider_from_host("api.anthropic.com"), ProviderKind::Anthropic);
        assert_eq!(detect_provider_from_host("api.openai.com"), ProviderKind::OpenAI);
    }

    #[test]
    fn test_detect_provider_mixed_case_ssrf_bypass() {
        // CRITICAL: these must NOT fall through to Unknown
        assert_eq!(detect_provider_from_host("API.ANTHROPIC.COM"), ProviderKind::Anthropic);
        assert_eq!(detect_provider_from_host("Api.Anthropic.Com"), ProviderKind::Anthropic);
        assert_eq!(detect_provider_from_host("API.OPENAI.COM"), ProviderKind::OpenAI);
        assert_eq!(detect_provider_from_host("API.X.AI"), ProviderKind::XAI);
    }

    #[test]
    fn test_detect_provider_unknown() {
        assert_eq!(detect_provider_from_host("evil.com"), ProviderKind::Unknown);
        assert_eq!(detect_provider_from_host("notanthropic.com"), ProviderKind::Unknown);
        assert_eq!(detect_provider_from_host(""), ProviderKind::Unknown);
    }

    #[test]
    fn test_gemini_adapter_write_tools() {
        let a = GeminiAdapter;
        assert!(a.write_tools().contains(&"write_file"));
        assert!(a.write_tools().contains(&"replace"));
        assert!(!a.write_tools().contains(&"run_shell_command"));
    }

    #[test]
    fn test_gemini_adapter_canonical_names() {
        let a = GeminiAdapter;
        assert_eq!(a.canonical_tool_name("write_file"),        "Write");
        assert_eq!(a.canonical_tool_name("replace"),           "Edit");
        assert_eq!(a.canonical_tool_name("read_file"),         "Read");
        assert_eq!(a.canonical_tool_name("list_directory"),    "LS");
        assert_eq!(a.canonical_tool_name("glob"),              "Glob");
        assert_eq!(a.canonical_tool_name("grep_search"),       "Grep");
        assert_eq!(a.canonical_tool_name("run_shell_command"), "Bash");
        assert_eq!(a.canonical_tool_name("save_memory"),       "save_memory");
    }
}

pub fn cost_usd(_provider: ProviderKind, model: &str, input_tokens: u32, output_tokens: u32, cache_read_tokens: u32, cache_creation_tokens: u32) -> f64 {
    let (input_cost, output_cost) = crate::pricing::PricingTable::global().lookup(model);
    (input_tokens as f64 / 1_000_000.0) * input_cost
        + (output_tokens as f64 / 1_000_000.0) * output_cost
        + (cache_read_tokens as f64 / 1_000_000.0) * input_cost * 0.1
        + (cache_creation_tokens as f64 / 1_000_000.0) * input_cost * 1.25
}

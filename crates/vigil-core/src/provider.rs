use std::fmt;

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
    match host {
        h if h.contains("api.anthropic.com") => ProviderKind::Anthropic,
        h if h.contains("api.openai.com") => ProviderKind::OpenAI,
        h if h.contains("generativelanguage.googleapis.com") => ProviderKind::Gemini,
        h if h.contains("openrouter.ai") => ProviderKind::OpenRouter,
        h if h.contains("api.x.ai") => ProviderKind::XAI,
        _ => ProviderKind::Unknown,
    }
}

pub fn cost_usd(_provider: ProviderKind, model: &str, input_tokens: u32, output_tokens: u32, cache_read_tokens: u32, cache_creation_tokens: u32) -> f64 {
    let m = model.to_lowercase();
    let (input_cost, output_cost) = if m.contains("claude-opus-4") {
        (15.0, 75.0)
    } else if m.contains("claude-sonnet-4") || m.contains("claude-3-5-sonnet") {
        (3.0, 15.0)
    } else if m.contains("claude-haiku-4") || m.contains("claude-3-7-haiku") {
        (0.80, 4.0)
    } else if m.contains("gpt-4o") && m.contains("mini") {
        (0.15, 0.60)
    } else if m.contains("gpt-4o") {
        (2.50, 10.0)
    } else if m.contains("o3") || m.contains("o4") {
        (10.0, 40.0)
    } else {
        (3.0, 15.0)
    };
    (input_tokens as f64 / 1_000_000.0) * input_cost
        + (output_tokens as f64 / 1_000_000.0) * output_cost
        + (cache_read_tokens as f64 / 1_000_000.0) * input_cost * 0.1
        + (cache_creation_tokens as f64 / 1_000_000.0) * input_cost * 1.25
}

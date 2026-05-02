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
    let (input_cost, output_cost) = crate::pricing::PricingTable::global().lookup(model);
    (input_tokens as f64 / 1_000_000.0) * input_cost
        + (output_tokens as f64 / 1_000_000.0) * output_cost
        + (cache_read_tokens as f64 / 1_000_000.0) * input_cost * 0.1
        + (cache_creation_tokens as f64 / 1_000_000.0) * input_cost * 1.25
}

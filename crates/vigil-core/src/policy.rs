use crate::Event;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub action: PolicyAction,
    pub matcher: PolicyMatcher,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PolicyAction {
    Allow,
    Deny,
    Confirm,
    LogOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PolicyMatcher {
    #[serde(rename = "ToolCall")]
    ToolCall { tool_name_pattern: String },
    #[serde(rename = "FsWriteOutside")]
    FsWriteOutside { root: String },
    #[serde(rename = "FsPath")]
    FsPath { path_pattern: String },
    #[serde(rename = "NetworkDomain")]
    NetworkDomain { deny_unless_in: Vec<String> },
    #[serde(rename = "TokenBudget")]
    TokenBudget { max_tokens: u32 },
    #[serde(rename = "AnyLlmRequest")]
    AnyLlmRequest,
    #[serde(rename = "ToolCallInput")]
    ToolCallInput {
        tool_name_pattern: String,
        input_field: String,
        value_pattern: String,
    },
    #[serde(rename = "SubAgentDepth")]
    SubAgentDepth { max_depth: u32 },
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub action: PolicyAction,
    pub policy_name: Option<String>,
    pub reason: Option<String>,
}

/// Fast, in-process policy engine. Compiles regex patterns once at construction.
pub struct PolicyEngine {
    config: PolicyConfig,
    compiled_patterns: Vec<CompiledPatterns>,
}

#[derive(Debug)]
struct CompiledPatterns {
    tool_name_regex: Option<Regex>,
    path_regex: Option<Regex>,
    input_field_regex: Option<Regex>,
}

impl PolicyConfig {
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn safe_defaults() -> Self {
        Self {
            policies: vec![
                Policy {
                    name: "block-destructive-shell".to_string(),
                    matcher: PolicyMatcher::ToolCall {
                        tool_name_pattern: "Bash".to_string(),
                    },
                    action: PolicyAction::Deny,
                },
                Policy {
                    name: "token-budget-warning".to_string(),
                    matcher: PolicyMatcher::TokenBudget {
                        max_tokens: 1_000_000,
                    },
                    action: PolicyAction::LogOnly,
                },
            ],
        }
    }
}

impl PolicyEngine {
    /// Create a new policy engine from a config.
    pub fn new(config: PolicyConfig) -> anyhow::Result<Self> {
        // Pre-compile all regex patterns
        let mut compiled_patterns = Vec::new();

        for policy in &config.policies {
            let mut patterns = CompiledPatterns {
                tool_name_regex: None,
                path_regex: None,
                input_field_regex: None,
            };

            match &policy.matcher {
                PolicyMatcher::ToolCall { tool_name_pattern } => {
                    patterns.tool_name_regex = Some(Regex::new(&format!(
                        "(?i){}",
                        regex::escape(tool_name_pattern)
                    ))?);
                }
                PolicyMatcher::FsPath { path_pattern } => {
                    patterns.path_regex = Some(Regex::new(&format!(
                        "(?i){}",
                        regex::escape(path_pattern)
                    ))?);
                }
                PolicyMatcher::ToolCallInput {
                    tool_name_pattern,
                    value_pattern, ..
                } => {
                    patterns.tool_name_regex = Some(Regex::new(&format!(
                        "(?i){}",
                        regex::escape(tool_name_pattern)
                    ))?);
                    patterns.input_field_regex = Some(Regex::new(&format!(
                        "(?i){}",
                        regex::escape(value_pattern)
                    ))?);
                }
                _ => {}
            }

            compiled_patterns.push(patterns);
        }

        Ok(Self {
            config,
            compiled_patterns,
        })
    }

    pub fn policy_count(&self) -> usize {
        self.config.policies.len()
    }

    /// Load a policy engine from a YAML file.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let config = PolicyConfig::load_from_file(path)?;
        Self::new(config)
    }

    /// Create an empty policy engine that allows all events.
    pub fn default() -> Self {
        Self {
            config: PolicyConfig {
                policies: Vec::new(),
            },
            compiled_patterns: Vec::new(),
        }
    }

    /// Evaluate an event against the policy set.
    /// Returns the first matching policy's decision, or Allow if none match.
    pub fn evaluate(&self, event: &Event, session_total_tokens: u32) -> PolicyDecision {
        // Check each policy in order; first match wins
        for (idx, policy) in self.config.policies.iter().enumerate() {
            if self.matches(&policy.matcher, event, session_total_tokens, idx) {
                let reason = self.matcher_reason(&policy.matcher, event);
                return PolicyDecision {
                    action: policy.action.clone(),
                    policy_name: Some(policy.name.clone()),
                    reason,
                };
            }
        }

        // No match = allow
        PolicyDecision {
            action: PolicyAction::Allow,
            policy_name: None,
            reason: None,
        }
    }

    fn matches(
        &self,
        matcher: &PolicyMatcher,
        event: &Event,
        session_total_tokens: u32,
        policy_idx: usize,
    ) -> bool {
        match matcher {
            PolicyMatcher::ToolCall { .. } => {
                if let Event::ToolCall { tool_name, .. } = event {
                    if let Some(regex) = &self.compiled_patterns[policy_idx].tool_name_regex {
                        return regex.is_match(tool_name);
                    }
                }
                false
            }
            PolicyMatcher::FsWriteOutside { root } => {
                if let Event::FsWrite { path, .. } = event {
                    return !path.starts_with(root);
                }
                false
            }
            PolicyMatcher::FsPath { .. } => {
                match event {
                    Event::FsRead { path, .. } | Event::FsWrite { path, .. } => {
                        if let Some(regex) = &self.compiled_patterns[policy_idx].path_regex {
                            return regex.is_match(path);
                        }
                    }
                    _ => {}
                }
                false
            }
            PolicyMatcher::NetworkDomain { deny_unless_in } => {
                if let Event::LlmRequest { provider, .. } = event {
                    return !deny_unless_in.contains(provider);
                }
                false
            }
            PolicyMatcher::TokenBudget { max_tokens } => {
                return session_total_tokens >= *max_tokens;
            }
            PolicyMatcher::AnyLlmRequest => {
                matches!(event, Event::LlmRequest { .. })
            }
            PolicyMatcher::ToolCallInput {
                tool_name_pattern: _,
                input_field,
                ..
            } => {
                if let Event::ToolCall { tool_name, input, .. } = event {
                    // Check tool name first
                    if let Some(tool_regex) = &self.compiled_patterns[policy_idx].tool_name_regex {
                        if !tool_regex.is_match(tool_name) {
                            return false;
                        }
                    }
                    // Check input field and value
                    if let Some(field_value) = input.get(input_field) {
                        if let Some(field_str) = field_value.as_str() {
                            if let Some(value_regex) = &self.compiled_patterns[policy_idx]
                                .input_field_regex
                            {
                                return value_regex.is_match(field_str);
                            }
                        }
                    }
                }
                false
            }
            PolicyMatcher::SubAgentDepth { max_depth } => {
                if let Event::SubAgentSpawned { depth, .. } = event {
                    return *depth > *max_depth;
                }
                false
            }
        }
    }

    fn matcher_reason(&self, matcher: &PolicyMatcher, event: &Event) -> Option<String> {
        match matcher {
            PolicyMatcher::ToolCall { tool_name_pattern } => {
                if let Event::ToolCall { tool_name: _, .. } = event {
                    Some(format!(
                        "ToolCall matched pattern '{}'",
                        tool_name_pattern
                    ))
                } else {
                    None
                }
            }
            PolicyMatcher::FsWriteOutside { root } => {
                if let Event::FsWrite { path, .. } = event {
                    Some(format!("FsWrite outside root '{}': {}", root, path))
                } else {
                    None
                }
            }
            PolicyMatcher::FsPath { path_pattern } => {
                Some(format!("FsPath matched pattern '{}'", path_pattern))
            }
            PolicyMatcher::NetworkDomain { deny_unless_in: _ } => {
                if let Event::LlmRequest { provider, .. } = event {
                    Some(format!(
                        "NetworkDomain '{}' not in allowlist",
                        provider
                    ))
                } else {
                    None
                }
            }
            PolicyMatcher::TokenBudget { max_tokens } => {
                Some(format!(
                    "Token budget exceeded: {} max tokens",
                    max_tokens
                ))
            }
            PolicyMatcher::AnyLlmRequest => Some("AnyLlmRequest matched".to_string()),
            PolicyMatcher::ToolCallInput {
                tool_name_pattern,
                input_field,
                value_pattern,
            } => {
                Some(format!(
                    "ToolCall {} input field {} matched pattern '{}'",
                    tool_name_pattern, input_field, value_pattern
                ))
            }
            PolicyMatcher::SubAgentDepth { max_depth } => {
                if let Event::SubAgentSpawned { depth, tool_name, .. } = event {
                    Some(format!(
                        "sub-agent depth {} exceeds max {}  (tool: {})",
                        depth, max_depth, tool_name
                    ))
                } else {
                    Some(format!("sub-agent depth limit: max {}", max_depth))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn tool_call(name: &str) -> Event {
        Event::ToolCall {
            agent: "test".to_string(),
            tool_name: name.to_string(),
            tool_use_id: None,
            correlation_id: None,
            input: Default::default(),
            session_id: Uuid::new_v4(),
        }
    }

    fn fs_write(path: &str) -> Event {
        Event::FsWrite {
            path: path.to_string(),
            bytes: 0,
            lines_added: 0,
            lines_removed: 0,
            hunk_count: 0,
            session_id: Uuid::new_v4(),
        }
    }

    fn make_engine(policies: Vec<Policy>) -> PolicyEngine {
        PolicyEngine::new(PolicyConfig { policies }).expect("valid engine")
    }

    #[test]
    fn test_empty_engine_allows_all() {
        let e = PolicyEngine::default();
        let decision = e.evaluate(&tool_call("Bash"), 0);
        assert!(matches!(decision.action, PolicyAction::Allow));
    }

    #[test]
    fn test_tool_call_deny() {
        let e = make_engine(vec![Policy {
            name: "no-bash".into(),
            action: PolicyAction::Deny,
            matcher: PolicyMatcher::ToolCall { tool_name_pattern: "Bash".into() },
        }]);
        let d = e.evaluate(&tool_call("Bash"), 0);
        assert!(matches!(d.action, PolicyAction::Deny));
        assert_eq!(d.policy_name.as_deref(), Some("no-bash"));
    }

    #[test]
    fn test_tool_call_allows_non_matching() {
        let e = make_engine(vec![Policy {
            name: "no-bash".into(),
            action: PolicyAction::Deny,
            matcher: PolicyMatcher::ToolCall { tool_name_pattern: "Bash".into() },
        }]);
        let d = e.evaluate(&tool_call("Read"), 0);
        assert!(matches!(d.action, PolicyAction::Allow));
    }

    #[test]
    fn test_tool_call_case_insensitive() {
        let e = make_engine(vec![Policy {
            name: "no-bash".into(),
            action: PolicyAction::Deny,
            matcher: PolicyMatcher::ToolCall { tool_name_pattern: "bash".into() },
        }]);
        let d = e.evaluate(&tool_call("Bash"), 0);
        assert!(matches!(d.action, PolicyAction::Deny));
    }

    #[test]
    fn test_first_match_wins() {
        let e = make_engine(vec![
            Policy {
                name: "allow-bash".into(),
                action: PolicyAction::Allow,
                matcher: PolicyMatcher::ToolCall { tool_name_pattern: "Bash".into() },
            },
            Policy {
                name: "deny-bash".into(),
                action: PolicyAction::Deny,
                matcher: PolicyMatcher::ToolCall { tool_name_pattern: "Bash".into() },
            },
        ]);
        let d = e.evaluate(&tool_call("Bash"), 0);
        assert!(matches!(d.action, PolicyAction::Allow));
        assert_eq!(d.policy_name.as_deref(), Some("allow-bash"));
    }

    #[test]
    fn test_fs_path_deny() {
        let e = make_engine(vec![Policy {
            name: "no-env".into(),
            action: PolicyAction::Deny,
            matcher: PolicyMatcher::FsPath { path_pattern: ".env".into() },
        }]);
        let d = e.evaluate(&fs_write("/project/.env"), 0);
        assert!(matches!(d.action, PolicyAction::Deny));
    }

    #[test]
    fn test_fs_write_outside_root() {
        let e = make_engine(vec![Policy {
            name: "confine".into(),
            action: PolicyAction::Deny,
            matcher: PolicyMatcher::FsWriteOutside { root: "/project".into() },
        }]);
        let d_outside = e.evaluate(&fs_write("/tmp/evil"), 0);
        assert!(matches!(d_outside.action, PolicyAction::Deny));
        let d_inside = e.evaluate(&fs_write("/project/src/main.rs"), 0);
        assert!(matches!(d_inside.action, PolicyAction::Allow));
    }

    #[test]
    fn test_token_budget() {
        let e = make_engine(vec![Policy {
            name: "token-limit".into(),
            action: PolicyAction::LogOnly,
            matcher: PolicyMatcher::TokenBudget { max_tokens: 1000 },
        }]);
        assert!(matches!(e.evaluate(&tool_call("Read"), 999).action, PolicyAction::Allow));
        assert!(matches!(e.evaluate(&tool_call("Read"), 1000).action, PolicyAction::LogOnly));
        assert!(matches!(e.evaluate(&tool_call("Read"), 1001).action, PolicyAction::LogOnly));
    }

    #[test]
    fn test_tool_call_input_match() {
        let e = make_engine(vec![Policy {
            name: "no-rm-rf".into(),
            action: PolicyAction::Deny,
            matcher: PolicyMatcher::ToolCallInput {
                tool_name_pattern: "Bash".into(),
                input_field: "command".into(),
                value_pattern: "rm -rf".into(),
            },
        }]);
        let dangerous = Event::ToolCall {
            agent: "test".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: None,
            correlation_id: None,
            input: json!({"command": "rm -rf /"}),
            session_id: Uuid::new_v4(),
        };
        let safe = Event::ToolCall {
            agent: "test".to_string(),
            tool_name: "Bash".to_string(),
            tool_use_id: None,
            correlation_id: None,
            input: json!({"command": "ls -la"}),
            session_id: Uuid::new_v4(),
        };
        assert!(matches!(e.evaluate(&dangerous, 0).action, PolicyAction::Deny));
        assert!(matches!(e.evaluate(&safe, 0).action, PolicyAction::Allow));
    }
}

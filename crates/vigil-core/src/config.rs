use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::policy::{Policy, PolicyAction, PolicyMatcher};

/// Top-level vigil configuration (TOML format).
/// Replaces the old YAML PolicyConfig for new users.
/// Old --policy YAML files continue to work through PolicyEngine::from_file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct VigilConfig {
    #[serde(default)]
    pub proxy: ProxySection,
    #[serde(default)]
    pub session: SessionSection,
    #[serde(default)]
    pub pii: PiiSection,
    #[serde(default)]
    pub policies: Vec<ConfigPolicy>,
    #[serde(default)]
    pub budget: BudgetSection,
    #[serde(default)]
    pub notify: NotifySection,
    #[serde(default)]
    pub drift: DriftSection,
}

fn default_blocked_commands() -> Vec<String> {
    vec![
        "rm -rf".to_string(),
        "dd if=".to_string(),
        "mkfs".to_string(),
        ":(){ :|:& };:".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProxySection {
    pub port: Option<u16>,
    pub metrics_port: Option<u16>,
    /// Gate writes at this risk level or above. "Low", "Medium", or "High".
    /// None (the default) disables write approval gating.
    #[serde(default)]
    pub write_approval_threshold: Option<String>,
    /// Shell command substrings to block. Each entry is matched as a
    /// case-sensitive substring against Bash/shell tool call inputs.
    /// Best-effort — not a security boundary; a determined agent can bypass
    /// simple substring checks. Defaults to a short list of destructive
    /// patterns. Set to [] to disable all blocking.
    #[serde(default = "default_blocked_commands")]
    pub blocked_commands: Vec<String>,
    /// Emit a ToolTimeout alert if no LlmRequest follows a tool call within
    /// this many seconds. None disables the check. Recommended: 600 (10 min).
    #[serde(default)]
    pub tool_timeout_secs: Option<u64>,
    /// If set, automatically kill the agent process after this many seconds
    /// of tool silence (must be >= tool_timeout_secs). Alert-only opt-in.
    #[serde(default)]
    pub tool_timeout_kill_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SessionSection {
    pub store_raw: Option<bool>,
    pub sessions_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PiiSection {
    pub watchlist_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BudgetSection {
    pub max_cost_usd: Option<f64>,
    pub max_tokens: Option<u32>,
    /// Time window when agent is allowed to run, "HH:MM-HH:MM" local time.
    pub allowed_hours: Option<String>,
    #[serde(default)]
    pub max_burn_rate_usd_per_min: Option<f64>,
    #[serde(default)]
    pub loop_detect_threshold: Option<u32>,
    /// Emit a soft CostAlert warning (without stopping) at this spend level.
    #[serde(default)]
    pub cost_alert_usd: Option<f64>,
    /// Emit a SessionDurationAlert (and optionally stop) after this many minutes.
    #[serde(default)]
    pub max_session_duration_mins: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NotifySection {
    /// HTTP endpoint to POST alert events to. Fire-and-forget with 3 retries.
    #[serde(default)]
    pub webhook: Option<String>,
    /// Subset of alert labels to forward. Empty = all alerts.
    /// Valid labels: BURN, TOUT, EXFL, LOOP, WAPPR, COST, DURA, DENY, DRFT
    #[serde(default)]
    pub webhook_events: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DriftSection {
    #[serde(default)]
    pub baseline_turns: Option<usize>,
    #[serde(default)]
    pub window_turns: Option<usize>,
    #[serde(default)]
    pub acceleration_multiplier: Option<f64>,
    #[serde(default)]
    pub acceleration_min_tokens: Option<u32>,
    #[serde(default)]
    pub stall_threshold: Option<usize>,
    #[serde(default)]
    pub debounce_events: Option<u32>,
}

impl DriftSection {
    pub fn to_drift_config(&self) -> crate::drift::DriftConfig {
        let d = crate::drift::DriftConfig::default();
        crate::drift::DriftConfig {
            baseline_turns:          self.baseline_turns.unwrap_or(d.baseline_turns),
            window_turns:            self.window_turns.unwrap_or(d.window_turns),
            acceleration_multiplier: self.acceleration_multiplier.unwrap_or(d.acceleration_multiplier),
            acceleration_min_tokens: self.acceleration_min_tokens.unwrap_or(d.acceleration_min_tokens),
            stall_threshold:         self.stall_threshold.unwrap_or(d.stall_threshold),
            debounce_events:         self.debounce_events.unwrap_or(d.debounce_events),
        }
    }
}

/// A policy rule as it appears in vigil.toml.
/// Structurally identical to policy::Policy so they can be freely converted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPolicy {
    pub name: String,
    pub action: PolicyAction,
    pub matcher: PolicyMatcher,
}

impl From<ConfigPolicy> for Policy {
    fn from(r: ConfigPolicy) -> Self {
        Self { name: r.name, action: r.action, matcher: r.matcher }
    }
}

impl VigilConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    pub fn validate(&self) -> anyhow::Result<Vec<String>> {
        let mut warnings = Vec::new();
        if self.policies.is_empty() && self.proxy.blocked_commands.is_empty() {
            warnings.push("No policies or blocked commands defined — all events will be allowed".to_string());
        }
        if let Some(hours) = &self.budget.allowed_hours {
            if !hours.contains('-') || hours.len() != 11 {
                return Err(anyhow::anyhow!(
                    "budget.allowed_hours must be HH:MM-HH:MM, got: {}",
                    hours
                ));
            }
        }
        Ok(warnings)
    }

    pub fn explain(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("proxy port: {}\n", self.proxy.port.unwrap_or(8877)));
        if let Some(max_cost) = self.budget.max_cost_usd {
            out.push_str(&format!("cost budget: ${:.4}\n", max_cost));
        }
        if let Some(max_tok) = self.budget.max_tokens {
            out.push_str(&format!("token budget: {}\n", max_tok));
        }
        if self.policies.is_empty() {
            out.push_str("policies: none (allow all)\n");
        } else {
            out.push_str(&format!("policies ({}):\n", self.policies.len()));
            for p in &self.policies {
                out.push_str(&format!("  {} -> {:?}\n", p.name, p.action));
            }
        }
        out
    }

    /// Convert the policies in this config to the format PolicyEngine expects.
    /// Blocked commands are prepended as synthetic ToolCallInput deny policies.
    pub fn to_policies(&self) -> Vec<Policy> {
        let mut policies: Vec<Policy> = self.proxy.blocked_commands.iter().map(|pattern| Policy {
            name: format!("block-cmd:{}", pattern),
            action: PolicyAction::Deny,
            matcher: PolicyMatcher::ToolCallInput {
                tool_name_pattern: "Bash".to_string(),
                input_field: "command".to_string(),
                value_pattern: pattern.clone(),
            },
        }).collect();
        policies.extend(self.policies.iter().cloned().map(Into::into));
        policies
    }
}

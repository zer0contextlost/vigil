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
        if self.policies.is_empty() {
            warnings.push("No policies defined — all events will be allowed".to_string());
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
    pub fn to_policies(&self) -> Vec<Policy> {
        self.policies.iter().cloned().map(Into::into).collect()
    }
}

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
    #[serde(default)]
    pub report: Option<ReportConfig>,
    #[serde(default)]
    pub window: Option<WindowConfig>,
    #[serde(default)]
    pub web: WebSection,
    #[serde(default)]
    pub approval: ApprovalSection,
    #[serde(default)]
    pub policy_stack: PolicyStackSection,
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
    /// Port to bind the web dashboard on 127.0.0.1. Default off (None).
    /// Set to a port (e.g. 8878) to enable the browser dashboard.
    #[serde(default)]
    pub dashboard_port: Option<u16>,
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
    /// Emit SubAgentSpawned and deny when Task tool call count exceeds this value.
    /// Each Task invocation increments the session counter; the policy fires when
    /// the count exceeds max_sub_agent_depth.
    #[serde(default)]
    pub max_sub_agent_depth: Option<u32>,
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

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct ReportConfig {
    /// Turns before first FsWrite to warn (default: 5)
    pub turn_to_first_write_warn: Option<u32>,
    /// Turns before first FsWrite to flag (default: 15)
    pub turn_to_first_write_flag: Option<u32>,
    /// Input token growth multiplier to warn (default: 1.5)
    pub input_growth_warn_multiplier: Option<f64>,
    /// Input token growth multiplier to flag (default: 2.0)
    pub input_growth_flag_multiplier: Option<f64>,
    /// Re-read count per path to warn (default: 2)
    pub reread_warn_count: Option<u32>,
    /// Re-read count per path to flag (default: 3)
    pub reread_flag_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WindowConfig {
    /// vigil TUI window X position in pixels
    pub tui_x: Option<i32>,
    /// vigil TUI window Y position in pixels
    pub tui_y: Option<i32>,
    /// vigil TUI window width in pixels
    pub tui_width: Option<u32>,
    /// vigil TUI window height in pixels
    pub tui_height: Option<u32>,
    /// Agent window X position in pixels
    pub agent_x: Option<i32>,
    /// Agent window Y position in pixels
    pub agent_y: Option<i32>,
    /// Agent window width in pixels
    pub agent_width: Option<u32>,
    /// Agent window height in pixels
    pub agent_height: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WebSection {
    /// Port to bind the browser dashboard on 127.0.0.1. Omit to disable.
    /// Supersedes [proxy] dashboard_port when both are set.
    #[serde(default)]
    pub port: Option<u16>,
}

/// Per-path write-approval trust tiers.
/// Each entry is a glob-style pattern (supports `*` wildcard and `/`-terminated prefixes).
/// Examples:
///   yolo_paths  = ["src/utils/", "tests/", "*.md"]
///   watch_paths = ["src/", "*.ts"]
///   lockdown_paths = [".env", "src/config/", "*.pem"]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSection {
    /// Paths that NEVER need write approval, even if write_approval_threshold is set.
    #[serde(default)]
    pub yolo_paths: Vec<String>,
    /// Paths that ALWAYS need write approval, regardless of risk level.
    #[serde(default)]
    pub watch_paths: Vec<String>,
    /// Paths that ALWAYS need write approval and are shown with an elevated warning.
    #[serde(default)]
    pub lockdown_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyStackSection {
    /// Load ~/.vigil/vigil.toml as the base policy layer. Default: true.
    #[serde(default = "default_true")]
    pub inherit_global: bool,
    /// Load the nearest vigil.toml walking up from cwd as a policy layer. Default: true.
    #[serde(default = "default_true")]
    pub inherit_repo: bool,
}

fn default_true() -> bool { true }

impl Default for PolicyStackSection {
    fn default() -> Self {
        Self { inherit_global: true, inherit_repo: true }
    }
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
        if let Some(max_depth) = self.budget.max_sub_agent_depth {
            policies.push(Policy {
                name: "sub-agent-depth-limit".to_string(),
                action: PolicyAction::Deny,
                matcher: PolicyMatcher::SubAgentDepth { max_depth },
            });
        }
        policies.extend(self.policies.iter().cloned().map(Into::into));
        policies
    }

    /// Return the list of config file paths that vigil should watch for hot-reload.
    /// Includes ~/.vigil/vigil.toml (if present) and the explicit --config path.
    pub fn find_config_paths(explicit: Option<&Path>) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Global config layer
        let home = if cfg!(target_os = "windows") {
            std::env::var("USERPROFILE").ok()
        } else {
            std::env::var("HOME").ok()
        };
        if let Some(global) = home.map(|h| PathBuf::from(h).join(".vigil").join("vigil.toml")) {
            if global.exists() {
                paths.push(global);
            }
        }

        // Repo config layer: nearest vigil.toml walking up from cwd
        if let Ok(cwd) = std::env::current_dir() {
            let mut dir: &Path = cwd.as_path();
            loop {
                let candidate = dir.join("vigil.toml");
                if candidate.exists() {
                    let is_explicit = explicit.map(|e| {
                        std::fs::canonicalize(e).ok() == std::fs::canonicalize(&candidate).ok()
                    }).unwrap_or(false);
                    if !is_explicit && !paths.contains(&candidate) {
                        paths.push(candidate);
                    }
                    break;
                }
                match dir.parent() {
                    Some(p) => dir = p,
                    None => break,
                }
            }
        }

        // Explicit --config layer
        if let Some(exp) = explicit {
            let exp_pb = exp.to_path_buf();
            if exp_pb.exists() && !paths.contains(&exp_pb) {
                paths.push(exp_pb);
            }
        }

        paths
    }

    /// Merge multiple config layers into one. Later layers override scalars;
    /// policies from all layers are concatenated (global-first order).
    pub fn merge_layers(layers: Vec<Self>) -> Self {
        let mut merged = Self::default();
        for layer in layers {
            if layer.proxy.port.is_some()                       { merged.proxy.port = layer.proxy.port; }
            if layer.proxy.dashboard_port.is_some()             { merged.proxy.dashboard_port = layer.proxy.dashboard_port; }
            if layer.proxy.write_approval_threshold.is_some()   { merged.proxy.write_approval_threshold = layer.proxy.write_approval_threshold; }
            if !layer.proxy.blocked_commands.is_empty()         { merged.proxy.blocked_commands = layer.proxy.blocked_commands; }
            if layer.proxy.tool_timeout_secs.is_some()          { merged.proxy.tool_timeout_secs = layer.proxy.tool_timeout_secs; }
            if layer.proxy.tool_timeout_kill_secs.is_some()     { merged.proxy.tool_timeout_kill_secs = layer.proxy.tool_timeout_kill_secs; }
            if layer.session.store_raw.is_some()                { merged.session.store_raw = layer.session.store_raw; }
            if layer.session.sessions_dir.is_some()             { merged.session.sessions_dir = layer.session.sessions_dir; }
            if layer.pii.watchlist_file.is_some()               { merged.pii.watchlist_file = layer.pii.watchlist_file; }
            if layer.budget.max_cost_usd.is_some()              { merged.budget.max_cost_usd = layer.budget.max_cost_usd; }
            if layer.budget.max_tokens.is_some()                { merged.budget.max_tokens = layer.budget.max_tokens; }
            if layer.budget.allowed_hours.is_some()             { merged.budget.allowed_hours = layer.budget.allowed_hours; }
            if layer.budget.max_burn_rate_usd_per_min.is_some() { merged.budget.max_burn_rate_usd_per_min = layer.budget.max_burn_rate_usd_per_min; }
            if layer.budget.loop_detect_threshold.is_some()     { merged.budget.loop_detect_threshold = layer.budget.loop_detect_threshold; }
            if layer.budget.cost_alert_usd.is_some()            { merged.budget.cost_alert_usd = layer.budget.cost_alert_usd; }
            if layer.budget.max_session_duration_mins.is_some() { merged.budget.max_session_duration_mins = layer.budget.max_session_duration_mins; }
            if layer.budget.max_sub_agent_depth.is_some()       { merged.budget.max_sub_agent_depth = layer.budget.max_sub_agent_depth; }
            if layer.notify.webhook.is_some()                   { merged.notify.webhook = layer.notify.webhook; }
            if !layer.notify.webhook_events.is_empty()          { merged.notify.webhook_events = layer.notify.webhook_events; }
            if layer.drift.baseline_turns.is_some()             { merged.drift.baseline_turns = layer.drift.baseline_turns; }
            if layer.drift.window_turns.is_some()               { merged.drift.window_turns = layer.drift.window_turns; }
            if layer.drift.acceleration_multiplier.is_some()    { merged.drift.acceleration_multiplier = layer.drift.acceleration_multiplier; }
            if layer.drift.acceleration_min_tokens.is_some()    { merged.drift.acceleration_min_tokens = layer.drift.acceleration_min_tokens; }
            if layer.drift.stall_threshold.is_some()            { merged.drift.stall_threshold = layer.drift.stall_threshold; }
            if layer.drift.debounce_events.is_some()            { merged.drift.debounce_events = layer.drift.debounce_events; }
            if layer.report.is_some()                           { merged.report = layer.report; }
            if layer.window.is_some()                           { merged.window = layer.window; }
            if layer.web.port.is_some()                         { merged.web.port = layer.web.port; }
            if !layer.approval.yolo_paths.is_empty()            { merged.approval.yolo_paths = layer.approval.yolo_paths; }
            if !layer.approval.watch_paths.is_empty()           { merged.approval.watch_paths = layer.approval.watch_paths; }
            if !layer.approval.lockdown_paths.is_empty()        { merged.approval.lockdown_paths = layer.approval.lockdown_paths; }
            // Policies are additive: global → repo → explicit, in order.
            merged.policies.extend(layer.policies);
        }
        merged
    }
}

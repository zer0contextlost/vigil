use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

use crate::envelope::TimestampedEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub agent: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub total_input_tokens: u32,
    pub total_output_tokens: u32,
    pub total_cost_usd: f64,
    pub policy_violations: u32,
    #[serde(default)]
    pub pii_detections: u32,
    pub events: Vec<TimestampedEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: Uuid,
    pub agent: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub total_input_tokens: u32,
    pub total_output_tokens: u32,
    pub total_cost_usd: f64,
    pub policy_violations: u32,
    pub event_count: usize,
    #[serde(default)]
    pub name: Option<String>,
}

impl Session {
    pub fn new(agent: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            agent,
            started_at: Utc::now(),
            ended_at: None,
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cost_usd: 0.0,
            policy_violations: 0,
            pii_detections: 0,
            events: Vec::new(),
        }
    }

    pub fn record(&mut self, event: TimestampedEvent) {
        self.events.push(event);
    }

    pub fn cost_summary(&self) -> String {
        format!(
            "${:.4} ({} in / {} out)",
            self.total_cost_usd, self.total_input_tokens, self.total_output_tokens
        )
    }

    pub fn finish(&mut self) {
        self.ended_at = Some(Utc::now());
    }

    pub fn to_summary(&self) -> SessionSummary {
        SessionSummary {
            id: self.id,
            agent: self.agent.clone(),
            started_at: self.started_at,
            ended_at: self.ended_at,
            total_input_tokens: self.total_input_tokens,
            total_output_tokens: self.total_output_tokens,
            total_cost_usd: self.total_cost_usd,
            policy_violations: self.policy_violations,
            event_count: self.events.len(),
            name: None,
        }
    }

    pub fn save(&self) -> anyhow::Result<PathBuf> {
        let sessions_dir = Self::sessions_dir()?;
        let file_path = sessions_dir.join(format!("{}.json", self.id));
        let json = serde_json::to_string_pretty(&self)?;
        std::fs::write(&file_path, json)?;
        Ok(file_path)
    }

    pub fn load(id: &Uuid) -> anyhow::Result<Self> {
        let sessions_dir = Self::sessions_dir()?;
        let file_path = sessions_dir.join(format!("{}.json", id));
        let json = std::fs::read_to_string(&file_path)?;
        let session = serde_json::from_str(&json)?;
        Ok(session)
    }

    pub fn list_all() -> anyhow::Result<Vec<SessionSummary>> {
        use crate::store::SessionMeta;

        let sessions_dir = Self::sessions_dir()?;
        if !sessions_dir.exists() {
            return Ok(Vec::new());
        }

        let mut summaries: std::collections::HashMap<Uuid, SessionSummary> = std::collections::HashMap::new();

        for entry in std::fs::read_dir(&sessions_dir)? {
            let entry = entry?;
            let path = entry.path();
            let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // New format: <uuid>.meta.json
            if fname.ends_with(".meta.json") {
                if let Ok(json) = std::fs::read_to_string(&path) {
                    if let Ok(meta) = serde_json::from_str::<SessionMeta>(&json) {
                        let summary = SessionSummary {
                            id: meta.session_id,
                            agent: meta.agent.clone(),
                            started_at: meta.started_at,
                            ended_at: meta.ended_at,
                            total_input_tokens: meta.total_input_tokens,
                            total_output_tokens: meta.total_output_tokens,
                            total_cost_usd: meta.total_cost_usd,
                            policy_violations: meta.policy_violations,
                            event_count: meta.event_count as usize,
                            name: meta.name.clone(),
                        };
                        summaries.insert(meta.session_id, summary);
                    }
                }
            }

            // Legacy format: <uuid>.json (no .meta suffix)
            if path.extension().and_then(|s| s.to_str()) == Some("json")
                && !fname.ends_with(".meta.json")
                && !fname.ends_with(".summary.json")
            {
                if let Ok(json) = std::fs::read_to_string(&path) {
                    if let Ok(session) = serde_json::from_str::<Session>(&json) {
                        // Only insert if not already present from meta.json
                        summaries.entry(session.id).or_insert_with(|| session.to_summary());
                    }
                }
            }
        }

        let mut result: Vec<SessionSummary> = summaries.into_values().collect();
        result.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        Ok(result)
    }

    /// Look up a session by name label. Returns the first match.
    pub fn find_by_name(name: &str) -> anyhow::Result<Option<SessionSummary>> {
        Ok(Self::list_all()?.into_iter().find(|s| {
            s.name.as_deref().map(|n| n.eq_ignore_ascii_case(name)).unwrap_or(false)
        }))
    }

    pub fn sessions_dir() -> anyhow::Result<PathBuf> {
        let home_dir = if cfg!(target_os = "windows") {
            std::env::var("USERPROFILE").ok()
        } else {
            std::env::var("HOME").ok()
        }
        .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;

        let sessions_dir = PathBuf::from(home_dir).join(".vigil").join("sessions");
        std::fs::create_dir_all(&sessions_dir)?;
        Ok(sessions_dir)
    }
}

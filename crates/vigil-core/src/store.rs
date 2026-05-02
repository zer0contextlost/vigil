use anyhow::Result;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use uuid::Uuid;

use crate::envelope::Envelope;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub session_id: Uuid,
    pub agent: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub total_cost_usd: f64,
    pub total_input_tokens: u32,
    pub total_output_tokens: u32,
    pub event_count: u64,
    pub pii_detections: u32,
    pub policy_violations: u32,
}

pub struct SessionStore {
    pub session_id: Uuid,
    pub ndjson_path: PathBuf,
    meta_path: PathBuf,
    file: File,
    pub event_count: u64,
    pub last_hash: String,
    session_key: [u8; 32],
    pub meta: SessionMeta,
}

impl SessionStore {
    pub fn create(session_id: Uuid, agent: &str) -> Result<Self> {
        let dir = sessions_dir()?;
        let ndjson_path = dir.join(format!("{}.ndjson", session_id));
        let meta_path = dir.join(format!("{}.meta.json", session_id));

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ndjson_path)?;

        let mut session_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_key);

        let meta = SessionMeta {
            session_id,
            agent: agent.to_string(),
            started_at: Utc::now(),
            ended_at: None,
            total_cost_usd: 0.0,
            total_input_tokens: 0,
            total_output_tokens: 0,
            event_count: 0,
            pii_detections: 0,
            policy_violations: 0,
        };

        Ok(Self {
            session_id,
            ndjson_path,
            meta_path,
            file,
            event_count: 0,
            last_hash: String::new(),
            session_key,
            meta,
        })
    }

    /// Append one envelope to the NDJSON file, update the hash chain, fsync.
    pub fn append(&mut self, envelope: &Envelope) -> Result<()> {
        let mut env = envelope.clone();
        env.prev_hash = self.last_hash.clone();
        self.last_hash = env.compute_hash();

        let mut line = serde_json::to_vec(&env)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_data()?;
        self.event_count += 1;
        self.meta.event_count = self.event_count;
        Ok(())
    }

    /// Atomically rewrite the sidecar meta file.
    pub fn flush_meta(&mut self) -> Result<()> {
        let tmp = self.meta_path.with_extension("tmp");
        let json = serde_json::to_vec_pretty(&self.meta)?;
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &self.meta_path)?;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        self.meta.ended_at = Some(Utc::now());
        self.flush_meta()
    }

    pub fn session_key(&self) -> &[u8; 32] {
        &self.session_key
    }

    /// Read all envelopes from an existing NDJSON session file.
    pub fn load_envelopes(session_id: &Uuid) -> Result<Vec<Envelope>> {
        let path = sessions_dir()?.join(format!("{}.ndjson", session_id));
        if !path.exists() {
            return Ok(vec![]);
        }
        let content = std::fs::read_to_string(&path)?;
        let mut envelopes = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(env) = serde_json::from_str::<Envelope>(line) {
                envelopes.push(env);
            }
        }
        Ok(envelopes)
    }

    pub fn load_meta(session_id: &Uuid) -> Result<SessionMeta> {
        let path = sessions_dir()?.join(format!("{}.meta.json", session_id));
        let json = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

pub fn sessions_dir() -> Result<PathBuf> {
    let home = if cfg!(target_os = "windows") {
        std::env::var("USERPROFILE").ok()
    } else {
        std::env::var("HOME").ok()
    }
    .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;

    let dir = PathBuf::from(home).join(".vigil").join("sessions");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

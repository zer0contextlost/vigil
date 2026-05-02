use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    pub session_id: Uuid,
    pub agent: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub session_cost_usd: f64,
    pub session_tokens: u32,
    pub burn_rate_per_min: f64,
    pub last_event: String,
    pub needs_attention: bool,
    pub pid: u32,
}

pub fn active_dir() -> anyhow::Result<PathBuf> {
    let home = if cfg!(target_os = "windows") {
        std::env::var("USERPROFILE").ok()
    } else {
        std::env::var("HOME").ok()
    }
    .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    let dir = PathBuf::from(home).join(".vigil").join("active");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub struct ActiveSessionHandle {
    pub path: PathBuf,
}

impl ActiveSessionHandle {
    /// Write/overwrite the lock file atomically.
    pub fn write(&self, session: &ActiveSession) -> anyhow::Result<()> {
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(session)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Delete the lock file on exit.
    pub fn remove(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn create_handle(session_id: &Uuid) -> anyhow::Result<ActiveSessionHandle> {
    let path = active_dir()?.join(format!("{}.lock", session_id));
    Ok(ActiveSessionHandle { path })
}

/// Read all active sessions from lock files. Silently skips stale/unparseable files.
pub fn list_active() -> Vec<ActiveSession> {
    let Ok(dir) = active_dir() else { return vec![] };
    let Ok(entries) = std::fs::read_dir(&dir) else { return vec![] };
    let mut sessions = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("lock") {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(session) = serde_json::from_str::<ActiveSession>(&content) {
                use sysinfo::System;
                let mut sys = System::new_all();
                sys.refresh_all();
                if sys.process(sysinfo::Pid::from(session.pid as usize)).is_some() {
                    sessions.push(session);
                } else {
                    // Stale lock file — remove it
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
    sessions.sort_by_key(|s| s.started_at);
    sessions
}

pub fn update_active(path: &std::path::Path, update: impl FnOnce(&mut ActiveSession)) {
    if let Ok(content) = std::fs::read_to_string(path) {
        if let Ok(mut session) = serde_json::from_str::<ActiveSession>(&content) {
            update(&mut session);
            let tmp = path.with_extension("tmp");
            if let Ok(bytes) = serde_json::to_vec_pretty(&session) {
                let _ = std::fs::write(&tmp, bytes);
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }
}

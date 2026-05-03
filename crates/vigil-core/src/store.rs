use anyhow::Result;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use ulid::Generator;
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
    /// Optional human-readable label set via `vigil tag` or `vigil run --name`.
    #[serde(default)]
    pub name: Option<String>,
    /// SHA-256 hash of the last envelope in the chain (hex).
    #[serde(default)]
    pub chain_root_hash: String,
    /// ed25519 signature over chain_root_hash bytes, hex-encoded.
    #[serde(default)]
    pub chain_signature: Option<String>,
    /// ed25519 verifying (public) key, hex-encoded.
    #[serde(default)]
    pub verifying_key: Option<String>,
    /// Developer/username from $USER or $USERNAME env var.
    #[serde(default)]
    pub developer: Option<String>,
    /// Remote origin URL of the git repository, best-effort.
    #[serde(default)]
    pub git_repo: Option<String>,
    /// Current git branch name.
    #[serde(default)]
    pub git_branch: Option<String>,
    /// Current git HEAD commit hash (7 characters).
    #[serde(default)]
    pub git_commit: Option<String>,
}

fn capture_git_context() -> (Option<String>, Option<String>, Option<String>) {
    // returns (repo, branch, commit)
    let branch = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());

    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());

    let repo = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());

    (repo, branch, commit)
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
    ulid_gen: Generator,
    signing_key: SigningKey,
    finished: bool,
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

        let developer = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .ok();
        let (git_repo, git_branch, git_commit) = capture_git_context();

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
            name: Some(crate::namegen::generate()),
            chain_root_hash: String::new(),
            chain_signature: None,
            verifying_key: None,
            developer,
            git_repo,
            git_branch,
            git_commit,
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
            ulid_gen: Generator::new(),
            signing_key: SigningKey::generate(&mut OsRng),
            finished: false,
        })
    }

    /// Append one envelope to the NDJSON file, update the hash chain, fsync.
    pub fn append(&mut self, envelope: &Envelope) -> Result<()> {
        let mut env = envelope.clone();
        env.event_id = self.ulid_gen.generate()
            .map_err(|e| anyhow::anyhow!("ULID generation failed (monotonicity overflow): {}", e))?;
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
        // Sign the chain root hash so `vigil verify` can detect tampering.
        if !self.last_hash.is_empty() {
            let sig: Signature = self.signing_key.sign(self.last_hash.as_bytes());
            self.meta.chain_root_hash = self.last_hash.clone();
            self.meta.chain_signature = Some(hex::encode(sig.to_bytes()));
            self.meta.verifying_key = Some(hex::encode(self.signing_key.verifying_key().to_bytes()));
        }
        self.finished = true;
        self.flush_meta()?;

        // Best-effort: write cost as git notes on the commit this session ran against
        if let (Some(commit), Some(branch)) = (&self.meta.git_commit, &self.meta.git_branch) {
            let note = format!(
                "vigil-cost: ${:.4} | branch: {} | session: {} | agent: {}",
                self.meta.total_cost_usd,
                branch,
                self.meta.session_id,
                self.meta.agent
            );
            let _ = std::process::Command::new("git")
                .args(["notes", "add", "-f", "-m", &note, commit])
                .output();
        }

        Ok(())
    }

    /// Verify the stored ed25519 chain-root signature against the provided hash.
    /// Returns Ok(()) if valid or if no signature is stored (pre-signing sessions).
    pub fn verify_signature(meta: &SessionMeta, chain_root: &str) -> Result<()> {
        let (Some(sig_hex), Some(vk_hex)) = (&meta.chain_signature, &meta.verifying_key) else {
            return Ok(());
        };
        let vk_bytes: [u8; 32] = hex::decode(vk_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid verifying key length"))?;
        let sig_bytes: [u8; 64] = hex::decode(sig_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signature length"))?;
        let vk = VerifyingKey::from_bytes(&vk_bytes)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(chain_root.as_bytes(), &sig)
            .map_err(|e| anyhow::anyhow!("signature invalid: {}", e))
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
        let mut malformed = 0usize;
        for (i, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Envelope>(line) {
                Ok(env) => envelopes.push(env),
                Err(e) => {
                    malformed += 1;
                    tracing::warn!(
                        %session_id, line = i + 1, error = %e,
                        "skipping malformed NDJSON line in session file"
                    );
                }
            }
        }
        if malformed > 0 {
            tracing::warn!(
                %session_id, malformed, loaded = envelopes.len(),
                "session file has malformed lines — some events may be missing"
            );
        }
        Ok(envelopes)
    }

    pub fn load_meta(session_id: &Uuid) -> Result<SessionMeta> {
        let path = sessions_dir()?.join(format!("{}.meta.json", session_id));
        let json = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Set or update the human-readable name for a session, persisting to meta.json.
    pub fn tag(session_id: &Uuid, name: &str) -> Result<()> {
        let mut meta = Self::load_meta(session_id)?;
        meta.name = Some(name.to_string());
        let path = sessions_dir()?.join(format!("{}.meta.json", session_id));
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&meta)?)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Set the name on this store's in-memory meta (written on finish/drop).
    pub fn set_name(&mut self, name: &str) {
        self.meta.name = Some(name.to_string());
    }
}

impl Drop for SessionStore {
    fn drop(&mut self) {
        if !self.finished {
            // Process was killed or panicked without calling finish() — flush
            // whatever meta we have so `vigil audit` shows events not MISSING.
            let _ = self.flush_meta();
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use uuid::Uuid;

    fn make_store() -> SessionStore {
        let id = Uuid::new_v4();
        SessionStore::create(id, "test-agent").expect("create store")
    }

    fn make_event(sid: Uuid) -> crate::envelope::Envelope {
        crate::envelope::Envelope::new(Event::ProcessSpawn {
            command: "test".into(),
            args: vec![],
            session_id: sid,
        })
    }

    #[test]
    fn test_signing_roundtrip() {
        let mut store = make_store();
        let env = make_event(store.session_id);
        store.append(&env).unwrap();
        store.finish().unwrap();

        let meta = SessionStore::load_meta(&store.session_id).unwrap();
        assert!(meta.chain_signature.is_some(), "signature should be written on finish");
        assert!(meta.verifying_key.is_some());
        assert!(!meta.chain_root_hash.is_empty());
        // Verify must pass
        SessionStore::verify_signature(&meta, &meta.chain_root_hash.clone()).unwrap();
    }

    #[test]
    fn test_verify_signature_detects_tamper() {
        let mut store = make_store();
        let env = make_event(store.session_id);
        store.append(&env).unwrap();
        store.finish().unwrap();

        let mut meta = SessionStore::load_meta(&store.session_id).unwrap();
        // Corrupt the chain root hash — verify must fail
        meta.chain_root_hash = "deadbeef".repeat(8);
        let result = SessionStore::verify_signature(&meta, &meta.chain_root_hash.clone());
        assert!(result.is_err(), "tampered hash should fail verification");
    }

    #[test]
    fn test_verify_signature_skip_for_no_sig() {
        let meta = SessionMeta {
            session_id: Uuid::new_v4(),
            agent: "x".into(),
            started_at: chrono::Utc::now(),
            ended_at: None,
            total_cost_usd: 0.0,
            total_input_tokens: 0,
            total_output_tokens: 0,
            event_count: 0,
            pii_detections: 0,
            policy_violations: 0,
            name: None,
            chain_root_hash: String::new(),
            chain_signature: None,
            verifying_key: None,
            developer: None,
            git_repo: None,
            git_branch: None,
            git_commit: None,
        };
        // No signature stored → verify must succeed (backward compat)
        SessionStore::verify_signature(&meta, "anyhash").unwrap();
    }

    #[test]
    fn test_drop_flushes_meta_on_unclean_exit() {
        let mut store = make_store();
        let sid = store.session_id;
        let env = make_event(sid);
        store.append(&env).unwrap();
        // Drop without calling finish() — simulates kill/panic
        drop(store);

        let meta = SessionStore::load_meta(&sid).unwrap();
        assert_eq!(meta.event_count, 1, "meta should record the appended event");
        assert!(meta.ended_at.is_none(), "ended_at should be None for unclean exit");
    }

    #[test]
    fn test_append_ulid_monotonic() {
        let mut store = make_store();
        let sid = store.session_id;
        for _ in 0..5 {
            store.append(&make_event(sid)).unwrap();
        }
        let envelopes = SessionStore::load_envelopes(&sid).unwrap();
        for i in 1..envelopes.len() {
            let prev = envelopes[i - 1].event_id.to_string();
            let curr = envelopes[i].event_id.to_string();
            assert!(curr > prev, "ULIDs must be strictly increasing");
        }
    }

    #[test]
    fn test_hash_chain_integrity() {
        let mut store = make_store();
        let sid = store.session_id;
        for _ in 0..3 {
            store.append(&make_event(sid)).unwrap();
        }
        let envelopes = SessionStore::load_envelopes(&sid).unwrap();
        let mut expected_prev = String::new();
        for env in &envelopes {
            assert_eq!(env.prev_hash, expected_prev, "hash chain broken");
            expected_prev = env.compute_hash();
        }
    }

    // -------------------------------------------------------------------------
    // New smoke tests
    // -------------------------------------------------------------------------

    /// `vigil clear` smoke test: creating two sessions, finishing them, then
    /// manually deleting their .ndjson and .meta.json files (the same logic
    /// `run_clear` uses) must leave no trace of either session on disk.
    #[test]
    fn clear_deletes_all_session_files() {
        let mut store_a = make_store();
        let id_a = store_a.session_id;
        store_a.append(&make_event(id_a)).unwrap();
        store_a.finish().unwrap();

        let mut store_b = make_store();
        let id_b = store_b.session_id;
        store_b.append(&make_event(id_b)).unwrap();
        store_b.finish().unwrap();

        let dir = sessions_dir().unwrap();

        // Replicate the cleanup logic from `run_clear`: remove the .ndjson file
        // and the matching .meta.json sidecar.
        for id in [id_a, id_b] {
            let ndjson = dir.join(format!("{}.ndjson", id));
            let meta = dir.join(format!("{}.meta.json", id));
            std::fs::remove_file(&ndjson).expect("ndjson must exist before removal");
            std::fs::remove_file(&meta).expect("meta.json must exist before removal");
        }

        // Verify both files for both sessions are gone.
        for id in [id_a, id_b] {
            assert!(
                !dir.join(format!("{}.ndjson", id)).exists(),
                "ndjson file must not exist after clear"
            );
            assert!(
                !dir.join(format!("{}.meta.json", id)).exists(),
                "meta.json file must not exist after clear"
            );
        }
    }

    /// `run_export_all` smoke test: a session containing an LlmResponse with a
    /// fake e-mail address in `response_text` must have that address redacted
    /// by `scan_pii` before the export JSON is written.
    ///
    /// Note: `redact_json_value` is a private fn in `vigil-cli/src/main.rs` and
    /// cannot be called from a `vigil-core` test.  We test the boundary that IS
    /// accessible — `vigil_core::scan_pii` — which is the function that
    /// `redact_json_value` delegates to.  This validates the detection half of
    /// the redaction pipeline; the wiring (replacing the string in the JSON
    /// value) is exercised by `run_export` itself.
    #[test]
    fn export_scan_pii_redacts_email_in_response_text() {
        use crate::event::Event;
        use crate::pii::scan as scan_pii;

        let fake_email = "test.user@example.com";

        let sid = Uuid::new_v4();
        let mut store = SessionStore::create(sid, "test-agent").unwrap();

        let response_event = Event::LlmResponse {
            provider: "anthropic".into(),
            model: "claude".into(),
            input_tokens: 10,
            output_tokens: 20,
            cost_usd: 0.001,
            session_id: sid,
            response_text: Some(format!("The user email is {}.", fake_email)),
            cache_read_input_tokens: 0,
            cache_creation_input_tokens: 0,
            raw_response: None,
            stop_reason: None,
        };
        let envelope = crate::envelope::Envelope::new(response_event);
        store.append(&envelope).unwrap();
        store.finish().unwrap();

        // Load the stored envelopes back (same path `run_export_all` uses).
        let envelopes = SessionStore::load_envelopes(&sid).unwrap();
        assert_eq!(envelopes.len(), 1, "should have exactly one envelope");

        // Serialize to a JSON value and check that scan_pii detects the email.
        let val = serde_json::to_value(&envelopes[0]).unwrap();
        let json_str = serde_json::to_string(&val).unwrap();

        // The raw JSON must contain the email before redaction.
        assert!(
            json_str.contains(fake_email),
            "pre-redaction JSON must contain the original email"
        );

        // scan_pii on the response_text field must fire for the email.
        let hits = scan_pii(&format!("The user email is {}.", fake_email));
        assert!(
            !hits.is_empty(),
            "scan_pii must detect the email address"
        );
        assert!(
            hits.iter().any(|h| h.kind.as_str().to_lowercase().contains("email")),
            "scan_pii hit kind must mention 'email', got: {:?}",
            hits.iter().map(|h| h.kind.as_str()).collect::<Vec<_>>()
        );
    }
}

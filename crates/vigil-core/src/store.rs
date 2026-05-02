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
    /// SHA-256 hash of the last envelope in the chain (hex).
    #[serde(default)]
    pub chain_root_hash: String,
    /// ed25519 signature over chain_root_hash bytes, hex-encoded.
    #[serde(default)]
    pub chain_signature: Option<String>,
    /// ed25519 verifying (public) key, hex-encoded.
    #[serde(default)]
    pub verifying_key: Option<String>,
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
            chain_root_hash: String::new(),
            chain_signature: None,
            verifying_key: None,
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
        self.flush_meta()
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
            chain_root_hash: String::new(),
            chain_signature: None,
            verifying_key: None,
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
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ulid::Ulid;
use uuid::Uuid;

use crate::event::Event;

pub const SCHEMA_VERSION: u8 = 1;

fn default_schema_version() -> u8 { SCHEMA_VERSION }
fn default_event_id() -> Ulid { Ulid::new() }
fn default_turn_id() -> Uuid { Uuid::new_v4() }

/// Versioned event envelope. Replaces the old TimestampedEvent.
/// All new fields carry `#[serde(default = ...)]` so old session files
/// that lack them can still be deserialized without error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(default = "default_schema_version")]
    pub schema_version: u8,
    #[serde(default = "default_event_id")]
    pub event_id: Ulid,
    #[serde(default)]
    pub session_id: Uuid,
    #[serde(default)]
    pub parent_event_id: Option<Ulid>,
    #[serde(default = "default_turn_id")]
    pub turn_id: Uuid,
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub prev_hash: String,
    pub event: Event,
}

impl Envelope {
    pub fn new(event: Event) -> Self {
        let session_id = extract_session_id(&event);
        Self {
            schema_version: SCHEMA_VERSION,
            event_id: Ulid::new(),
            session_id,
            parent_event_id: None,
            turn_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            prev_hash: String::new(),
            event,
        }
    }

    /// Canonical bytes for hash-chain: serialise with prev_hash cleared so
    /// content hashes are stable regardless of chain position.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut copy = self.clone();
        copy.prev_hash = String::new();
        serde_json::to_vec(&copy).unwrap_or_default()
    }

    pub fn compute_hash(&self) -> String {
        hex::encode(Sha256::digest(&self.canonical_bytes()))
    }
}

/// Backward-compat alias — all existing `TimestampedEvent` call sites compile
/// unchanged because `TimestampedEvent::new(event)` resolves to `Envelope::new`.
pub type TimestampedEvent = Envelope;

fn extract_session_id(event: &Event) -> Uuid {
    match event {
        Event::LlmRequest { session_id, .. }
        | Event::LlmResponse { session_id, .. }
        | Event::ToolCall { session_id, .. }
        | Event::ToolCallResult { session_id, .. }
        | Event::FsRead { session_id, .. }
        | Event::FsWrite { session_id, .. }
        | Event::ProcessSpawn { session_id, .. }
        | Event::McpCall { session_id, .. }
        | Event::PiiAlert { session_id, .. }
        | Event::BurnRateAlert { session_id, .. }
        | Event::LoopAlert { session_id, .. }
        | Event::WriteApprovalRequired { session_id, .. }
        | Event::WriteApprovalDecision { session_id, .. } => *session_id,
    }
}

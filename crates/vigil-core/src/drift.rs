use std::collections::{HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::event::Event;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DriftSignal {
    /// Output token count is trending sharply upward versus the early-session baseline.
    OutputTokenAcceleration,
    /// N consecutive LlmRequest events with no FsWrite and no novel FsRead path between them.
    ProgressStall,
    /// Response negates the existence of a path or tool that the session has clearly used.
    SelfContradiction,
}

impl DriftSignal {
    pub fn as_str(&self) -> &'static str {
        match self {
            DriftSignal::OutputTokenAcceleration => "OutputTokenAcceleration",
            DriftSignal::ProgressStall           => "ProgressStall",
            DriftSignal::SelfContradiction       => "SelfContradiction",
        }
    }
}

/// Payload returned by `DriftDetector::check`. The caller wraps this in
/// `Event::DriftAlert` and pushes it onto the filter pipeline like any other alert.
#[derive(Debug, Clone)]
pub struct DriftAlertPayload {
    pub signal: DriftSignal,
    pub details: String,
    pub session_id: uuid::Uuid,
}

/// Tunables. All have sensible defaults; override via `[drift]` in vigil.toml.
#[derive(Debug, Clone)]
pub struct DriftConfig {
    /// How many of the first LlmResponse events form the baseline average.
    pub baseline_turns: usize,
    /// Sliding window of recent output_tokens used to compute the rolling average.
    pub window_turns: usize,
    /// Multiplier on the baseline that the window average must exceed to fire.
    pub acceleration_multiplier: f64,
    /// Output_tokens floor; stops a 50-token baseline from making any 150-token answer "drift".
    pub acceleration_min_tokens: u32,
    /// Consecutive LlmRequests without an FsWrite or novel FsRead before ProgressStall fires.
    pub stall_threshold: usize,
    /// Events to suppress the same signal after it fires once.
    pub debounce_events: u32,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            baseline_turns: 5,
            window_turns: 5,
            acceleration_multiplier: 3.0,
            acceleration_min_tokens: 200,
            stall_threshold: 5,
            debounce_events: 25,
        }
    }
}

pub struct DriftDetector {
    cfg: DriftConfig,

    // OutputTokenAcceleration
    baseline: Vec<u32>,
    recent_outputs: VecDeque<u32>,

    // ProgressStall
    consecutive_requests: usize,
    seen_paths: HashSet<String>,

    // SelfContradiction
    used_tools: HashSet<String>,
    written_paths: HashSet<String>,

    // Debounce
    debounce_accel: u32,
    debounce_stall: u32,
    debounce_contra: u32,
}

impl DriftDetector {
    pub fn new() -> Self {
        Self::with_config(DriftConfig::default())
    }

    pub fn with_config(cfg: DriftConfig) -> Self {
        Self {
            recent_outputs: VecDeque::with_capacity(cfg.window_turns),
            baseline: Vec::with_capacity(cfg.baseline_turns),
            cfg,
            consecutive_requests: 0,
            seen_paths: HashSet::new(),
            used_tools: HashSet::new(),
            written_paths: HashSet::new(),
            debounce_accel: 0,
            debounce_stall: 0,
            debounce_contra: 0,
        }
    }

    /// Inspect one event. Returns `Some(payload)` when a drift signal fires (after debounce).
    pub fn check(&mut self, event: &Event) -> Option<DriftAlertPayload> {
        self.tick_debounce();

        match event {
            Event::LlmRequest { session_id, .. } => {
                self.consecutive_requests = self.consecutive_requests.saturating_add(1);
                if self.consecutive_requests >= self.cfg.stall_threshold && self.debounce_stall == 0 {
                    let n = self.consecutive_requests;
                    self.debounce_stall = self.cfg.debounce_events;
                    self.consecutive_requests = 0;
                    return Some(DriftAlertPayload {
                        signal: DriftSignal::ProgressStall,
                        details: format!(
                            "{} consecutive LlmRequests with no FsWrite and no novel FsRead",
                            n
                        ),
                        session_id: *session_id,
                    });
                }
                None
            }

            Event::LlmResponse { output_tokens, response_text, session_id, .. } => {
                // Self-contradiction checked first (uses existing state, not token counts)
                if let Some(text) = response_text {
                    if self.debounce_contra == 0 {
                        if let Some(reason) = self.detect_contradiction(text) {
                            self.debounce_contra = self.cfg.debounce_events;
                            return Some(DriftAlertPayload {
                                signal: DriftSignal::SelfContradiction,
                                details: reason,
                                session_id: *session_id,
                            });
                        }
                    }
                }

                // Accumulate baseline and rolling window
                if self.baseline.len() < self.cfg.baseline_turns {
                    self.baseline.push(*output_tokens);
                }
                if self.recent_outputs.len() == self.cfg.window_turns {
                    self.recent_outputs.pop_front();
                }
                self.recent_outputs.push_back(*output_tokens);

                if self.baseline.len() == self.cfg.baseline_turns
                    && self.recent_outputs.len() == self.cfg.window_turns
                    && self.debounce_accel == 0
                {
                    let baseline_avg = self.baseline.iter().copied().map(f64::from).sum::<f64>()
                        / self.baseline.len() as f64;
                    let window_avg = self.recent_outputs.iter().copied().map(f64::from).sum::<f64>()
                        / self.recent_outputs.len() as f64;

                    if window_avg >= self.cfg.acceleration_min_tokens as f64
                        && baseline_avg > 0.0
                        && window_avg / baseline_avg >= self.cfg.acceleration_multiplier
                    {
                        self.debounce_accel = self.cfg.debounce_events;
                        return Some(DriftAlertPayload {
                            signal: DriftSignal::OutputTokenAcceleration,
                            details: format!(
                                "rolling avg {:.0} tok over last {} turns is {:.1}x baseline {:.0}",
                                window_avg,
                                self.cfg.window_turns,
                                window_avg / baseline_avg,
                                baseline_avg,
                            ),
                            session_id: *session_id,
                        });
                    }
                }
                None
            }

            Event::ToolCall { tool_name, .. } => {
                self.used_tools.insert(tool_name.to_lowercase());
                None
            }

            Event::FsRead { path, .. } => {
                if self.seen_paths.insert(path.clone()) {
                    self.consecutive_requests = 0;
                }
                None
            }

            Event::FsWrite { path, .. } => {
                self.written_paths.insert(path.clone());
                self.seen_paths.insert(path.clone());
                self.consecutive_requests = 0;
                None
            }

            _ => None,
        }
    }

    fn tick_debounce(&mut self) {
        self.debounce_accel = self.debounce_accel.saturating_sub(1);
        self.debounce_stall = self.debounce_stall.saturating_sub(1);
        self.debounce_contra = self.debounce_contra.saturating_sub(1);
    }

    const NEGATIONS: &'static [&'static str] = &[
        "i haven't",
        "i have not",
        "i didn't",
        "i did not",
        "i never",
        "there are no",
        "there is no",
        "no such file",
        "does not exist",
        "doesn't exist",
    ];

    fn detect_contradiction(&self, response_text: &str) -> Option<String> {
        // Cap at 64 KiB to prevent O(n) allocation on runaway model output.
        let text = if response_text.len() > 65_536 {
            &response_text[..65_536]
        } else {
            response_text
        };
        let lower = text.to_lowercase();
        if !Self::NEGATIONS.iter().any(|p| lower.contains(p)) {
            return None;
        }

        // Split on ". " (period + space), "!", "?", and newlines to avoid splitting
        // file extensions like "drift.rs" at the dot.
        let sentences: Vec<&str> = lower
            .split(|c: char| c == '!' || c == '?' || c == '\n')
            .flat_map(|s| s.split(". "))
            .collect();
        for sentence in sentences {
            let sentence = sentence.trim();
            if sentence.is_empty() {
                continue;
            }
            if !Self::NEGATIONS.iter().any(|p| sentence.contains(p)) {
                continue;
            }

            for path in &self.written_paths {
                let basename = std::path::Path::new(path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(path)
                    .to_lowercase();
                if basename.len() >= 4 && sentence.contains(&basename) {
                    return Some(format!(
                        "response negates existence near `{}`, but session wrote {}",
                        basename, path
                    ));
                }
            }

            // Whole-word match for tool names to avoid short common-word false positives.
            for tool in &self.used_tools {
                if tool.len() >= 5 && Self::word_in_sentence(tool, sentence) {
                    return Some(format!(
                        "response negates use of `{}`, but session has invoked it",
                        tool
                    ));
                }
            }
        }
        None
    }

    /// Returns true if `word` appears as a whole word (surrounded by non-alphanumeric
    /// characters or at string boundaries) in `sentence`.
    fn word_in_sentence(word: &str, sentence: &str) -> bool {
        if word.is_empty() {
            return false;
        }
        let mut start = 0;
        while let Some(pos) = sentence[start..].find(word) {
            let abs = start + pos;
            let before_ok = abs == 0
                || !sentence.as_bytes()[abs - 1].is_ascii_alphanumeric();
            let after_ok = abs + word.len() >= sentence.len()
                || !sentence.as_bytes()[abs + word.len()].is_ascii_alphanumeric();
            if before_ok && after_ok {
                return true;
            }
            start = abs + word.len(); // skip past the match to avoid O(n²) re-scanning
        }
        false
    }
}

impl Default for DriftDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn req(sid: Uuid) -> Event {
        Event::LlmRequest {
            provider: "anthropic".into(),
            model: "claude".into(),
            input_tokens: 100,
            session_id: sid,
            last_user_message: None,
            system_prompt: None,
            raw_request: None,
            turn_number: 0,
        }
    }

    fn resp(sid: Uuid, out: u32, text: Option<String>) -> Event {
        Event::LlmResponse {
            provider: "anthropic".into(),
            model: "claude".into(),
            input_tokens: 100,
            output_tokens: out,
            cost_usd: 0.01,
            session_id: sid,
            response_text: text,
            cache_read_input_tokens: 0,
            cache_creation_input_tokens: 0,
            raw_response: None,
            stop_reason: None,
        }
    }

    #[test]
    fn output_acceleration_fires_after_baseline_then_runaway() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::new();
        for _ in 0..5 {
            assert!(d.check(&resp(sid, 200, None)).is_none());
        }
        let mut alert = None;
        for _ in 0..5 {
            if let Some(a) = d.check(&resp(sid, 800, None)) {
                alert = Some(a);
            }
        }
        let a = alert.expect("acceleration must fire");
        assert_eq!(a.signal, DriftSignal::OutputTokenAcceleration);
    }

    #[test]
    fn output_acceleration_does_not_fire_on_low_token_baseline() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::new();
        for _ in 0..5 { d.check(&resp(sid, 10, None)); }
        for _ in 0..5 {
            assert!(
                d.check(&resp(sid, 100, None)).is_none(),
                "low-token responses must not trigger acceleration"
            );
        }
    }

    #[test]
    fn progress_stall_fires_on_consecutive_requests() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::new();
        for _ in 0..4 {
            assert!(d.check(&req(sid)).is_none());
        }
        let alert = d.check(&req(sid)).expect("stall must fire on the 5th request");
        assert_eq!(alert.signal, DriftSignal::ProgressStall);
    }

    #[test]
    fn novel_fs_read_resets_stall() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::new();
        for _ in 0..4 { d.check(&req(sid)); }
        d.check(&Event::FsRead { path: "src/main.rs".into(), session_id: sid });
        assert!(d.check(&req(sid)).is_none(), "novel FsRead resets the stall counter");
    }

    #[test]
    fn re_read_does_not_reset_stall() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::new();
        d.check(&Event::FsRead { path: "src/main.rs".into(), session_id: sid });
        for _ in 0..4 { d.check(&req(sid)); }
        d.check(&Event::FsRead { path: "src/main.rs".into(), session_id: sid });
        let alert = d.check(&req(sid)).expect("stall must still fire after re-read");
        assert_eq!(alert.signal, DriftSignal::ProgressStall);
    }

    #[test]
    fn fs_write_resets_stall() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::new();
        for _ in 0..4 { d.check(&req(sid)); }
        d.check(&Event::FsWrite { path: "src/x.rs".into(), bytes: 10, session_id: sid, lines_added: 0, lines_removed: 0, hunk_count: 0 });
        assert!(d.check(&req(sid)).is_none());
    }

    #[test]
    fn self_contradiction_fires_on_negated_written_path() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::new();
        d.check(&Event::FsWrite { path: "src/drift.rs".into(), bytes: 10, session_id: sid, lines_added: 0, lines_removed: 0, hunk_count: 0 });
        let text = "I haven't created drift.rs yet, would you like me to?".to_string();
        let alert = d.check(&resp(sid, 50, Some(text))).expect("contradiction must fire");
        assert_eq!(alert.signal, DriftSignal::SelfContradiction);
    }

    #[test]
    fn self_contradiction_no_false_positive_on_unrelated_negation() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::new();
        d.check(&Event::FsWrite { path: "src/drift.rs".into(), bytes: 10, session_id: sid, lines_added: 0, lines_removed: 0, hunk_count: 0 });
        let text = "I haven't tested edge cases yet.".to_string();
        assert!(d.check(&resp(sid, 50, Some(text))).is_none());
    }

    #[test]
    fn debounce_suppresses_repeat_stall() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::with_config(DriftConfig {
            stall_threshold: 3,
            debounce_events: 10,
            ..DriftConfig::default()
        });
        for _ in 0..3 { d.check(&req(sid)); }
        for _ in 0..3 {
            assert!(d.check(&req(sid)).is_none(), "second stall within debounce window must be suppressed");
        }
    }

    #[test]
    fn tool_call_event_recorded_for_contradiction() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::new();
        d.check(&Event::ToolCall {
            agent: "claude".into(),
            tool_name: "WebFetch".into(),
            input: json!({}),
            session_id: sid,
            tool_use_id: None,
            correlation_id: None,
        });
        let text = "I never used WebFetch in this session.".to_string();
        let alert = d.check(&resp(sid, 50, Some(text))).expect("must fire on tool contradiction");
        assert_eq!(alert.signal, DriftSignal::SelfContradiction);
    }

    // -------------------------------------------------------------------------
    // New smoke tests
    // -------------------------------------------------------------------------

    /// After acceleration fires and the debounce window expires (debounce_events=3),
    /// a second acceleration episode must fire again.
    #[test]
    fn acceleration_debounce_resets_after_window() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::with_config(DriftConfig {
            baseline_turns: 2,
            window_turns: 2,
            acceleration_multiplier: 3.0,
            acceleration_min_tokens: 200,
            stall_threshold: 5,
            debounce_events: 3,
        });

        // Establish baseline: 2 low-token responses. After these, window=[50,50].
        d.check(&resp(sid, 50, None));
        d.check(&resp(sid, 50, None));

        // First high-token response: window becomes [50, 500], avg=275, 5.5x baseline.
        // Both window and baseline are full — fires immediately.
        let first = d.check(&resp(sid, 500, None));
        assert!(
            first.is_some(),
            "first acceleration episode must fire"
        );
        assert_eq!(first.unwrap().signal, DriftSignal::OutputTokenAcceleration);

        // tick_debounce runs before the check on every event, so with debounce_events=3
        // the sequence is: debounce 3→2 (suppressed), 2→1 (suppressed), 1→0 (fires).
        // Two suppressed events, then re-fire on the third.
        d.check(&resp(sid, 500, None)); // debounce 3→2, suppressed
        d.check(&resp(sid, 500, None)); // debounce 2→1, suppressed
        let second = d.check(&resp(sid, 500, None)); // debounce 1→0, fires
        assert!(
            second.is_some(),
            "acceleration must re-fire after debounce window expires"
        );
        assert_eq!(second.unwrap().signal, DriftSignal::OutputTokenAcceleration);
    }

    /// Stall fires, then an FsWrite resets consecutive_requests,
    /// then enough LlmRequests re-fire the stall.
    #[test]
    fn stall_resets_after_novel_write_then_reaccumulates() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::with_config(DriftConfig {
            stall_threshold: 3,
            debounce_events: 1,
            ..DriftConfig::default()
        });

        // First stall: 3 consecutive requests.
        d.check(&req(sid));
        d.check(&req(sid));
        let first = d.check(&req(sid));
        assert!(first.is_some(), "first stall must fire");
        assert_eq!(first.unwrap().signal, DriftSignal::ProgressStall);

        // FsWrite resets the counter (debounce tick happens inside each check call,
        // so after 1 event the stall debounce is back to 0).
        d.check(&Event::FsWrite { path: "src/new.rs".into(), bytes: 100, session_id: sid, lines_added: 0, lines_removed: 0, hunk_count: 0 });

        // Re-accumulate: 3 more consecutive requests should re-fire the stall.
        d.check(&req(sid));
        d.check(&req(sid));
        let second = d.check(&req(sid));
        assert!(second.is_some(), "stall must re-fire after FsWrite reset");
        assert_eq!(second.unwrap().signal, DriftSignal::ProgressStall);
    }

    /// Even with a strong negation phrase in the response text, no alert should
    /// fire when no paths have been written and no tools have been used.
    #[test]
    fn no_contradiction_without_written_paths() {
        let sid = Uuid::new_v4();
        let mut d = DriftDetector::new();
        // No FsWrite or ToolCall — written_paths and used_tools are both empty.
        let text = "I haven't created main.rs, there is no such file, I never wrote it.".to_string();
        let alert = d.check(&resp(sid, 50, Some(text)));
        assert!(
            alert.is_none(),
            "no contradiction alert without any written paths or used tools"
        );
    }
}

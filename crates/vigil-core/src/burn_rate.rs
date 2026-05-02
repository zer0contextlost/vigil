use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::Instant;

pub struct BurnRateTracker {
    /// Sliding window: (instant, cost_usd) — entries older than window_secs are dropped
    window: VecDeque<(Instant, f64)>,
    window_secs: f64,
    session_start: Instant,
    session_cost: f64,
}

impl BurnRateTracker {
    pub fn new() -> Self {
        Self {
            window: VecDeque::new(),
            window_secs: 120.0, // 2-minute sliding window
            session_start: Instant::now(),
            session_cost: 0.0,
        }
    }

    /// Record a new cost event. Returns (rate_per_min, projected_total).
    pub fn record(&mut self, cost: f64) -> (f64, f64) {
        let now = Instant::now();
        self.session_cost += cost;
        self.window.push_back((now, cost));

        // Drop entries outside the window
        let cutoff = self.window_secs;
        while let Some(&(ts, _)) = self.window.front() {
            if now.duration_since(ts).as_secs_f64() > cutoff {
                self.window.pop_front();
            } else {
                break;
            }
        }

        (self.rate_per_min(), self.projected_total())
    }

    pub fn rate_per_min(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let window_cost: f64 = self.window.iter().map(|(_, c)| c).sum();
        // With a single data point use time since session start so the very first
        // expensive call can still trigger a burn-rate alert.
        let elapsed = if self.window.len() == 1 {
            self.session_start.elapsed().as_secs_f64()
        } else {
            self.window.back().unwrap().0
                .duration_since(self.window.front().unwrap().0)
                .as_secs_f64()
        };
        if elapsed < 1.0 {
            return 0.0;
        }
        window_cost / elapsed * 60.0
    }

    pub fn projected_total(&self) -> f64 {
        let rate = self.rate_per_min();
        if rate == 0.0 {
            return self.session_cost;
        }
        let elapsed_mins = self.session_start.elapsed().as_secs_f64() / 60.0;
        // naive projection: assume rate stays constant for another elapsed_mins
        self.session_cost + rate * elapsed_mins
    }
}

pub struct LoopDetector {
    counts: HashMap<(String, u64), u32>,
    threshold: u32,
}

impl LoopDetector {
    pub fn new(threshold: u32) -> Self {
        Self {
            counts: HashMap::new(),
            threshold,
        }
    }

    /// Returns the repeat count if this tool+input_hash has hit the threshold,
    /// None otherwise. Uses a simple hash of the input string.
    pub fn check(&mut self, tool_name: &str, input: &str) -> Option<u32> {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let mut h = DefaultHasher::new();
        input.hash(&mut h);
        let key = (tool_name.to_string(), h.finish());
        let count = self.counts.entry(key).or_insert(0);
        *count += 1;
        if *count >= self.threshold {
            Some(*count)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_burn_rate_single_point_returns_sane_values() {
        // rate_per_min() returns 0 when elapsed < 1s (intentional guard to avoid
        // garbage rates in the opening burst). projected_total should still return
        // at least the accumulated session cost.
        let mut tracker = BurnRateTracker::new();
        let (rate, projected) = tracker.record(1.0);
        assert!(rate >= 0.0, "rate must be >= 0, got {}", rate);
        assert!(projected >= 1.0, "projected must be >= session_cost (1.0), got {}", projected);
    }

    #[test]
    fn test_burn_rate_accumulates_cost() {
        let mut tracker = BurnRateTracker::new();
        tracker.record(0.25);
        tracker.record(0.25);
        let (_, projected) = tracker.record(0.50);
        // session_cost == 1.0; projected >= session_cost always
        assert!(projected >= 1.0, "projected must be >= accumulated cost 1.0, got {}", projected);
    }

    #[test]
    fn test_burn_rate_empty_is_zero() {
        let tracker = BurnRateTracker::new();
        assert_eq!(tracker.rate_per_min(), 0.0);
    }

    #[test]
    fn test_projected_total_with_no_data_returns_session_cost() {
        let mut tracker = BurnRateTracker::new();
        let (_, projected) = tracker.record(0.5);
        assert!(projected >= 0.5);
    }

    #[test]
    fn test_loop_detector_fires_at_threshold() {
        let mut det = LoopDetector::new(3);
        assert!(det.check("bash", "ls -la").is_none());
        assert!(det.check("bash", "ls -la").is_none());
        let hit = det.check("bash", "ls -la");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap(), 3);
    }

    #[test]
    fn test_loop_detector_different_inputs_no_false_positive() {
        let mut det = LoopDetector::new(2);
        assert!(det.check("bash", "ls").is_none());
        assert!(det.check("bash", "pwd").is_none()); // different input, no hit
        assert!(det.check("read", "ls").is_none());  // different tool
    }
}

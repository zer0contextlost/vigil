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

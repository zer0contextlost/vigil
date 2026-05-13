use chrono::{Local, Timelike};
use crate::config::BudgetSection;

#[derive(Debug, Clone, PartialEq)]
pub enum BudgetStatus {
    Ok,
    CostExceeded { limit: f64, actual: f64 },
    TokensExceeded { limit: u32, actual: u32 },
    OutsideAllowedHours { window: String },
}

pub struct BudgetEnforcer {
    budget: BudgetSection,
}

impl BudgetEnforcer {
    pub fn new(budget: BudgetSection) -> Self {
        Self { budget }
    }

    pub fn check(&self, total_cost_usd: f64, total_tokens: u32) -> BudgetStatus {
        if let Some(window) = &self.budget.allowed_hours {
            if !self.is_in_allowed_hours(window) {
                return BudgetStatus::OutsideAllowedHours { window: window.clone() };
            }
        }
        if let Some(max_cost) = self.budget.max_cost_usd {
            if total_cost_usd > max_cost {
                return BudgetStatus::CostExceeded { limit: max_cost, actual: total_cost_usd };
            }
        }
        if let Some(max_tok) = self.budget.max_tokens {
            if total_tokens > max_tok {
                return BudgetStatus::TokensExceeded { limit: max_tok, actual: total_tokens };
            }
        }
        BudgetStatus::Ok
    }

    fn is_in_allowed_hours(&self, window: &str) -> bool {
        let parts: Vec<&str> = window.split('-').collect();
        if parts.len() != 2 {
            return true;
        }
        let now = Local::now();
        let current_minutes = now.hour() * 60 + now.minute();

        let parse_hhmm = |s: &str| -> Option<u32> {
            let p: Vec<&str> = s.split(':').collect();
            if p.len() != 2 {
                return None;
            }
            let h: u32 = p[0].parse().ok()?;
            let m: u32 = p[1].parse().ok()?;
            Some(h * 60 + m)
        };

        let start = match parse_hhmm(parts[0]) {
            Some(v) => v,
            None => return true,
        };
        let end = match parse_hhmm(parts[1]) {
            Some(v) => v,
            None => return true,
        };

        if start <= end {
            current_minutes >= start && current_minutes <= end
        } else {
            current_minutes >= start || current_minutes <= end
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(max_cost: Option<f64>, max_tokens: Option<u32>) -> BudgetEnforcer {
        BudgetEnforcer::new(BudgetSection {
            max_cost_usd: max_cost,
            max_tokens: max_tokens,
            ..Default::default()
        })
    }

    #[test]
    fn test_ok_when_no_limits() {
        let e = budget(None, None);
        assert_eq!(e.check(999.0, 999_999), BudgetStatus::Ok);
    }

    #[test]
    fn test_cost_exceeded() {
        let e = budget(Some(5.0), None);
        assert_eq!(
            e.check(5.01, 0),
            BudgetStatus::CostExceeded { limit: 5.0, actual: 5.01 }
        );
    }

    #[test]
    fn test_cost_at_limit_is_ok() {
        let e = budget(Some(5.0), None);
        assert_eq!(e.check(5.0, 0), BudgetStatus::Ok);
    }

    #[test]
    fn test_tokens_exceeded() {
        let e = budget(None, Some(1000));
        assert_eq!(
            e.check(0.0, 1001),
            BudgetStatus::TokensExceeded { limit: 1000, actual: 1001 }
        );
    }

    #[test]
    fn test_tokens_at_limit_is_ok() {
        let e = budget(None, Some(1000));
        assert_eq!(e.check(0.0, 1000), BudgetStatus::Ok);
    }

    #[test]
    fn test_cost_checked_before_tokens() {
        let e = budget(Some(1.0), Some(100));
        // Both limits exceeded — cost fires first
        assert_eq!(
            e.check(2.0, 200),
            BudgetStatus::CostExceeded { limit: 1.0, actual: 2.0 }
        );
    }

    #[test]
    fn test_malformed_allowed_hours_passes() {
        let mut e = BudgetEnforcer::new(BudgetSection {
            allowed_hours: Some("bad-format".to_string()),
            ..Default::default()
        });
        // Malformed window → allow always
        assert_eq!(e.check(0.0, 0), BudgetStatus::Ok);
        // Restore fields to avoid unused-mut warning
        e.budget.allowed_hours = None;
        assert_eq!(e.check(0.0, 0), BudgetStatus::Ok);
    }

    #[test]
    fn test_always_allowed_window() {
        // "00:00-23:59" spans the entire day — should always be in window
        let e = BudgetEnforcer::new(BudgetSection {
            allowed_hours: Some("00:00-23:59".to_string()),
            max_cost_usd: None,
            max_tokens: None,
            ..Default::default()
        });
        assert_eq!(e.check(0.0, 0), BudgetStatus::Ok);
    }
}

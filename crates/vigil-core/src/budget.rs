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
            current_minutes >= start && current_minutes < end
        } else {
            current_minutes >= start || current_minutes < end
        }
    }
}

use std::sync::OnceLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricing {
    pub pattern: String,
    pub input_per_million: f64,
    pub output_per_million: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PricingTable {
    #[serde(rename = "model")]
    pub models: Vec<ModelPricing>,
}

impl PricingTable {
    /// Returns (input_per_million, output_per_million) for a model string.
    /// Tries each entry's pattern as a case-insensitive substring match.
    /// Falls back to (3.0, 15.0) if nothing matches.
    pub fn lookup(&self, model: &str) -> (f64, f64) {
        let m = model.to_lowercase();
        for entry in &self.models {
            if m.contains(&entry.pattern.to_lowercase()) {
                return (entry.input_per_million, entry.output_per_million);
            }
        }
        (3.0, 15.0)
    }

    /// Load from ~/.vigil/pricing.toml. On any error (missing, parse fail),
    /// returns PricingTable with built-in default entries.
    pub fn load() -> Self {
        let path = {
            let home = if cfg!(target_os = "windows") {
                std::env::var("USERPROFILE").ok()
            } else {
                std::env::var("HOME").ok()
            };
            home.map(|h| std::path::PathBuf::from(h).join(".vigil").join("pricing.toml"))
        };

        if let Some(p) = path {
            if let Ok(content) = std::fs::read_to_string(&p) {
                if let Ok(table) = toml::from_str::<PricingTable>(&content) {
                    return table;
                }
            }
        }

        Self::defaults()
    }

    /// Built-in default pricing (matches the hardcoded values in provider.rs).
    pub fn defaults() -> Self {
        Self {
            models: vec![
                ModelPricing { pattern: "claude-opus-4-7".into(), input_per_million: 15.0, output_per_million: 75.0 },
                ModelPricing { pattern: "claude-opus-4".into(), input_per_million: 15.0, output_per_million: 75.0 },
                ModelPricing { pattern: "claude-sonnet-4".into(), input_per_million: 3.0, output_per_million: 15.0 },
                ModelPricing { pattern: "claude-3-5-sonnet".into(), input_per_million: 3.0, output_per_million: 15.0 },
                ModelPricing { pattern: "claude-haiku-4".into(), input_per_million: 0.80, output_per_million: 4.0 },
                ModelPricing { pattern: "claude-3-7-haiku".into(), input_per_million: 0.80, output_per_million: 4.0 },
                ModelPricing { pattern: "gemini-3.1-pro".into(),      input_per_million: 2.0,  output_per_million: 12.0 },
                ModelPricing { pattern: "gemini-3-flash".into(),       input_per_million: 0.5,  output_per_million: 3.0  },
                ModelPricing { pattern: "gemini-2.5-flash-lite".into(),input_per_million: 0.10, output_per_million: 0.40 },
                ModelPricing { pattern: "gemini-2.5-flash".into(),     input_per_million: 0.30, output_per_million: 2.50 },
                ModelPricing { pattern: "gpt-4o-mini".into(), input_per_million: 0.15, output_per_million: 0.60 },
                ModelPricing { pattern: "gpt-4o".into(), input_per_million: 2.50, output_per_million: 10.0 },
                ModelPricing { pattern: "o3".into(), input_per_million: 10.0, output_per_million: 40.0 },
                ModelPricing { pattern: "o4".into(), input_per_million: 10.0, output_per_million: 40.0 },
            ],
        }
    }

    /// Process-global singleton — loaded once, reused everywhere.
    pub fn global() -> &'static PricingTable {
        static INSTANCE: OnceLock<PricingTable> = OnceLock::new();
        INSTANCE.get_or_init(Self::load)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gemini_pricing_lookup() {
        let t = PricingTable::defaults();
        assert_eq!(t.lookup("gemini-3.1-pro"),       (2.0,  12.0));
        assert_eq!(t.lookup("gemini-3-flash"),        (0.5,  3.0 ));
        assert_eq!(t.lookup("gemini-2.5-flash-lite"), (0.10, 0.40));
        assert_eq!(t.lookup("gemini-2.5-flash"),      (0.30, 2.50));
    }

    #[test]
    fn test_gemini_flash_lite_does_not_match_flash() {
        // gemini-2.5-flash-lite must NOT match the gemini-2.5-flash entry
        let t = PricingTable::defaults();
        let (input, _) = t.lookup("gemini-2.5-flash-lite");
        assert_eq!(input, 0.10, "flash-lite matched flash entry — ordering is wrong");
    }
}

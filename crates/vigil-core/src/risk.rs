/// Severity level returned by the risk scorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

pub struct RiskScore {
    pub level: RiskLevel,
    pub reasons: Vec<String>,
}

/// Crown jewels: paths whose substring matches these patterns are High risk.
const CROWN_JEWELS: &[&str] = &[
    ".env", "secret", "credential", "password", "auth", "migration",
    "payment", "billing", "private_key", "id_rsa", "id_ed25519",
];

pub fn score_write(path: &str, before: &str, after: &str) -> RiskScore {
    let mut reasons: Vec<String> = Vec::new();
    let mut level = RiskLevel::Low;

    // Crown jewels path check
    let path_lower = path.to_lowercase();
    for pattern in CROWN_JEWELS {
        if path_lower.contains(pattern) {
            reasons.push(format!("path matches crown jewels pattern '{}'", pattern));
            level = level.max(RiskLevel::High);
            break;
        }
    }

    // Compute line-level diff stats
    let before_lines: Vec<&str> = before.lines().collect();
    let after_lines: Vec<&str> = after.lines().collect();

    let deleted = before_lines.iter().filter(|l| !after_lines.contains(l)).count();
    let added = after_lines.iter().filter(|l| !before_lines.contains(l)).count();
    let total_before = before_lines.len().max(1);

    // More than 40% of lines deleted → High
    if deleted > 0 && deleted * 100 / total_before > 40 {
        reasons.push(format!("{}% of lines deleted ({} of {})", deleted * 100 / total_before, deleted, total_before));
        level = level.max(RiskLevel::High);
    } else if deleted > 10 {
        reasons.push(format!("{} lines deleted", deleted));
        level = level.max(RiskLevel::Medium);
    }

    // New file (before is empty, after is non-empty) → Low unless crown jewels
    if before.is_empty() && !after.is_empty() {
        reasons.push("new file".to_string());
        // don't upgrade level — new files are usually fine
    }

    // Large file (>500 lines after) → Medium unless already higher
    if after_lines.len() > 500 {
        reasons.push(format!("large file ({} lines)", after_lines.len()));
        level = level.max(RiskLevel::Medium);
    }

    if reasons.is_empty() {
        reasons.push(format!("{} lines added, {} deleted", added, deleted));
    }

    RiskScore { level, reasons }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crown_jewels_path() {
        let score = score_write(".env", "", "SECRET=abc");
        assert_eq!(score.level, RiskLevel::High);
        assert!(score.reasons.iter().any(|r| r.contains("crown jewels")));
    }

    #[test]
    fn test_new_file_is_low() {
        let score = score_write("src/main.rs", "", "fn main() {}");
        assert_eq!(score.level, RiskLevel::Low);
        assert!(score.reasons.iter().any(|r| r.contains("new file")));
    }

    #[test]
    fn test_high_deletion_ratio() {
        let before: String = (0..10).map(|i| format!("line{}\n", i)).collect();
        let after = "line0\n";
        let score = score_write("src/lib.rs", &before, after);
        assert_eq!(score.level, RiskLevel::High);
    }

    #[test]
    fn test_medium_deletion_count() {
        // 30 unique lines before; keep 18, delete 12 (40% exactly is NOT > 40%, so Medium not High)
        // 12 / 30 * 100 = 40, which is NOT > 40, so we get Medium from the deleted > 10 branch.
        let before: String = (0..30).map(|i| format!("unique_line_{}\n", i)).collect();
        let after: String = (0..18).map(|i| format!("unique_line_{}\n", i)).collect();
        let score = score_write("src/lib.rs", &before, &after);
        assert_eq!(score.level, RiskLevel::Medium);
    }

    #[test]
    fn test_large_file_medium() {
        let after: String = (0..501).map(|i| format!("line{}\n", i)).collect();
        let score = score_write("src/big.rs", "", &after);
        // new file + large → Medium (crown jewels check would override to High)
        assert!(score.level >= RiskLevel::Medium);
    }

    #[test]
    fn test_ord_risk_level() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert_eq!(RiskLevel::Low.max(RiskLevel::High), RiskLevel::High);
    }
}

use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct PiiMatch {
    pub kind: String,
    pub snippet: String,
}

struct Patterns {
    email: Regex,
    phone_us: Regex,
    ssn: Regex,
    credit_card: Regex,
    aws_key: Regex,
    github_pat: Regex,
    jwt: Regex,
    ipv4: Regex,
    url_with_id: Regex,
}

static PATTERNS: OnceLock<Patterns> = OnceLock::new();

fn patterns() -> &'static Patterns {
    PATTERNS.get_or_init(|| Patterns {
        email: Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap(),
        phone_us: Regex::new(
            r"\b(?:\+?1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]?[2-9]\d{2}[\s.\-]?\d{4}\b",
        )
        .unwrap(),
        ssn: Regex::new(r"\b(\d{3})[\s\-]?(\d{2})[\s\-]?(\d{4})\b").unwrap(),
        // Raw digit runs 13-19 long; we Luhn-validate before reporting
        credit_card: Regex::new(r"\b\d{13,19}\b").unwrap(),
        aws_key: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
        github_pat: Regex::new(r"\bghp_[A-Za-z0-9]{36}\b").unwrap(),
        jwt: Regex::new(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b").unwrap(),
        ipv4: Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        )
        .unwrap(),
        url_with_id: Regex::new(
            r"https?://[^\s]*(?:email|user(?:id|name|_id)?|account|ssn|phone|token|api[_\-]?key)=[^&\s]+",
        )
        .unwrap(),
    })
}

fn ssn_valid(area: &str, group: &str, serial: &str) -> bool {
    area != "000" && area != "666" && !area.starts_with('9')
        && group != "00"
        && serial != "0000"
}

/// Luhn algorithm — returns true for valid card numbers.
fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for ch in digits.chars().rev() {
        let Some(d) = ch.to_digit(10) else { return false };
        let d = if double {
            let v = d * 2;
            if v > 9 { v - 9 } else { v }
        } else {
            d
        };
        sum += d;
        double = !double;
    }
    sum % 10 == 0
}

fn redact(s: &str, keep: usize) -> String {
    let len = s.chars().count();
    if len <= keep {
        return "***".to_string();
    }
    let tail: String = s.chars().rev().take(keep).collect::<Vec<_>>().into_iter().rev().collect();
    format!("***{}", tail)
}

/// Scan `text` against a personal watchlist (literal case-insensitive substring match —
/// NOT regex; special characters in terms are treated as plain text).
/// Terms are things like your full name, address, phone number as you wrote it, etc.
pub fn scan_watchlist<'a>(text: &str, terms: &'a [String]) -> Vec<PiiMatch> {
    let lower = text.to_lowercase();
    terms
        .iter()
        .filter(|t| !t.trim().is_empty() && lower.contains(&t.to_lowercase()))
        .map(|_t| PiiMatch {
            kind: "watchlist".into(),
            // Never echo back any part of the watchlist term — it is user-supplied PII.
            snippet: "[watchlist term]".into(),
        })
        .collect()
}

/// Scan `text` for PII and return all matches found.
pub fn scan(text: &str) -> Vec<PiiMatch> {
    let p = patterns();
    let mut hits: Vec<PiiMatch> = Vec::new();

    for m in p.email.find_iter(text) {
        hits.push(PiiMatch { kind: "email".into(), snippet: redact(m.as_str(), 6) });
    }
    for m in p.phone_us.find_iter(text) {
        hits.push(PiiMatch { kind: "phone".into(), snippet: redact(m.as_str(), 4) });
    }
    for cap in p.ssn.captures_iter(text) {
        let (area, group, serial) = (&cap[1], &cap[2], &cap[3]);
        if ssn_valid(area, group, serial) {
            hits.push(PiiMatch { kind: "SSN".into(), snippet: "***-**-****".into() });
        }
    }
    for m in p.credit_card.find_iter(text) {
        let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
        if luhn_valid(&digits) {
            hits.push(PiiMatch { kind: "credit card".into(), snippet: redact(&digits, 4) });
        }
    }
    for m in p.aws_key.find_iter(text) {
        hits.push(PiiMatch { kind: "AWS key".into(), snippet: redact(m.as_str(), 4) });
    }
    for m in p.github_pat.find_iter(text) {
        hits.push(PiiMatch { kind: "GitHub PAT".into(), snippet: redact(m.as_str(), 4) });
    }
    for m in p.jwt.find_iter(text) {
        hits.push(PiiMatch { kind: "JWT".into(), snippet: redact(m.as_str(), 8) });
    }
    for m in p.ipv4.find_iter(text) {
        // Skip loopback/private ranges — those are expected in tool call payloads
        let s = m.as_str();
        if s.starts_with("127.") || s.starts_with("192.168.") || s.starts_with("10.") {
            continue;
        }
        hits.push(PiiMatch { kind: "IP address".into(), snippet: s.to_string() });
    }
    for m in p.url_with_id.find_iter(text) {
        hits.push(PiiMatch { kind: "URL+PII param".into(), snippet: redact(m.as_str(), 12) });
    }

    hits
}

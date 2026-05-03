use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct PiiMatch {
    pub kind: String,
    pub snippet: String,
}

struct Patterns {
    // Personal data
    email: Regex,
    phone_us: Regex,
    ssn: Regex,
    credit_card: Regex,
    ipv4: Regex,
    url_with_id: Regex,
    // Prefix-anchored secrets — high confidence, low false-positive rate
    secrets: Vec<(&'static str, Regex)>,
    // PEM private key header (multi-provider)
    pem_private_key: Regex,
}

static PATTERNS: OnceLock<Patterns> = OnceLock::new();

fn patterns() -> &'static Patterns {
    PATTERNS.get_or_init(|| {
        let secrets: Vec<(&'static str, Regex)> = vec![
            // Anthropic
            ("Anthropic API key",   Regex::new(r"sk-ant-api[0-9]+-[A-Za-z0-9_\-]{40,}").unwrap()),
            // OpenAI
            ("OpenAI API key",      Regex::new(r"\bsk-[A-Za-z0-9]{48}\b").unwrap()),
            ("OpenAI project key",  Regex::new(r"\bsk-proj-[A-Za-z0-9_\-]{40,}\b").unwrap()),
            // GitHub tokens
            ("GitHub PAT",          Regex::new(r"\bghp_[A-Za-z0-9]{36}\b").unwrap()),
            ("GitHub Actions token",Regex::new(r"\bghs_[A-Za-z0-9]{36}\b").unwrap()),
            ("GitHub OAuth token",  Regex::new(r"\bgho_[A-Za-z0-9]{36}\b").unwrap()),
            ("GitHub refresh token",Regex::new(r"\bghr_[A-Za-z0-9]{36}\b").unwrap()),
            // AWS
            ("AWS access key",      Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap()),
            ("AWS secret key hint", Regex::new(r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*\S{40}").unwrap()),
            // Google
            ("Google API key",      Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap()),
            ("Google OAuth token",  Regex::new(r"\bya29\.[0-9A-Za-z\-_]{60,}\b").unwrap()),
            // Stripe
            ("Stripe secret key",   Regex::new(r"\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b").unwrap()),
            ("Stripe publishable key", Regex::new(r"\bpk_(?:live|test)_[A-Za-z0-9]{24,}\b").unwrap()),
            ("Stripe restricted key", Regex::new(r"\brk_(?:live|test)_[A-Za-z0-9]{24,}\b").unwrap()),
            // Slack
            ("Slack bot token",     Regex::new(r"\bxoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+\b").unwrap()),
            ("Slack user token",    Regex::new(r"\bxoxp-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]+\b").unwrap()),
            ("Slack app token",     Regex::new(r"\bxapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]+\b").unwrap()),
            // npm
            ("npm token",           Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").unwrap()),
            // SendGrid
            ("SendGrid API key",    Regex::new(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b").unwrap()),
            // Mailgun
            ("Mailgun API key",     Regex::new(r"\bkey-[0-9a-zA-Z]{32}\b").unwrap()),
            // HuggingFace
            ("HuggingFace token",   Regex::new(r"\bhf_[A-Za-z0-9]{34,}\b").unwrap()),
            // Twilio
            ("Twilio account SID",  Regex::new(r"\bAC[a-f0-9]{32}\b").unwrap()),
            // Cloudflare
            ("Cloudflare API token", Regex::new(r"(?i)cloudflare[_-]?(?:api[_-]?)?token\s*[:=]\s*\S{40}").unwrap()),
            // Databricks / generic ML platform tokens
            ("Databricks token",    Regex::new(r"\bdapi[a-f0-9]{32}\b").unwrap()),
            // JWT
            ("JWT",                 Regex::new(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap()),
            // Generic: high-entropy value after common secret key names
            ("API secret",          Regex::new(r"(?i)(?:api[_-]?(?:key|secret|token)|auth[_-]?token|access[_-]?token|secret[_-]?key)\s*[:=]\s*\S{32,}").unwrap()),
        ];
        Patterns {
            email: Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap(),
            phone_us: Regex::new(
                r"\b(?:\+?1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]?[2-9]\d{2}[\s.\-]?\d{4}\b",
            ).unwrap(),
            ssn: Regex::new(r"\b(\d{3})[\s\-]?(\d{2})[\s\-]?(\d{4})\b").unwrap(),
            credit_card: Regex::new(r"\b\d{13,19}\b").unwrap(),
            ipv4: Regex::new(
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            ).unwrap(),
            url_with_id: Regex::new(
                r"https?://[^\s]*(?:email|user(?:id|name|_id)?|account|ssn|phone|token|api[_\-]?key)=[^&\s]+",
            ).unwrap(),
            pem_private_key: Regex::new(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            ).unwrap(),
            secrets,
        }
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

/// Scan `text` for PII and secrets. Returns all matches found.
pub fn scan(text: &str) -> Vec<PiiMatch> {
    let p = patterns();
    let mut hits: Vec<PiiMatch> = Vec::new();

    // Prefix-anchored secrets — check first so they shadow generic patterns below
    for (kind, re) in &p.secrets {
        for m in re.find_iter(text) {
            hits.push(PiiMatch { kind: kind.to_string(), snippet: redact(m.as_str(), 4) });
        }
    }

    // PEM private key (single match per occurrence, no body needed)
    for _ in p.pem_private_key.find_iter(text) {
        hits.push(PiiMatch { kind: "PEM private key".into(), snippet: "-----BEGIN ***".into() });
    }

    // Personal data
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
    for m in p.ipv4.find_iter(text) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watchlist_no_term_echo() {
        let terms = vec!["SuperSecret123".to_string()];
        let hits = scan_watchlist("I know SuperSecret123 exists", &terms);
        assert_eq!(hits.len(), 1);
        assert!(!hits[0].snippet.contains("SuperSecret"));
        assert!(!hits[0].snippet.contains("123"));
        assert_eq!(hits[0].snippet, "[watchlist term]");
    }

    #[test]
    fn test_watchlist_case_insensitive_match() {
        let terms = vec!["john doe".to_string()];
        let hits = scan_watchlist("Hello JOHN DOE please sign in", &terms);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_watchlist_no_match() {
        let terms = vec!["secret".to_string()];
        let hits = scan_watchlist("nothing interesting here", &terms);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_watchlist_empty_terms_ignored() {
        let terms = vec!["".to_string(), "  ".to_string()];
        let hits = scan_watchlist("anything", &terms);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_scan_email() {
        let hits = scan("send mail to user@example.com please");
        assert!(hits.iter().any(|h| h.kind == "email"));
        assert!(!hits.iter().any(|h| h.snippet.contains("user@example.com")));
    }

    #[test]
    fn test_scan_aws_key() {
        let hits = scan("key is AKIAIOSFODNN7EXAMPLE");
        assert!(hits.iter().any(|h| h.kind == "AWS access key"), "hits: {:?}", hits);
    }

    #[test]
    fn test_scan_github_pat() {
        let hits = scan("token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890");
        assert!(hits.iter().any(|h| h.kind == "GitHub PAT"), "hits: {:?}", hits);
    }

    #[test]
    fn test_scan_openai_key() {
        // Old OpenAI key format: sk- + 48 alphanumeric chars
        let hits = scan("my key is sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv");
        assert!(hits.iter().any(|h| h.kind == "OpenAI API key"), "hits: {:?}", hits);
    }

    #[test]
    fn test_scan_anthropic_key() {
        let hits = scan("export ANTHROPIC_API_KEY=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(hits.iter().any(|h| h.kind == "Anthropic API key"), "hits: {:?}", hits);
    }

    #[test]
    fn test_scan_stripe_key() {
        let input = format!("STRIPE_SECRET_KEY=sk_live_{}", "abcdefghijklmnopqrstuvwx");
        let hits = scan(&input);
        assert!(hits.iter().any(|h| h.kind == "Stripe secret key"), "hits: {:?}", hits);
    }

    #[test]
    fn test_scan_slack_token() {
        let input = format!("token: xoxb-{}-{}-{}", "123456789012", "123456789012", "abcdefghijklmnopqrstuvwx");
        let hits = scan(&input);
        assert!(hits.iter().any(|h| h.kind == "Slack bot token"), "hits: {:?}", hits);
    }

    #[test]
    fn test_scan_google_api_key() {
        let hits = scan("AIzaSyD-9tSrke72I6e0DVFGmN6Az_5eVjHaVkg");
        assert!(hits.iter().any(|h| h.kind == "Google API key"), "hits: {:?}", hits);
    }

    #[test]
    fn test_scan_pem_private_key() {
        let hits = scan("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA");
        assert!(hits.iter().any(|h| h.kind == "PEM private key"), "hits: {:?}", hits);
    }

    #[test]
    fn test_scan_huggingface_token() {
        let input = format!("HF_TOKEN=hf_{}", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh");
        let hits = scan(&input);
        assert!(hits.iter().any(|h| h.kind == "HuggingFace token"), "hits: {:?}", hits);
    }

    #[test]
    fn test_scan_no_false_positive_loopback() {
        let hits = scan("connecting to 127.0.0.1 and 192.168.1.1");
        assert!(!hits.iter().any(|h| h.kind == "IP address"));
    }

    #[test]
    fn test_scan_public_ip() {
        let hits = scan("server at 8.8.8.8 is up");
        assert!(hits.iter().any(|h| h.kind == "IP address"));
    }

    #[test]
    fn test_scan_sendgrid_key() {
        let hits = scan("SG.AAAAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        assert!(hits.iter().any(|h| h.kind == "SendGrid API key"), "hits: {:?}", hits);
    }

    #[test]
    fn test_scan_npm_token() {
        let hits = scan("//registry.npmjs.org/:_authToken=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assert!(hits.iter().any(|h| h.kind == "npm token"), "hits: {:?}", hits);
    }
}

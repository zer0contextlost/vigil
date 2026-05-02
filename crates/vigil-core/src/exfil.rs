use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::OnceLock;

fn compiled_patterns() -> &'static [Regex] {
    static COMPILED: OnceLock<Vec<Regex>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        PATTERNS.iter().filter_map(|p| Regex::new(p).ok()).collect()
    })
}

fn base64_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9+/]{32,}={0,2}").unwrap())
}

/// A set of SHA-256 fingerprints of known-sensitive values seen in file reads.
#[derive(Debug, Default, Clone)]
pub struct CredentialTracker {
    fingerprints: HashSet<[u8; 32]>,
}

impl CredentialTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest file content: extract credential candidates and fingerprint them.
    pub fn ingest_file(&mut self, content: &str, path: &str) {
        for cred in extract_credentials(content, path) {
            self.fingerprints.insert(fingerprint(&cred));
        }
    }

    /// Check outbound text for any known fingerprints. Returns partially-redacted matching snippets.
    pub fn check_outbound(&self, text: &str) -> Vec<String> {
        let mut hits = Vec::new();
        for candidate in extract_candidates(text) {
            if self.fingerprints.contains(&fingerprint(&candidate)) {
                hits.push(redact(&candidate));
            }
        }
        hits
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }
}

fn fingerprint(s: &str) -> [u8; 32] {
    let hash = Sha256::digest(s.trim().as_bytes());
    hash.into()
}

/// Credential patterns shared between ingest and outbound check.
const PATTERNS: &[&str] = &[
    r"sk-ant-[a-zA-Z0-9\-_]{20,}",   // Anthropic API key
    r"sk-[a-zA-Z0-9]{48}",           // OpenAI API key
    r"ghp_[a-zA-Z0-9]{36}",          // GitHub PAT
    r"AKIA[A-Z0-9]{16}",             // AWS access key
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[^-]+-----END", // Private key block
];

/// Extract credential candidates from file content.
/// Two sources: direct regex matches and .env KEY=value pairs.
fn extract_credentials(content: &str, path: &str) -> Vec<String> {
    let mut creds = Vec::new();

    // .env-style: KEY=value lines where value length > 8
    let path_lower = path.to_lowercase();
    let is_env_file = path_lower.ends_with(".env")
        || path_lower.contains(".env.")
        || path_lower.contains("/.env")
        || path_lower.contains("\\.env");

    if is_env_file {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some(eq) = line.find('=') {
                let value = line[eq + 1..].trim().trim_matches('"').trim_matches('\'');
                if value.len() > 8 {
                    creds.push(value.to_string());
                }
            }
        }
    }

    // Direct regex patterns for high-value credential strings
    for re in compiled_patterns() {
        for mat in re.find_iter(content) {
            let s = mat.as_str().to_string();
            if s.len() > 8 {
                creds.push(s);
            }
        }
    }

    creds
}

/// Extract candidate strings from outbound text to check against stored fingerprints.
fn extract_candidates(text: &str) -> Vec<String> {
    let mut candidates = Vec::new();

    // Named credential patterns
    for re in compiled_patterns() {
        for mat in re.find_iter(text) {
            candidates.push(mat.as_str().to_string());
        }
    }

    // Base64-ish tokens (catches many bearer tokens / API keys)
    for mat in base64_pattern().find_iter(text) {
        candidates.push(mat.as_str().to_string());
    }

    // KEY=value style inline (e.g. env var in a shell command)
    for line in text.lines() {
        if let Some(eq) = line.find('=') {
            let value = line[eq + 1..].trim().trim_matches('"').trim_matches('\'');
            if value.len() > 16 && !value.contains(' ') {
                candidates.push(value.to_string());
            }
        }
    }

    candidates
}

fn redact(s: &str) -> String {
    if s.len() <= 8 {
        return "***".to_string();
    }
    let keep = 4;
    format!("{}***", &s[..keep])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_file_ingest_and_detect() {
        let mut tracker = CredentialTracker::new();
        let env_content = "API_KEY=sk-ant-api03-supersecrettoken12345678\nDB_PASS=mypassword99\n";
        tracker.ingest_file(env_content, "/project/.env");
        assert!(!tracker.is_empty());

        let prompt = "Here is my key: API_KEY=sk-ant-api03-supersecrettoken12345678";
        let hits = tracker.check_outbound(prompt);
        assert!(!hits.is_empty(), "should detect exfil of env value");
    }

    #[test]
    fn test_no_false_positive_for_unrelated_content() {
        let mut tracker = CredentialTracker::new();
        tracker.ingest_file("API_KEY=sk-ant-api03-supersecrettoken12345678\n", "/project/.env");

        let prompt = "This is a normal message with no secrets.";
        let hits = tracker.check_outbound(prompt);
        assert!(hits.is_empty());
    }

    #[test]
    fn test_github_pat_detection() {
        let mut tracker = CredentialTracker::new();
        let file = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n";
        tracker.ingest_file(file, "/home/user/.gitconfig");

        let outbound = "Authorization: Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let hits = tracker.check_outbound(outbound);
        assert!(!hits.is_empty());
    }
}

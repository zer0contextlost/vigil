//! Indirect prompt injection detection for tool results.

/// A detected injection pattern with its category and the matched snippet.
#[derive(Debug, Clone)]
pub struct InjectionFinding {
    pub category: &'static str,
    pub snippet: String,
}

/// Scan text for known prompt injection patterns.
/// Returns findings (may be empty).
pub fn scan_for_injection(text: &str) -> Vec<InjectionFinding> {
    // Cap input to prevent OOM
    let text = if text.len() > 65_536 { &text[..65_536] } else { text };
    let lower = text.to_lowercase();

    let mut findings = Vec::new();

    // Instruction override patterns
    for phrase in &[
        "ignore previous instructions",
        "ignore all previous",
        "disregard previous",
        "forget your instructions",
        "ignore your instructions",
        "override your instructions",
        "new instructions:",
        "updated instructions:",
        "system prompt:",
        "you are now",
        "act as if",
        "pretend you are",
    ] {
        if lower.contains(phrase) {
            findings.push(InjectionFinding {
                category: "instruction-override",
                snippet: extract_snippet(text, &lower, phrase),
            });
            break; // one finding per category
        }
    }

    // Hidden system-tag injection
    for tag in &["<system>", "</system>", "<|system|>", "[system]", "[[system]]", "<instructions>"] {
        if lower.contains(tag) {
            findings.push(InjectionFinding {
                category: "system-tag",
                snippet: extract_snippet(text, &lower, tag),
            });
            break;
        }
    }

    // Bidi / zero-width Unicode attacks
    let suspicious_unicode: &[char] = &[
        '\u{200B}', // zero-width space
        '\u{200C}', // zero-width non-joiner
        '\u{200D}', // zero-width joiner
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', // bidi overrides
        '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', // bidi isolates
        '\u{FEFF}', // BOM / zero-width no-break space
    ];
    let count = text.chars().filter(|c| suspicious_unicode.contains(c)).count();
    if count >= 3 {
        findings.push(InjectionFinding {
            category: "hidden-unicode",
            snippet: format!("{} hidden Unicode characters detected", count),
        });
    }

    // Large base64 blobs (> 512 chars) in non-binary context — common exfil/payload delivery
    if let Some(pos) = find_large_base64(text) {
        findings.push(InjectionFinding {
            category: "base64-payload",
            snippet: format!("base64 blob at offset {}", pos),
        });
    }

    findings
}

fn extract_snippet(text: &str, lower: &str, needle: &str) -> String {
    if let Some(pos) = lower.find(needle) {
        let start = pos.saturating_sub(20);
        let end = (pos + needle.len() + 60).min(text.len());
        format!("...{}...", &text[start..end])
    } else {
        needle.to_string()
    }
}

fn find_large_base64(text: &str) -> Option<usize> {
    let b64_chars = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=';
    let bytes = text.as_bytes();
    let mut run_start = 0;
    let mut run_len = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b64_chars(b as char) {
            if run_len == 0 { run_start = i; }
            run_len += 1;
            if run_len > 512 {
                return Some(run_start);
            }
        } else {
            run_len = 0;
        }
    }
    None
}

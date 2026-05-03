use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Structural digest of an LLM request body used as the replay cache key.
///
/// Stable across: CLAUDE.md edits, tool result content changes, UUID/timestamp
/// drift in user text, and sampling parameter tweaks. Breaks (correctly) when
/// the human turn sequence or tool-call structure diverges from the recording.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestKey(pub String);

impl RequestKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RequestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Build a `RequestKey` from a raw JSON request body.
///
/// Components hashed: model name, normalized system prompt, sorted tool-name
/// set, and a turn skeleton (human text digests + tool-result positions +
/// assistant tool-use names). See individual helpers for what is dropped.
pub fn build_request_key(body: &Value) -> RequestKey {
    let model = body.get("model").and_then(|v| v.as_str()).unwrap_or("unknown");
    let system_hash = hash_system(body.get("system"));
    let tools_hash = hash_tools(body.get("tools"));
    let turns_hash = hash_turns(body.get("messages"));
    let combined = format!("{}|{}|{}|{}", model, system_hash, tools_hash, turns_hash);
    RequestKey(sha256_hex(combined.as_bytes()))
}

// ── Hashing helpers ──────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn sha256_short(data: &[u8]) -> String {
    hex::encode(&Sha256::digest(data)[..16])
}

fn hash_system(system: Option<&Value>) -> String {
    let text = match system {
        None => return sha256_hex(b""),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|b| {
                if b.get("type").and_then(|t| t.as_str()) == Some("text") {
                    b.get("text").and_then(|t| t.as_str()).map(str::to_string)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => return sha256_hex(b""),
    };
    sha256_hex(normalize_system(&text).as_bytes())
}

/// Strip dynamic sections from the system prompt before hashing.
///
/// `<system-reminder>` blocks are removed entirely — they contain memory
/// and date context that changes every session. CLAUDE.md body text is
/// replaced with `SHA256(path)[..16]` so the key is stable across edits
/// while still distinguishing projects with different CLAUDE.md paths.
fn normalize_system(text: &str) -> String {
    static REMINDER_RE: OnceLock<Regex> = OnceLock::new();

    let stripped = REMINDER_RE
        .get_or_init(|| Regex::new(r"(?s)<system-reminder>.*?</system-reminder>").unwrap())
        .replace_all(text, "")
        .into_owned();

    replace_claude_md_bodies(&stripped)
}

/// Walk `Contents of …CLAUDE.md…:` headers and replace each body with a
/// path-derived hash. Avoids lookahead (not supported by the regex crate)
/// by collecting header positions first, then substituting bodies in order.
fn replace_claude_md_bodies(text: &str) -> String {
    static HEADER_RE: OnceLock<Regex> = OnceLock::new();
    let header_re = HEADER_RE
        .get_or_init(|| Regex::new(r"Contents of ([^\n]*CLAUDE\.md[^\n]*):[^\n]*\n").unwrap());

    let headers: Vec<(usize, usize, String)> = header_re
        .captures_iter(text)
        .map(|caps| {
            let m = caps.get(0).unwrap();
            let path = caps.get(1).map_or("", |c| c.as_str()).trim().to_string();
            (m.start(), m.end(), path)
        })
        .collect();

    if headers.is_empty() {
        return text.to_string();
    }

    let mut result = String::with_capacity(text.len());
    let mut pos = 0;

    for (i, (hdr_start, hdr_end, path)) in headers.iter().enumerate() {
        result.push_str(&text[pos..*hdr_start]);
        result.push_str(&text[*hdr_start..*hdr_end]);
        result.push_str(&format!("<claude-md:{}>\n", &sha256_hex(path.as_bytes())[..16]));
        // Body extends to the start of the next CLAUDE.md header, or end of text.
        pos = if i + 1 < headers.len() { headers[i + 1].0 } else { text.len() };
    }

    result.push_str(&text[pos..]);
    result
}

fn hash_tools(tools: Option<&Value>) -> String {
    let arr = match tools.and_then(|v| v.as_array()) {
        None => return sha256_hex(b""),
        Some(a) => a,
    };
    let mut names: Vec<&str> = arr
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();
    names.sort_unstable();
    sha256_hex(names.join(",").as_bytes())
}

/// Hash the turn skeleton.
///
/// What is kept:
/// - User text turns: SHA-256 of normalized text (UUIDs, timestamps, ANSI stripped)
/// - User tool_result turns: position index + is_error flag (content dropped)
/// - Assistant tool_use turns: position index + tool name (input dropped)
///
/// What is dropped:
/// - Assistant text (synthesized; not part of the request)
/// - Tool result content (changes every run)
/// - Tool input arguments (change every run based on prior tool results)
fn hash_turns(messages: Option<&Value>) -> String {
    let arr = match messages.and_then(|v| v.as_array()) {
        None => return sha256_hex(b""),
        Some(a) => a,
    };

    let mut tokens: Vec<String> = Vec::new();

    for msg in arr {
        let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("");
        let blocks = content_blocks(msg.get("content"));

        match role {
            "user" => {
                let mut result_idx: u32 = 0;
                for block in &blocks {
                    match block.get("type").and_then(|t| t.as_str()) {
                        Some("text") => {
                            let text = block.get("text").and_then(|t| t.as_str()).unwrap_or("");
                            tokens.push(format!("U:T:{}", sha256_short(normalize_text(text).as_bytes())));
                        }
                        Some("tool_result") => {
                            let is_err = block.get("is_error").and_then(|v| v.as_bool()).unwrap_or(false);
                            tokens.push(format!("U:R:{}:{}", result_idx, if is_err { 1 } else { 0 }));
                            result_idx += 1;
                        }
                        _ => {}
                    }
                }
            }
            "assistant" => {
                let mut tool_idx: u32 = 0;
                for block in &blocks {
                    if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                        let name = block.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                        tokens.push(format!("A:C:{}:{}", tool_idx, name));
                        tool_idx += 1;
                    }
                    // assistant text blocks: intentionally dropped
                }
            }
            _ => {}
        }
    }

    sha256_hex(tokens.join("|").as_bytes())
}

/// Normalize content to a slice of blocks regardless of String vs Array form.
fn content_blocks(content: Option<&Value>) -> Vec<Value> {
    match content {
        Some(Value::String(s)) => vec![json!({"type": "text", "text": s})],
        Some(Value::Array(blocks)) => blocks.clone(),
        _ => vec![],
    }
}

/// Strip noise from user text before hashing: UUIDs, ISO 8601 timestamps,
/// ANSI escape codes, and runs of whitespace.
fn normalize_text(text: &str) -> String {
    static ANSI_RE: OnceLock<Regex> = OnceLock::new();
    static UUID_RE: OnceLock<Regex> = OnceLock::new();
    static TS_RE: OnceLock<Regex> = OnceLock::new();
    static WS_RE: OnceLock<Regex> = OnceLock::new();

    let s = ANSI_RE
        .get_or_init(|| Regex::new(r"\x1b\[[0-9;]*[mGKHFABCDJsu]").unwrap())
        .replace_all(text, "")
        .into_owned();

    let s = UUID_RE
        .get_or_init(|| {
            Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
                .unwrap()
        })
        .replace_all(&s, "<uuid>")
        .into_owned();

    let s = TS_RE
        .get_or_init(|| {
            Regex::new(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b").unwrap()
        })
        .replace_all(&s, "<ts>")
        .into_owned();

    WS_RE
        .get_or_init(|| Regex::new(r"\s+").unwrap())
        .replace_all(&s, " ")
        .trim()
        .to_string()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn req(model: &str, system: Option<&str>, messages: Value) -> Value {
        let mut body = json!({ "model": model, "messages": messages });
        if let Some(s) = system {
            body["system"] = json!(s);
        }
        body
    }

    fn user_text(text: &str) -> Value {
        json!({"role": "user", "content": [{"type": "text", "text": text}]})
    }

    fn user_tool_result(id: &str, content: &str, is_error: bool) -> Value {
        json!({"role": "user", "content": [{"type": "tool_result", "tool_use_id": id, "content": content, "is_error": is_error}]})
    }

    fn assistant_tool_use(name: &str, id: &str, input: Value) -> Value {
        json!({"role": "assistant", "content": [{"type": "tool_use", "id": id, "name": name, "input": input}]})
    }

    fn assistant_text(text: &str) -> Value {
        json!({"role": "assistant", "content": [{"type": "text", "text": text}]})
    }

    #[test]
    fn same_body_produces_same_key() {
        let body = req("claude-sonnet-4-6", Some("Be helpful."), json!([user_text("hello")]));
        assert_eq!(build_request_key(&body), build_request_key(&body));
    }

    #[test]
    fn different_model_produces_different_key() {
        let a = req("claude-sonnet-4-6", None, json!([user_text("hello")]));
        let b = req("claude-opus-4-7", None, json!([user_text("hello")]));
        assert_ne!(build_request_key(&a), build_request_key(&b));
    }

    #[test]
    fn uuid_in_user_text_stripped_before_hashing() {
        let a = req("m", None, json!([user_text("session 550e8400-e29b-41d4-a716-446655440000 done")]));
        let b = req("m", None, json!([user_text("session 6ba7b810-9dad-11d1-80b4-00c04fd430c8 done")]));
        // Different UUIDs should produce the same key after normalization
        assert_eq!(build_request_key(&a), build_request_key(&b));
    }

    #[test]
    fn timestamp_in_user_text_stripped() {
        let a = req("m", None, json!([user_text("started at 2026-05-03T14:22:01Z")]));
        let b = req("m", None, json!([user_text("started at 2025-01-15T09:00:00Z")]));
        assert_eq!(build_request_key(&a), build_request_key(&b));
    }

    #[test]
    fn tool_result_content_dropped_position_kept() {
        let messages_a = json!([
            user_text("read the file"),
            assistant_tool_use("Read", "tu_1", json!({"file_path": "/foo.rs"})),
            user_tool_result("tu_1", "fn main() {}", false)
        ]);
        let messages_b = json!([
            user_text("read the file"),
            assistant_tool_use("Read", "tu_1", json!({"file_path": "/foo.rs"})),
            user_tool_result("tu_1", "fn different_content() { let x = 42; }", false)
        ]);
        let a = req("m", None, messages_a);
        let b = req("m", None, messages_b);
        assert_eq!(build_request_key(&a), build_request_key(&b));
    }

    #[test]
    fn tool_result_is_error_flag_distinguishes_key() {
        let messages_ok = json!([
            user_text("do it"),
            assistant_tool_use("Bash", "tu_1", json!({"command": "ls"})),
            user_tool_result("tu_1", "file.txt", false)
        ]);
        let messages_err = json!([
            user_text("do it"),
            assistant_tool_use("Bash", "tu_1", json!({"command": "ls"})),
            user_tool_result("tu_1", "file.txt", true)
        ]);
        assert_ne!(build_request_key(&req("m", None, messages_ok)),
                   build_request_key(&req("m", None, messages_err)));
    }

    #[test]
    fn assistant_text_dropped() {
        let messages_a = json!([user_text("hello"), assistant_text("I'll help you with that.")]);
        let messages_b = json!([user_text("hello"), assistant_text("Sure thing!")]);
        assert_eq!(build_request_key(&req("m", None, messages_a)),
                   build_request_key(&req("m", None, messages_b)));
    }

    #[test]
    fn tool_call_sequence_order_matters() {
        // Swapping two tool calls should produce a different key
        let messages_a = json!([
            user_text("go"),
            assistant_tool_use("Read",  "t1", json!({})),
            assistant_tool_use("Write", "t2", json!({}))
        ]);
        let messages_b = json!([
            user_text("go"),
            assistant_tool_use("Write", "t1", json!({})),
            assistant_tool_use("Read",  "t2", json!({}))
        ]);
        assert_ne!(build_request_key(&req("m", None, messages_a)),
                   build_request_key(&req("m", None, messages_b)));
    }

    #[test]
    fn tools_schema_hashes_names_only_not_descriptions() {
        let tools_a = json!([{"name": "Read",  "description": "Read a file.", "input_schema": {}}]);
        let tools_b = json!([{"name": "Read",  "description": "Reads a file from the filesystem.", "input_schema": {}}]);
        let mut body_a = req("m", None, json!([user_text("hi")]));
        let mut body_b = req("m", None, json!([user_text("hi")]));
        body_a["tools"] = tools_a;
        body_b["tools"] = tools_b;
        assert_eq!(build_request_key(&body_a), build_request_key(&body_b));
    }

    #[test]
    fn tools_schema_order_independent() {
        let mut body_a = req("m", None, json!([user_text("hi")]));
        let mut body_b = req("m", None, json!([user_text("hi")]));
        body_a["tools"] = json!([{"name": "Read"}, {"name": "Write"}]);
        body_b["tools"] = json!([{"name": "Write"}, {"name": "Read"}]);
        assert_eq!(build_request_key(&body_a), build_request_key(&body_b));
    }

    #[test]
    fn system_reminder_stripped() {
        let sys_a = "You are an assistant.\n<system-reminder>date: 2026-05-03</system-reminder>\nHelp the user.";
        let sys_b = "You are an assistant.\n<system-reminder>date: 2025-01-01, some other memory</system-reminder>\nHelp the user.";
        assert_eq!(build_request_key(&req("m", Some(sys_a), json!([user_text("hi")]))),
                   build_request_key(&req("m", Some(sys_b), json!([user_text("hi")]))));
    }

    #[test]
    fn claude_md_edits_do_not_change_key() {
        let sys_a = "System header.\nContents of C:\\users\\cliff\\.claude\\CLAUDE.md (instructions):\n# old instructions\ndo X\n";
        let sys_b = "System header.\nContents of C:\\users\\cliff\\.claude\\CLAUDE.md (instructions):\n# new instructions after edit\ndo Y instead\n";
        assert_eq!(build_request_key(&req("m", Some(sys_a), json!([user_text("hi")]))),
                   build_request_key(&req("m", Some(sys_b), json!([user_text("hi")]))));
    }

    #[test]
    fn different_claude_md_paths_produce_different_keys() {
        let sys_a = "Contents of /project-a/CLAUDE.md:\n# instructions\n";
        let sys_b = "Contents of /project-b/CLAUDE.md:\n# instructions\n";
        assert_ne!(build_request_key(&req("m", Some(sys_a), json!([user_text("hi")]))),
                   build_request_key(&req("m", Some(sys_b), json!([user_text("hi")]))));
    }

    #[test]
    fn normalize_text_strips_ansi() {
        assert_eq!(normalize_text("\x1b[32mgreen\x1b[0m"), "green");
    }

    #[test]
    fn normalize_text_collapses_whitespace() {
        assert_eq!(normalize_text("hello   world\n\tthere"), "hello world there");
    }
}

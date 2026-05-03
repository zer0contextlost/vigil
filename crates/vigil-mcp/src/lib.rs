//! vigil-mcp — MCP server and proxy shim for vigil.
//!
//! Two modes:
//! 1. `run_mcp_server()` — self-contained MCP server (JSON-RPC over stdio) exposing
//!    vigil-aware tools: `vigil_status`, `vigil_sessions`, `vigil_policy_check`.
//!    Used by `vigil mcp` and configured in `claude_desktop_config.json`.
//!
//! 2. `McpShim` — transparent MCP proxy that spawns a real MCP server as a child
//!    process and intercepts tool calls for PII scanning and event logging.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{self, BufRead, Write};
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use uuid::Uuid;
use vigil_core::{AnthropicAdapter, Event, ProviderAdapter, TimestampedEvent};

// ---------------------------------------------------------------------------
// MCP server — JSON-RPC 2.0 over stdio
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Request {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct Response {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorObj>,
}

#[derive(Debug, Serialize)]
struct ErrorObj {
    code: i32,
    message: String,
}

/// Run vigil as a self-contained MCP server over stdio.
///
/// Speaks JSON-RPC 2.0, responds to `initialize`, `tools/list`, and `tools/call`.
/// Intended to be launched by Claude Desktop or Cursor via `vigil mcp`.
pub fn run_mcp_server() -> anyhow::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("Parse error: {}", e) }
                });
                writeln!(out, "{}", resp)?;
                out.flush()?;
                continue;
            }
        };

        // Notifications have no id — don't respond.
        if req.id.is_none() && req.method.starts_with("notifications/") {
            continue;
        }

        let id = req.id.clone().unwrap_or(Value::Null);
        let result = handle_method(&req.method, &req.params);

        let resp = match result {
            Ok(r) => Response {
                jsonrpc: "2.0".into(),
                id,
                result: Some(r),
                error: None,
            },
            Err(e) => Response {
                jsonrpc: "2.0".into(),
                id,
                result: None,
                error: Some(e),
            },
        };

        writeln!(out, "{}", serde_json::to_string(&resp)?)?;
        out.flush()?;
    }
    Ok(())
}

fn handle_method(method: &str, params: &Value) -> Result<Value, ErrorObj> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "vigil-mcp",
                "version": env!("CARGO_PKG_VERSION")
            },
            "capabilities": { "tools": {} }
        })),

        "tools/list" => Ok(json!({
            "tools": [
                {
                    "name": "vigil_status",
                    "description": "Get current vigil proxy status: active sessions, alert counts, proxy port.",
                    "inputSchema": { "type": "object", "properties": {}, "required": [] }
                },
                {
                    "name": "vigil_sessions",
                    "description": "List recent vigil sessions with cost and name.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "integer",
                                "description": "Max sessions to return (default 10)"
                            }
                        },
                        "required": []
                    }
                },
                {
                    "name": "vigil_policy_check",
                    "description": "Check whether a tool call would be allowed by vigil's current policy. Returns allow or confirm.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "tool_name": { "type": "string" },
                            "input": { "type": "object" }
                        },
                        "required": ["tool_name"]
                    }
                }
            ]
        })),

        "tools/call" => {
            let tool_name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or(ErrorObj {
                    code: -32602,
                    message: "missing name".into(),
                })?;
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            call_tool(tool_name, &args)
        }

        _ => Err(ErrorObj {
            code: -32601,
            message: format!("Method not found: {}", method),
        }),
    }
}

fn call_tool(name: &str, args: &Value) -> Result<Value, ErrorObj> {
    match name {
        "vigil_status" => {
            let active_count = vigil_active_dir()
                .and_then(|d| std::fs::read_dir(d).ok())
                .map(|entries| entries.count())
                .unwrap_or(0);

            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!(
                        "vigil-mcp v{}\nActive sessions: {}\nProxy: check ~/.vigil/active/ for session details",
                        env!("CARGO_PKG_VERSION"),
                        active_count
                    )
                }]
            }))
        }

        "vigil_sessions" => {
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(10) as usize;

            match vigil_core::session::Session::list_all() {
                Ok(sessions) => {
                    let rows: Vec<String> = sessions
                        .iter()
                        .take(limit)
                        .map(|s| {
                            let name = s.name.as_deref().unwrap_or("—");
                            let cost = format!("${:.4}", s.total_cost_usd);
                            let date = s.started_at.format("%Y-%m-%d %H:%M").to_string();
                            format!(
                                "{} | {} | {} | {}",
                                &s.id.to_string()[..8],
                                name,
                                cost,
                                date
                            )
                        })
                        .collect();
                    let text = if rows.is_empty() {
                        "No sessions found.".to_string()
                    } else {
                        format!(
                            "ID       | Name            | Cost   | Started\n{}\n{}",
                            "-".repeat(60),
                            rows.join("\n")
                        )
                    };
                    Ok(json!({ "content": [{ "type": "text", "text": text }] }))
                }
                Err(e) => Ok(json!({
                    "content": [{ "type": "text", "text": format!("Error listing sessions: {}", e) }]
                })),
            }
        }

        "vigil_policy_check" => {
            let tool_name = args
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let write_tools = AnthropicAdapter.write_tools();
            let verdict = if write_tools.contains(&tool_name) {
                "confirm (write tool — may require approval)"
            } else {
                "allow"
            };
            Ok(json!({
                "content": [{ "type": "text", "text": format!("Tool '{}': {}", tool_name, verdict) }]
            }))
        }

        _ => Err(ErrorObj {
            code: -32601,
            message: format!("Unknown tool: {}", name),
        }),
    }
}

fn vigil_active_dir() -> Option<std::path::PathBuf> {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()?;
    Some(std::path::PathBuf::from(home).join(".vigil").join("active"))
}

// ---------------------------------------------------------------------------
// MCP shim — transparent proxy around a real MCP server
// ---------------------------------------------------------------------------

/// MCP runs over stdio JSON-RPC. The shim spawns the real MCP server as a child process
/// and pipes stdin/stdout through, intercepting tools/call requests and logging them as
/// McpCall events. This allows vigil to observe all MCP tool invocations without requiring
/// changes to the agent tools themselves.
#[derive(Debug, Clone)]
pub struct McpShimConfig {
    pub server_command: String,
    pub server_args: Vec<String>,
    pub session_id: Uuid,
    pub pii_watchlist: Vec<String>,
}

pub struct McpShim {
    config: McpShimConfig,
    event_tx: mpsc::Sender<TimestampedEvent>,
}

// JSON-RPC 2.0 message shapes for parsing inside the shim
#[derive(Deserialize, Debug)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Deserialize, Debug)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: Option<Value>,
    result: Option<Value>,
    #[allow(dead_code)]
    error: Option<Value>,
}

impl McpShim {
    pub fn new(config: McpShimConfig, event_tx: mpsc::Sender<TimestampedEvent>) -> Self {
        Self { config, event_tx }
    }

    pub async fn run(&self) -> Result<()> {
        // Spawn the real MCP server as a child process
        let mut child = tokio::process::Command::new(&self.config.server_command)
            .args(&self.config.server_args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;

        let mut child_stdin = child.stdin.take().expect("child stdin");
        let child_stdout = child.stdout.take().expect("child stdout");

        let mut our_stdin = tokio::io::BufReader::new(tokio::io::stdin());
        let mut child_stdout_reader = tokio::io::BufReader::new(child_stdout);

        let event_tx_req = self.event_tx.clone();
        let server_name = self.config.server_command.clone();
        let session_id = self.config.session_id;

        let event_tx_res = self.event_tx.clone();
        let server_name_res = server_name.clone();
        let response_task = tokio::spawn(async move {
            let mut line = String::new();
            let mut our_stdout = tokio::io::stdout();
            loop {
                line.clear();
                match child_stdout_reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(line.trim()) {
                            if let Some(result) = &resp.result {
                                let event = TimestampedEvent::new(Event::McpCall {
                                    server: server_name_res.clone(),
                                    method: "tools/call/response".to_string(),
                                    params: result.clone(),
                                    session_id,
                                });
                                event_tx_res.send(event).await.ok();
                            }
                        }
                        our_stdout.write_all(line.as_bytes()).await.ok();
                        our_stdout.flush().await.ok();
                    }
                    Err(_) => break,
                }
            }
        });

        let mut line = String::new();
        loop {
            line.clear();
            match our_stdin.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(line.trim()) {
                        if req.method == "tools/call" {
                            let (tool_name, input) = if let Some(params) = &req.params {
                                let name = params
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                let args = params
                                    .get("arguments")
                                    .cloned()
                                    .unwrap_or(Value::Null);
                                (name, args)
                            } else {
                                ("unknown".to_string(), Value::Null)
                            };

                            {
                                let param_text = input.to_string();
                                let mut hits = vigil_core::scan_pii(&param_text);
                                hits.extend(vigil_core::scan_watchlist(
                                    &param_text,
                                    &self.config.pii_watchlist,
                                ));
                                if !hits.is_empty() {
                                    let kinds: Vec<String> = {
                                        let mut seen = HashSet::new();
                                        hits.iter()
                                            .filter(|h| seen.insert(h.kind.clone()))
                                            .map(|h| h.kind.clone())
                                            .collect()
                                    };
                                    let pii_event = TimestampedEvent::new(Event::PiiAlert {
                                        source: format!("mcp:{}", tool_name),
                                        kinds,
                                        session_id,
                                    });
                                    event_tx_req.send(pii_event).await.ok();
                                }
                            }

                            let event = TimestampedEvent::new(Event::McpCall {
                                server: server_name.clone(),
                                method: format!("tools/call:{}", tool_name),
                                params: input,
                                session_id,
                            });
                            event_tx_req.send(event).await.ok();
                        }
                    }
                    child_stdin.write_all(line.as_bytes()).await?;
                    child_stdin.flush().await?;
                }
                Err(e) => {
                    eprintln!("MCP shim stdin error: {}", e);
                    break;
                }
            }
        }

        response_task.abort();
        child.wait().await?;
        Ok(())
    }
}

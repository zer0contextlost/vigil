use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use uuid::Uuid;
use vigil_core::{Event, TimestampedEvent};

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

// JSON-RPC 2.0 message shapes for parsing
#[derive(Deserialize, Debug)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Deserialize, Debug)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Option<Value>,
    result: Option<Value>,
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

        // Set up readers and event channel
        let mut our_stdin = tokio::io::BufReader::new(tokio::io::stdin());
        let mut child_stdout_reader = tokio::io::BufReader::new(child_stdout);

        let event_tx_req = self.event_tx.clone();
        let server_name = self.config.server_command.clone();
        let session_id = self.config.session_id;

        // Task: read child stdout, forward to our stdout, intercept responses
        let event_tx_res = self.event_tx.clone();
        let server_name_res = server_name.clone();
        let response_task = tokio::spawn(async move {
            let mut line = String::new();
            let mut our_stdout = tokio::io::stdout();
            loop {
                line.clear();
                match child_stdout_reader.read_line(&mut line).await {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        // Try to parse as JSON-RPC response
                        if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(line.trim()) {
                            // Log tool call results
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
                        // Always forward to our stdout
                        our_stdout.write_all(line.as_bytes()).await.ok();
                        our_stdout.flush().await.ok();
                    }
                    Err(_) => break,
                }
            }
        });

        // Main loop: read our stdin, intercept tools/call, forward to child stdin
        let mut line = String::new();
        loop {
            line.clear();
            match our_stdin.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    // Try to parse as JSON-RPC request
                    if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(line.trim()) {
                        if req.method == "tools/call" {
                            // Extract tool name and input from params
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

                            // PII scan on tool call params
                            {
                                let param_text = input.to_string();
                                let mut hits = vigil_core::scan_pii(&param_text);
                                hits.extend(vigil_core::scan_watchlist(&param_text, &self.config.pii_watchlist));
                                if !hits.is_empty() {
                                    let kinds: Vec<String> = {
                                        let mut seen = HashSet::new();
                                        hits.iter().filter(|h| seen.insert(h.kind.clone())).map(|h| h.kind.clone()).collect()
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
                    // Always forward to child stdin
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

use anyhow::Result;
use clap::Parser;
use serde_json;
use uuid::Uuid;
use vigil_mcp::{McpShim, McpShimConfig};

#[derive(Parser)]
#[command(name = "vigil-mcp-shim")]
#[command(about = "MCP protocol shim — transparently intercepts and logs MCP tool calls")]
struct Cli {
    /// The real MCP server command to proxy
    server_command: String,
    /// Arguments to pass to the server command
    server_args: Vec<String>,
    /// vigil daemon socket to send events to (optional, prints to stderr if not set)
    #[arg(long)]
    vigil_socket: Option<String>,
    /// Session ID to tag events with (UUID format)
    #[arg(long)]
    session_id: Option<String>,
    /// Write events to this NDJSON file (appends)
    #[arg(long)]
    ndjson: Option<std::path::PathBuf>,
    /// PII watchlist file (one term per line)
    #[arg(long)]
    pii_watchlist: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let session_id = cli.session_id
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::new_v4);

    let pii_watchlist: Vec<String> = cli.pii_watchlist
        .as_deref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect())
        .unwrap_or_default();

    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1000);

    let ndjson_path = cli.ndjson.clone();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut ndjson_file = if let Some(ref path) = ndjson_path {
            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
                .ok()
        } else {
            None
        };
        while let Some(event) = event_rx.recv().await {
            if let Some(ref mut f) = ndjson_file {
                if let Ok(mut line) = serde_json::to_vec(&event) {
                    line.push(b'\n');
                    f.write_all(&line).await.ok();
                    f.flush().await.ok();
                }
            } else {
                eprintln!("[vigil-mcp] {:?}", event);
            }
        }
    });

    let config = McpShimConfig {
        server_command: cli.server_command,
        server_args: cli.server_args,
        session_id,
        pii_watchlist,
    };

    let shim = McpShim::new(config, event_tx);
    shim.run().await
}

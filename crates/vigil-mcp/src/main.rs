use anyhow::Result;
use clap::Parser;
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // For now, events go to stderr (future: send to vigil daemon via unix socket)
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1000);

    // Print events to stderr so they don't corrupt stdout (which the agent reads)
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            eprintln!("[vigil-mcp] {:?}", event);
        }
    });

    let config = McpShimConfig {
        server_command: cli.server_command,
        server_args: cli.server_args,
    };

    let shim = McpShim::new(config, event_tx);
    shim.run().await
}

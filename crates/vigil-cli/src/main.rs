use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use vigil_core::{session::Session, store::SessionStore, AlertLabel, CredentialTracker, Event, PolicyEngine, TimestampedEvent, BudgetEnforcer, BudgetStatus, BurnRateTracker, LoopDetector, PluginHost, PluginContext, PluginDecision};
use vigil_proxy::Proxy;
use vigil_tui::{App, BrowseAction};
use vigil_watch::{WatchConfig, Watcher};

#[derive(Parser)]
#[command(name = "vigil")]
#[command(about = "Runtime observability and policy enforcement for AI coding agents", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum PluginTemplate {
    /// React to alerts — good for notifications and webhooks
    Alert,
    /// Gate tool calls — allow or block based on custom logic
    Gatekeeper,
    /// Log events — write structured data to a file or external system
    Logger,
    /// Blank slate — all three methods stubbed, no logic
    Blank,
}

#[derive(Subcommand)]
enum PluginCommands {
    /// List plugins in ~/.vigil/plugins/
    List,
    /// Show the plugins directory path
    Dir,
    /// Scaffold a new plugin crate with an interactive template picker
    New {
        /// Name of the plugin (used as the crate name and directory)
        name: String,
        /// Template to use (skips the interactive prompt)
        #[arg(long, short)]
        template: Option<PluginTemplate>,
        /// Directory to create the plugin in (default: ./<name>)
        #[arg(long, short)]
        path: Option<PathBuf>,
    },
    /// Copy a compiled plugin (.dll/.so/.dylib) into the auto-load directory
    Install {
        /// Path to the compiled shared library
        path: PathBuf,
    },
    /// Validate a compiled plugin without installing it (checks ABI/rustc compatibility)
    Check {
        /// Path to the compiled shared library to validate
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// Run an AI agent under observation
    Run {
        /// Port for HTTPS proxy
        #[arg(long, default_value = "8877")]
        port: u16,

        /// Policy configuration file
        #[arg(long)]
        policy: Option<PathBuf>,

        /// vigil.toml configuration file
        #[arg(long)]
        config: Option<PathBuf>,

        /// Write debug log to this file (tail -f <file> to watch in another terminal)
        #[arg(long)]
        log_file: Option<PathBuf>,

        /// File containing personal watchlist terms for PII detection (one per line)
        #[arg(long)]
        pii_watchlist: Option<PathBuf>,

        /// Shared library plugin(s) to load (.dll / .so / .dylib). May be repeated.
        #[arg(long = "plugin")]
        plugins: Vec<PathBuf>,

        /// Human-readable label for this session (shown in vigil sessions / browse)
        #[arg(long)]
        name: Option<String>,

        /// Agent command and arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        agent_and_args: Vec<String>,
    },

    /// Initialize a policy file for this project
    Init {
        /// Output path (default: .agent-sentinel.yaml)
        #[arg(long, default_value = ".agent-sentinel.yaml")]
        output: PathBuf,
        /// Overwrite if exists
        #[arg(long)]
        force: bool,
    },

    /// List past sessions (text table)
    Sessions,

    /// Browse past sessions in an interactive TUI
    Browse,

    /// Tag a session with a human-readable name
    Tag {
        /// Session ID (UUID) or existing name
        session_id: String,
        /// Label to assign
        name: String,
    },

    /// Manage vigil plugins
    Plugins {
        #[command(subcommand)]
        action: PluginCommands,
    },

    /// Replay a recorded session
    Replay {
        /// Session ID to replay
        session_id: String,
    },

    /// Verify hash chain integrity of a recorded session
    Audit {
        /// Session ID (UUID) to audit
        session_id: String,
    },

    /// Verify hash chain and ed25519 signature of a recorded session
    Verify {
        /// Session ID (UUID) to verify
        session_id: String,
    },

    /// Export a session to NDJSON with PII redacted
    Export {
        /// Session ID (UUID) to export
        session_id: String,
        /// Output file path (default: stdout)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Show all currently active vigil sessions
    Ps,

    /// Replay a session prefix and continue with a live agent
    Fork {
        /// Session ID to fork from
        session_id: String,
        /// Replay the first N events, then go live (0 = full session prefix)
        #[arg(long, default_value = "0")]
        prefix_events: usize,
        /// Agent command and arguments (same as vigil run)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        agent_and_args: Vec<String>,
    },

    /// Start the proxy and TUI without spawning an agent (for Cursor, IDEs, etc.)
    Proxy {
        /// Port for the proxy
        #[arg(long, default_value = "8877")]
        port: u16,

        /// Policy configuration file
        #[arg(long)]
        policy: Option<PathBuf>,

        /// vigil.toml configuration file
        #[arg(long)]
        config: Option<PathBuf>,

        /// Write debug log to this file
        #[arg(long)]
        log_file: Option<PathBuf>,

        /// File containing personal watchlist terms for PII detection (one per line)
        #[arg(long)]
        pii_watchlist: Option<PathBuf>,

        /// Shared library plugin(s) to load. May be repeated.
        #[arg(long = "plugin")]
        plugins: Vec<PathBuf>,

        /// Human-readable label for this session
        #[arg(long)]
        name: Option<String>,
    },

    /// Delete session files older than N days
    Prune {
        /// Delete sessions older than this many days
        #[arg(long, default_value = "30")]
        older_than: u64,
        /// Show what would be deleted without deleting
        #[arg(long)]
        dry_run: bool,
    },
}

// ---------------------------------------------------------------------------
// Windows: spawn agent in its own console window using CreateProcessW directly.
// When tokio's Command spawns with CREATE_NEW_CONSOLE, Rust still sets
// STARTF_USESTDHANDLES so the child inherits vigil's terminal handles — the
// new window appears empty and Claude's TUI corrupts vigil's screen.
// Calling CreateProcessW with bInheritHandles=FALSE lets Windows assign the
// new console's own stdin/stdout/stderr to the child automatically.
// ---------------------------------------------------------------------------
#[cfg(windows)]
mod win_console {
    use anyhow::{anyhow, Result};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, FALSE};
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, WaitForSingleObject, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
        CREATE_NEW_CONSOLE,
    };

    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

    pub struct WinChild {
        pub pid: u32,
        handle: HANDLE,
    }

    // HANDLE (isize) is Send — we only access it from spawn_blocking.
    unsafe impl Send for WinChild {}

    impl Drop for WinChild {
        fn drop(&mut self) {
            if self.handle != 0 {
                unsafe {
                    CloseHandle(self.handle);
                }
            }
        }
    }

    impl WinChild {
        pub fn pid(&self) -> u32 {
            self.pid
        }

        pub async fn wait(&mut self) {
            let handle = self.handle;
            tokio::task::spawn_blocking(move || unsafe {
                WaitForSingleObject(handle, INFINITE);
            })
            .await
            .ok();
        }
    }

    fn build_cmdline(program: &str, args: &[String]) -> Vec<u16> {
        let mut s = String::new();
        for (i, arg) in std::iter::once(&program.to_string()).chain(args.iter()).enumerate() {
            if i > 0 {
                s.push(' ');
            }
            if arg.contains(|c: char| c == ' ' || c == '\t' || c == '"') {
                s.push('"');
                for c in arg.chars() {
                    if c == '"' {
                        s.push('\\');
                    }
                    s.push(c);
                }
                s.push('"');
            } else {
                s.push_str(arg);
            }
        }
        OsStr::new(&s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn build_env_block(extra: &[(&str, &str)]) -> Vec<u16> {
        use std::collections::HashMap;
        let mut env: HashMap<String, String> = std::env::vars().collect();
        for (k, v) in extra {
            env.insert(k.to_string(), v.to_string());
        }
        let mut block: Vec<u16> = Vec::new();
        for (k, v) in &env {
            let entry = format!("{}={}", k, v);
            block.extend(OsStr::new(&entry).encode_wide());
            block.push(0);
        }
        block.push(0); // double-null terminator
        block
    }

    pub fn spawn(program: &str, args: &[String], extra_env: &[(&str, &str)]) -> Result<WinChild> {
        let mut cmdline = build_cmdline(program, args);
        let env_block = build_env_block(extra_env);

        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpReserved: std::ptr::null_mut(),
            lpDesktop: std::ptr::null_mut(),
            lpTitle: std::ptr::null_mut(),
            dwX: 0,
            dwY: 0,
            dwXSize: 0,
            dwYSize: 0,
            dwXCountChars: 0,
            dwYCountChars: 0,
            dwFillAttribute: 0,
            // KEY: dwFlags = 0 means STARTF_USESTDHANDLES is NOT set.
            // Windows then assigns the new console's stdin/stdout/stderr to the child.
            dwFlags: 0,
            wShowWindow: 0,
            cbReserved2: 0,
            lpReserved2: std::ptr::null_mut(),
            hStdInput: 0,
            hStdOutput: 0,
            hStdError: 0,
        };

        let mut pi = PROCESS_INFORMATION {
            hProcess: 0,
            hThread: 0,
            dwProcessId: 0,
            dwThreadId: 0,
        };

        let ok = unsafe {
            CreateProcessW(
                std::ptr::null(),                                   // lpApplicationName
                cmdline.as_mut_ptr(),                               // lpCommandLine
                std::ptr::null(),                                   // lpProcessAttributes
                std::ptr::null(),                                   // lpThreadAttributes
                FALSE,                                              // bInheritHandles = FALSE
                CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,    // dwCreationFlags
                env_block.as_ptr() as *const _,                     // lpEnvironment (UTF-16)
                std::ptr::null(),                                   // lpCurrentDirectory (inherit)
                &si,                                                // lpStartupInfo
                &mut pi,                                            // lpProcessInformation
            )
        };

        if ok == FALSE {
            let err = unsafe { GetLastError() };
            // ERROR_FILE_NOT_FOUND (2): program may be a .cmd/.bat script that requires
            // cmd.exe to interpret (e.g. cursor.cmd, aider.cmd installed by pip/npm).
            // Retry once by wrapping in `cmd.exe /C <original cmdline>`.
            if err == 2 {
                let cmd_args: Vec<String> =
                    std::iter::once("/C".to_string())
                        .chain(std::iter::once(program.to_string()))
                        .chain(args.iter().cloned())
                        .collect();
                let mut cmdline2 = build_cmdline("cmd.exe", &cmd_args);
                let ok2 = unsafe {
                    CreateProcessW(
                        std::ptr::null(),
                        cmdline2.as_mut_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                        FALSE,
                        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                        env_block.as_ptr() as *const _,
                        std::ptr::null(),
                        &si,
                        &mut pi,
                    )
                };
                if ok2 == FALSE {
                    let err2 = unsafe { GetLastError() };
                    return Err(anyhow!(
                        "cannot launch {:?} (error {}) or via cmd.exe /C (error {})",
                        program, err, err2
                    ));
                }
            } else {
                return Err(anyhow!(
                    "CreateProcessW failed: Windows error code {}",
                    err
                ));
            }
        }

        unsafe { CloseHandle(pi.hThread); } // we don't need the thread handle

        tracing::info!(pid = pi.dwProcessId, cmd = program, "agent spawned in new console window");
        Ok(WinChild {
            pid: pi.dwProcessId,
            handle: pi.hProcess,
        })
    }

    /// Convenience: return a one-shot tokio task that resolves when the process exits.
    pub fn wait_task(mut child: WinChild) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { child.wait().await })
    }
}

// ---------------------------------------------------------------------------
// Logging initialisation — writes to a file so it doesn't corrupt the TUI.
// ---------------------------------------------------------------------------
fn init_logging(log_file: Option<&PathBuf>) {
    let Some(path) = log_file else {
        return; // No log file → no tracing output (stdout/stderr corrupts TUI)
    };
    use std::fs::OpenOptions;
    use tracing_subscriber::fmt;

    let file = match OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("vigil: cannot open log file {}: {}", path.display(), e);
            return;
        }
    };

    fmt()
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false)
        .with_level(true)
        .with_target(true)
        .init();

    tracing::info!("vigil logging started → {}", path.display());
}

// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            run_interactive().await?;
        }
        Some(Commands::Run {
            port,
            policy,
            config,
            log_file,
            pii_watchlist,
            plugins,
            name,
            agent_and_args,
        }) => {
            let watchlist = load_pii_watchlist(pii_watchlist.as_deref());
            let config_path_str = config.as_deref().map(|p| p.display().to_string());
            let vigil_config = config.as_deref()
                .and_then(|p| vigil_core::VigilConfig::load(p).ok());
            let mut plugin_host = PluginHost::new();
            // Auto-load plugins from ~/.vigil/plugins/
            if let Ok(dir) = plugins_dir() {
                load_plugins_from_dir(&dir, &mut plugin_host);
            }
            for path in &plugins {
                match plugin_host.load_from_file(path) {
                    Ok(()) => println!("Loaded plugin: {}", path.display()),
                    Err(e) => eprintln!("Warning: {}", e),
                }
            }
            run_agent_with_plugins(port, policy, log_file.as_ref(), agent_and_args, watchlist, vigil_config, config_path_str, plugin_host, name).await?;
        }
        Some(Commands::Init { output, force }) => {
            vigil_init(output, force).await?;
        }
        Some(Commands::Browse) => {
            loop {
                let summaries = Session::list_all()?;
                match vigil_tui::run_session_browser(summaries).await? {
                    Some(BrowseAction::Replay(id)) => {
                        let envelopes = vigil_core::store::SessionStore::load_envelopes(&id)?;
                        let (tx, rx) = tokio::sync::mpsc::channel(envelopes.len().max(1));
                        let envelopes_clone = envelopes.clone();
                        tokio::spawn(async move {
                            for (i, env) in envelopes_clone.iter().enumerate() {
                                if i > 0 {
                                    let prev_ts = envelopes_clone[i - 1].timestamp;
                                    let delta = env.timestamp.signed_duration_since(prev_ts);
                                    let ms = delta.num_milliseconds().max(0).min(500) as u64;
                                    if ms > 0 { tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await; }
                                }
                                if tx.send(env.clone()).await.is_err() { break; }
                            }
                        });
                        let meta = vigil_core::store::SessionStore::load_meta(&id).ok();
                        let agent = meta.as_ref().map(|m| m.agent.clone()).unwrap_or_else(|| "unknown".to_string());
                        let mut session = vigil_core::session::Session::new(agent);
                        session.id = id;
                        let mut app = App::new(session);
                        app.is_replay = true;
                        vigil_tui::run_tui(app, rx).await?;
                        // Return to the browser after replay ends.
                    }
                    Some(BrowseAction::Delete(id)) => {
                        confirm_delete_session(&id)?;
                        // Return to the browser after deletion.
                    }
                    Some(BrowseAction::Quit) | None => break,
                }
            }
        }
        Some(Commands::Tag { session_id, name }) => {
            let uuid = resolve_session_id(&session_id)?;
            SessionStore::tag(&uuid, &name)?;
            println!("Tagged session {} as {:?}", uuid, name);
        }
        Some(Commands::Plugins { action }) => {
            run_plugins_command(action).await?;
        }
        Some(Commands::Sessions) => {
            let summaries = Session::list_all()?;
            if summaries.is_empty() {
                println!("No sessions found. Run 'vigil run -- <agent>' to start one.");
                return Ok(());
            }
            println!(
                "{:<36}  {:<12}  {:<20}  {:>8}  {:>6}  {:>5}",
                "ID", "AGENT", "STARTED", "COST", "TOKENS", "VIOLS"
            );
            println!("{}", "-".repeat(95));
            for s in &summaries {
                let _duration = s
                    .ended_at
                    .map(|e| format_duration(e - s.started_at))
                    .unwrap_or_else(|| "running".to_string());
                println!(
                    "{:<36}  {:<12}  {:<20}  {:>8}  {:>6}  {:>5}",
                    s.id,
                    truncate(&s.agent, 12),
                    s.started_at.format("%Y-%m-%d %H:%M:%S"),
                    format!("${:.4}", s.total_cost_usd),
                    s.total_input_tokens + s.total_output_tokens,
                    s.policy_violations,
                );
            }
        }
        Some(Commands::Audit { session_id }) => {
            run_audit(&session_id)?;
        }
        Some(Commands::Verify { session_id }) => {
            run_verify(&session_id)?;
        }
        Some(Commands::Export { session_id, output }) => {
            run_export(&session_id, output.as_deref())?;
        }
        Some(Commands::Ps) => {
            run_ps()?;
        }
        Some(Commands::Fork { session_id, prefix_events, agent_and_args }) => {
            run_fork(&session_id, prefix_events, agent_and_args).await?;
        }
        Some(Commands::Proxy { port, policy, config, log_file, pii_watchlist, plugins, name }) => {
            let watchlist = load_pii_watchlist(pii_watchlist.as_deref());
            let config_path_str = config.as_deref().map(|p| p.display().to_string());
            let vigil_config = config.as_deref()
                .and_then(|p| vigil_core::VigilConfig::load(p).ok());
            let mut plugin_host = PluginHost::new();
            if let Ok(dir) = plugins_dir() {
                load_plugins_from_dir(&dir, &mut plugin_host);
            }
            for path in &plugins {
                match plugin_host.load_from_file(path) {
                    Ok(()) => println!("Loaded plugin: {}", path.display()),
                    Err(e) => eprintln!("Warning: {}", e),
                }
            }
            run_proxy_mode(port, policy, log_file.as_ref(), watchlist, vigil_config, config_path_str, plugin_host, name).await?;
        }
        Some(Commands::Replay { session_id }) => {
            let uuid = uuid::Uuid::parse_str(&session_id)
                .context("Invalid session ID — use the full UUID from 'vigil sessions'")?;

            let envelopes = vigil_core::store::SessionStore::load_envelopes(&uuid)?;
            if !envelopes.is_empty() {
                println!("Replaying session {} ({} events, NDJSON)...", session_id, envelopes.len());
                let (tx, rx) = tokio::sync::mpsc::channel(envelopes.len().max(1));
                let envelopes_clone = envelopes.clone();
                tokio::spawn(async move {
                    for (i, event) in envelopes_clone.iter().enumerate() {
                        if i > 0 {
                            let prev_ts = envelopes_clone[i - 1].timestamp;
                            let delta = event.timestamp.signed_duration_since(prev_ts);
                            let ms = delta.num_milliseconds().max(0).min(500) as u64;
                            if ms > 0 {
                                tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
                            }
                        }
                        if tx.send(event.clone()).await.is_err() {
                            break;
                        }
                    }
                });
                let meta = vigil_core::store::SessionStore::load_meta(&uuid).ok();
                let agent = meta.as_ref().map(|m| m.agent.clone()).unwrap_or_else(|| "unknown".to_string());
                let mut session = vigil_core::session::Session::new(agent);
                session.id = uuid;
                let mut app = App::new(session);
                app.is_replay = true;
                vigil_tui::run_tui(app, rx).await?;
            } else {
                let session = vigil_core::session::Session::load(&uuid)?;
                println!("Replaying session {} ({} events, JSON)...", session_id, session.events.len());
                let (tx, rx) = tokio::sync::mpsc::channel(session.events.len().max(1));
                for event in &session.events {
                    tx.try_send(event.clone()).ok();
                }
                drop(tx);
                let mut app = App::new(session);
                app.is_replay = true;
                vigil_tui::run_tui(app, rx).await?;
            }
        }
        Some(Commands::Prune { older_than, dry_run }) => {
            run_prune(older_than, dry_run)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// vigil audit
// ---------------------------------------------------------------------------

fn run_audit(session_id: &str) -> Result<()> {
    let uuid = uuid::Uuid::parse_str(session_id)
        .context("Invalid session ID — use the full UUID from 'vigil sessions'")?;

    let envelopes = vigil_core::store::SessionStore::load_envelopes(&uuid)?;
    let actual_count = envelopes.len();

    println!("vigil audit: {}", session_id);
    println!("Events:     {}", actual_count);

    // --- Hash chain check ---
    let mut chain_ok = true;
    let mut chain_msg = String::from("OK");
    let mut expected_prev = String::new();

    for (i, env) in envelopes.iter().enumerate() {
        if env.prev_hash != expected_prev {
            chain_ok = false;
            chain_msg = format!(
                "BROKEN at event {}, expected {} got {}",
                i,
                expected_prev,
                env.prev_hash
            );
            break;
        }
        expected_prev = env.compute_hash();
    }
    println!("Hash chain: {}", chain_msg);

    // --- ULID monotonicity check ---
    let mut ulid_ok = true;
    let mut ulid_msg = String::from("OK");

    if actual_count > 1 {
        for i in 1..envelopes.len() {
            let prev_str = envelopes[i - 1].event_id.to_string();
            let curr_str = envelopes[i].event_id.to_string();
            if curr_str <= prev_str {
                ulid_ok = false;
                ulid_msg = if curr_str == prev_str {
                    format!("DUPLICATE ULID at events {} and {}", i - 1, i)
                } else {
                    format!("OUT OF ORDER at event {}", i)
                };
                break;
            }
        }
    }
    println!("ULID order: {}", ulid_msg);

    // --- Meta count check ---
    let (meta_ok, meta_msg) = match vigil_core::store::SessionStore::load_meta(&uuid) {
        Ok(meta) => {
            if meta.event_count == actual_count as u64 {
                (true, String::from("OK"))
            } else {
                (
                    false,
                    format!(
                        "MISMATCH meta={} actual={}",
                        meta.event_count, actual_count
                    ),
                )
            }
        }
        Err(e) => (false, format!("MISSING ({})", e)),
    };
    println!("Meta count: {}", meta_msg);
    println!();

    let issues = [!chain_ok, !ulid_ok, !meta_ok]
        .iter()
        .filter(|&&f| f)
        .count();

    if issues == 0 {
        println!("PASS");
    } else {
        println!("FAIL -- {} issue(s) found", issues);
        std::process::exit(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// vigil verify
// ---------------------------------------------------------------------------

fn run_verify(session_id: &str) -> Result<()> {
    let uuid = uuid::Uuid::parse_str(session_id)
        .context("Invalid session ID — use the full UUID from 'vigil sessions'")?;

    let envelopes = vigil_core::store::SessionStore::load_envelopes(&uuid)?;
    let actual_count = envelopes.len();

    println!("vigil verify: {}", session_id);
    println!("Events:     {}", actual_count);

    // --- Hash chain ---
    let mut chain_ok = true;
    let mut chain_msg = String::from("OK");
    let mut expected_prev = String::new();
    let mut final_hash = String::new();

    for (i, env) in envelopes.iter().enumerate() {
        if env.prev_hash != expected_prev {
            chain_ok = false;
            chain_msg = format!(
                "BROKEN at event {}, expected {} got {}",
                i, expected_prev, env.prev_hash
            );
            break;
        }
        final_hash = env.compute_hash();
        expected_prev = final_hash.clone();
    }
    println!("Hash chain: {}", chain_msg);

    // --- ed25519 signature ---
    let (sig_ok, sig_msg) = match vigil_core::store::SessionStore::load_meta(&uuid) {
        Ok(meta) => {
            if meta.chain_signature.is_none() {
                (true, "SKIP (session predates signing)".to_string())
            } else if meta.chain_root_hash != final_hash {
                (false, format!("MISMATCH meta root={} actual={}", meta.chain_root_hash, final_hash))
            } else {
                match vigil_core::store::SessionStore::verify_signature(&meta, &final_hash) {
                    Ok(()) => (true, "OK".to_string()),
                    Err(e) => (false, format!("INVALID: {}", e)),
                }
            }
        }
        Err(e) => (false, format!("MISSING ({})", e)),
    };
    println!("Signature:  {}", sig_msg);
    println!();

    let issues = [!chain_ok, !sig_ok].iter().filter(|&&f| f).count();
    if issues == 0 {
        println!("PASS");
    } else {
        println!("FAIL -- {} issue(s) found", issues);
        std::process::exit(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// vigil export
// ---------------------------------------------------------------------------

fn run_export(session_id: &str, output: Option<&std::path::Path>) -> Result<()> {
    let uuid = uuid::Uuid::parse_str(session_id)
        .context("Invalid session ID — use the full UUID from 'vigil sessions'")?;

    let envelopes = vigil_core::store::SessionStore::load_envelopes(&uuid)?;
    if envelopes.is_empty() {
        anyhow::bail!("No events found for session {}", session_id);
    }

    let mut out_lines: Vec<String> = Vec::with_capacity(envelopes.len());
    for env in &envelopes {
        let mut val = serde_json::to_value(env)?;
        redact_json_value(&mut val);
        out_lines.push(serde_json::to_string(&val)?);
    }

    let content = out_lines.join("\n") + "\n";

    if let Some(path) = output {
        std::fs::write(path, &content)?;
        println!("Exported {} events (redacted) → {}", envelopes.len(), path.display());
    } else {
        print!("{}", content);
    }

    Ok(())
}

/// Recursively walk a JSON value and replace any string that contains PII
/// with "[REDACTED:<kind>]".
fn redact_json_value(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::String(s) => {
            let hits = vigil_core::scan_pii(s);
            if !hits.is_empty() {
                let labels: Vec<_> = hits.iter().map(|h| h.kind.as_str()).collect();
                *s = format!("[REDACTED:{}]", labels.join(","));
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() { redact_json_value(v); }
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() { redact_json_value(v); }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// vigil fork
// ---------------------------------------------------------------------------

async fn run_fork(
    session_id_str: &str,
    prefix_events: usize,
    agent_and_args: Vec<String>,
) -> Result<()> {
    let uuid = uuid::Uuid::parse_str(session_id_str)
        .context("Invalid session ID — use the full UUID from 'vigil sessions'")?;

    let envelopes = vigil_core::store::SessionStore::load_envelopes(&uuid)?;
    if envelopes.is_empty() {
        anyhow::bail!("Session {} not found or empty", session_id_str);
    }

    let prefix = if prefix_events == 0 {
        envelopes.len() // fork from end = full replay then go live
    } else {
        prefix_events.min(envelopes.len())
    };

    println!("vigil fork: {} ({} prefix events)", session_id_str, prefix);
    println!("Replaying prefix...");

    let meta = vigil_core::store::SessionStore::load_meta(&uuid).ok();
    let agent_name = if !agent_and_args.is_empty() {
        agent_and_args[0].clone()
    } else {
        meta.as_ref()
            .map(|m| m.agent.clone())
            .unwrap_or_else(|| "unknown".to_string())
    };

    let new_session_id = uuid::Uuid::new_v4();
    let store = vigil_core::store::SessionStore::create(new_session_id, &agent_name).ok();

    let (tx, rx) = tokio::sync::mpsc::channel::<vigil_core::TimestampedEvent>(1024);

    // Send prefix events instantly (no timestamp pacing)
    let prefix_envelopes = envelopes[..prefix].to_vec();
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        for env in prefix_envelopes {
            if tx_clone.send(env).await.is_err() {
                break;
            }
        }
        // tx_clone dropped here — if no live agent, TUI will see channel close
    });

    let mut session = vigil_core::session::Session::new(agent_name.clone());
    session.id = new_session_id;
    let mut app = App::new(session);
    app.store = store;
    app.is_replay = agent_and_args.is_empty();

    if agent_and_args.is_empty() {
        // Pure replay with no live continuation — drop our tx copy so the TUI
        // sees the channel close after the prefix is consumed.
        drop(tx);
        vigil_tui::run_tui(app, rx).await?;
    } else {
        // Show prefix in TUI first (instant replay), then start a live session.
        // Drop tx so the TUI exits after the prefix events are displayed.
        drop(tx);
        vigil_tui::run_tui(app, rx).await?;

        println!();
        println!("Fork prefix complete. Starting live session...");
        println!();

        let watchlist = load_pii_watchlist(None);
        let port = find_available_port(8877)?;
        run_agent(port, None, None, agent_and_args, watchlist, None, None).await?;
    }

    Ok(())
}

async fn run_interactive() -> Result<()> {
    let recent = Session::list_all().unwrap_or_default();
    let Some(command_line) = vigil_tui::run_launcher(recent).await? else {
        return Ok(());
    };
    let args = shell_split(&command_line);
    if args.is_empty() {
        return Ok(());
    }
    let watchlist = load_pii_watchlist(None);
    run_agent(8877, None, None, args, watchlist, None, None).await
}

/// Load PII watchlist terms: explicit file path first, then auto-load ~/.vigil/watchlist.txt.
fn load_pii_watchlist(explicit: Option<&std::path::Path>) -> Vec<String> {
    let path = if let Some(p) = explicit {
        p.to_path_buf()
    } else {
        let home = if cfg!(target_os = "windows") {
            std::env::var("USERPROFILE").ok()
        } else {
            std::env::var("HOME").ok()
        };
        match home {
            Some(h) => PathBuf::from(h).join(".vigil").join("watchlist.txt"),
            None => return vec![],
        }
    };

    match std::fs::read_to_string(&path) {
        Ok(content) => content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect(),
        Err(_) => vec![],
    }
}

/// Split a command string into argv-style tokens, respecting double-quoted groups.
fn shell_split(s: &str) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in s.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

async fn run_agent(
    port: u16,
    policy: Option<PathBuf>,
    log_file: Option<&PathBuf>,
    agent_and_args: Vec<String>,
    pii_watchlist: Vec<String>,
    config: Option<vigil_core::VigilConfig>,
    config_path: Option<String>,
) -> Result<()> {
    run_agent_with_plugins(port, policy, log_file, agent_and_args, pii_watchlist, config, config_path, PluginHost::new(), None).await
}

/// Start the proxy and TUI without spawning an agent process.
/// Use this with IDEs (Cursor, etc.) that connect to vigil via their own
/// "Override Base URL" setting rather than being launched by vigil.
pub async fn run_proxy_mode(
    port: u16,
    policy: Option<PathBuf>,
    log_file: Option<&PathBuf>,
    pii_watchlist: Vec<String>,
    config: Option<vigil_core::VigilConfig>,
    config_path: Option<String>,
    plugins: PluginHost,
    session_name: Option<String>,
) -> Result<()> {
    init_logging(log_file);

    let label = session_name.clone().unwrap_or_else(|| "proxy".to_string());
    let session = Session::new(label.clone());
    let session_id = session.id;
    let mut store = SessionStore::create(session_id, &label).ok();
    if let Some(ref n) = session_name {
        if let Some(ref mut s) = store { s.set_name(n.as_str()); }
    }

    let engine = if let Some(policy_path) = &policy {
        PolicyEngine::from_file(policy_path)?
    } else if let Some(cfg) = &config {
        let policies = cfg.to_policies();
        if policies.is_empty() { PolicyEngine::default() }
        else { PolicyEngine::new(vigil_core::PolicyConfig { policies })? }
    } else {
        PolicyEngine::default()
    };
    let engine = Arc::new(engine);

    let plugin_host = Arc::new(plugins);
    let ctx_start = make_plugin_ctx(session_id);
    plugin_host.dispatch_session_start(&ctx_start).await;
    let (raw_tx, mut raw_rx) = tokio::sync::mpsc::channel::<TimestampedEvent>(1000);
    let (filtered_tx, filtered_rx) = tokio::sync::mpsc::channel::<TimestampedEvent>(1000);

    let write_approval_threshold = config.as_ref()
        .and_then(|c| c.proxy.write_approval_threshold.as_deref())
        .and_then(|s| match s.to_lowercase().as_str() {
            "low" => Some(vigil_core::RiskLevel::Low),
            "medium" => Some(vigil_core::RiskLevel::Medium),
            "high" => Some(vigil_core::RiskLevel::High),
            _ => None,
        });

    let (decision_tx, mut decision_rx) = tokio::sync::mpsc::channel::<(uuid::Uuid, bool)>(32);

    let outbound_hook: Option<vigil_proxy::OutboundHookFn> = if plugin_host.is_empty() {
        None
    } else {
        let ph = plugin_host.clone();
        let ctx = make_plugin_ctx(session_id);
        Some(std::sync::Arc::new(move |provider: String, body: serde_json::Value| {
            let ph = ph.clone();
            let ctx = ctx.clone();
            Box::pin(async move { ph.dispatch_outbound_request(&ctx, &provider, &body).await })
                as std::pin::Pin<Box<dyn std::future::Future<Output = Option<serde_json::Value>> + Send>>
        }))
    };

    let proxy_config = vigil_proxy::ProxyConfig {
        port,
        ca_cert_path: None,
        upstream_override: None,
        pii_watchlist,
        write_approval_threshold,
        outbound_hook,
    };
    let proxy = vigil_proxy::Proxy::new(proxy_config, raw_tx.clone());
    let pending_approvals_for_resolver = proxy.pending_approvals.clone();
    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = proxy.run().await {
            tracing::error!(err = %e, "proxy error");
        }
    });

    let resolver_handle = tokio::spawn(async move {
        while let Some((approval_id, approved)) = decision_rx.recv().await {
            let tx = { pending_approvals_for_resolver.lock().unwrap().remove(&approval_id) };
            if let Some(tx) = tx { let _ = tx.send(approved); }
        }
    });

    println!("vigil v{} — proxy mode", env!("CARGO_PKG_VERSION"));
    println!("Session ID: {}", session_id);
    println!("Proxy listening on http://127.0.0.1:{}", port);
    println!();
    println!("Point your agent or IDE at this proxy:");
    println!("  Anthropic: ANTHROPIC_BASE_URL=http://127.0.0.1:{}", port);
    println!("  OpenAI:    OPENAI_BASE_URL=http://127.0.0.1:{}", port);
    println!("  Cursor:    Settings > Models > Override OpenAI Base URL = http://127.0.0.1:{}/v1", port);
    println!();
    println!("Press 'q' in the dashboard to stop.");
    println!();

    let loop_threshold = config.as_ref().and_then(|c| c.budget.loop_detect_threshold).unwrap_or(5);
    let plugin_host_filter = plugin_host.clone();
    let engine_clone = engine.clone();
    let filter_handle = tokio::spawn(async move {
        let mut loop_detector = LoopDetector::new(loop_threshold);
        let mut cred_tracker = CredentialTracker::new();
        while let Some(event) = raw_rx.recv().await {
            if let Event::FsRead { path, .. } = &event.event {
                if let Ok(content) = std::fs::read_to_string(path) {
                    cred_tracker.ingest_file(&content, path);
                }
            }
            if let Event::ToolCall { tool_name, input, session_id: sid, .. } = &event.event {
                let input_str = serde_json::to_string(input).unwrap_or_default();
                if let Some(count) = loop_detector.check(tool_name, &input_str) {
                    let detail = serde_json::json!({"tool_name": tool_name, "repeat_count": count});
                    let alert = TimestampedEvent::new(Event::LoopAlert {
                        tool_name: tool_name.clone(), repeat_count: count, session_id: *sid,
                    });
                    let ctx = make_plugin_ctx(*sid);
                    plugin_host_filter.dispatch_alert(&ctx, AlertLabel::Loop, &detail).await;
                    plugin_host_filter.dispatch_event(&ctx, &alert).await;
                    filtered_tx.send(alert).await.ok();
                }
            }

            // Credential exfiltration detection — check child process command-line args
            if let Event::ProcessSpawn { command, args, session_id: sid } = &event.event {
                if !cred_tracker.is_empty() {
                    let mut combined = command.clone();
                    for arg in args {
                        combined.push(' ');
                        combined.push_str(arg);
                    }
                    let hits = cred_tracker.check_outbound(&combined);
                    if !hits.is_empty() {
                        let detail = serde_json::json!({"source": command, "matches": hits});
                        let alert = TimestampedEvent::new(Event::ExfilAlert {
                            matches: hits.clone(),
                            source: command.clone(),
                            session_id: *sid,
                        });
                        let ctx = make_plugin_ctx(*sid);
                        plugin_host_filter.dispatch_alert(&ctx, AlertLabel::Exfil, &detail).await;
                        plugin_host_filter.dispatch_event(&ctx, &alert).await;
                        filtered_tx.send(alert).await.ok();
                    }
                }
            }

            let decision = engine_clone.evaluate(&event.event, 0);
            match decision.action {
                vigil_core::PolicyAction::Deny => {
                    if let Event::ToolCall { agent, tool_name, session_id, .. } = &event.event {
                        let detail = serde_json::json!({"tool_name": tool_name, "policy": decision.policy_name, "reason": decision.reason});
                        let ctx = make_plugin_ctx(*session_id);
                        plugin_host_filter.dispatch_alert(&ctx, AlertLabel::Deny, &detail).await;
                        let blocked = TimestampedEvent::new(Event::ToolCallResult {
                            agent: agent.clone(), tool_name: tool_name.clone(),
                            blocked: true, session_id: *session_id,
                        });
                        plugin_host_filter.dispatch_event(&ctx, &blocked).await;
                        filtered_tx.send(blocked).await.ok();
                    }
                }
                _ => {
                    if let Event::ToolCall { tool_name, input, agent, session_id, .. } = &event.event {
                        let ctx = make_plugin_ctx(*session_id);
                        if let PluginDecision::Deny(reason) = plugin_host_filter.dispatch_tool_call(&ctx, tool_name, input).await {
                            let detail = serde_json::json!({"tool_name": tool_name, "policy": "plugin", "reason": reason});
                            plugin_host_filter.dispatch_alert(&ctx, AlertLabel::Deny, &detail).await;
                            let blocked = TimestampedEvent::new(Event::ToolCallResult {
                                agent: agent.clone(), tool_name: tool_name.clone(),
                                blocked: true, session_id: *session_id,
                            });
                            plugin_host_filter.dispatch_event(&ctx, &blocked).await;
                            filtered_tx.send(blocked).await.ok();
                            continue;
                        }
                        plugin_host_filter.dispatch_event(&ctx, &event).await;
                    } else {
                        let ctx = make_plugin_ctx(session_id);
                        plugin_host_filter.dispatch_event(&ctx, &event).await;
                    }
                    filtered_tx.send(event).await.ok();
                }
            }
        }
    });

    let mut app = App::new(session);
    app.store = store;
    app.config_path = config_path;
    app.decision_tx = Some(decision_tx);
    vigil_tui::run_tui(app, filtered_rx).await?;

    proxy_handle.abort();
    filter_handle.abort();
    resolver_handle.abort();
    let ctx_end = make_plugin_ctx(session_id);
    plugin_host.dispatch_session_end(&ctx_end).await;
    Ok(())
}

pub async fn run_agent_with_plugins(
    port: u16,
    policy: Option<PathBuf>,
    log_file: Option<&PathBuf>,
    agent_and_args: Vec<String>,
    pii_watchlist: Vec<String>,
    config: Option<vigil_core::VigilConfig>,
    config_path: Option<String>,
    plugins: PluginHost,
    session_name: Option<String>,
) -> Result<()> {
    init_logging(log_file);

    if agent_and_args.is_empty() {
        anyhow::bail!("No agent command provided");
    }

    let agent_name = agent_and_args[0].clone();
    let session = Session::new(agent_name.clone());
    let session_id = session.id;
    let mut store = SessionStore::create(session_id, &agent_name).ok();

    if let Some(ref n) = session_name {
        if let Some(ref mut s) = store { s.set_name(n.as_str()); }
    }

    let active_handle = vigil_core::create_handle(&session_id).ok();
    if let Some(ref handle) = active_handle {
        let _ = handle.write(&vigil_core::ActiveSession {
            session_id,
            agent: agent_name.clone(),
            started_at: chrono::Utc::now(),
            session_cost_usd: 0.0,
            session_tokens: 0,
            burn_rate_per_min: 0.0,
            last_event: "starting".to_string(),
            needs_attention: false,
            pid: std::process::id(),
        });
    }

    let engine = if let Some(policy_path) = &policy {
        PolicyEngine::from_file(policy_path)?
    } else if let Some(cfg) = &config {
        let policies = cfg.to_policies();
        if policies.is_empty() {
            PolicyEngine::default()
        } else {
            PolicyEngine::new(vigil_core::PolicyConfig { policies })?
        }
    } else {
        PolicyEngine::default()
    };
    let engine = Arc::new(engine);

    // Warn when no enforcement is active. Check the compiled policy count rather
    // than the raw config lists so defaults (blocked_commands) are counted too.
    let observational_only = config.is_none() || engine.policy_count() == 0;

    let budget_enforcer = config.as_ref().map(|c| BudgetEnforcer::new(c.budget.clone()));
    let burn_rate_limit = config.as_ref().and_then(|c| c.budget.max_burn_rate_usd_per_min);
    let loop_threshold = config.as_ref()
        .and_then(|c| c.budget.loop_detect_threshold)
        .unwrap_or(5);
    let tool_timeout_secs = config.as_ref().and_then(|c| c.proxy.tool_timeout_secs);
    let tool_timeout_kill_secs = config.as_ref().and_then(|c| c.proxy.tool_timeout_kill_secs);
    let cost_alert_usd = config.as_ref().and_then(|c| c.budget.cost_alert_usd);
    let max_session_duration_mins = config.as_ref().and_then(|c| c.budget.max_session_duration_mins);
    let webhook_notifier = config.as_ref()
        .and_then(|c| c.notify.webhook.clone())
        .map(|url| vigil_core::WebhookNotifier::new(url,
            config.as_ref().map(|c| c.notify.webhook_events.clone()).unwrap_or_default()));

    let plugin_host = Arc::new(plugins);

    let (raw_tx, mut raw_rx) = tokio::sync::mpsc::channel::<TimestampedEvent>(1000);
    let (filtered_tx, filtered_rx) = tokio::sync::mpsc::channel::<TimestampedEvent>(1000);

    println!("vigil v{}", env!("CARGO_PKG_VERSION"));
    println!("Session ID: {}", session_id);
    println!("Agent: {}", agent_name);
    if let Some(lf) = log_file {
        println!("Log file: {} (tail -f to watch in another terminal)", lf.display());
    }
    println!();
    println!("Starting proxy on port {}...", port);
    println!("Routing agent traffic via ANTHROPIC_BASE_URL=http://127.0.0.1:{}", port);
    println!();
    println!("Press 'q' in the dashboard to quit");
    if observational_only {
        println!("NOTE: running in observational mode — no blocked_commands or policies configured.");
    }
    println!();

    let proxy_url = format!("http://127.0.0.1:{}", port);
    tracing::info!(port, "starting vigil proxy");

    let write_approval_threshold = config.as_ref()
        .and_then(|c| c.proxy.write_approval_threshold.as_deref())
        .and_then(|s| match s.to_lowercase().as_str() {
            "low" => Some(vigil_core::RiskLevel::Low),
            "medium" => Some(vigil_core::RiskLevel::Medium),
            "high" => Some(vigil_core::RiskLevel::High),
            _ => None,
        });

    let (decision_tx, mut decision_rx) = tokio::sync::mpsc::channel::<(uuid::Uuid, bool)>(32);

    let outbound_hook: Option<vigil_proxy::OutboundHookFn> = if plugin_host.is_empty() {
        None
    } else {
        let ph = plugin_host.clone();
        let ctx = make_plugin_ctx(session_id);
        Some(std::sync::Arc::new(move |provider: String, body: serde_json::Value| {
            let ph = ph.clone();
            let ctx = ctx.clone();
            Box::pin(async move { ph.dispatch_outbound_request(&ctx, &provider, &body).await })
                as std::pin::Pin<Box<dyn std::future::Future<Output = Option<serde_json::Value>> + Send>>
        }))
    };

    let proxy_config = vigil_proxy::ProxyConfig {
        port,
        ca_cert_path: None,
        upstream_override: None,
        pii_watchlist,
        write_approval_threshold,
        outbound_hook,
    };
    let proxy = Proxy::new(proxy_config, raw_tx.clone());
    let pending_approvals_for_resolver = proxy.pending_approvals.clone();
    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = proxy.run().await {
            tracing::error!(err = %e, "proxy error");
            eprintln!("Proxy error: {}", e);
        }
    });

    let resolver_handle = tokio::spawn(async move {
        while let Some((approval_id, approved)) = decision_rx.recv().await {
            let tx = {
                let mut map = pending_approvals_for_resolver.lock().unwrap();
                map.remove(&approval_id)
            };
            if let Some(tx) = tx {
                let _ = tx.send(approved);
            }
        }
    });

    // Spawn the agent process.
    // On Windows: CreateProcessW with bInheritHandles=FALSE + CREATE_NEW_CONSOLE
    //   → Claude gets its own console window with proper stdin/stdout/stderr.
    // On other platforms: tokio Command in the same terminal (no TUI collision there).
    tracing::info!(cmd = %agent_name, "spawning agent");

    #[cfg(windows)]
    let (child_pid, child_wait_handle) = {
        let extra_env = [("ANTHROPIC_BASE_URL", proxy_url.as_str())];
        let child = win_console::spawn(&agent_and_args[0], &agent_and_args[1..], &extra_env)?;
        let pid = child.pid();
        let wait_handle = win_console::wait_task(child);
        (pid, wait_handle)
    };

    #[cfg(not(windows))]
    let (child_pid, mut tokio_child) = {
        use tokio::process::Command;
        let mut cmd = Command::new(&agent_and_args[0]);
        if agent_and_args.len() > 1 {
            cmd.args(&agent_and_args[1..]);
        }
        cmd.env("ANTHROPIC_BASE_URL", &proxy_url);
        let mut child = cmd.spawn()?;
        let pid = child.id().unwrap_or(0);
        (pid, child)
    };

    tracing::info!(pid = child_pid, "agent process started");

    let ctx_start = make_plugin_ctx(session_id);
    plugin_host.dispatch_session_start(&ctx_start).await;

    let watch_config = WatchConfig {
        watch_path: std::env::current_dir()?,
        agent_pid: child_pid,
        session_id,
    };
    let watcher = Watcher::new(watch_config, raw_tx.clone());
    let watcher_handle = tokio::spawn(async move {
        if let Err(e) = watcher.run().await {
            tracing::error!(err = %e, "watcher error");
            eprintln!("Watcher error: {}", e);
        }
    });

    // Shared state for tool timeout tracking: (started_at, tool_name, alerted)
    let last_tool_call: std::sync::Arc<std::sync::Mutex<Option<(std::time::Instant, String, bool)>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));

    if let Some(timeout_secs) = tool_timeout_secs {
        let state = last_tool_call.clone();
        let tx = filtered_tx.clone();
        let sid = session_id;
        let kill_secs = tool_timeout_kill_secs;
        let kill_pid = child_pid;
        let plugin_host_tout = plugin_host.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(5));
            loop {
                ticker.tick().await;
                let snapshot = state.lock().ok()
                    .and_then(|g| g.as_ref().map(|(t, n, a)| (t.elapsed(), n.clone(), *a)));
                if let Some((elapsed, tool_name, alerted)) = snapshot {
                    let secs = elapsed.as_secs();
                    if secs >= timeout_secs && !alerted {
                        if let Ok(mut g) = state.lock() {
                            if let Some(ref mut v) = *g { v.2 = true; }
                        }
                        let ev = TimestampedEvent::new(Event::ToolTimeout {
                            tool_name: tool_name.clone(),
                            elapsed_secs: secs,
                            session_id: sid,
                        });
                        let detail = serde_json::json!({"tool_name": tool_name, "elapsed_secs": secs});
                        let ctx = make_plugin_ctx(sid);
                        plugin_host_tout.dispatch_alert(&ctx, AlertLabel::Timeout, &detail).await;
                        plugin_host_tout.dispatch_event(&ctx, &ev).await;
                        tx.send(ev).await.ok();
                        eprintln!("[TIMEOUT] Tool '{}' has been running {}s with no response", tool_name, secs);
                    }
                    if let Some(ks) = kill_secs {
                        if secs >= ks {
                            eprintln!("[TIMEOUT] Killing agent (pid {}) after {}s", kill_pid, secs);
                            #[cfg(windows)]
                            { let _ = std::process::Command::new("taskkill")
                                .args(["/PID", &kill_pid.to_string(), "/F"]).output(); }
                            #[cfg(not(windows))]
                            { let _ = std::process::Command::new("kill")
                                .args(["-TERM", &kill_pid.to_string()]).output(); }
                            break;
                        }
                    }
                }
            }
        });
    }

    // Session duration timer — fires once after max_session_duration_mins.
    if let Some(duration_mins) = max_session_duration_mins {
        let tx = filtered_tx.clone();
        let sid = session_id;
        let notifier = webhook_notifier.clone();
        let plugin_host_dura = plugin_host.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(duration_mins * 60)).await;
            let ev = TimestampedEvent::new(Event::SessionDurationAlert {
                elapsed_mins: duration_mins,
                session_id: sid,
            });
            let detail = serde_json::json!({"elapsed_mins": duration_mins});
            if let Some(ref n) = notifier {
                n.send("DURA", &sid.to_string(), detail.clone());
            }
            let ctx = make_plugin_ctx(sid);
            plugin_host_dura.dispatch_alert(&ctx, AlertLabel::Duration, &detail).await;
            plugin_host_dura.dispatch_event(&ctx, &ev).await;
            tx.send(ev).await.ok();
            eprintln!("[DURATION] Session has been running {}min", duration_mins);
        });
    }

    // Policy filter: evaluate every raw event and forward allowed ones to the TUI.
    let lock_path = active_handle.as_ref().map(|h| h.path.clone());
    let engine_clone = engine.clone();
    let session_id_for_alerts = session_id;
    let last_tool_call_filter = last_tool_call.clone();
    let notifier_filter = webhook_notifier.clone();
    let plugin_host_filter = plugin_host.clone();
    let filter_handle = tokio::spawn(async move {
        let mut session_tokens = 0u32;
        let mut session_cost = 0f64;
        let mut cost_alerted = false;
        let mut burn_tracker = BurnRateTracker::new();
        let mut loop_detector = LoopDetector::new(loop_threshold);
        let mut cred_tracker = CredentialTracker::new();
        while let Some(event) = raw_rx.recv().await {
            // Tool timeout tracking: arm on ToolCall, disarm on LlmRequest
            if let Event::ToolCall { tool_name, .. } = &event.event {
                if let Ok(mut g) = last_tool_call_filter.lock() {
                    *g = Some((std::time::Instant::now(), tool_name.clone(), false));
                }
            }
            // Disarm on any event that signals the tool finished: normal completion
            // (LlmRequest) or blocked by policy (ToolCallResult { blocked: true }).
            if matches!(&event.event,
                Event::LlmRequest { .. }
                | Event::ToolCallResult { .. }
            ) {
                if let Ok(mut g) = last_tool_call_filter.lock() {
                    *g = None;
                }
            }

            if let Event::LlmRequest { input_tokens, .. } = &event.event {
                session_tokens = session_tokens.saturating_add(*input_tokens);
            }

            // Credential exfiltration detection — ingest file reads
            if let Event::FsRead { path, .. } = &event.event {
                if let Ok(content) = std::fs::read_to_string(path) {
                    cred_tracker.ingest_file(&content, path);
                }
            }

            // Credential exfiltration detection — check LLM prompts
            if let Event::LlmRequest { last_user_message, system_prompt, session_id: sid, .. } = &event.event {
                if !cred_tracker.is_empty() {
                    let mut combined = String::new();
                    if let Some(msg) = last_user_message { combined.push_str(msg); combined.push('\n'); }
                    if let Some(sys) = system_prompt { combined.push_str(sys); combined.push('\n'); }
                    if !combined.is_empty() {
                        let hits = cred_tracker.check_outbound(&combined);
                        if !hits.is_empty() {
                            let detail = serde_json::json!({"source": "llm_request", "matches": hits});
                            let alert = TimestampedEvent::new(Event::ExfilAlert {
                                matches: hits.clone(),
                                source: "llm_request".to_string(),
                                session_id: *sid,
                            });
                            if let Some(ref n) = notifier_filter {
                                n.send("EXFL", &sid.to_string(), detail.clone());
                            }
                            let ctx = make_plugin_ctx(*sid);
                            plugin_host_filter.dispatch_alert(&ctx, AlertLabel::Exfil, &detail).await;
                            plugin_host_filter.dispatch_event(&ctx, &alert).await;
                            filtered_tx.send(alert).await.ok();
                        }
                    }
                }
            }

            // Credential exfiltration detection — check shell tool call inputs
            if let Event::ToolCall { tool_name, input, session_id: sid, .. } = &event.event {
                let shell_tools = ["Bash", "bash", "shell", "run_command", "execute"];
                if shell_tools.iter().any(|t| tool_name.eq_ignore_ascii_case(t)) {
                    if !cred_tracker.is_empty() {
                        let cmd = input.to_string();
                        let hits = cred_tracker.check_outbound(&cmd);
                        if !hits.is_empty() {
                            let detail = serde_json::json!({"source": tool_name, "matches": hits});
                            let alert = TimestampedEvent::new(Event::ExfilAlert {
                                matches: hits.clone(),
                                source: tool_name.clone(),
                                session_id: *sid,
                            });
                            if let Some(ref n) = notifier_filter {
                                n.send("EXFL", &sid.to_string(), detail.clone());
                            }
                            let ctx = make_plugin_ctx(*sid);
                            plugin_host_filter.dispatch_alert(&ctx, AlertLabel::Exfil, &detail).await;
                            plugin_host_filter.dispatch_event(&ctx, &alert).await;
                            filtered_tx.send(alert).await.ok();
                        }
                    }
                }
            }

            // Credential exfiltration detection — check child process command-line args
            if let Event::ProcessSpawn { command, args, session_id: sid } = &event.event {
                if !cred_tracker.is_empty() {
                    let mut combined = command.clone();
                    for arg in args {
                        combined.push(' ');
                        combined.push_str(arg);
                    }
                    let hits = cred_tracker.check_outbound(&combined);
                    if !hits.is_empty() {
                        let detail = serde_json::json!({"source": command, "matches": hits});
                        let alert = TimestampedEvent::new(Event::ExfilAlert {
                            matches: hits.clone(),
                            source: command.clone(),
                            session_id: *sid,
                        });
                        if let Some(ref n) = notifier_filter {
                            n.send("EXFL", &sid.to_string(), detail.clone());
                        }
                        let ctx = make_plugin_ctx(*sid);
                        plugin_host_filter.dispatch_alert(&ctx, AlertLabel::Exfil, &detail).await;
                        plugin_host_filter.dispatch_event(&ctx, &alert).await;
                        filtered_tx.send(alert).await.ok();
                    }
                }
            }

            if let Event::LlmResponse { input_tokens, output_tokens, cost_usd, .. } = &event.event {
                session_tokens = session_tokens.saturating_add(input_tokens.saturating_add(*output_tokens));
                session_cost += cost_usd;
                if let Some(ref path) = lock_path {
                    vigil_core::update_active(path, |s| {
                        s.session_cost_usd = session_cost;
                        s.session_tokens = session_tokens;
                        s.last_event = "RES".to_string();
                    });
                }
            }

            // Soft cost alert — fires once when cost_alert_usd threshold is crossed
            if !cost_alerted {
                if let Some(threshold) = cost_alert_usd {
                    if session_cost >= threshold {
                        cost_alerted = true;
                        let detail = serde_json::json!({"threshold_usd": threshold, "session_cost_usd": session_cost});
                        let alert = TimestampedEvent::new(Event::CostAlert {
                            threshold_usd: threshold,
                            session_cost_usd: session_cost,
                            session_id: session_id_for_alerts,
                        });
                        if let Some(ref n) = notifier_filter {
                            n.send("COST", &session_id_for_alerts.to_string(), detail.clone());
                        }
                        let ctx = make_plugin_ctx(session_id_for_alerts);
                        plugin_host_filter.dispatch_alert(&ctx, AlertLabel::Cost, &detail).await;
                        plugin_host_filter.dispatch_event(&ctx, &alert).await;
                        filtered_tx.send(alert).await.ok();
                        eprintln!("[COST] Session cost ${:.4} crossed alert threshold ${:.4}", session_cost, threshold);
                    }
                }
            }

            if let Event::LlmResponse { cost_usd, .. } = &event.event {
                let (rate, projected) = burn_tracker.record(*cost_usd);
                if let Some(limit) = burn_rate_limit {
                    if rate > limit {
                        let detail = serde_json::json!({"rate_per_min_usd": rate, "projected_total_usd": projected});
                        let alert = TimestampedEvent::new(Event::BurnRateAlert {
                            rate_per_min_usd: rate,
                            projected_total_usd: projected,
                            session_cost_usd: session_cost,
                            session_id: session_id_for_alerts,
                        });
                        if let Some(ref n) = notifier_filter {
                            n.send("BURN", &session_id_for_alerts.to_string(), detail.clone());
                        }
                        let ctx = make_plugin_ctx(session_id_for_alerts);
                        plugin_host_filter.dispatch_alert(&ctx, AlertLabel::BurnRate, &detail).await;
                        plugin_host_filter.dispatch_event(&ctx, &alert).await;
                        filtered_tx.send(alert).await.ok();
                        if let Some(ref path) = lock_path {
                            vigil_core::update_active(path, |s| {
                                s.burn_rate_per_min = rate;
                                s.needs_attention = true;
                                s.last_event = "BURN".to_string();
                            });
                        }
                    }
                }
            }

            if let Event::ToolCall { tool_name, input, session_id: sid, .. } = &event.event {
                let input_str = serde_json::to_string(input).unwrap_or_default();
                if let Some(count) = loop_detector.check(tool_name, &input_str) {
                    let detail = serde_json::json!({"tool_name": tool_name, "repeat_count": count});
                    let alert = TimestampedEvent::new(Event::LoopAlert {
                        tool_name: tool_name.clone(),
                        repeat_count: count,
                        session_id: *sid,
                    });
                    if let Some(ref n) = notifier_filter {
                        n.send("LOOP", &sid.to_string(), detail.clone());
                    }
                    let ctx = make_plugin_ctx(*sid);
                    plugin_host_filter.dispatch_alert(&ctx, AlertLabel::Loop, &detail).await;
                    plugin_host_filter.dispatch_event(&ctx, &alert).await;
                    filtered_tx.send(alert).await.ok();
                    if let Some(ref path) = lock_path {
                        vigil_core::update_active(path, |s| {
                            s.needs_attention = true;
                            s.last_event = "LOOP".to_string();
                        });
                    }
                }
            }

            if let Some(ref enforcer) = budget_enforcer {
                match enforcer.check(session_cost, session_tokens) {
                    BudgetStatus::Ok => {}
                    BudgetStatus::CostExceeded { limit, actual } => {
                        tracing::warn!(limit, actual, "budget: cost limit exceeded");
                        eprintln!("[BUDGET] Cost limit ${:.4} exceeded (actual ${:.4}) — stopping", limit, actual);
                        break;
                    }
                    BudgetStatus::TokensExceeded { limit, actual } => {
                        tracing::warn!(limit, actual, "budget: token limit exceeded");
                        eprintln!("[BUDGET] Token limit {} exceeded (actual {}) — stopping", limit, actual);
                        break;
                    }
                    BudgetStatus::OutsideAllowedHours { window } => {
                        tracing::warn!(%window, "budget: outside allowed hours");
                        eprintln!("[BUDGET] Outside allowed hours {} — stopping", window);
                        break;
                    }
                }
            }

            if let Event::WriteApprovalRequired { .. } = &event.event {
                if let Some(ref path) = lock_path {
                    vigil_core::update_active(path, |s| {
                        s.needs_attention = true;
                        s.last_event = "WAPPR".to_string();
                    });
                }
            }

            let decision = engine_clone.evaluate(&event.event, session_tokens);
            tracing::debug!(
                action = ?decision.action,
                policy = ?decision.policy_name,
                "policy decision"
            );

            match decision.action {
                vigil_core::PolicyAction::Deny => {
                    tracing::warn!(
                        policy = ?decision.policy_name,
                        reason = ?decision.reason,
                        "event denied by policy"
                    );
                    eprintln!(
                        "[POLICY DENY] {} — {}",
                        decision.policy_name.as_deref().unwrap_or("hardcoded"),
                        decision.reason.as_deref().unwrap_or("")
                    );
                    if let Event::ToolCall {
                        agent,
                        tool_name,
                        session_id,
                        ..
                    } = &event.event
                    {
                        let detail = serde_json::json!({
                            "tool_name": tool_name,
                            "policy": decision.policy_name,
                            "reason": decision.reason,
                        });
                        if let Some(ref n) = notifier_filter {
                            n.send("DENY", &session_id.to_string(), detail.clone());
                        }
                        let ctx = make_plugin_ctx(*session_id);
                        plugin_host_filter.dispatch_alert(&ctx, AlertLabel::Deny, &detail).await;
                        let blocked = TimestampedEvent::new(Event::ToolCallResult {
                            agent: agent.clone(),
                            tool_name: tool_name.clone(),
                            blocked: true,
                            session_id: *session_id,
                        });
                        plugin_host_filter.dispatch_event(&ctx, &blocked).await;
                        filtered_tx.send(blocked).await.ok();
                    }
                }
                _ => {
                    // After policy allows, consult plugins for tool calls.
                    if let Event::ToolCall { tool_name, input, agent, session_id, .. } = &event.event {
                        let ctx = make_plugin_ctx(*session_id);
                        if let PluginDecision::Deny(reason) = plugin_host_filter.dispatch_tool_call(&ctx, tool_name, input).await {
                            eprintln!("[PLUGIN DENY] {} — {}", tool_name, reason);
                            let detail = serde_json::json!({
                                "tool_name": tool_name,
                                "policy": "plugin",
                                "reason": reason,
                            });
                            if let Some(ref n) = notifier_filter {
                                n.send("DENY", &session_id.to_string(), detail.clone());
                            }
                            plugin_host_filter.dispatch_alert(&ctx, AlertLabel::Deny, &detail).await;
                            let blocked = TimestampedEvent::new(Event::ToolCallResult {
                                agent: agent.clone(),
                                tool_name: tool_name.clone(),
                                blocked: true,
                                session_id: *session_id,
                            });
                            plugin_host_filter.dispatch_event(&ctx, &blocked).await;
                            filtered_tx.send(blocked).await.ok();
                            continue;
                        }
                        plugin_host_filter.dispatch_event(&ctx, &event).await;
                    } else {
                        let ctx = make_plugin_ctx(session_id_for_alerts);
                        plugin_host_filter.dispatch_event(&ctx, &event).await;
                    }
                    filtered_tx.send(event).await.ok();
                }
            }
        }
    });

    let mut app = App::new(session);
    app.store = store;
    app.config_path = config_path;
    app.decision_tx = Some(decision_tx);
    let mut tui_handle = tokio::spawn(async move { vigil_tui::run_tui(app, filtered_rx).await });

    // Wait for TUI exit (user pressed q) or agent exit — whichever comes first.
    // When the agent exits first, give in-flight proxy tasks a window to emit
    // their final LlmResponse events before we abort the filter and close the TUI.
    #[cfg(windows)]
    tokio::select! {
        _ = &mut tui_handle => {
            tracing::info!("TUI exited");
        }
        _ = child_wait_handle => {
            tracing::info!("agent process exited");
            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
            filter_handle.abort();
        }
    }

    #[cfg(not(windows))]
    tokio::select! {
        _ = &mut tui_handle => {
            tracing::info!("TUI exited");
        }
        _ = tokio_child.wait() => {
            tracing::info!("agent process exited");
            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
            filter_handle.abort();
        }
    }

    let final_app = tui_handle.await.ok().and_then(|r| r.ok());

    proxy_handle.abort();
    watcher_handle.abort();
    filter_handle.abort();
    resolver_handle.abort();

    if let Some(mut app) = final_app {
        app.session.finish();
        if let Some(ref mut store) = app.store {
            match store.finish() {
                Ok(()) => {
                    tracing::info!(path = %store.ndjson_path.display(), "session saved");
                    println!("Session saved: {}", store.ndjson_path.display());
                }
                Err(e) => {
                    tracing::error!(err = %e, "failed to save session");
                    eprintln!("Failed to save session: {}", e);
                }
            }
        }

        println!();
        println!("Session complete: {}", session_id);
        println!("Agent: {}", agent_name);
        println!("Total cost: {}", app.session.cost_summary());
        println!("Policy violations: {}", app.session.policy_violations);
    } else {
        println!();
        println!("Session complete: {}", session_id);
        println!("Agent: {}", agent_name);
    }

    let ctx_end = make_plugin_ctx(session_id);
    plugin_host.dispatch_session_end(&ctx_end).await;

    if let Some(ref handle) = active_handle {
        handle.remove();
    }

    Ok(())
}

fn run_ps() -> anyhow::Result<()> {
    let sessions = vigil_core::list_active();
    if sessions.is_empty() {
        println!("No active vigil sessions.");
        return Ok(());
    }
    println!(
        "{:<36}  {:<12}  {:>10}  {:>8}  {:>10}  {}",
        "SESSION ID", "AGENT", "TOKENS", "COST", "$/MIN", "STATUS"
    );
    println!("{}", "-".repeat(85));
    for s in &sessions {
        let status = if s.needs_attention {
            "! ATTENTION".to_string()
        } else {
            s.last_event.clone()
        };
        println!(
            "{:<36}  {:<12}  {:>10}  {:>8}  {:>10}  {}",
            s.session_id,
            truncate(&s.agent, 12),
            s.session_tokens,
            format!("${:.4}", s.session_cost_usd),
            format!("${:.3}/m", s.burn_rate_per_min),
            status,
        );
    }
    Ok(())
}

fn detect_project_type() -> &'static str {
    let current_dir = std::path::Path::new(".");
    if current_dir.join("Cargo.toml").exists() {
        "rust"
    } else if current_dir.join("package.json").exists() {
        "node"
    } else if current_dir.join("pyproject.toml").exists()
        || current_dir.join("requirements.txt").exists()
    {
        "python"
    } else if current_dir.join("go.mod").exists() {
        "go"
    } else if current_dir.join("Gemfile").exists() {
        "ruby"
    } else if current_dir.join("pom.xml").exists() || current_dir.join("build.gradle").exists() {
        "java"
    } else {
        "generic"
    }
}

fn generate_policy_yaml(project_type: &str) -> String {
    let base_policies = r#"# vigil policy — generated by `vigil init`
# Docs: https://github.com/vigil-dev/vigil

policies:
  # Block shell commands that could destroy data
  - name: block-destructive-shell
    matcher:
      type: ToolCall
      tool_name_pattern: "Bash"
    action: Confirm

  # Warn when token spend is high
  - name: token-budget-1m
    matcher:
      type: TokenBudget
      max_tokens: 1000000
    action: LogOnly

  # Block writes outside the project root
  - name: no-writes-outside-project
    matcher:
      type: FsWriteOutside
      root: "."
    action: Deny
"#;

    match project_type {
        "rust" => format!(
            "{}{}",
            base_policies,
            r#"
  # Protect secrets from leaking
  - name: no-env-reads
    matcher:
      type: FsPath
      path_pattern: ".env"
    action: LogOnly

  # Don't let agent modify CI config without confirmation
  - name: confirm-ci-changes
    matcher:
      type: FsPath
      path_pattern: ".github"
    action: Confirm
"#
        ),
        "node" => format!(
            "{}{}",
            base_policies,
            r#"
  # Node: protect secrets
  - name: no-env-reads
    matcher:
      type: FsPath
      path_pattern: ".env"
    action: LogOnly

  # Don't let agent push to npm
  - name: no-npm-publish
    matcher:
      type: ToolCallInput
      tool_name_pattern: "Bash"
      input_field: "command"
      value_pattern: "npm publish"
    action: Deny
"#
        ),
        "python" => format!(
            "{}{}",
            base_policies,
            r#"
  - name: no-env-reads
    matcher:
      type: FsPath
      path_pattern: ".env"
    action: LogOnly

  - name: no-pip-install-global
    matcher:
      type: ToolCallInput
      tool_name_pattern: "Bash"
      input_field: "command"
      value_pattern: "pip install"
    action: LogOnly
"#
        ),
        _ => base_policies.to_string(),
    }
}

async fn vigil_init(output: PathBuf, force: bool) -> Result<()> {
    if output.exists() && !force {
        println!(
            "'{}' already exists. Use --force to overwrite.",
            output.display()
        );
        return Ok(());
    }

    let project_type = detect_project_type();
    let policy_yaml = generate_policy_yaml(project_type);

    std::fs::write(&output, &policy_yaml)?;

    println!(
        "Created {} for {} project",
        output.display(),
        project_type
    );
    println!();
    println!("Active policies:");
    for line in policy_yaml.lines() {
        if line.trim().starts_with("name:") {
            let name = line
                .trim()
                .trim_start_matches("name:")
                .trim()
                .trim_matches('"');
            println!("  • {}", name);
        }
    }
    println!();
    println!(
        "Run with: vigil run --policy {} -- <agent>",
        output.display()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Plugin helpers
// ---------------------------------------------------------------------------

fn plugins_dir() -> anyhow::Result<PathBuf> {
    let home = if cfg!(target_os = "windows") {
        std::env::var("USERPROFILE").ok()
    } else {
        std::env::var("HOME").ok()
    }.ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    Ok(PathBuf::from(home).join(".vigil").join("plugins"))
}

fn make_plugin_ctx(session_id: uuid::Uuid) -> PluginContext {
    PluginContext {
        session_id,
        config_dir: plugins_dir().unwrap_or_default(),
        host_version: env!("CARGO_PKG_VERSION"),
    }
}

fn load_plugins_from_dir(dir: &PathBuf, host: &mut PluginHost) {
    if !dir.exists() { return; }
    let dylib_exts = if cfg!(target_os = "windows") { vec!["dll"] }
        else if cfg!(target_os = "macos") { vec!["dylib"] }
        else { vec!["so"] };
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if dylib_exts.contains(&ext) {
                    match host.load_from_file(&path) {
                        Ok(()) => println!("Auto-loaded plugin: {}", path.display()),
                        Err(e) => eprintln!("Warning: {}", e),
                    }
                }
            }
        }
    }
}

async fn run_plugins_command(action: PluginCommands) -> anyhow::Result<()> {
    match action {
        PluginCommands::Dir => {
            let dir = plugins_dir()?;
            println!("{}", dir.display());
            println!("Place .dll / .so / .dylib files here to auto-load on vigil run.");
        }

        PluginCommands::List => {
            let dir = plugins_dir()?;
            if !dir.exists() {
                println!("Plugin directory {} does not exist yet.", dir.display());
                println!("Run `vigil plugins new <name>` to scaffold your first plugin.");
                return Ok(());
            }
            let dylib_exts = dylib_extensions();
            let mut found = false;
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if dylib_exts.contains(&ext) {
                            let size = path.metadata().map(|m| m.len()).unwrap_or(0);
                            println!("  {}  ({} KB)", path.file_name().unwrap_or_default().to_string_lossy(), size / 1024);
                            found = true;
                        }
                    }
                }
            }
            if !found {
                println!("No plugins in {}.", dir.display());
                println!("Run `vigil plugins new <name>` to scaffold one.");
            }
        }

        PluginCommands::Install { path } => {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !dylib_extensions().contains(&ext) {
                anyhow::bail!("Expected a shared library (.dll / .so / .dylib), got: {}", path.display());
            }
            if !path.exists() {
                anyhow::bail!("File not found: {}", path.display());
            }
            let dir = plugins_dir()?;
            std::fs::create_dir_all(&dir)?;
            let dest = dir.join(path.file_name().unwrap());
            std::fs::copy(&path, &dest)?;
            println!("Installed {} → {}", path.file_name().unwrap().to_string_lossy(), dest.display());
            println!("It will auto-load on the next `vigil run`.");
        }

        PluginCommands::Check { path } => {
            println!("Checking plugin: {}", path.display());
            match PluginHost::check_file(&path) {
                Ok(name) => println!("OK  name={}", name),
                Err(e) => {
                    eprintln!("FAIL: {}", e);
                    std::process::exit(1);
                }
            }
        }

        PluginCommands::New { name, template, path } => {
            let template = match template {
                Some(t) => t,
                None => prompt_template()?,
            };
            let dest = path.unwrap_or_else(|| PathBuf::from(&name));
            scaffold_plugin(&name, &template, &dest)?;
        }
    }
    Ok(())
}

fn dylib_extensions() -> Vec<&'static str> {
    if cfg!(target_os = "windows") { vec!["dll"] }
    else if cfg!(target_os = "macos") { vec!["dylib"] }
    else { vec!["so"] }
}

fn prompt_template() -> anyhow::Result<PluginTemplate> {
    println!();
    println!("What should this plugin do?");
    println!("  1. React to alerts  — notifications, webhooks, Slack");
    println!("  2. Gate tool calls  — allow or block based on custom logic");
    println!("  3. Log events       — structured logging to file or external system");
    println!("  4. Blank slate      — all three methods stubbed, no logic");
    println!();
    print!("Choice [1-4] (default: 1): ");
    use std::io::Write as _;
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(match line.trim() {
        "2" => PluginTemplate::Gatekeeper,
        "3" => PluginTemplate::Logger,
        "4" => PluginTemplate::Blank,
        _   => PluginTemplate::Alert,
    })
}

fn scaffold_plugin(name: &str, template: &PluginTemplate, dest: &PathBuf) -> anyhow::Result<()> {
    if dest.exists() {
        anyhow::bail!("{} already exists", dest.display());
    }
    let src_dir = dest.join("src");
    std::fs::create_dir_all(&src_dir)?;

    // Cargo.toml
    let crate_name = name.replace('-', "_").to_lowercase();
    std::fs::write(dest.join("Cargo.toml"), format!(
r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
vigil-plugin = {{ git = "https://github.com/zer0contextlost/vigil" }}
serde_json = "1.0"
"#))?;

    // rust-toolchain.toml — pins the channel so vtable layout matches
    std::fs::write(dest.join("rust-toolchain.toml"),
r#"[toolchain]
channel = "stable"
"#)?;

    // .gitignore
    std::fs::write(dest.join(".gitignore"),
r#"/target/
Cargo.lock
"#)?;

    // src/lib.rs — template-specific
    let lib_rs = match template {
        PluginTemplate::Alert     => template_alert(name),
        PluginTemplate::Gatekeeper => template_gatekeeper(name),
        PluginTemplate::Logger    => template_logger(name),
        PluginTemplate::Blank     => template_blank(name),
    };
    std::fs::write(src_dir.join("lib.rs"), lib_rs)?;

    // Install script (Windows)
    std::fs::write(dest.join("install.ps1"), format!(
r#"# Build and install {name} into the vigil auto-load directory
cargo build --release
$dll = Get-ChildItem target\release\*.dll | Select-Object -First 1
if ($dll) {{
    $pluginsDir = "$env:USERPROFILE\.vigil\plugins"
    New-Item -ItemType Directory -Force $pluginsDir | Out-Null
    Copy-Item $dll.FullName $pluginsDir -Force
    Write-Host "Installed $($dll.Name) → $pluginsDir"
}} else {{
    Write-Host "Build failed — no .dll found in target\release\"
}}
"#))?;

    // Install script (Unix)
    std::fs::write(dest.join("install.sh"), format!(
r#"#!/usr/bin/env bash
# Build and install {name} into the vigil auto-load directory
set -e
cargo build --release
EXT=$([ "$(uname)" = "Darwin" ] && echo "dylib" || echo "so")
LIB=$(ls target/release/*.{crate_name}.$EXT 2>/dev/null | head -1 || ls target/release/lib{crate_name}.$EXT 2>/dev/null | head -1 || ls target/release/*.$EXT 2>/dev/null | head -1)
if [ -z "$LIB" ]; then
    echo "Build failed — no .$EXT found in target/release/"
    exit 1
fi
mkdir -p ~/.vigil/plugins
cp "$LIB" ~/.vigil/plugins/
echo "Installed $(basename $LIB) → ~/.vigil/plugins/"
"#))?;
    #[cfg(unix)]
    { use std::os::unix::fs::PermissionsExt; let _ = std::fs::set_permissions(dest.join("install.sh"), std::fs::Permissions::from_mode(0o755)); }

    println!();
    println!("Created {}/ with {} template.", dest.display(), template_label(template));
    println!();
    println!("  Next steps:");
    println!("    cd {}", dest.display());
    println!("    # Edit src/lib.rs");
    if cfg!(windows) {
        println!("    .\\install.ps1          # build + copy to ~/.vigil/plugins/");
    } else {
        println!("    ./install.sh           # build + copy to ~/.vigil/plugins/");
    }
    println!("    vigil plugins list     # confirm it's loaded");
    println!("    vigil run -- claude    # it auto-loads on every run");
    println!();
    Ok(())
}

fn template_label(t: &PluginTemplate) -> &'static str {
    match t {
        PluginTemplate::Alert      => "alert-notifier",
        PluginTemplate::Gatekeeper => "tool-gatekeeper",
        PluginTemplate::Logger     => "event-logger",
        PluginTemplate::Blank      => "blank",
    }
}

fn template_alert(name: &str) -> String {
    format!(r#"//! {name} - vigil alert-notifier plugin
//!
//! Reacts to vigil alerts (BURN, LOOP, EXFL, DENY, COST, DURA, TOUT, WAPPR, PII).
//! Edit `on_alert` to forward alerts to Slack, a webhook, a file, etc.
//!
//! Configuration via environment variables:
//!   PLUGIN_WEBHOOK_URL - URL to POST alerts to (optional)

use vigil_plugin::{{async_trait, declare_plugin, AlertLabel, PluginContext, Value, VigilPlugin}};

pub struct {struct_name} {{
    webhook_url: Option<String>,
}}

impl {struct_name} {{
    fn new() -> Self {{
        Self {{
            webhook_url: std::env::var("PLUGIN_WEBHOOK_URL").ok(),
        }}
    }}
}}

#[async_trait]
impl VigilPlugin for {struct_name} {{
    fn name(&self) -> &str {{ "{name}" }}

    async fn on_alert(&self, ctx: &PluginContext, label: AlertLabel, detail: &Value) {{
        let msg = format!(
            "[vigil {{}}] session={{}} {{}}",
            label.code(),
            &ctx.session_id.to_string()[..8],
            detail,
        );
        eprintln!("{{}}", msg);

        if let Some(url) = &self.webhook_url {{
            // Spawn a task so we don't block the event loop.
            let url = url.clone();
            let body = serde_json::json!({{
                "label": label,
                "session_id": ctx.session_id.to_string(),
                "detail": detail,
            }});
            tokio::spawn(async move {{
                // Add your HTTP client here — e.g. reqwest:
                // let _ = reqwest::Client::new().post(&url).json(&body).send().await;
                let _ = (url, body); // remove this line once you add the client
            }});
        }}
    }}
}}

declare_plugin!({struct_name}::new());
"#,
        name = name,
        struct_name = to_struct_name(name),
    )
}

fn template_gatekeeper(name: &str) -> String {
    format!(r#"//! {name} - vigil tool-gatekeeper plugin
//!
//! Inspects every tool call that the built-in policy engine allows.
//! Return `PluginDecision::Deny(reason)` to block; the agent receives
//! an HTTP 403 and a DENY alert fires in the TUI.
//!
//! Configuration via environment variables:
//!   PLUGIN_BLOCK_TOOLS - comma-separated tool name substrings to deny
//!                        e.g. "Bash,WebSearch"

use vigil_plugin::{{async_trait, declare_plugin, PluginContext, PluginDecision, Value, VigilPlugin}};

pub struct {struct_name} {{
    block_patterns: Vec<String>,
}}

impl {struct_name} {{
    fn new() -> Self {{
        let block_patterns = std::env::var("PLUGIN_BLOCK_TOOLS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase)
            .collect();
        Self {{ block_patterns }}
    }}
}}

#[async_trait]
impl VigilPlugin for {struct_name} {{
    fn name(&self) -> &str {{ "{name}" }}

    async fn on_tool_call(
        &self,
        _ctx: &PluginContext,
        tool_name: &str,
        input: &Value,
    ) -> PluginDecision {{
        // --- pattern-based block (driven by PLUGIN_BLOCK_TOOLS env var) ---
        let lower = tool_name.to_lowercase();
        for pattern in &self.block_patterns {{
            if lower.contains(pattern.as_str()) {{
                return PluginDecision::Deny(format!(
                    "{name}: '{{}}' matches blocked pattern '{{}}'",
                    tool_name, pattern,
                ));
            }}
        }}

        // --- add your own logic here ---
        // Example: block any shell command containing "rm -rf"
        // if tool_name.eq_ignore_ascii_case("Bash") {{
        //     if input.to_string().contains("rm -rf") {{
        //         return PluginDecision::Deny("rm -rf is not allowed".into());
        //     }}
        // }}

        let _ = input; // remove when you use input
        PluginDecision::Allow
    }}
}}

declare_plugin!({struct_name}::new());
"#,
        name = name,
        struct_name = to_struct_name(name),
    )
}

fn template_logger(name: &str) -> String {
    format!(r#"//! {name} - vigil event-logger plugin
//!
//! Writes every event to a NDJSON file for offline analysis.
//!
//! Configuration via environment variables:
//!   PLUGIN_LOG_PATH - path to log file (default: ~/.vigil/{name}.ndjson)

use std::fs::{{File, OpenOptions}};
use std::io::Write;
use std::sync::Mutex;
use vigil_plugin::{{async_trait, declare_plugin, AlertLabel, Envelope, PluginContext, Value, VigilPlugin}};

pub struct {struct_name} {{
    file: Mutex<File>,
}}

impl {struct_name} {{
    fn new() -> Self {{
        let path = std::env::var("PLUGIN_LOG_PATH").unwrap_or_else(|_| {{
            let home = std::env::var(if cfg!(windows) {{ "USERPROFILE" }} else {{ "HOME" }})
                .unwrap_or_default();
            format!("{{}}/.vigil/{name}.ndjson", home)
        }});
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("{name}: cannot open {{}}: {{}}", path, e));
        Self {{ file: Mutex::new(file) }}
    }}

    fn write(&self, record: &serde_json::Value) {{
        if let Ok(line) = serde_json::to_string(record) {{
            if let Ok(mut f) = self.file.lock() {{
                let _ = writeln!(f, "{{}}", line);
            }}
        }}
    }}
}}

#[async_trait]
impl VigilPlugin for {struct_name} {{
    fn name(&self) -> &str {{ "{name}" }}

    async fn on_event(&self, ctx: &PluginContext, envelope: &Envelope) {{
        self.write(&serde_json::json!({{
            "type": "event",
            "session_id": ctx.session_id,
            "envelope": envelope,
        }}));
    }}

    async fn on_alert(&self, ctx: &PluginContext, label: AlertLabel, detail: &Value) {{
        self.write(&serde_json::json!({{
            "type": "alert",
            "session_id": ctx.session_id,
            "label": label.code(),
            "detail": detail,
        }}));
    }}
}}

declare_plugin!({struct_name}::new());
"#,
        name = name,
        struct_name = to_struct_name(name),
    )
}

fn template_blank(name: &str) -> String {
    format!(r#"//! {name} - vigil plugin
//!
//! All three hooks are stubbed. Implement what you need.

use vigil_plugin::{{async_trait, declare_plugin, AlertLabel, Envelope, PluginContext, PluginDecision, Value, VigilPlugin}};

pub struct {struct_name};

#[async_trait]
impl VigilPlugin for {struct_name} {{
    fn name(&self) -> &str {{ "{name}" }}

    async fn on_event(&self, _ctx: &PluginContext, _envelope: &Envelope) {{}}

    async fn on_alert(&self, _ctx: &PluginContext, _label: AlertLabel, _detail: &Value) {{}}

    async fn on_tool_call(&self, _ctx: &PluginContext, _tool_name: &str, _input: &Value) -> PluginDecision {{
        PluginDecision::Allow
    }}
}}

declare_plugin!({struct_name});
"#,
        name = name,
        struct_name = to_struct_name(name),
    )
}

fn to_struct_name(name: &str) -> String {
    name.split(['-', '_'])
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut c = s.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Session helpers
// ---------------------------------------------------------------------------

/// Resolve a session ID string — accepts full UUID or a human-readable name label.
fn resolve_session_id(s: &str) -> anyhow::Result<uuid::Uuid> {
    if let Ok(uuid) = uuid::Uuid::parse_str(s) {
        return Ok(uuid);
    }
    // Try name lookup
    match Session::find_by_name(s)? {
        Some(summary) => Ok(summary.id),
        None => anyhow::bail!("No session found with ID or name {:?}", s),
    }
}

/// Delete all files for a session after confirmation.
fn confirm_delete_session(id: &uuid::Uuid) -> anyhow::Result<()> {
    println!("Delete session {}? This cannot be undone. [y/N] ", id);
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if line.trim().eq_ignore_ascii_case("y") {
        let dir = vigil_core::store::sessions_dir()?;
        for ext in &["ndjson", "meta.json"] {
            let path = dir.join(format!("{}.{}", id, ext));
            if path.exists() { std::fs::remove_file(&path)?; }
        }
        println!("Session {} deleted.", id);
    } else {
        println!("Cancelled.");
    }
    Ok(())
}

fn run_prune(older_than_days: u64, dry_run: bool) -> anyhow::Result<()> {
    let dir = vigil_core::store::sessions_dir()?;
    if !dir.exists() {
        println!("No sessions directory found.");
        return Ok(());
    }

    let cutoff = std::time::SystemTime::now()
        - std::time::Duration::from_secs(older_than_days * 86400);

    let mut deleted = 0u64;
    let mut freed = 0u64;

    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(ext) = path.extension().and_then(|e| e.to_str()) else { continue };
            // Only look at .ndjson files (each session has one); meta.json is handled below
            if ext != "ndjson" { continue }
            let Ok(meta) = entry.metadata() else { continue };
            let Ok(modified) = meta.modified() else { continue };
            if modified >= cutoff { continue }

            let size = meta.len();
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();

            if dry_run {
                println!("would delete: {} ({} KB)", path.file_name().unwrap_or_default().to_string_lossy(), size / 1024);
            } else {
                std::fs::remove_file(&path).ok();
                // Remove companion meta file
                let meta_path = dir.join(format!("{}.meta.json", stem));
                if meta_path.exists() { std::fs::remove_file(&meta_path).ok(); }
                deleted += 1;
                freed += size;
            }
        }
    }

    if dry_run {
        println!("Dry run — no files deleted. Remove --dry-run to prune.");
    } else {
        println!("Pruned {} session(s), freed {} KB.", deleted, freed / 1024);
    }
    Ok(())
}

fn find_available_port(start: u16) -> anyhow::Result<u16> {
    for port in start..=start.saturating_add(20) {
        if std::net::TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], port))).is_ok() {
            return Ok(port);
        }
    }
    anyhow::bail!("no available port found in range {}–{}", start, start.saturating_add(20))
}

fn format_duration(d: chrono::Duration) -> String {
    let total_secs = d.num_seconds();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    if hours > 0 {
        format!("{}h{:02}m", hours, minutes)
    } else if minutes > 0 {
        format!("{}m{:02}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() > n {
        format!("{}...", &s[..n.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use vigil_core::{session::Session, store::SessionStore, CredentialTracker, Event, PolicyConfig, PolicyEngine, TimestampedEvent, BudgetEnforcer, BudgetStatus, BurnRateTracker, LoopDetector};
use vigil_proxy::Proxy;
use vigil_tui::App;
use vigil_watch::{WatchConfig, Watcher};

#[derive(Parser)]
#[command(name = "vigil")]
#[command(about = "Runtime observability and policy enforcement for AI coding agents", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
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

    /// List past sessions
    Sessions,

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
        let mut env_block = build_env_block(extra_env);

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
            return Err(anyhow!(
                "CreateProcessW failed: Windows error code {}",
                err
            ));
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
            agent_and_args,
        }) => {
            let watchlist = load_pii_watchlist(pii_watchlist.as_deref());
            let config_path_str = config.as_deref().map(|p| p.display().to_string());
            let vigil_config = config.as_deref()
                .and_then(|p| vigil_core::VigilConfig::load(p).ok());
            run_agent(port, policy, log_file.as_ref(), agent_and_args, watchlist, vigil_config, config_path_str).await?;
        }
        Some(Commands::Init { output, force }) => {
            vigil_init(output, force).await?;
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
        Some(Commands::Ps) => {
            run_ps()?;
        }
        Some(Commands::Fork { session_id, prefix_events, agent_and_args }) => {
            run_fork(&session_id, prefix_events, agent_and_args).await?;
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
            if curr_str < prev_str {
                ulid_ok = false;
                ulid_msg = format!("OUT OF ORDER at event {}", i);
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
        run_agent(8877, None, None, agent_and_args, watchlist, None, None).await?;
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
    init_logging(log_file);

    if agent_and_args.is_empty() {
        anyhow::bail!("No agent command provided");
    }

    let agent_name = agent_and_args[0].clone();
    let session = Session::new(agent_name.clone());
    let session_id = session.id;
    let store = SessionStore::create(session_id, &agent_name).ok();

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

    let proxy_config = vigil_proxy::ProxyConfig {
        port,
        ca_cert_path: None,
        upstream_override: None,
        pii_watchlist,
        write_approval_threshold,
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

    // Policy filter: evaluate every raw event and forward allowed ones to the TUI.
    let lock_path = active_handle.as_ref().map(|h| h.path.clone());
    let engine_clone = engine.clone();
    let session_id_for_alerts = session_id;
    let filter_handle = tokio::spawn(async move {
        let mut session_tokens = 0u32;
        let mut session_cost = 0f64;
        let mut burn_tracker = BurnRateTracker::new();
        let mut loop_detector = LoopDetector::new(loop_threshold);
        let mut cred_tracker = CredentialTracker::new();
        while let Some(event) = raw_rx.recv().await {
            if let Event::LlmRequest { input_tokens, .. } = &event.event {
                session_tokens += input_tokens;
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
                            let alert = TimestampedEvent::new(Event::ExfilAlert {
                                matches: hits,
                                source: "llm_request".to_string(),
                                session_id: *sid,
                            });
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
                            let alert = TimestampedEvent::new(Event::ExfilAlert {
                                matches: hits,
                                source: tool_name.clone(),
                                session_id: *sid,
                            });
                            filtered_tx.send(alert).await.ok();
                        }
                    }
                }
            }

            if let Event::LlmResponse { input_tokens, output_tokens, cost_usd, .. } = &event.event {
                session_tokens += input_tokens + output_tokens;
                session_cost += cost_usd;
                if let Some(ref path) = lock_path {
                    vigil_core::update_active(path, |s| {
                        s.session_cost_usd = session_cost;
                        s.session_tokens = session_tokens;
                        s.last_event = "RES".to_string();
                    });
                }
            }

            if let Event::LlmResponse { cost_usd, .. } = &event.event {
                let (rate, projected) = burn_tracker.record(*cost_usd);
                if let Some(limit) = burn_rate_limit {
                    if rate > limit {
                        let alert = TimestampedEvent::new(Event::BurnRateAlert {
                            rate_per_min_usd: rate,
                            projected_total_usd: projected,
                            session_cost_usd: session_cost,
                            session_id: session_id_for_alerts,
                        });
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
                    let alert = TimestampedEvent::new(Event::LoopAlert {
                        tool_name: tool_name.clone(),
                        repeat_count: count,
                        session_id: *sid,
                    });
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
                        let blocked = TimestampedEvent::new(Event::ToolCallResult {
                            agent: agent.clone(),
                            tool_name: tool_name.clone(),
                            blocked: true,
                            session_id: *session_id,
                        });
                        filtered_tx.send(blocked).await.ok();
                    }
                }
                _ => {
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

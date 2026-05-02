use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use vigil_core::{session::Session, Event, PolicyEngine, TimestampedEvent};
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
            log_file,
            pii_watchlist,
            agent_and_args,
        }) => {
            let watchlist = load_pii_watchlist(pii_watchlist.as_deref());
            run_agent(port, policy, log_file.as_ref(), agent_and_args, watchlist).await?;
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
        Some(Commands::Replay { session_id }) => {
            let uuid = uuid::Uuid::parse_str(&session_id)
                .context("Invalid session ID — use the full UUID from 'vigil sessions'")?;
            let session = Session::load(&uuid)?;
            println!(
                "Replaying session {} ({} events)...",
                session_id,
                session.events.len()
            );

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
    run_agent(8877, None, None, args, watchlist).await
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
) -> Result<()> {
    init_logging(log_file);

    if agent_and_args.is_empty() {
        anyhow::bail!("No agent command provided");
    }

    let agent_name = agent_and_args[0].clone();
    let session = Session::new(agent_name.clone());
    let session_id = session.id;

    let engine = if let Some(policy_path) = &policy {
        PolicyEngine::from_file(policy_path)?
    } else {
        PolicyEngine::default()
    };
    let engine = Arc::new(engine);

    let (raw_tx, mut raw_rx) = tokio::sync::mpsc::channel::<TimestampedEvent>(1000);
    let (filtered_tx, filtered_rx) = tokio::sync::mpsc::channel::<TimestampedEvent>(1000);

    println!("vigil v0.1.0");
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
    println!();

    let proxy_url = format!("http://127.0.0.1:{}", port);
    tracing::info!(port, "starting vigil proxy");

    let proxy_config = vigil_proxy::ProxyConfig {
        port,
        ca_cert_path: None,
        upstream_override: None,
        pii_watchlist,
    };
    let proxy = Proxy::new(proxy_config, raw_tx.clone());
    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = proxy.run().await {
            tracing::error!(err = %e, "proxy error");
            eprintln!("Proxy error: {}", e);
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
    let engine_clone = engine.clone();
    let filter_handle = tokio::spawn(async move {
        let mut session_tokens = 0u32;
        while let Some(event) = raw_rx.recv().await {
            if let Event::LlmRequest { input_tokens, .. } = &event.event {
                session_tokens += input_tokens;
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

    let app = App::new(session);
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

    if let Some(mut app) = final_app {
        app.session.finish();
        match app.session.save() {
            Ok(path) => {
                tracing::info!(path = %path.display(), "session saved");
                println!("Session saved: {}", path.display());
            }
            Err(e) => {
                tracing::error!(err = %e, "failed to save session");
                eprintln!("Failed to save session: {}", e);
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

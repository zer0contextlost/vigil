use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vigil_core::{Event, TimestampedEvent};

pub struct WatchConfig {
    pub watch_path: PathBuf,
    pub agent_pid: u32,
    pub session_id: uuid::Uuid,
}

pub struct Watcher {
    config: WatchConfig,
    event_tx: tokio::sync::mpsc::Sender<TimestampedEvent>,
}

/// Paths recently written by the LLM proxy layer (tool calls).
/// Used to de-duplicate notify events so we don't double-count Write/Edit tool results.
type RecentWrites = Arc<Mutex<HashMap<String, Instant>>>;

/// Noise-filter: skip these path patterns in file system watch output.
fn is_noisy_path(path: &str) -> bool {
    let noisy = [
        "\\.git\\",
        "/.git/",
        "\\target\\",
        "/target/",
        "\\node_modules\\",
        "/node_modules/",
        "\\.vigil\\",
        "/.vigil/",
        "~$",        // Office temp files
        ".tmp",
        ".swp",
        ".lock",
    ];
    noisy.iter().any(|n| path.contains(n))
        || path.ends_with(".pyc")
        || path.ends_with("__pycache__")
}

impl Watcher {
    pub fn new(
        config: WatchConfig,
        event_tx: tokio::sync::mpsc::Sender<TimestampedEvent>,
    ) -> Self {
        Self { config, event_tx }
    }

    pub async fn run(&self) -> Result<()> {
        let (proc_tx, mut proc_rx) = tokio::sync::mpsc::channel::<Event>(1000);

        let agent_pid = self.config.agent_pid;
        let session_id = self.config.session_id;
        let proc_handle = tokio::spawn(async move {
            process_monitor_task(agent_pid, session_id, proc_tx).await;
        });

        let event_tx_proc = self.event_tx.clone();
        let proc_forward = tokio::spawn(async move {
            while let Some(event) = proc_rx.recv().await {
                let _ = event_tx_proc.send(TimestampedEvent::new(event)).await;
            }
        });

        // File system watcher — emits FsWrite for shell-executed writes not from tool calls.
        let recent_writes: RecentWrites = Arc::new(Mutex::new(HashMap::new()));
        let fs_handle = self.spawn_fs_watcher(session_id, recent_writes);

        tokio::select! {
            _ = proc_handle => {}
            _ = proc_forward => {}
            _ = fs_handle => {}
        }

        Ok(())
    }

    fn spawn_fs_watcher(
        &self,
        session_id: uuid::Uuid,
        recent_writes: RecentWrites,
    ) -> tokio::task::JoinHandle<()> {
        use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher};
        use std::sync::mpsc as std_mpsc;

        let watch_path = self.config.watch_path.clone();
        let event_tx = self.event_tx.clone();

        tokio::task::spawn_blocking(move || {
            let (std_tx, std_rx) = std_mpsc::channel();
            let mut watcher = match RecommendedWatcher::new(
                move |res| { let _ = std_tx.send(res); },
                notify::Config::default().with_poll_interval(Duration::from_millis(500)),
            ) {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!(err=%e, "fs watcher init failed");
                    return;
                }
            };

            if let Err(e) = watcher.watch(&watch_path, RecursiveMode::Recursive) {
                tracing::warn!(err=%e, path=%watch_path.display(), "fs watcher start failed");
                return;
            }

            tracing::info!(path=%watch_path.display(), "fs watcher started");

            // Purge de-dup entries older than 2 seconds.
            let purge_interval = Duration::from_secs(2);
            let mut last_purge = Instant::now();

            for result in std_rx {
                match result {
                    Ok(event) => {
                        let is_write = matches!(
                            event.kind,
                            EventKind::Create(_) | EventKind::Modify(notify::event::ModifyKind::Data(_))
                        );
                        if !is_write {
                            continue;
                        }

                        // Purge stale de-dup entries.
                        if last_purge.elapsed() > purge_interval {
                            let mut rw = recent_writes.lock().unwrap_or_else(|e| e.into_inner());
                            rw.retain(|_, t| t.elapsed() < purge_interval);
                            last_purge = Instant::now();
                        }

                        for path in event.paths {
                            let path_str = path.to_string_lossy().to_string();
                            if is_noisy_path(&path_str) {
                                continue;
                            }

                            // De-duplicate: skip if this path was recently written by a tool call.
                            {
                                let rw = recent_writes.lock().unwrap_or_else(|e| e.into_inner());
                                if rw.get(&path_str).map(|t| t.elapsed() < purge_interval).unwrap_or(false) {
                                    continue;
                                }
                            }

                            let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                            let fs_event = TimestampedEvent::new(Event::FsWrite {
                                path: path_str,
                                bytes,
                                lines_added: 0,
                                lines_removed: 0,
                                hunk_count: 0,
                                session_id,
                            });
                            // Best-effort; if the channel is full, drop the event.
                            let _ = event_tx.try_send(fs_event);
                        }
                    }
                    Err(e) => {
                        tracing::debug!(err=%e, "fs watch event error");
                    }
                }
            }
        })
    }
}

async fn process_monitor_task(
    agent_pid: u32,
    session_id: uuid::Uuid,
    tx: tokio::sync::mpsc::Sender<Event>,
) {
    use sysinfo::System;

    let mut system = System::new_all();
    let mut seen_pids: HashSet<u32> = HashSet::new();
    seen_pids.insert(agent_pid);

    tracing::info!(agent_pid, "process monitor started");

    loop {
        system.refresh_all();

        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();
            if seen_pids.contains(&pid_u32) {
                continue;
            }
            if let Some(depth) = descendant_depth(&system, pid_u32, agent_pid) {
                seen_pids.insert(pid_u32);
                let name = process.name().to_string();
                tracing::info!(pid = pid_u32, name = %name, depth, agent_pid, "child process detected");
                let _ = tx.try_send(Event::ProcessSpawn {
                    command: name,
                    args: vec![],
                    session_id,
                });
            }
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Returns Some(depth) if `pid` is a descendant of `ancestor` within 4 levels.
fn descendant_depth(system: &sysinfo::System, pid: u32, ancestor: u32) -> Option<usize> {
    let mut current = pid;
    for depth in 1..=4 {
        let process = system.process(sysinfo::Pid::from(current as usize))?;
        let parent_u32 = process.parent()?.as_u32();
        if parent_u32 == ancestor {
            return Some(depth);
        }
        if parent_u32 <= 4 {
            return None;
        }
        current = parent_u32;
    }
    None
}

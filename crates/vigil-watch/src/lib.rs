use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;
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

        let event_tx = self.event_tx.clone();
        let proc_forward = tokio::spawn(async move {
            while let Some(event) = proc_rx.recv().await {
                let _ = event_tx.send(TimestampedEvent::new(event)).await;
            }
        });

        tokio::select! {
            _ = proc_handle => {}
            _ = proc_forward => {}
        }

        Ok(())
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

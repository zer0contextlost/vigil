use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use crossterm::{
    event::{Event as CrossEvent, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use dashmap::DashMap;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, TableState, Wrap},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use uuid::Uuid;
use vigil_core::{store::SessionStore, Event, TimestampedEvent};

// ── Wire protocol ────────────────────────────────────────────────────────────

pub type AgentId = Uuid;

/// All messages exchanged between agent proxies and the fleet hub.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum FleetMsg {
    // Agent → Hub
    Register {
        agent_id: AgentId,
        agent_name: String,
    },
    AgentEvent {
        agent_id: AgentId,
        event: TimestampedEvent,
    },
    ConfirmRequest {
        agent_id: AgentId,
        approval_id: Uuid,
        tool_name: String,
        policy_name: String,
        timeout_secs: u32,
    },
    // Hub → Agent
    ConfirmDecision {
        approval_id: Uuid,
        approved: bool,
    },
    Ack,
}

// ── Frame codec (4-byte LE length prefix + JSON body) ────────────────────────

async fn read_frame(stream: &mut TcpStream) -> Result<Option<FleetMsg>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        anyhow::bail!("fleet frame too large: {} bytes", len);
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    let msg = serde_json::from_slice(&body).context("fleet frame deserialize")?;
    Ok(Some(msg))
}

// ── Per-agent state ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AgentState {
    pub agent_id: AgentId,
    pub name: String,
    pub connected_at: std::time::SystemTime,
    pub last_event: Option<Instant>,
    pub event_count: usize,
    pub blocked_count: usize,
    pub last_tool: Option<String>,
}

impl AgentState {
    fn new(agent_id: AgentId, name: String) -> Self {
        Self {
            agent_id,
            name,
            connected_at: std::time::SystemTime::now(),
            last_event: None,
            event_count: 0,
            blocked_count: 0,
            last_tool: None,
        }
    }
}

// ── Hub ──────────────────────────────────────────────────────────────────────

pub struct FleetHub {
    pub agents: Arc<DashMap<AgentId, AgentState>>,
    pub event_tx: broadcast::Sender<(AgentId, TimestampedEvent)>,
    /// approval_id → (agent_id, oneshot sender back to the agent connection task)
    pub confirm_pending: Arc<Mutex<std::collections::HashMap<Uuid, (AgentId, oneshot::Sender<bool>)>>>,
    /// Pre-built policy engine; rebuilt on reload, None when no policy loaded.
    pub policy: Arc<tokio::sync::RwLock<Option<Arc<vigil_core::PolicyEngine>>>>,
}

impl FleetHub {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(4096);
        Self {
            agents: Arc::new(DashMap::new()),
            event_tx,
            confirm_pending: Arc::new(Mutex::new(std::collections::HashMap::new())),
            policy: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }
}

// ── Hub server ───────────────────────────────────────────────────────────────

pub async fn run_hub(
    bind: SocketAddr,
    policy_path: Option<PathBuf>,
    _config: Option<vigil_core::VigilConfig>,
) -> Result<()> {
    let hub = Arc::new(FleetHub::new());

    // Warn if binding to a non-loopback address.
    if !bind.ip().is_loopback() {
        eprintln!("[vigil hub] WARNING: binding to {} — hub will be reachable from the network. Consider using 127.0.0.1 for local-only use.", bind);
    }

    // Load hub-level policy if provided.
    if let Some(ref p) = policy_path {
        match vigil_core::PolicyConfig::load_from_file(p) {
            Ok(cfg) => {
                match vigil_core::PolicyEngine::new(cfg) {
                    Ok(engine) => {
                        *hub.policy.write().await = Some(Arc::new(engine));
                        eprintln!("[vigil hub] Policy loaded from {}", p.display());
                    }
                    Err(e) => eprintln!("[vigil hub] Warning: could not compile policy '{}': {}", p.display(), e),
                }
            }
            Err(e) => eprintln!("[vigil hub] Warning: could not load policy '{}': {}", p.display(), e),
        }
    }

    let listener = TcpListener::bind(bind).await
        .with_context(|| format!("cannot bind hub to {}", bind))?;

    eprintln!("[vigil hub] Listening on {} — agents connect with `vigil proxy --hub {}`", bind, bind);

    // Session recorder — aggregates all agent events into a fleet session file.
    let fleet_session_id = Uuid::new_v4();
    let mut recorder_store = SessionStore::create(fleet_session_id, "fleet").ok();
    if let Some(ref s) = recorder_store {
        eprintln!("[vigil hub] Fleet session: {} ({})", fleet_session_id, s.ndjson_path.display());
    }
    let mut recorder_rx = hub.event_tx.subscribe();
    let recorder_handle = tokio::spawn(async move {
        loop {
            match recorder_rx.recv().await {
                Ok((_agent_id, event)) => {
                    if let Some(ref mut store) = recorder_store {
                        store.append(&event).ok();
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(n, "fleet recorder lagged");
                }
            }
        }
        if let Some(ref store) = recorder_store {
            eprintln!("[vigil hub] Fleet session saved: {}", store.ndjson_path.display());
        }
    });

    let hub_for_tui = hub.clone();
    let mut tui_handle = tokio::spawn(async move {
        if let Err(e) = run_fleet_tui(hub_for_tui).await {
            eprintln!("[vigil hub] TUI error: {}", e);
        }
    });

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer)) => {
                        tracing::debug!(%peer, "fleet: agent connected");
                        let hub = hub.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_agent_connection(hub, stream).await {
                                tracing::warn!(err = %e, "fleet: agent connection error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(err = %e, "fleet: accept error");
                    }
                }
            }
            _ = &mut tui_handle => break,
        }
    }

    recorder_handle.abort();
    Ok(())
}

async fn handle_agent_connection(hub: Arc<FleetHub>, mut stream: TcpStream) -> Result<()> {
    // First frame must be Register.
    let first = read_frame(&mut stream).await?
        .context("agent disconnected before Register")?;

    let (agent_id, agent_name) = match first {
        FleetMsg::Register { agent_id, agent_name } => (agent_id, agent_name),
        _ => anyhow::bail!("expected Register as first frame"),
    };

    // Reject duplicate agent_id to prevent impersonation.
    if hub.agents.contains_key(&agent_id) {
        anyhow::bail!("agent_id {} already registered", agent_id);
    }

    // Sanitize agent name: strip control chars and cap at 64 chars.
    let agent_name: String = agent_name
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();

    hub.agents.insert(agent_id, AgentState::new(agent_id, agent_name.clone()));
    eprintln!("[vigil hub] Agent '{}' ({}) connected", agent_name, &agent_id.to_string()[..8]);

    // Outbound channel for hub → agent messages (confirm decisions, etc.)
    let (out_tx, mut out_rx) = mpsc::channel::<FleetMsg>(64);

    let (mut read_half, mut write_half) = stream.into_split();

    // Writer task: drain out_rx and write frames.
    tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let body = match serde_json::to_vec(&msg) {
                Ok(b) => b,
                Err(e) => { tracing::warn!(err=%e, "fleet: serialize error"); continue; }
            };
            let len = (body.len() as u32).to_le_bytes();
            if write_half.write_all(&len).await.is_err() { break; }
            if write_half.write_all(&body).await.is_err() { break; }
            let _ = write_half.flush().await;
        }
    });

    // Reader loop: handle inbound frames from agent.
    loop {
        let mut len_buf = [0u8; 4];
        match read_half.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(_) => break,
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 1024 * 1024 { break; }
        let mut body = vec![0u8; len];
        if read_half.read_exact(&mut body).await.is_err() { break; }
        let msg: FleetMsg = match serde_json::from_slice(&body) {
            Ok(m) => m,
            Err(e) => { tracing::warn!(err=%e, "fleet: invalid frame"); continue; }
        };

        match msg {
            FleetMsg::AgentEvent { event, .. } => {
                // Update agent stats.
                if let Some(mut state) = hub.agents.get_mut(&agent_id) {
                    state.event_count += 1;
                    state.last_event = Some(Instant::now());
                    if let Event::ToolCall { ref tool_name, .. } = event.event {
                        state.last_tool = Some(tool_name.clone());
                    }
                    if let Event::ToolCallResult { blocked: true, .. } = event.event {
                        state.blocked_count += 1;
                    }
                }

                // Hub-level policy evaluation (engine pre-built on policy load).
                let hub_action = {
                    let policy_guard = hub.policy.read().await;
                    if let Some(ref engine) = *policy_guard {
                        let d = engine.evaluate(&event.event, 0);
                        Some((d.action, d.policy_name))
                    } else {
                        None
                    }
                };

                if let Some((action, policy_name)) = hub_action {
                    match action {
                        vigil_core::PolicyAction::Deny => {
                            eprintln!("[vigil hub] DENY agent={} policy={}", &agent_id.to_string()[..8], policy_name.as_deref().unwrap_or("?"));
                            // Can't synchronously block agent from here, but log it.
                        }
                        vigil_core::PolicyAction::Confirm => {
                            // Show confirm overlay on hub TUI. Auto-denies after timeout.
                            let approval_id = Uuid::new_v4();
                            let tool_name = match &event.event {
                                Event::ToolCall { tool_name, .. } => tool_name.clone(),
                                _ => "unknown".to_string(),
                            };
                            let pn = policy_name.unwrap_or_else(|| "hub-policy".to_string());
                            let (dec_tx, dec_rx) = oneshot::channel::<bool>();
                            hub.confirm_pending.lock().await.insert(approval_id, (agent_id, dec_tx));
                            let _ = hub.event_tx.send((agent_id, TimestampedEvent::new(
                                Event::ConfirmApprovalRequired {
                                    approval_id, tool_name, policy_name: pn,
                                    timeout_secs: 30, session_id: agent_id,
                                }
                            )));
                            let out_c = out_tx.clone();
                            let confirm_map = hub.confirm_pending.clone();
                            let event_tx = hub.event_tx.clone();
                            tokio::spawn(async move {
                                let result = tokio::time::timeout(
                                    std::time::Duration::from_secs(30),
                                    async { dec_rx.await.unwrap_or(false) },
                                ).await.unwrap_or(false);
                                confirm_map.lock().await.remove(&approval_id);
                                let _ = event_tx.send((agent_id, TimestampedEvent::new(
                                    Event::ConfirmApprovalDecision { approval_id, approved: result, session_id: agent_id }
                                )));
                                let _ = out_c.send(FleetMsg::ConfirmDecision { approval_id, approved: result }).await;
                            });
                        }
                        vigil_core::PolicyAction::LogOnly => {
                            eprintln!("[vigil hub] LOG  agent={} policy={}", &agent_id.to_string()[..8], policy_name.as_deref().unwrap_or("?"));
                        }
                        vigil_core::PolicyAction::Allow => {}
                    }
                }

                let _ = hub.event_tx.send((agent_id, event));
            }
            FleetMsg::ConfirmRequest { approval_id, tool_name, policy_name, timeout_secs, .. } => {
                let (decision_tx, decision_rx) = oneshot::channel::<bool>();
                {
                    let mut map = hub.confirm_pending.lock().await;
                    map.insert(approval_id, (agent_id, decision_tx));
                }
                // Broadcast a synthetic ConfirmApprovalRequired into the event stream.
                let _ = hub.event_tx.send((agent_id, TimestampedEvent::new(
                    Event::ConfirmApprovalRequired {
                        approval_id,
                        tool_name,
                        policy_name,
                        timeout_secs,
                        session_id: agent_id,
                    }
                )));
                // Spawn timeout + resolution task.
                let out = out_tx.clone();
                let confirm_map = hub.confirm_pending.clone();
                let event_tx = hub.event_tx.clone();
                tokio::spawn(async move {
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(timeout_secs as u64),
                        async { decision_rx.await.unwrap_or(false) },
                    ).await.unwrap_or(false);

                    // Remove from pending (may already be gone if decided early).
                    confirm_map.lock().await.remove(&approval_id);
                    let _ = event_tx.send((agent_id, TimestampedEvent::new(
                        Event::ConfirmApprovalDecision { approval_id, approved: result, session_id: agent_id }
                    )));
                    let _ = out.send(FleetMsg::ConfirmDecision { approval_id, approved: result }).await;
                });
            }
            _ => {}
        }
    }

    hub.agents.remove(&agent_id);
    eprintln!("[vigil hub] Agent '{}' ({}) disconnected", agent_name, &agent_id.to_string()[..8]);
    Ok(())
}

// ── Fleet TUI ────────────────────────────────────────────────────────────────

const EVENT_RING_SIZE: usize = 500;

struct FleetApp {
    hub: Arc<FleetHub>,
    event_ring: VecDeque<(AgentId, TimestampedEvent)>,
    agent_table_state: TableState,
    /// approval_id currently shown in the confirm overlay.
    pending_confirm: Option<(Uuid, AgentId, String, String, u32, Instant)>,
    should_quit: bool,
}

impl FleetApp {
    fn new(hub: Arc<FleetHub>) -> Self {
        Self {
            hub,
            event_ring: VecDeque::with_capacity(EVENT_RING_SIZE),
            agent_table_state: TableState::default(),
            pending_confirm: None,
            should_quit: false,
        }
    }

    fn push_event(&mut self, agent_id: AgentId, event: TimestampedEvent) {
        match &event.event {
            Event::ConfirmApprovalRequired { approval_id, tool_name, policy_name, timeout_secs, .. } => {
                self.pending_confirm = Some((*approval_id, agent_id, tool_name.clone(), policy_name.clone(), *timeout_secs, Instant::now()));
            }
            Event::ConfirmApprovalDecision { approval_id, .. } => {
                if self.pending_confirm.as_ref().map(|p| p.0 == *approval_id).unwrap_or(false) {
                    self.pending_confirm = None;
                }
            }
            _ => {}
        }
        if self.event_ring.len() >= EVENT_RING_SIZE {
            self.event_ring.pop_front();
        }
        self.event_ring.push_back((agent_id, event));
    }

    fn handle_key(&mut self, key: KeyCode) {
        if let Some((approval_id, agent_id, _, _, _, _)) = &self.pending_confirm {
            let aid = *approval_id;
            let _agid = *agent_id;
            match key {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let map = self.hub.confirm_pending.clone();
                    tokio::spawn(async move {
                        let sender = { map.lock().await.remove(&aid).map(|(_, s)| s) };
                        if let Some(s) = sender { let _ = s.send(true); }
                    });
                    self.pending_confirm = None;
                }
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    let map = self.hub.confirm_pending.clone();
                    tokio::spawn(async move {
                        let sender = { map.lock().await.remove(&aid).map(|(_, s)| s) };
                        if let Some(s) = sender { let _ = s.send(false); }
                    });
                    self.pending_confirm = None;
                }
                _ => {}
            }
            return;
        }
        match key {
            KeyCode::Char('q') | KeyCode::Char('Q') => { self.should_quit = true; }
            KeyCode::Up => {
                let i = self.agent_table_state.selected().map(|i| i.saturating_sub(1)).unwrap_or(0);
                self.agent_table_state.select(Some(i));
            }
            KeyCode::Down => {
                let count = self.hub.agents.len();
                if count > 0 {
                    let i = self.agent_table_state.selected().map(|i| (i + 1).min(count - 1)).unwrap_or(0);
                    self.agent_table_state.select(Some(i));
                }
            }
            _ => {}
        }
    }
}

async fn run_fleet_tui(hub: Arc<FleetHub>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = FleetApp::new(hub.clone());
    let mut event_rx = hub.event_tx.subscribe();

    loop {
        terminal.draw(|f| draw_fleet(&mut app, f))?;

        // Non-blocking event drain with 100ms poll.
        if crossterm::event::poll(std::time::Duration::from_millis(100))? {
            if let CrossEvent::Key(key) = crossterm::event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.handle_key(key.code);
                }
            }
        }

        // Drain up to 64 pending hub events per frame to prevent livelock under load.
        for _ in 0..64 {
            match event_rx.try_recv() {
                Ok((agent_id, event)) => app.push_event(agent_id, event),
                Err(_) => break,
            }
        }

        if app.should_quit { break; }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn draw_fleet(app: &mut FleetApp, frame: &mut Frame) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),   // title bar
            Constraint::Min(6),      // agent table
            Constraint::Length(12),  // event stream
            Constraint::Length(1),   // help bar
        ])
        .split(area);

    // Title bar
    let agent_count = app.hub.agents.len();
    let title = format!(
        " vigil fleet  {} agent{}  connected",
        agent_count,
        if agent_count == 1 { "" } else { "s" }
    );
    frame.render_widget(
        Paragraph::new(Span::styled(title, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        chunks[0],
    );

    // Agent table
    draw_agent_table(app, frame, chunks[1]);

    // Event stream or confirm overlay
    if app.pending_confirm.is_some() {
        draw_confirm_overlay(app, frame, chunks[2]);
    } else {
        draw_event_stream(app, frame, chunks[2]);
    }

    // Help bar
    let help_text = if app.pending_confirm.is_some() {
        "y=approve  n=deny"
    } else {
        "q=quit  up/dn=select agent"
    };
    frame.render_widget(
        Paragraph::new(Span::styled(help_text, Style::default().fg(Color::DarkGray))),
        chunks[3],
    );
}

fn draw_agent_table(app: &mut FleetApp, frame: &mut Frame, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Agent").style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Cell::from("ID").style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Cell::from("Events").style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Cell::from("Blocked").style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Cell::from("Last tool").style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
    ]);

    let mut agents: Vec<_> = app.hub.agents.iter()
        .map(|e| e.value().clone())
        .collect();
    agents.sort_by_key(|a| a.name.clone());

    let rows: Vec<Row> = agents.iter().map(|a| {
        let idle_secs = a.last_event.map(|t| t.elapsed().as_secs()).unwrap_or(0);
        let status_color = if idle_secs < 5 { Color::Green } else if idle_secs < 30 { Color::Yellow } else { Color::DarkGray };
        let id_short = a.agent_id.to_string()[..8].to_string();
        Row::new(vec![
            Cell::from(a.name.clone()).style(Style::default().fg(status_color)),
            Cell::from(id_short),
            Cell::from(a.event_count.to_string()),
            Cell::from(a.blocked_count.to_string()).style(
                if a.blocked_count > 0 { Style::default().fg(Color::Red) } else { Style::default() }
            ),
            Cell::from(a.last_tool.as_deref().unwrap_or("—").to_string()),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Percentage(25),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Percentage(40),
    ])
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled("Agents", Style::default().fg(Color::White)))
            .border_style(Style::default().fg(Color::DarkGray)),
    )
    .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    frame.render_stateful_widget(table, area, &mut app.agent_table_state);
}

fn draw_event_stream(app: &FleetApp, frame: &mut Frame, area: Rect) {
    let visible = (area.height as usize).saturating_sub(2);
    let items: Vec<ListItem> = app.event_ring.iter()
        .rev()
        .take(visible)
        .rev()
        .map(|(agent_id, event)| {
            let agent_short = agent_id.to_string();
            let agent_short = &agent_short[..8];
            let time = event.timestamp.format("%H:%M:%S");
            let (label, label_style) = event_label(&event.event);
            let summary = event_summary_short(&event.event);
            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", time), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("[{}] ", agent_short), Style::default().fg(Color::Blue)),
                Span::styled(format!("{} ", label), label_style),
                Span::styled(summary, Style::default().fg(Color::White)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled("Events (all agents)", Style::default().fg(Color::White)))
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(list, area);
}

fn draw_confirm_overlay(app: &FleetApp, frame: &mut Frame, area: Rect) {
    let Some((_approval_id, agent_id, ref tool_name, ref policy_name, timeout_secs, started_at)) = app.pending_confirm else {
        return;
    };
    let elapsed = started_at.elapsed().as_secs();
    let remaining = (timeout_secs as u64).saturating_sub(elapsed);
    let agent_short = &agent_id.to_string()[..8];

    let lines: Vec<Line<'static>> = vec![
        Line::from(Span::styled("  POLICY CONFIRM REQUIRED (fleet hub)".to_string(),
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  ───────────────────────────────────".to_string(),
            Style::default().fg(Color::Magenta))),
        Line::from(vec![
            Span::styled("  Agent:  ".to_string(), Style::default().fg(Color::DarkGray)),
            Span::styled(agent_short.to_string(), Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Tool:   ".to_string(), Style::default().fg(Color::DarkGray)),
            Span::styled(tool_name.clone(), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Policy: ".to_string(), Style::default().fg(Color::DarkGray)),
            Span::styled(policy_name.clone(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Time:   ".to_string(), Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}s remaining", remaining),
                if remaining <= 5 { Style::default().fg(Color::Red).add_modifier(Modifier::BOLD) }
                else { Style::default().fg(Color::Yellow) },
            ),
        ]),
        Line::from("".to_string()),
        Line::from(vec![
            Span::styled("  [y] Approve   ".to_string(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled("[n] Deny".to_string(), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        ]),
    ];

    let pane = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(Span::styled("CONFIRM GATE  y=approve  n=deny",
                Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)))
            .border_style(Style::default().fg(Color::Magenta)))
        .wrap(Wrap { trim: false });
    frame.render_widget(pane, area);
}

fn event_label(event: &Event) -> (&'static str, Style) {
    match event {
        Event::LlmRequest { .. }   => ("REQ ", Style::default().fg(Color::Cyan).add_modifier(Modifier::DIM)),
        Event::LlmResponse { .. }  => ("RES ", Style::default().fg(Color::Cyan)),
        Event::ToolCall { .. }     => ("TOOL", Style::default().fg(Color::Yellow)),
        Event::ToolCallResult { blocked: true, .. } => ("BLOK", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Event::ToolCallResult { .. } => ("RSLT", Style::default().fg(Color::DarkGray)),
        Event::FsWrite { .. }      => ("FSWR", Style::default().fg(Color::Green)),
        Event::FsRead { .. }       => ("FSRD", Style::default().fg(Color::DarkGray)),
        Event::ConfirmApprovalRequired { .. } => ("CONF", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        Event::ConfirmApprovalDecision { .. } => ("CDEC", Style::default().fg(Color::Magenta)),
        Event::BurnRateAlert { .. } | Event::CostAlert { .. } => ("BURN", Style::default().fg(Color::Red)),
        Event::LoopAlert { .. }    => ("LOOP", Style::default().fg(Color::Red)),
        Event::PolicyReloaded { .. } => ("RLOD", Style::default().fg(Color::Yellow).add_modifier(Modifier::DIM)),
        _                          => ("    ", Style::default().fg(Color::DarkGray)),
    }
}

fn event_summary_short(event: &Event) -> String {
    match event {
        Event::LlmRequest { model, .. } => model.split('-').next().unwrap_or(model).to_string(),
        Event::LlmResponse { cost_usd, output_tokens, .. } => format!("${:.4}  {} tok", cost_usd, output_tokens),
        Event::ToolCall { tool_name, .. } => tool_name.clone(),
        Event::ToolCallResult { tool_name, blocked, .. } => {
            if *blocked { format!("{} BLOCKED", tool_name) } else { tool_name.clone() }
        }
        Event::FsWrite { path, .. } => path.chars().rev().take(40).collect::<String>().chars().rev().collect(),
        Event::FsRead { path, .. }  => path.chars().rev().take(40).collect::<String>().chars().rev().collect(),
        Event::ConfirmApprovalRequired { tool_name, policy_name, .. } => format!("{} ({})", tool_name, policy_name),
        Event::ConfirmApprovalDecision { approved, .. } => if *approved { "approved".to_string() } else { "denied".to_string() },
        Event::BurnRateAlert { rate_per_min_usd, .. } => format!("${:.4}/min", rate_per_min_usd),
        Event::PolicyReloaded { policy_count, .. } => format!("{} policies", policy_count),
        _ => String::new(),
    }
}

// ── Fleet client (runs inside vigil proxy/run) ───────────────────────────────

/// Connects to a fleet hub. Returns:
/// - `Sender<FleetMsg>`: push outbound messages (AgentEvent, ConfirmRequest) to hub
/// - `Receiver<FleetMsg>`: receive inbound messages (ConfirmDecision, Ack) from hub
pub fn spawn_fleet_client(
    hub_addr: SocketAddr,
    agent_id: AgentId,
    agent_name: String,
) -> (mpsc::Sender<FleetMsg>, mpsc::Receiver<FleetMsg>) {
    let (out_tx, mut out_rx) = mpsc::channel::<FleetMsg>(512);
    let (in_tx, in_rx) = mpsc::channel::<FleetMsg>(64);

    tokio::spawn(async move {
        let mut backoff_ms = 100u64;
        loop {
            let stream = match TcpStream::connect(hub_addr).await {
                Ok(s) => { backoff_ms = 100; s }
                Err(e) => {
                    tracing::warn!(err=%e, addr=%hub_addr, "fleet: connect failed, retry in {}ms", backoff_ms);
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(5000);
                    continue;
                }
            };

            let (mut read_half, mut write_half) = stream.into_split();

            // Send Register.
            let reg = FleetMsg::Register { agent_id, agent_name: agent_name.clone() };
            if let Ok(body) = serde_json::to_vec(&reg) {
                let len = (body.len() as u32).to_le_bytes();
                let _ = write_half.write_all(&len).await;
                let _ = write_half.write_all(&body).await;
                let _ = write_half.flush().await;
            }

            // Shutdown channel: signals the writer to stop when reader exits.
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

            // Writer task: drains out_rx and writes frames to hub.
            let writer = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        msg = out_rx.recv() => {
                            let msg = match msg {
                                Some(m) => m,
                                None => return (out_rx, false), // all senders dropped — exit cleanly
                            };
                            let body = match serde_json::to_vec(&msg) {
                                Ok(b) => b,
                                Err(_) => continue,
                            };
                            let len = (body.len() as u32).to_le_bytes();
                            if write_half.write_all(&len).await.is_err() { return (out_rx, true); }
                            if write_half.write_all(&body).await.is_err() { return (out_rx, true); }
                            let _ = write_half.flush().await;
                        }
                        _ = &mut shutdown_rx => return (out_rx, true),
                    }
                }
            });

            // Reader loop: reads inbound frames from hub using read_exact (correct framing).
            let reconnect = loop {
                let mut len_buf = [0u8; 4];
                match read_half.read_exact(&mut len_buf).await {
                    Ok(_) => {}
                    Err(_) => break true,
                }
                let len = u32::from_le_bytes(len_buf) as usize;
                if len > 1024 * 1024 { break true; }
                let mut body = vec![0u8; len];
                if read_half.read_exact(&mut body).await.is_err() { break true; }
                if let Ok(msg) = serde_json::from_slice::<FleetMsg>(&body) {
                    if in_tx.send(msg).await.is_err() { break false; } // receiver dropped
                }
            };

            // Signal writer to stop and recover out_rx for the next reconnect cycle.
            let _ = shutdown_tx.send(());
            let (recovered_rx, _) = writer.await.unwrap_or_else(|_| (mpsc::channel(512).1, false));
            out_rx = recovered_rx;

            if !reconnect { return; } // clean exit (receiver dropped)
            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
            backoff_ms = (backoff_ms * 2).min(5000);
        }
    });

    (out_tx, in_rx)
}

/// Convenience: wrap a TimestampedEvent into a FleetMsg::AgentEvent frame.
pub fn fleet_event(agent_id: AgentId, event: TimestampedEvent) -> FleetMsg {
    FleetMsg::AgentEvent { agent_id, event }
}

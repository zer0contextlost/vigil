use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, TableState, Wrap},
    Frame, Terminal,
};
use serde_json;
use vigil_core::TimestampedEvent;
use vigil_core::session::{Session, SessionSummary};

#[derive(Default)]
pub struct EventCounts {
    pub requests: usize,
    pub responses: usize,
    pub tools: usize,
    pub results: usize,
    pub blocked: usize,
    pub fs_reads: usize,
    pub fs_writes: usize,
    pub spawns: usize,
    pub mcp: usize,
    pub burn_alerts: usize,
    pub loop_alerts: usize,
    pub exfil_alerts: usize,
    pub drift_alerts: usize,
    pub sub_agent_spawns: usize,
    pub injection_alerts: usize,
}

#[derive(Debug, Clone)]
pub struct PendingApprovalInfo {
    pub approval_id: uuid::Uuid,
    pub path: String,
    pub risk_level: String,
    pub reasons: Vec<String>,
    pub before: String,
    pub after: String,
}

pub struct App {
    pub session: Session,
    pub store: Option<vigil_core::store::SessionStore>,
    pub config_path: Option<String>,
    pub event_log: Vec<Line<'static>>,
    pub raw_events: Vec<TimestampedEvent>,
    pub selected: usize,
    pub should_quit: bool,
    pub is_replay: bool,
    pub agent_done: bool,
    pub auto_scroll: bool,
    pub visible_height: usize,
    pub scroll_offset: usize,
    pub detail_focused: bool,
    pub detail_scroll: usize,
    pub counts: EventCounts,
    /// Most recent burn rate ($/min) from the last BurnRateAlert, if any.
    pub last_burn_rate: Option<f64>,
    /// Channel to send approval decisions back to the resolver task.
    pub decision_tx: Option<tokio::sync::mpsc::Sender<(uuid::Uuid, bool)>>,
    /// Pending write approval waiting for user input.
    pub pending_approval: Option<PendingApprovalInfo>,
}

impl App {
    pub fn new(session: Session) -> Self {
        Self {
            session,
            store: None,
            config_path: None,
            event_log: Vec::new(),
            raw_events: Vec::new(),
            selected: 0,
            should_quit: false,
            is_replay: false,
            agent_done: false,
            auto_scroll: true,
            visible_height: 20,
            scroll_offset: 0,
            detail_focused: false,
            detail_scroll: 0,
            counts: EventCounts::default(),
            last_burn_rate: None,
            decision_tx: None,
            pending_approval: None,
        }
    }

    pub fn push_event(&mut self, event: &TimestampedEvent) {
        match &event.event {
            vigil_core::Event::LlmRequest { .. } => {
                self.counts.requests += 1;
            }
            vigil_core::Event::LlmResponse { input_tokens, output_tokens, cost_usd, .. } => {
                self.session.total_input_tokens += input_tokens;
                self.session.total_output_tokens += output_tokens;
                self.session.total_cost_usd += cost_usd;
                self.counts.responses += 1;
            }
            vigil_core::Event::ToolCall { .. } => {
                self.counts.tools += 1;
            }
            vigil_core::Event::ToolCallResult { blocked, .. } => {
                if *blocked {
                    self.session.policy_violations += 1;
                    self.counts.blocked += 1;
                }
                self.counts.results += 1;
            }
            vigil_core::Event::FsRead { .. } => {
                self.counts.fs_reads += 1;
            }
            vigil_core::Event::FsWrite { .. } => {
                self.counts.fs_writes += 1;
            }
            vigil_core::Event::ProcessSpawn { .. } => {
                self.counts.spawns += 1;
            }
            vigil_core::Event::McpCall { .. } => {
                self.counts.mcp += 1;
            }
            vigil_core::Event::PiiAlert { .. } => {
                self.session.pii_detections += 1;
            }
            vigil_core::Event::BurnRateAlert { rate_per_min_usd, .. } => {
                self.counts.burn_alerts += 1;
                self.last_burn_rate = Some(*rate_per_min_usd);
            }
            vigil_core::Event::LoopAlert { .. } => {
                self.counts.loop_alerts += 1;
            }
            vigil_core::Event::WriteApprovalRequired { approval_id, path, risk_level, reasons, before, after, .. } => {
                self.pending_approval = Some(PendingApprovalInfo {
                    approval_id: *approval_id,
                    path: path.clone(),
                    risk_level: risk_level.clone(),
                    reasons: reasons.clone(),
                    before: before.clone(),
                    after: after.clone(),
                });
            }
            vigil_core::Event::WriteApprovalDecision { approval_id, .. } => {
                if self.pending_approval.as_ref().map(|p| p.approval_id == *approval_id).unwrap_or(false) {
                    self.pending_approval = None;
                }
            }
            vigil_core::Event::ExfilAlert { .. } => {
                self.counts.exfil_alerts += 1;
            }
            vigil_core::Event::ToolTimeout { .. } => {}
            vigil_core::Event::CostAlert { .. } => {}
            vigil_core::Event::SessionDurationAlert { .. } => {}
            vigil_core::Event::DriftAlert { .. } => {
                self.counts.drift_alerts += 1;
            }
            vigil_core::Event::SubAgentSpawned { .. } => {
                self.counts.sub_agent_spawns += 1;
            }
            vigil_core::Event::PromptInjectionAlert { .. } => {
                self.counts.injection_alerts += 1;
            }
        }
        if !self.is_replay {
            if let Some(ref mut store) = self.store {
                let _ = store.append(event);
            }
        }
        self.session.record(event.clone());
        self.event_log.push(format_event_line(event));
        self.raw_events.push(event.clone());

        if self.auto_scroll {
            self.selected = self.event_log.len().saturating_sub(1);
            self.scroll_to_selected();
        }
    }

    fn scroll_to_selected(&mut self) {
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        } else if self.selected >= self.scroll_offset + self.visible_height {
            self.scroll_offset = self.selected + 1 - self.visible_height;
        }
    }

    fn max_scroll(&self) -> usize {
        self.event_log.len().saturating_sub(self.visible_height)
    }

    fn at_bottom(&self) -> bool {
        self.selected + 1 >= self.event_log.len()
    }

    pub fn on_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.detail_focused {
                    self.detail_focused = false;
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Tab => {
                self.detail_focused = !self.detail_focused;
            }
            KeyCode::Up => {
                if self.detail_focused {
                    self.detail_scroll = self.detail_scroll.saturating_sub(1);
                } else {
                    self.auto_scroll = false;
                    if self.selected > 0 {
                        self.selected -= 1;
                        self.detail_scroll = 0;
                        self.scroll_to_selected();
                    }
                }
            }
            KeyCode::Down => {
                if self.detail_focused {
                    self.detail_scroll += 1;
                } else {
                    if self.selected + 1 < self.event_log.len() {
                        self.selected += 1;
                        self.detail_scroll = 0;
                        self.scroll_to_selected();
                    }
                    if self.at_bottom() {
                        self.auto_scroll = true;
                    }
                }
            }
            KeyCode::PageUp => {
                if self.detail_focused {
                    self.detail_scroll = self.detail_scroll.saturating_sub(10);
                } else {
                    self.auto_scroll = false;
                    self.selected = self.selected.saturating_sub(self.visible_height);
                    self.detail_scroll = 0;
                    self.scroll_to_selected();
                }
            }
            KeyCode::PageDown => {
                if self.detail_focused {
                    self.detail_scroll += 10;
                } else {
                    let last = self.event_log.len().saturating_sub(1);
                    self.selected = (self.selected + self.visible_height).min(last);
                    self.detail_scroll = 0;
                    self.scroll_to_selected();
                    if self.at_bottom() {
                        self.auto_scroll = true;
                    }
                }
            }
            KeyCode::Home => {
                if self.detail_focused {
                    self.detail_scroll = 0;
                } else {
                    self.auto_scroll = false;
                    self.selected = 0;
                    self.scroll_offset = 0;
                    self.detail_scroll = 0;
                }
            }
            KeyCode::End => {
                if !self.detail_focused {
                    self.auto_scroll = true;
                    self.selected = self.event_log.len().saturating_sub(1);
                    self.scroll_offset = self.max_scroll();
                    self.detail_scroll = 0;
                }
            }
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if let Some(ref info) = self.pending_approval {
                    let id = info.approval_id;
                    if let Some(ref tx) = self.decision_tx {
                        let tx = tx.clone();
                        tokio::spawn(async move { let _ = tx.send((id, true)).await; });
                    }
                    self.pending_approval = None;
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                if let Some(ref info) = self.pending_approval {
                    let id = info.approval_id;
                    if let Some(ref tx) = self.decision_tx {
                        let tx = tx.clone();
                        tokio::spawn(async move { let _ = tx.send((id, false)).await; });
                    }
                    self.pending_approval = None;
                }
            }
            _ => {}
        }
    }
}

// ─── event list row ──────────────────────────────────────────────────────────

fn format_event_line(event: &TimestampedEvent) -> Line<'static> {
    let time = event.timestamp.format("%H:%M:%S").to_string();

    let (label, label_style) = match &event.event {
        vigil_core::Event::LlmRequest { .. } =>
            ("REQ ", Style::default().fg(Color::Cyan).add_modifier(Modifier::DIM)),
        vigil_core::Event::LlmResponse { .. } =>
            ("RES ", Style::default().fg(Color::Cyan)),
        vigil_core::Event::ToolCall { .. } =>
            ("TOOL", Style::default().fg(Color::Yellow)),
        vigil_core::Event::ToolCallResult { blocked: true, .. } =>
            ("DENY", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        vigil_core::Event::ToolCallResult { .. } =>
            ("OK  ", Style::default().fg(Color::Green).add_modifier(Modifier::DIM)),
        vigil_core::Event::FsRead { .. } =>
            ("READ", Style::default().fg(Color::Gray)),
        vigil_core::Event::FsWrite { .. } =>
            ("WRIT", Style::default().fg(Color::Magenta)),
        vigil_core::Event::ProcessSpawn { .. } =>
            ("PROC", Style::default().fg(Color::Yellow).add_modifier(Modifier::DIM)),
        vigil_core::Event::McpCall { .. } =>
            ("MCP ", Style::default().fg(Color::Cyan).add_modifier(Modifier::DIM)),
        vigil_core::Event::PiiAlert { .. } =>
            ("PII!", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        vigil_core::Event::BurnRateAlert { .. } =>
            ("BURN", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        vigil_core::Event::LoopAlert { .. } =>
            ("LOOP", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        vigil_core::Event::WriteApprovalRequired { .. } =>
            ("WAPPR", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        vigil_core::Event::WriteApprovalDecision { .. } =>
            ("WDECID", Style::default().fg(Color::Green)),
        vigil_core::Event::ExfilAlert { .. } =>
            ("EXFL", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        vigil_core::Event::ToolTimeout { .. } =>
            ("TOUT", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        vigil_core::Event::CostAlert { .. } =>
            ("COST", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        vigil_core::Event::SessionDurationAlert { .. } =>
            ("DURA", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        vigil_core::Event::DriftAlert { .. } =>
            ("DRFT", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        vigil_core::Event::SubAgentSpawned { .. } =>
            ("TASK", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        vigil_core::Event::PromptInjectionAlert { .. } =>
            ("PINJ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
    };

    let summary = event_summary(event);
    let is_alert = matches!(
        &event.event,
        vigil_core::Event::ToolCallResult { blocked: true, .. }
        | vigil_core::Event::PiiAlert { .. }
        | vigil_core::Event::BurnRateAlert { .. }
        | vigil_core::Event::LoopAlert { .. }
        | vigil_core::Event::ExfilAlert { .. }
        | vigil_core::Event::ToolTimeout { .. }
        | vigil_core::Event::CostAlert { .. }
        | vigil_core::Event::SessionDurationAlert { .. }
        | vigil_core::Event::DriftAlert { .. }
        | vigil_core::Event::SubAgentSpawned { .. }
        | vigil_core::Event::PromptInjectionAlert { .. }
    );
    let summary_style = if is_alert {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::White)
    };

    Line::from(vec![
        Span::styled(format!("{} ", time), Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{} ", label), label_style),
        Span::styled(summary, summary_style),
    ])
}

fn event_summary(event: &TimestampedEvent) -> String {
    match &event.event {
        vigil_core::Event::LlmRequest { provider, model, last_user_message, .. } => {
            let model_short = model.split('-').next().unwrap_or(&model);
            match last_user_message.as_deref().map(|s| truncate(s, 45)) {
                Some(p) if !p.is_empty() => format!("{}/{} \"{}\"", provider, model_short, p),
                _ => format!("{}/{}", provider, model_short),
            }
        }
        vigil_core::Event::LlmResponse { provider, model, input_tokens, output_tokens, cost_usd, response_text, cache_read_input_tokens, cache_creation_input_tokens, .. } => {
            let model_short = model.split('-').next().unwrap_or(&model);
            let cache_str = if *cache_read_input_tokens > 0 || *cache_creation_input_tokens > 0 {
                format!(" c_r:{} c_w:{}", cache_read_input_tokens, cache_creation_input_tokens)
            } else {
                String::new()
            };
            let base = format!("{}/{} {}in {}out{} ${:.4}", provider, model_short, input_tokens, output_tokens, cache_str, cost_usd);
            match response_text.as_deref().map(|s| truncate(s, 30)) {
                Some(p) if !p.is_empty() => format!("{} \"{}\"", base, p),
                _ => base,
            }
        }
        vigil_core::Event::ToolCall { tool_name, .. } => tool_name.clone(),
        vigil_core::Event::ToolCallResult { tool_name, blocked, .. } =>
            format!("{} [{}]", tool_name, if *blocked { "DENIED" } else { "ok" }),
        vigil_core::Event::FsRead { path, .. } => truncate(&path, 60),
        vigil_core::Event::FsWrite { path, bytes, .. } =>
            format!("{} ({}B)", truncate(&path, 50), bytes),
        vigil_core::Event::ProcessSpawn { command, .. } => command.clone(),
        vigil_core::Event::McpCall { server, method, .. } =>
            format!("{}/{}", server, method),
        vigil_core::Event::PiiAlert { source, kinds, .. } =>
            format!("in {} -- {}", source, kinds.join(", ")),
        vigil_core::Event::BurnRateAlert { rate_per_min_usd, projected_total_usd, .. } =>
            format!("${:.3}/min projected ${:.2}", rate_per_min_usd, projected_total_usd),
        vigil_core::Event::LoopAlert { tool_name, repeat_count, .. } =>
            format!("{} repeated {}x", tool_name, repeat_count),
        vigil_core::Event::WriteApprovalRequired { path, risk_level, .. } =>
            format!("write approval required: {} [{}]", truncate(path, 40), risk_level),
        vigil_core::Event::WriteApprovalDecision { approved, .. } =>
            format!("write {}", if *approved { "approved" } else { "rejected" }),
        vigil_core::Event::ExfilAlert { source, matches, .. } =>
            format!("{}: {}", source, matches.join(", ")),
        vigil_core::Event::ToolTimeout { tool_name, elapsed_secs, .. } =>
            format!("{} running {}s with no response", tool_name, elapsed_secs),
        vigil_core::Event::CostAlert { threshold_usd, session_cost_usd, .. } =>
            format!("cost ${:.4} crossed alert threshold ${:.4}", session_cost_usd, threshold_usd),
        vigil_core::Event::SessionDurationAlert { elapsed_mins, .. } =>
            format!("session running {}min", elapsed_mins),
        vigil_core::Event::DriftAlert { signal, details, .. } =>
            format!("{}: {}", signal.as_str(), truncate(details, 60)),
        vigil_core::Event::SubAgentSpawned { depth, .. } =>
            format!("Sub-agent spawned (depth {})", depth),
        vigil_core::Event::PromptInjectionAlert { category, .. } =>
            format!("Prompt injection: {}", category),
    }
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    let flat: String = s.chars().map(|c| if c == '\n' || c == '\r' { ' ' } else { c }).collect();
    if flat.chars().count() > max {
        let end = flat.char_indices().nth(max).map(|(i, _)| i).unwrap_or(flat.len());
        format!("{}...", &flat[..end])
    } else {
        flat
    }
}

// ─── detail pane ─────────────────────────────────────────────────────────────

fn detail_lines(event: &TimestampedEvent) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = Vec::new();

    match &event.event {
        vigil_core::Event::LlmRequest { provider, model, last_user_message, system_prompt, .. } => {
            out.push(header_line(format!("REQUEST  {}/{}", provider, model), Color::Cyan));
            if let Some(sys) = system_prompt {
                out.push(sep_line("system prompt"));
                for l in sys.lines() { out.push(body_line(l)); }
            }
            if let Some(msg) = last_user_message {
                out.push(sep_line("user message"));
                for l in msg.lines() { out.push(body_line(l)); }
            }
        }
        vigil_core::Event::LlmResponse { provider, model, input_tokens, output_tokens, cost_usd, response_text, cache_read_input_tokens, cache_creation_input_tokens, .. } => {
            let cache_detail = if *cache_read_input_tokens > 0 || *cache_creation_input_tokens > 0 {
                format!("  cache_r:{} cache_w:{}", cache_read_input_tokens, cache_creation_input_tokens)
            } else {
                String::new()
            };
            out.push(header_line(
                format!("RESPONSE  {}/{}  {}in {}out{}  ${:.4}", provider, model, input_tokens, output_tokens, cache_detail, cost_usd),
                Color::Cyan,
            ));
            match response_text {
                Some(text) => {
                    out.push(sep_line("assistant"));
                    for l in text.lines() { out.push(body_line(l)); }
                }
                None => {
                    out.push(Line::from(Span::styled(
                        "  (tool-use only -- no text content)",
                        Style::default().fg(Color::DarkGray),
                    )));
                }
            }
        }
        vigil_core::Event::ToolCall { agent, tool_name, input, .. } => {
            out.push(header_line(format!("TOOL CALL  {}  ->  {}", agent, tool_name), Color::Yellow));
            out.push(sep_line("input"));
            let pretty = serde_json::to_string_pretty(&input).unwrap_or_default();
            for l in pretty.lines() { out.push(body_line(l)); }
        }
        vigil_core::Event::ToolCallResult { agent, tool_name, blocked, .. } => {
            let (label, color) = if *blocked { ("DENIED", Color::Red) } else { ("ALLOWED", Color::Green) };
            out.push(header_line(
                format!("TOOL RESULT  {}  {}  [{}]", agent, tool_name, label),
                color,
            ));
        }
        vigil_core::Event::FsRead { path, .. } => {
            out.push(header_line("FS READ".to_string(), Color::Gray));
            out.push(body_line(&path));
        }
        vigil_core::Event::FsWrite { path, bytes, .. } => {
            out.push(header_line("FS WRITE".to_string(), Color::Magenta));
            out.push(body_line(&format!("{} ({} bytes)", path, bytes)));
        }
        vigil_core::Event::ProcessSpawn { command, args, .. } => {
            out.push(header_line("PROCESS SPAWN".to_string(), Color::Yellow));
            out.push(body_line(&format!("{} {}", command, args.join(" "))));
        }
        vigil_core::Event::McpCall { server, method, params, .. } => {
            out.push(header_line(format!("MCP  {}/{}", server, method), Color::Cyan));
            out.push(sep_line("params"));
            let pretty = serde_json::to_string_pretty(&params).unwrap_or_default();
            for l in pretty.lines() { out.push(body_line(l)); }
        }
        vigil_core::Event::PiiAlert { source, kinds, .. } => {
            out.push(header_line(format!("PII ALERT  source: {}", source), Color::Red));
            out.push(body_line(&format!("Detected: {}", kinds.join(", "))));
        }
        vigil_core::Event::BurnRateAlert { rate_per_min_usd, projected_total_usd, session_cost_usd, .. } => {
            out.push(header_line("BURN RATE ALERT".to_string(), Color::Red));
            out.push(body_line(&format!("Current rate:     ${:.4}/min", rate_per_min_usd)));
            out.push(body_line(&format!("Session cost so far: ${:.4}", session_cost_usd)));
            out.push(body_line(&format!("Projected total:  ${:.4}", projected_total_usd)));
        }
        vigil_core::Event::LoopAlert { tool_name, repeat_count, .. } => {
            out.push(header_line("LOOP DETECTED".to_string(), Color::Red));
            out.push(body_line(&format!("Tool:         {}", tool_name)));
            out.push(body_line(&format!("Repeat count: {}", repeat_count)));
            out.push(body_line("Same tool+input combination repeated too many times."));
        }
        vigil_core::Event::WriteApprovalRequired { path, risk_level, reasons, .. } => {
            out.push(header_line(format!("WRITE APPROVAL REQUIRED  [{}]", risk_level), Color::Yellow));
            out.push(body_line(&format!("Path: {}", path)));
            for r in reasons {
                out.push(body_line(&format!("  - {}", r)));
            }
        }
        vigil_core::Event::WriteApprovalDecision { approval_id, approved, .. } => {
            let (label, color) = if *approved { ("APPROVED", Color::Green) } else { ("REJECTED", Color::Red) };
            out.push(header_line(format!("WRITE DECISION  [{}]", label), color));
            out.push(body_line(&format!("approval_id: {}", approval_id)));
        }
        vigil_core::Event::ExfilAlert { source, matches, .. } => {
            out.push(header_line(format!("EXFIL ALERT  source: {}", source), Color::Red));
            out.push(body_line("Credential fingerprint(s) from a file read detected in outbound content:"));
            for m in matches {
                out.push(body_line(&format!("  [!] {}", m)));
            }
        }
        vigil_core::Event::ToolTimeout { tool_name, elapsed_secs, .. } => {
            out.push(header_line("TOOL TIMEOUT".to_string(), Color::Yellow));
            out.push(body_line(&format!("tool:    {}", tool_name)));
            out.push(body_line(&format!("elapsed: {}s ({:.1}min)", elapsed_secs, *elapsed_secs as f64 / 60.0)));
            out.push(body_line("The agent called this tool but no follow-up LLM request arrived in time."));
            out.push(body_line("The tool may be hung. Consider interrupting the session."));
        }
        vigil_core::Event::CostAlert { threshold_usd, session_cost_usd, .. } => {
            out.push(header_line("COST ALERT".to_string(), Color::Yellow));
            out.push(body_line(&format!("threshold:    ${:.4}", threshold_usd)));
            out.push(body_line(&format!("session cost: ${:.4}", session_cost_usd)));
            out.push(body_line("Soft alert — session continues. Set budget.max_cost_usd to stop the session."));
        }
        vigil_core::Event::SessionDurationAlert { elapsed_mins, .. } => {
            out.push(header_line("SESSION DURATION ALERT".to_string(), Color::Yellow));
            out.push(body_line(&format!("elapsed: {}min ({:.1}h)", elapsed_mins, *elapsed_mins as f64 / 60.0)));
            out.push(body_line("Session has exceeded budget.max_session_duration_mins."));
        }
        vigil_core::Event::DriftAlert { signal, details, .. } => {
            out.push(header_line(format!("DRIFT ALERT  {}", signal.as_str()), Color::Red));
            out.push(body_line(details));
        }
        vigil_core::Event::SubAgentSpawned { tool_name, depth, .. } => {
            out.push(header_line("SUB-AGENT SPAWNED".to_string(), Color::Cyan));
            out.push(body_line(&format!("tool:  {}", tool_name)));
            out.push(body_line(&format!("depth: {}", depth)));
        }
        vigil_core::Event::PromptInjectionAlert { tool_name, category, snippet, .. } => {
            out.push(header_line("PROMPT INJECTION ALERT".to_string(), Color::Red));
            out.push(body_line(&format!("tool_use_id: {}", tool_name)));
            out.push(body_line(&format!("category:    {}", category)));
            out.push(body_line(&format!("snippet:     {}", snippet)));
        }
    }

    out
}

fn header_line(s: String, color: Color) -> Line<'static> {
    Line::from(Span::styled(s, Style::default().fg(color).add_modifier(Modifier::BOLD)))
}

fn sep_line(label: &'static str) -> Line<'static> {
    Line::from(Span::styled(
        format!("  -- {} --", label),
        Style::default().fg(Color::DarkGray),
    ))
}

fn body_line(s: &str) -> Line<'static> {
    Line::from(Span::raw(format!("  {}", s)))
}

// ─── stats sidebar ────────────────────────────────────────────────────────────

fn stats_lines(app: &App) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = Vec::new();

    let sid = app.session.id.to_string();
    let sid_short = sid[..8.min(sid.len())].to_string();
    let name_display = app.session.name.clone().unwrap_or(sid_short);

    out.push(stat_row("session", truncate(&name_display, 18), Color::White));
    out.push(stat_row("agent", truncate(&app.session.agent, 14), Color::White));
    out.push(Line::from(""));

    let cost_color = if app.session.total_cost_usd > 0.0 { Color::Green } else { Color::DarkGray };
    out.push(stat_row("cost", format!("${:.4}", app.session.total_cost_usd), cost_color));
    out.push(stat_row("in", fmt_num(app.session.total_input_tokens) + " tok", Color::White));
    out.push(stat_row("out", fmt_num(app.session.total_output_tokens) + " tok", Color::White));
    out.push(Line::from(""));
    out.push(Line::from(Span::styled("--------------------", Style::default().fg(Color::DarkGray))));

    let c = &app.counts;
    if c.requests > 0  { out.push(count_row("req",     c.requests,  Color::Cyan)); }
    if c.responses > 0 { out.push(count_row("res",     c.responses, Color::Cyan)); }
    if c.tools > 0     { out.push(count_row("tool",    c.tools,     Color::Yellow)); }
    if c.results > 0   { out.push(count_row("result",  c.results,   Color::Green)); }
    if c.blocked > 0   { out.push(count_row("blocked", c.blocked,   Color::Red)); }
    if c.fs_reads > 0  { out.push(count_row("fsread",  c.fs_reads,  Color::Gray)); }
    if c.fs_writes > 0 { out.push(count_row("fswrite", c.fs_writes, Color::Magenta)); }
    if c.spawns > 0    { out.push(count_row("spawn",   c.spawns,    Color::Yellow)); }
    if c.mcp > 0       { out.push(count_row("mcp",     c.mcp,       Color::Cyan)); }

    out.push(Line::from(Span::styled("--------------------", Style::default().fg(Color::DarkGray))));

    let viols = app.session.policy_violations;
    let pii = app.session.pii_detections;
    out.push(stat_row(
        "violations",
        viols.to_string(),
        if viols > 0 { Color::Red } else { Color::DarkGray },
    ));
    out.push(stat_row(
        "pii",
        pii.to_string(),
        if pii > 0 { Color::Red } else { Color::DarkGray },
    ));

    if let Some(rate) = app.last_burn_rate {
        out.push(stat_row(
            "rate",
            format!("${:.3}/min", rate),
            Color::Red,
        ));
    }
    if c.burn_alerts > 0 {
        out.push(stat_row(
            "burn alerts",
            c.burn_alerts.to_string(),
            Color::Red,
        ));
    }
    if c.loop_alerts > 0 {
        out.push(stat_row(
            "loop alerts",
            c.loop_alerts.to_string(),
            Color::Red,
        ));
    }
    if c.exfil_alerts > 0 {
        out.push(stat_row(
            "exfil alerts",
            c.exfil_alerts.to_string(),
            Color::Red,
        ));
    }
    if c.drift_alerts > 0 {
        out.push(stat_row(
            "drift alerts",
            c.drift_alerts.to_string(),
            Color::Red,
        ));
    }
    if c.sub_agent_spawns > 0 {
        out.push(stat_row(
            "sub-agents",
            c.sub_agent_spawns.to_string(),
            Color::Yellow,
        ));
    }
    if c.injection_alerts > 0 {
        out.push(stat_row(
            "inj alerts",
            c.injection_alerts.to_string(),
            Color::Red,
        ));
    }

    out
}

fn stat_row(key: &'static str, val: String, val_color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{:<11}", key), Style::default().fg(Color::DarkGray)),
        Span::styled(val, Style::default().fg(val_color)),
    ])
}

fn count_row(key: &'static str, n: usize, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{:<8}", key), Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{:>5}", n), Style::default().fg(color)),
    ])
}

fn fmt_num(n: u32) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out.chars().rev().collect()
}

// ─── layout ──────────────────────────────────────────────────────────────────

pub fn draw(frame: &mut Frame, app: &mut App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(55),
            Constraint::Percentage(44),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(65),
            Constraint::Percentage(35),
        ])
        .split(root[1]);

    let panel_height = main[0].height.saturating_sub(2) as usize;
    if panel_height > 0 {
        app.visible_height = panel_height;
    }

    draw_header(frame, app, root[0]);
    draw_event_list(frame, app, main[0]);
    draw_stats_panel(frame, app, main[1]);
    draw_detail_pane(frame, app, root[2]);
    draw_help_bar(frame, app, root[3]);
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let sid = app.session.id.to_string();
    let sid_short = app.session.name.as_deref().unwrap_or(&sid[..8.min(sid.len())]);

    let status = if app.is_replay && app.agent_done {
        Span::styled(" REPLAY DONE ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD))
    } else if app.is_replay {
        Span::styled(" REPLAY ", Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else if app.agent_done {
        Span::styled(" DONE ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" LIVE ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD))
    };

    let position = if app.auto_scroll {
        Span::styled("  tail", Style::default().fg(Color::DarkGray))
    } else {
        Span::styled(
            format!("  {}/{}", app.selected + 1, app.event_log.len()),
            Style::default().fg(Color::Yellow),
        )
    };

    let quit_hint = if app.agent_done {
        Span::styled("  (q to exit)", Style::default().fg(Color::Green))
    } else {
        Span::raw("")
    };

    let cfg_span = match &app.config_path {
        Some(p) => Span::styled(format!("  cfg:{}", p), Style::default().fg(Color::DarkGray)),
        None => Span::raw(""),
    };

    let header = Paragraph::new(Line::from(vec![
        status,
        Span::raw("  "),
        Span::styled("vigil", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("  session {}  agent {}", sid_short, app.session.agent),
            Style::default().fg(Color::DarkGray),
        ),
        position,
        cfg_span,
        quit_hint,
    ]))
    .block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(Color::DarkGray)));

    frame.render_widget(header, area);
}

fn draw_event_list(frame: &mut Frame, app: &mut App, area: Rect) {
    let total = app.event_log.len();
    let start = app.scroll_offset.min(total);
    let end = (start + app.visible_height).min(total);

    let items: Vec<ListItem> = app.event_log[start..end]
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let abs = start + i;
            if abs == app.selected {
                ListItem::new(line.clone())
                    .style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
            } else {
                ListItem::new(line.clone())
            }
        })
        .collect();

    let title = if total > app.visible_height {
        format!("Events  {}-{} of {}", start + 1, end, total)
    } else {
        format!("Events  {}", total)
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(title, Style::default().fg(Color::White)))
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(list, area);
}

fn draw_stats_panel(frame: &mut Frame, app: &App, area: Rect) {
    let lines = stats_lines(app);
    let stats = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled("Stats", Style::default().fg(Color::White)))
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(stats, area);
}

fn draw_detail_pane(frame: &mut Frame, app: &App, area: Rect) {
    // If there is a pending approval, render the approval overlay instead.
    if let Some(ref info) = app.pending_approval {
        let mut lines: Vec<Line<'static>> = Vec::new();
        lines.push(Line::from(Span::styled(
            "  WRITE APPROVAL REQUIRED",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            "  -----------------------",
            Style::default().fg(Color::Red),
        )));
        lines.push(Line::from(vec![
            Span::styled("  Path:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(info.path.clone(), Style::default().fg(Color::White)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Risk:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(info.risk_level.clone(), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Reasons: ", Style::default().fg(Color::DarkGray)),
            Span::styled(info.reasons.join(", "), Style::default().fg(Color::Yellow)),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  --- BEFORE ---", Style::default().fg(Color::DarkGray))));
        for l in info.before.lines().take(20) {
            lines.push(Line::from(Span::styled(format!("  {}", l), Style::default().fg(Color::Gray))));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("  --- AFTER ---", Style::default().fg(Color::DarkGray))));
        for l in info.after.lines().take(20) {
            lines.push(Line::from(Span::styled(format!("  {}", l), Style::default().fg(Color::Green))));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  [y] Approve   ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled("[n] Reject", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        ]));

        let approval_pane = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Span::styled(
                        "WRITE APPROVAL REQUIRED  y=approve  n=reject",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ))
                    .border_style(Style::default().fg(Color::Yellow)),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(approval_pane, area);
        return;
    }

    let content = if app.raw_events.is_empty() {
        vec![Line::from(Span::styled(
            "  Select an event with up/down to inspect it here",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        let idx = app.selected.min(app.raw_events.len().saturating_sub(1));
        detail_lines(&app.raw_events[idx])
    };

    let (title, border_style) = if app.detail_focused {
        (
            "Detail  TAB=back to list  up/dn PgUp/PgDn Home=scroll",
            Style::default().fg(Color::Cyan),
        )
    } else {
        (
            "Detail  TAB=focus/scroll",
            Style::default().fg(Color::DarkGray),
        )
    };

    let detail = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(title, Style::default().fg(Color::White)))
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll as u16, 0));
    frame.render_widget(detail, area);
}

fn draw_help_bar(frame: &mut Frame, app: &App, area: Rect) {
    let text = if app.pending_approval.is_some() {
        "y=approve write  n=reject write"
    } else if app.detail_focused {
        "TAB=back  up/dn PgUp/PgDn Home=scroll detail  Esc=list"
    } else {
        "q=quit  up/dn=select  PgUp/PgDn  End=tail  TAB=detail"
    };
    let help = Paragraph::new(Span::styled(text, Style::default().fg(Color::DarkGray)));
    frame.render_widget(help, area);
}

// ─── launcher ────────────────────────────────────────────────────────────────

pub async fn run_launcher(recent: Vec<SessionSummary>) -> Result<Option<String>> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut input = String::new();
    let mut result: Option<String> = None;

    loop {
        terminal.draw(|f| draw_launcher(f, &input, &recent))?;

        if event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') if input.is_empty() => break,
                    KeyCode::Esc => break,
                    KeyCode::Enter => {
                        let trimmed = input.trim().to_string();
                        if !trimmed.is_empty() {
                            result = Some(trimmed);
                            break;
                        }
                    }
                    KeyCode::Backspace => { input.pop(); }
                    KeyCode::Char(c) => input.push(c),
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(result)
}

fn draw_launcher(frame: &mut Frame, input: &str, recent: &[SessionSummary]) {
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(5),
            Constraint::Length(1),
        ])
        .split(area);

    // Title bar
    let title = Paragraph::new(Line::from(vec![
        Span::styled("vigil", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled("  AI agent observability", Style::default().fg(Color::DarkGray)),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(title, chunks[0]);

    // Recent sessions
    let session_items: Vec<ListItem> = if recent.is_empty() {
        vec![ListItem::new(Span::styled(
            "  No previous sessions",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        recent.iter().take(8).map(|s| {
            let started = s.started_at.format("%Y-%m-%d %H:%M").to_string();
            let cost = format!("${:.4}", s.total_cost_usd);
            let tokens = s.total_input_tokens + s.total_output_tokens;
            ListItem::new(Line::from(vec![
                Span::styled(started, Style::default().fg(Color::DarkGray)),
                Span::raw("  "),
                Span::styled(format!("{:<14}", &s.agent), Style::default().fg(Color::White)),
                Span::styled(format!("{:>8}", cost), Style::default().fg(Color::Green)),
                Span::raw("  "),
                Span::styled(
                    format!("{} tok", fmt_num(tokens)),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{} events", s.event_count),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        }).collect()
    };

    let sessions_list = List::new(session_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled("Recent Sessions", Style::default().fg(Color::White)))
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(sessions_list, chunks[1]);

    // Input box
    let cursor = if (input.len() / 2) % 2 == 0 { "_" } else { "_" };
    let input_display = format!("{}{}", input, cursor);
    let input_widget = Paragraph::new(Span::styled(
        input_display,
        Style::default().fg(Color::White),
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(
                "Agent command",
                Style::default().fg(Color::White),
            ))
            .border_style(Style::default().fg(Color::Cyan)),
    )
    .wrap(Wrap { trim: false });
    frame.render_widget(input_widget, chunks[2]);

    // Help
    let help = Paragraph::new(Span::styled(
        "Enter=launch  Esc/q=quit  (agent runs in a new window, vigil monitors here)",
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(help, chunks[3]);
}

// ─── runtime ─────────────────────────────────────────────────────────────────

pub async fn run_tui(
    mut app: App,
    mut event_rx: tokio::sync::broadcast::Receiver<TimestampedEvent>,
) -> Result<App> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, &mut app, &mut event_rx).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result?;
    Ok(app)
}

async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    event_rx: &mut tokio::sync::broadcast::Receiver<TimestampedEvent>,
) -> Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;

        tokio::select! {
            // Stop polling the channel once it is closed so the timer branch
            // can fire and service keyboard input. Without this guard, recv()
            // resolves instantly on every iteration after the channel closes,
            // starving the keyboard poller and making 'q' unresponsive.
            event_result = event_rx.recv(), if !app.agent_done => {
                match event_result {
                    Ok(ts_event) => {
                        app.push_event(&ts_event);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        app.agent_done = true;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                }
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                if event::poll(std::time::Duration::from_millis(10))? {
                    if let Event::Key(key_event) = event::read()? {
                        if key_event.kind == KeyEventKind::Press {
                            app.on_key(key_event.code);
                            if app.should_quit { break; }
                        }
                    }
                }
            }
        }

        if app.should_quit { break; }
    }

    Ok(())
}

// ─── Session browser ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum BrowseAction {
    Replay(uuid::Uuid),
    Delete(uuid::Uuid),
    Quit,
}

struct BrowserState {
    sessions: Vec<vigil_core::session::SessionSummary>,
    table_state: TableState,
}

impl BrowserState {
    fn new(sessions: Vec<vigil_core::session::SessionSummary>) -> Self {
        let mut table_state = TableState::default();
        if !sessions.is_empty() {
            table_state.select(Some(0));
        }
        Self { sessions, table_state }
    }

    fn selected(&self) -> Option<&vigil_core::session::SessionSummary> {
        self.table_state.selected().and_then(|i| self.sessions.get(i))
    }

    fn move_up(&mut self) {
        if self.sessions.is_empty() { return; }
        let i = self.table_state.selected().unwrap_or(0);
        self.table_state.select(Some(if i == 0 { self.sessions.len() - 1 } else { i - 1 }));
    }

    fn move_down(&mut self) {
        if self.sessions.is_empty() { return; }
        let i = self.table_state.selected().unwrap_or(0);
        self.table_state.select(Some((i + 1) % self.sessions.len()));
    }
}

pub async fn run_session_browser(
    sessions: Vec<vigil_core::session::SessionSummary>,
) -> Result<Option<BrowseAction>> {
    if sessions.is_empty() {
        return Ok(None);
    }

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = BrowserState::new(sessions);

    let action = loop {
        terminal.draw(|f| draw_browser(f, &mut state))?;

        if event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press { continue; }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break Some(BrowseAction::Quit),
                    KeyCode::Up | KeyCode::Char('k') => state.move_up(),
                    KeyCode::Down | KeyCode::Char('j') => state.move_down(),
                    KeyCode::Enter | KeyCode::Char('r') => {
                        if let Some(s) = state.selected() {
                            break Some(BrowseAction::Replay(s.id));
                        }
                    }
                    KeyCode::Char('d') => {
                        if let Some(s) = state.selected() {
                            break Some(BrowseAction::Delete(s.id));
                        }
                    }
                    _ => {}
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(action)
}

fn draw_browser(frame: &mut Frame, state: &mut BrowserState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(12), Constraint::Length(1)])
        .split(area);

    // Column widths: Name(20), Agent(12), Started(16), Cost(10), Tokens(10), Events(7)
    let col_widths = [
        Constraint::Length(20),
        Constraint::Length(12),
        Constraint::Length(16),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(7),
    ];

    let header_style = Style::default().fg(Color::White).add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
    let header = Row::new([
        Cell::from("NAME / ID").style(header_style),
        Cell::from("AGENT").style(header_style),
        Cell::from("STARTED").style(header_style),
        Cell::from("COST").style(header_style),
        Cell::from("TOKENS").style(header_style),
        Cell::from("EVENTS").style(header_style),
    ]);

    let rows: Vec<Row> = state.sessions.iter().map(|s| {
        let label = s.name.clone().unwrap_or_else(|| s.id.to_string()[..8].to_string());
        let tokens = s.total_input_tokens + s.total_output_tokens;
        Row::new([
            Cell::from(truncate_str(&label, 20)),
            Cell::from(truncate_str(&s.agent, 12)),
            Cell::from(s.started_at.format("%Y-%m-%d %H:%M").to_string()),
            Cell::from(format!("${:.4}", s.total_cost_usd)),
            Cell::from(format!("{}", tokens)),
            Cell::from(format!("{}", s.event_count)),
        ])
    }).collect();

    let table = Table::new(rows, col_widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    format!(" vigil sessions ({}) ", state.sessions.len()),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                )),
        )
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, chunks[0], &mut state.table_state);

    // Detail panel
    let detail_text = if let Some(s) = state.selected() {
        let name_line = s.name.as_deref().unwrap_or("(unlabelled)");
        let duration = s.ended_at
            .map(|e| format_dur(e - s.started_at))
            .unwrap_or_else(|| "still running".to_string());
        format!(
            "Name:       {}\nID:         {}\nAgent:      {}\nStarted:    {}\nDuration:   {}\nCost:       ${:.6}\nTokens:     {} in / {} out\nEvents:     {}\nViolations: {}",
            name_line,
            s.id,
            s.agent,
            s.started_at.format("%Y-%m-%d %H:%M:%S UTC"),
            duration,
            s.total_cost_usd,
            s.total_input_tokens,
            s.total_output_tokens,
            s.event_count,
            s.policy_violations,
        )
    } else {
        "No session selected.".to_string()
    };

    let detail = Paragraph::new(detail_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(" Session detail ", Style::default().fg(Color::Yellow))),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(detail, chunks[1]);

    // Help bar
    let help = Paragraph::new(Span::styled(
        "  ↑/k ↓/j Navigate   Enter/r Replay   d Delete   q Quit",
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(help, chunks[2]);
}

fn format_dur(d: chrono::Duration) -> String {
    let s = d.num_seconds().abs();
    if s >= 3600 { format!("{}h{:02}m", s / 3600, (s % 3600) / 60) }
    else if s >= 60 { format!("{}m{:02}s", s / 60, s % 60) }
    else { format!("{}s", s) }
}

fn truncate_str(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() }
    else { format!("{}…", &s[..n.saturating_sub(1)]) }
}

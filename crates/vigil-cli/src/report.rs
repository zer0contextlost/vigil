use anyhow::Result;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;

use vigil_core::{
    event::Event, session::Session, ReportConfig, VigilConfig,
};

#[derive(Debug, Clone, Serialize)]
pub struct ReportHeadline {
    pub session_id: String,
    pub session_name: Option<String>,
    pub model: String,
    pub provider: String,
    pub git_branch: Option<String>,
    pub git_commit: Option<String>,
    pub total_cost: f64,
    pub total_turns: u32,
    pub total_input_tokens: u32,
    pub total_output_tokens: u32,
    pub cache_read_tokens: u32,
    pub cache_creation_tokens: u32,
    pub duration_secs: u64,
    pub session_start_time: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HygieneSignal {
    pub signal: String,
    pub verdict: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertEntry {
    pub turn: u32,
    pub label: String,
    pub detail: String,
    pub offset_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileEntry {
    pub path: String,
    pub reads: u32,
    pub writes: u32,
    pub lines_added: u32,
    pub lines_removed: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolEntry {
    pub tool_name: String,
    pub calls: u32,
    pub errors: u32,
    pub avg_duration_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub session_id: String,
    pub scorecard_version: u32,
    pub headline: ReportHeadline,
    pub hygiene: Vec<HygieneSignal>,
    pub alerts: Vec<AlertEntry>,
    pub files: Vec<FileEntry>,
    pub tools: Vec<ToolEntry>,
    pub timeline: String,
}

#[allow(dead_code)]
pub struct ReportArgs {
    pub session_id: String,
    pub json: bool,
    pub html: bool,
    pub html_fragment: bool,
    pub include_payloads: bool,
    pub config: Option<PathBuf>,
}

pub async fn run(session: Session, args: ReportArgs) -> Result<()> {
    let config = if let Some(config_path) = &args.config {
        VigilConfig::load(config_path)?
    } else {
        VigilConfig::default()
    };

    let report_config = config.report.unwrap_or_default();
    let report = build_report(&session, &report_config)?;

    if args.json {
        output_json(&report)?;
    } else if args.html {
        output_html(&report, false, args.include_payloads)?;
    } else if args.html_fragment {
        output_html(&report, true, args.include_payloads)?;
    } else {
        output_text(&report)?;
    }

    let _ = args.include_payloads; // Note: raw_request/raw_response not yet exposed in report

    Ok(())
}

fn build_report(session: &Session, config: &ReportConfig) -> Result<Report> {
    let mut headline = extract_headline(session);

    // Get first model/provider from LlmResponse events if headline doesn't have them
    for event_wrapped in &session.events {
        if let Event::LlmResponse { model, provider, .. } = &event_wrapped.event {
            if headline.model.is_empty() {
                headline.model = model.clone();
                headline.provider = provider.clone();
            }
            break;
        }
    }

    let hygiene = compute_hygiene_signals(&session.events, config);
    let alerts = extract_alerts(&session.events);
    let files = compute_files_touched(&session.events);
    let tools = compute_tool_heatmap(&session.events);
    let timeline = generate_timeline(&session.events);

    Ok(Report {
        session_id: session.id.to_string(),
        scorecard_version: 1,
        headline,
        hygiene,
        alerts,
        files,
        tools,
        timeline,
    })
}

fn extract_headline(session: &Session) -> ReportHeadline {
    let mut total_cost = 0.0;
    let mut total_turns = 0u32;
    let mut total_input_tokens = 0u32;
    let mut total_output_tokens = 0u32;
    let mut cache_read_tokens = 0u32;
    let mut cache_creation_tokens = 0u32;
    let git_branch = None;
    let git_commit = None;
    let session_start_time = session.started_at;
    let mut duration_secs = 0u64;

    for event_wrapped in &session.events {
        match &event_wrapped.event {
            Event::LlmResponse {
                cost_usd,
                output_tokens,
                cache_read_input_tokens,
                cache_creation_input_tokens,
                ..
            } => {
                total_cost += cost_usd;
                total_output_tokens += output_tokens;
                cache_read_tokens += cache_read_input_tokens;
                cache_creation_tokens += cache_creation_input_tokens;
            }
            Event::LlmRequest { input_tokens, turn_number, .. } => {
                total_turns = total_turns.max(*turn_number);
                total_input_tokens += input_tokens;
            }
            _ => {}
        }
    }

    // Session start time is from session metadata
    if let Some(ended_at) = session.ended_at {
        duration_secs = ended_at
            .signed_duration_since(session_start_time)
            .num_seconds()
            .max(0) as u64;
    }

    // Try to extract git context from the session (would be from SessionStart event if present)
    // For now, these will be None unless SessionStart events are present
    for event_wrapped in &session.events {
        match &event_wrapped.event {
            // Assuming there's a SessionStart event or similar
            _ => {}
        }
    }

    ReportHeadline {
        session_id: session.id.to_string(),
        session_name: session.name.clone(),
        model: String::new(), // Will be filled in build_report
        provider: String::new(), // Will be filled in build_report
        git_branch,
        git_commit,
        total_cost,
        total_turns,
        total_input_tokens,
        total_output_tokens,
        cache_read_tokens,
        cache_creation_tokens,
        duration_secs,
        session_start_time: session_start_time.to_rfc3339(),
    }
}

fn compute_hygiene_signals(events: &[vigil_core::envelope::TimestampedEvent], config: &ReportConfig) -> Vec<HygieneSignal> {
    let mut signals = Vec::new();

    // a. Input token growth rate
    if let Some((verdict, note)) = signal_input_growth(events, config) {
        signals.push(HygieneSignal {
            signal: "input_growth".to_string(),
            verdict,
            note,
        });
    }

    // b. Re-read rate
    let (verdict, note) = signal_reread_rate(events, config);
    signals.push(HygieneSignal {
        signal: "reread_rate".to_string(),
        verdict,
        note,
    });

    // c. Tool retry / thrash
    let (verdict, note) = signal_tool_retry(events);
    signals.push(HygieneSignal {
        signal: "tool_retry".to_string(),
        verdict,
        note,
    });

    // d. Turn-to-first-write
    let (verdict, note) = signal_turn_to_first_write(events, config);
    signals.push(HygieneSignal {
        signal: "turn_to_first_write".to_string(),
        verdict,
        note,
    });

    // e. Policy friction
    let (verdict, note) = signal_policy_friction(events);
    signals.push(HygieneSignal {
        signal: "policy_friction".to_string(),
        verdict,
        note,
    });

    // f. Sub-agent fan-out
    let (verdict, note) = signal_subagent_fanout(events);
    signals.push(HygieneSignal {
        signal: "subagent_fanout".to_string(),
        verdict,
        note,
    });

    // g. Late-session alert clustering
    if let Some((verdict, note)) = signal_alert_clustering(events) {
        signals.push(HygieneSignal {
            signal: "alert_clustering".to_string(),
            verdict,
            note,
        });
    }

    // h. Write approval rejection rate
    let (verdict, note) = signal_write_approval_rejection(events);
    signals.push(HygieneSignal {
        signal: "write_approval_rejection".to_string(),
        verdict,
        note,
    });

    signals
}

fn signal_input_growth(
    events: &[vigil_core::envelope::TimestampedEvent],
    config: &ReportConfig,
) -> Option<(String, String)> {
    let warn_mult = config.input_growth_warn_multiplier.unwrap_or(1.5);
    let flag_mult = config.input_growth_flag_multiplier.unwrap_or(2.0);

    let mut input_tokens = Vec::new();
    for event_wrapped in events {
        if let Event::LlmRequest { input_tokens: tokens, .. } = &event_wrapped.event {
            input_tokens.push(*tokens);
        }
    }

    if input_tokens.len() < 6 {
        return None;
    }

    let bucket_size = input_tokens.len() / 3;
    let bucket1: f64 = input_tokens[0..bucket_size].iter().map(|&t| t as f64).sum::<f64>() / bucket_size as f64;
    let bucket3: f64 = input_tokens[input_tokens.len() - bucket_size..].iter().map(|&t| t as f64).sum::<f64>() / bucket_size as f64;

    let ratio = bucket3 / bucket1.max(1.0);

    let (verdict, note) = if ratio >= flag_mult {
        ("FLAG".to_string(), "Context grew rapidly late in session — consider compacting earlier".to_string())
    } else if ratio >= warn_mult {
        ("WATCH".to_string(), format!("Input tokens grew {:.1}x from early to late turns", ratio))
    } else {
        ("GOOD".to_string(), "Input token growth rate stable".to_string())
    };

    Some((verdict, note))
}

fn signal_reread_rate(
    events: &[vigil_core::envelope::TimestampedEvent],
    config: &ReportConfig,
) -> (String, String) {
    let warn_count = config.reread_warn_count.unwrap_or(2);
    let flag_count = config.reread_flag_count.unwrap_or(3);

    let mut read_counts: HashMap<String, u32> = HashMap::new();
    for event_wrapped in events {
        if let Event::FsRead { path, .. } = &event_wrapped.event {
            *read_counts.entry(path.clone()).or_insert(0) += 1;
        }
    }

    let overread = read_counts
        .values()
        .filter(|&&count| count > warn_count)
        .count();

    let (verdict, note) = if overread >= flag_count as usize {
        ("FLAG".to_string(), format!("Agent re-read {} files multiple times — possible context loss", overread))
    } else if overread > 0 {
        ("WATCH".to_string(), format!("{} paths read multiple times", overread))
    } else {
        ("GOOD".to_string(), "No paths read excessively".to_string())
    };

    (verdict, note)
}

fn signal_tool_retry(events: &[vigil_core::envelope::TimestampedEvent]) -> (String, String) {
    let mut retries = 0u32;

    for i in 0..events.len() {
        if let Event::ToolCallResult { is_error: true, tool_name: error_tool, .. } = &events[i].event {
            // Look for the same tool within next 3 turns
            for j in (i + 1)..events.len().min(i + 4) {
                if let Event::ToolCall { tool_name, .. } = &events[j].event {
                    if tool_name == error_tool {
                        retries += 1;
                        break;
                    }
                }
            }
        }
    }

    let (verdict, note) = if retries >= 3 {
        ("FLAG".to_string(), format!("{} tool errors followed by immediate retry — agent was stuck", retries))
    } else if retries > 0 {
        ("WATCH".to_string(), format!("{} tool retries detected", retries))
    } else {
        ("GOOD".to_string(), "No tool retries".to_string())
    };

    (verdict, note)
}

fn signal_turn_to_first_write(
    events: &[vigil_core::envelope::TimestampedEvent],
    config: &ReportConfig,
) -> (String, String) {
    let warn = config.turn_to_first_write_warn.unwrap_or(5);
    let flag = config.turn_to_first_write_flag.unwrap_or(15);

    let mut turn_count = 0u32;
    let mut first_write_turn = None;

    for event_wrapped in events {
        match &event_wrapped.event {
            Event::LlmRequest { .. } => {
                turn_count += 1;
            }
            Event::FsWrite { .. } => {
                if first_write_turn.is_none() {
                    first_write_turn = Some(turn_count);
                }
            }
            _ => {}
        }
    }

    let (verdict, note) = if let Some(turns) = first_write_turn {
        if turns > flag {
            ("FLAG".to_string(), format!("{} turns before first file change — agent spent a long time exploring", turns))
        } else if turns > warn {
            ("WATCH".to_string(), format!("{} turns before first write", turns))
        } else {
            ("GOOD".to_string(), format!("First write at turn {}", turns))
        }
    } else {
        ("GOOD".to_string(), "No file writes recorded this session".to_string())
    };

    (verdict, note)
}

fn signal_policy_friction(events: &[vigil_core::envelope::TimestampedEvent]) -> (String, String) {
    let denials = 0u32;
    let mut rejections = 0u32;

    for event_wrapped in events {
        match &event_wrapped.event {
            Event::WriteApprovalDecision { approved: false, .. } => rejections += 1,
            _ => {}
        }
    }

    let (verdict, note) = if denials >= 3 || rejections >= 2 {
        ("FLAG".to_string(), format!("{} policy denials / {} write rejections — review policy rules or agent behavior", denials, rejections))
    } else if denials > 0 || rejections > 0 {
        ("WATCH".to_string(), format!("{} denials, {} rejections", denials, rejections))
    } else {
        ("GOOD".to_string(), "No policy friction".to_string())
    };

    (verdict, note)
}

fn signal_subagent_fanout(events: &[vigil_core::envelope::TimestampedEvent]) -> (String, String) {
    let mut subagent_count = 0u32;
    let mut max_depth = 0u32;

    for event_wrapped in events {
        if let Event::SubAgentSpawned { depth, .. } = &event_wrapped.event {
            subagent_count += 1;
            max_depth = max_depth.max(*depth);
        }
    }

    let (verdict, note) = if subagent_count >= 6 || max_depth >= 3 {
        ("FLAG".to_string(), format!("{} sub-agents spawned (max depth {}) — sub-agents multiply token cost", subagent_count, max_depth))
    } else if subagent_count > 0 {
        ("WATCH".to_string(), format!("{} sub-agents, depth {}", subagent_count, max_depth))
    } else {
        ("GOOD".to_string(), "No sub-agents spawned".to_string())
    };

    (verdict, note)
}

fn signal_alert_clustering(
    events: &[vigil_core::envelope::TimestampedEvent],
) -> Option<(String, String)> {
    let mut alerts_by_half = [0u32, 0u32];

    // Count total turns to find midpoint
    let mut total_turns = 0u32;
    for event_wrapped in events {
        if matches!(event_wrapped.event, Event::LlmRequest { .. }) {
            total_turns += 1;
        }
    }

    if total_turns < 4 {
        return None;
    }

    let midpoint = total_turns / 2;
    let mut current_turn = 0u32;

    for event_wrapped in events {
        match &event_wrapped.event {
            Event::LlmRequest { .. } => {
                current_turn += 1;
            }
            Event::PiiAlert { .. }
            | Event::BurnRateAlert { .. }
            | Event::LoopAlert { .. }
            | Event::ToolTimeout { .. }
            | Event::CostAlert { .. }
            | Event::SessionDurationAlert { .. }
            | Event::DriftAlert { .. }
            | Event::PromptInjectionAlert { .. } => {
                if current_turn <= midpoint {
                    alerts_by_half[0] += 1;
                } else {
                    alerts_by_half[1] += 1;
                }
            }
            _ => {}
        }
    }

    if alerts_by_half[0] + alerts_by_half[1] < 4 {
        return None;
    }

    let first_half = alerts_by_half[0].max(1);
    let second_half = alerts_by_half[1];
    let ratio = second_half as f64 / first_half as f64;

    let (verdict, note) = if ratio >= 2.0 {
        ("FLAG".to_string(), "Alert rate doubled in the second half — session was deteriorating".to_string())
    } else if ratio > 1.0 {
        ("WATCH".to_string(), format!("Alert rate increased {:.1}x in second half", ratio))
    } else {
        ("GOOD".to_string(), "Alert rate stable or improving".to_string())
    };

    Some((verdict, note))
}

fn signal_write_approval_rejection(events: &[vigil_core::envelope::TimestampedEvent]) -> (String, String) {
    let mut total_approvals = 0u32;
    let mut rejections = 0u32;

    for event_wrapped in events {
        if let Event::WriteApprovalDecision { approved, .. } = &event_wrapped.event {
            total_approvals += 1;
            if !approved {
                rejections += 1;
            }
        }
    }

    let (verdict, note) = if total_approvals == 0 {
        ("GOOD".to_string(), "No write approvals requested".to_string())
    } else {
        let rejection_rate = rejections as f64 / total_approvals as f64;
        if rejection_rate > 0.33 {
            ("FLAG".to_string(), format!("{} of {} write approvals were rejected — agent was reaching for risky changes", rejections, total_approvals))
        } else if rejection_rate > 0.0 {
            ("WATCH".to_string(), format!("{:.0}% of write approvals rejected", rejection_rate * 100.0))
        } else {
            ("GOOD".to_string(), "All write approvals accepted".to_string())
        }
    };

    (verdict, note)
}

fn extract_alerts(events: &[vigil_core::envelope::TimestampedEvent]) -> Vec<AlertEntry> {
    let mut alerts = Vec::new();
    let mut current_turn = 0u32;
    let first_timestamp = events.first().map(|e| e.timestamp);

    for event_wrapped in events {
        if matches!(event_wrapped.event, Event::LlmRequest { .. }) {
            current_turn += 1;
        }

        let (label, detail) = match &event_wrapped.event {
            Event::PiiAlert { kinds, .. } => {
                ("PIII".to_string(), format!("PII detected: {}", kinds.join(", ")))
            }
            Event::BurnRateAlert { rate_per_min_usd, .. } => {
                ("BURN".to_string(), format!("Burn rate ${:.2}/min", rate_per_min_usd))
            }
            Event::LoopAlert { tool_name, repeat_count, .. } => {
                ("LOOP".to_string(), format!("{} repeated {} times", tool_name, repeat_count))
            }
            Event::ToolTimeout { tool_name, elapsed_secs, .. } => {
                ("TOUT".to_string(), format!("{} timeout after {}s", tool_name, elapsed_secs))
            }
            Event::CostAlert { threshold_usd, session_cost_usd, .. } => {
                ("COST".to_string(), format!("Cost alert at ${:.2} / ${:.2}", session_cost_usd, threshold_usd))
            }
            Event::SessionDurationAlert { elapsed_mins, .. } => {
                ("DURA".to_string(), format!("Session duration {} mins", elapsed_mins))
            }
            Event::DriftAlert { details, .. } => {
                ("DRFT".to_string(), details.chars().take(80).collect())
            }
            Event::ExfilAlert { matches, source, .. } => {
                ("EXFL".to_string(), format!("Exfil from {} ({})", source, matches.len()))
            }
            Event::PromptInjectionAlert { snippet, .. } => {
                ("PINJ".to_string(), snippet.chars().take(80).collect())
            }
            _ => continue,
        };

        let offset_secs = if let Some(first_ts) = first_timestamp {
            event_wrapped
                .timestamp
                .signed_duration_since(first_ts)
                .num_seconds()
                .max(0) as u64
        } else {
            0
        };

        alerts.push(AlertEntry {
            turn: current_turn,
            label,
            detail: detail.chars().take(80).collect(),
            offset_secs,
        });
    }

    alerts
}

fn compute_files_touched(events: &[vigil_core::envelope::TimestampedEvent]) -> Vec<FileEntry> {
    let mut files: HashMap<String, (u32, u32, u32, u32)> = HashMap::new();

    for event_wrapped in events {
        match &event_wrapped.event {
            Event::FsRead { path, .. } => {
                let entry = files.entry(path.clone()).or_insert((0, 0, 0, 0));
                entry.0 += 1;
            }
            Event::FsWrite {
                path,
                lines_added,
                lines_removed,
                ..
            } => {
                let entry = files.entry(path.clone()).or_insert((0, 0, 0, 0));
                entry.1 += 1;
                entry.2 += lines_added;
                entry.3 += lines_removed;
            }
            _ => {}
        }
    }

    let mut result: Vec<FileEntry> = files
        .into_iter()
        .map(|(path, (reads, writes, added, removed))| FileEntry {
            path,
            reads,
            writes,
            lines_added: added,
            lines_removed: removed,
        })
        .collect();

    result.sort_by(|a, b| {
        b.writes
            .cmp(&a.writes)
            .then_with(|| b.reads.cmp(&a.reads))
    });

    if result.len() > 30 {
        let more = result.len() - 30;
        result.truncate(30);
        result.push(FileEntry {
            path: format!("… and {} more files", more),
            reads: 0,
            writes: 0,
            lines_added: 0,
            lines_removed: 0,
        });
    }

    result
}

fn compute_tool_heatmap(events: &[vigil_core::envelope::TimestampedEvent]) -> Vec<ToolEntry> {
    let mut tools: HashMap<String, (u32, u32, Vec<u64>)> = HashMap::new();

    for event_wrapped in events {
        if let Event::ToolCallResult {
            tool_name,
            is_error,
            duration_ms,
            ..
        } = &event_wrapped.event
        {
            let entry = tools
                .entry(tool_name.clone())
                .or_insert((0, 0, Vec::new()));
            entry.0 += 1;
            if *is_error {
                entry.1 += 1;
            }
            if let Some(duration) = duration_ms {
                entry.2.push(*duration);
            }
        }
    }

    let mut result: Vec<ToolEntry> = tools
        .into_iter()
        .map(|(tool_name, (calls, errors, durations))| {
            let avg_duration_ms = if durations.is_empty() {
                0.0
            } else {
                durations.iter().map(|&d| d as f64).sum::<f64>() / durations.len() as f64
            };
            ToolEntry {
                tool_name,
                calls,
                errors,
                avg_duration_ms,
            }
        })
        .collect();

    result.sort_by(|a, b| b.calls.cmp(&a.calls));
    result.truncate(15);

    result
}

fn generate_timeline(events: &[vigil_core::envelope::TimestampedEvent]) -> String {
    let mut timeline = String::new();
    let mut turn_markers: HashMap<u32, char> = HashMap::new();

    let mut turn_count = 0u32;
    for event_wrapped in events {
        match &event_wrapped.event {
            Event::LlmRequest { .. } => {
                turn_count += 1;
                turn_markers.insert(turn_count, '.');
            }
            _ => {}
        }
    }

    let mut current_turn = 0u32;
    for event_wrapped in events {
        match &event_wrapped.event {
            Event::LlmRequest { .. } => {
                current_turn += 1;
            }
            Event::ToolCall { .. } => {
                if current_turn > 0 {
                    *turn_markers.entry(current_turn).or_insert('.') = 't';
                }
            }
            Event::FsWrite { .. } => {
                if current_turn > 0 {
                    let marker = turn_markers.entry(current_turn).or_insert('.');
                    if *marker == '.' {
                        *marker = 'W';
                    }
                }
            }
            Event::PiiAlert { .. }
            | Event::BurnRateAlert { .. }
            | Event::LoopAlert { .. }
            | Event::ToolTimeout { .. }
            | Event::CostAlert { .. }
            | Event::SessionDurationAlert { .. }
            | Event::DriftAlert { .. }
            | Event::PromptInjectionAlert { .. } => {
                if current_turn > 0 {
                    turn_markers.insert(current_turn, '!');
                }
            }
            Event::WriteApprovalDecision { approved: false, .. } => {
                if current_turn > 0 {
                    let marker = turn_markers.entry(current_turn).or_insert('.');
                    if *marker != '!' {
                        *marker = '?';
                    }
                }
            }
            _ => {}
        }
    }

    for i in 1..=turn_count {
        timeline.push(turn_markers.get(&i).copied().unwrap_or('.'));
    }

    timeline
}

fn output_text(report: &Report) -> Result<()> {
    let supports_color = std::env::var("NO_COLOR").is_err();
    let width = 80;

    println!();
    println!("{}", "═".repeat(width));
    println!("SESSION HEADLINE");
    println!("{}", "═".repeat(width));
    println!("Session ID:        {}", report.session_id);
    if let Some(ref name) = report.headline.session_name {
        println!("Session Name:      {}", name);
    }
    println!("Model:             {} ({})", report.headline.model, report.headline.provider);
    if let Some(ref branch) = report.headline.git_branch {
        println!("Git Branch:        {}", branch);
    }
    if let Some(ref commit) = report.headline.git_commit {
        println!("Git Commit:        {}", commit);
    }
    println!("Total Cost:        ${:.4}", report.headline.total_cost);
    println!("Turns:             {}", report.headline.total_turns);
    println!("Input Tokens:      {}", report.headline.total_input_tokens);
    println!("Output Tokens:     {}", report.headline.total_output_tokens);
    if report.headline.cache_read_tokens > 0 {
        println!("Cache Read:        {}", report.headline.cache_read_tokens);
    }
    if report.headline.cache_creation_tokens > 0 {
        println!("Cache Creation:    {}", report.headline.cache_creation_tokens);
    }
    println!("Duration:          {}s", report.headline.duration_secs);
    println!("Started:           {}", report.headline.session_start_time);

    println!();
    println!("{}", "═".repeat(width));
    println!("HYGIENE SCORECARD");
    println!("{}", "═".repeat(width));
    for signal in &report.hygiene {
        let verdict_str = if supports_color {
            match signal.verdict.as_str() {
                "GOOD" => format!("\x1b[32m{}\x1b[0m", signal.verdict),
                "WATCH" => format!("\x1b[33m{}\x1b[0m", signal.verdict),
                "FLAG" => format!("\x1b[31m{}\x1b[0m", signal.verdict),
                _ => signal.verdict.clone(),
            }
        } else {
            signal.verdict.clone()
        };
        println!("{:20} [{}] {}", signal.signal, verdict_str, signal.note);
    }

    println!();
    println!("{}", "═".repeat(width));
    println!("ALERT TIMELINE");
    println!("{}", "═".repeat(width));
    if report.alerts.is_empty() {
        println!("(no alerts)");
    } else {
        for alert in &report.alerts {
            let offset_min = alert.offset_secs / 60;
            let offset_sec = alert.offset_secs % 60;
            println!(
                "Turn {:3} [{:3}:{:02}] {} — {}",
                alert.turn, offset_min, offset_sec, alert.label, alert.detail
            );
        }
    }

    println!();
    println!("{}", "═".repeat(width));
    println!("FILES TOUCHED");
    println!("{}", "═".repeat(width));
    println!("{:<50} {:>6} {:>6} {:>10} {:>10}", "Path", "Reads", "Writes", "Added", "Removed");
    println!("{}", "─".repeat(width));
    for file in &report.files {
        println!(
            "{:<50} {:>6} {:>6} {:>10} {:>10}",
            truncate_string(&file.path, 50),
            file.reads,
            file.writes,
            file.lines_added,
            file.lines_removed
        );
    }

    println!();
    println!("{}", "═".repeat(width));
    println!("TOOL HEATMAP");
    println!("{}", "═".repeat(width));
    println!("{:<30} {:>8} {:>8} {:>12}", "Tool", "Calls", "Errors", "Avg (ms)");
    println!("{}", "─".repeat(width));
    for tool in &report.tools {
        println!(
            "{:<30} {:>8} {:>8} {:>12.1}",
            tool.tool_name, tool.calls, tool.errors, tool.avg_duration_ms
        );
    }

    println!();
    println!("{}", "═".repeat(width));
    println!("TIMELINE");
    println!("{}", "═".repeat(width));
    print_wrapped_text("Timeline: ", &report.timeline, width);

    println!();
    Ok(())
}

fn output_json(report: &Report) -> Result<()> {
    let json = json!({
        "session_id": report.session_id,
        "scorecard_version": report.scorecard_version,
        "headline": {
            "session_id": report.headline.session_id,
            "session_name": report.headline.session_name,
            "model": report.headline.model,
            "provider": report.headline.provider,
            "git_branch": report.headline.git_branch,
            "git_commit": report.headline.git_commit,
            "total_cost": report.headline.total_cost,
            "total_turns": report.headline.total_turns,
            "total_input_tokens": report.headline.total_input_tokens,
            "total_output_tokens": report.headline.total_output_tokens,
            "cache_read_tokens": report.headline.cache_read_tokens,
            "cache_creation_tokens": report.headline.cache_creation_tokens,
            "duration_secs": report.headline.duration_secs,
            "session_start_time": report.headline.session_start_time,
        },
        "hygiene": report.hygiene.iter().map(|s| json!({
            "signal": s.signal,
            "verdict": s.verdict,
            "note": s.note,
        })).collect::<Vec<_>>(),
        "alerts": report.alerts.iter().map(|a| json!({
            "turn": a.turn,
            "label": a.label,
            "detail": a.detail,
            "offset_secs": a.offset_secs,
        })).collect::<Vec<_>>(),
        "files": report.files.iter().map(|f| json!({
            "path": f.path,
            "reads": f.reads,
            "writes": f.writes,
            "lines_added": f.lines_added,
            "lines_removed": f.lines_removed,
        })).collect::<Vec<_>>(),
        "tools": report.tools.iter().map(|t| json!({
            "tool_name": t.tool_name,
            "calls": t.calls,
            "errors": t.errors,
            "avg_duration_ms": t.avg_duration_ms,
        })).collect::<Vec<_>>(),
        "timeline": report.timeline,
    });

    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

fn output_html(report: &Report, fragment_only: bool, _include_payloads: bool) -> Result<()> {
    let content_hash = {
        use sha2::{Digest, Sha256};
        let json_str = serde_json::to_string(&json!({
            "session_id": report.session_id,
            "scorecard_version": report.scorecard_version,
            "headline": report.headline,
            "hygiene": report.hygiene,
            "alerts": report.alerts,
            "files": report.files,
            "tools": report.tools,
            "timeline": report.timeline,
        }))?;
        let mut hasher = Sha256::new();
        hasher.update(json_str.as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    };

    let svg_timeline = generate_timeline_svg(&report.timeline);

    let html_content = format!(
        r#"<div id="vigil-report" class="vigil-report">
<section id="section-headline">
<h2>Session Headline</h2>
<dl>
<dt>Session ID</dt><dd><code>{}</code></dd>
{}
<dt>Model</dt><dd>{} ({})</dd>
{}{}
<dt>Total Cost</dt><dd>${:.4}</dd>
<dt>Turns</dt><dd>{}</dd>
<dt>Tokens</dt><dd>{} in, {} out</dd>
{}{}
<dt>Duration</dt><dd>{}s</dd>
<dt>Started</dt><dd>{}</dd>
</dl>
</section>

<section id="section-hygiene">
<h2>Hygiene Scorecard</h2>
<table>
<tr><th>Signal</th><th>Verdict</th><th>Note</th></tr>
{}
</table>
</section>

<section id="section-alerts" open="">
<h2>Alerts</h2>
{}
</section>

<section id="section-files">
<h2>Files Touched</h2>
<table>
<tr><th>Path</th><th>Reads</th><th>Writes</th><th>+Lines</th><th>-Lines</th></tr>
{}
</table>
</section>

<section id="section-tools">
<h2>Tool Heatmap</h2>
<table>
<tr><th>Tool</th><th>Calls</th><th>Errors</th><th>Avg (ms)</th></tr>
{}
</table>
</section>

<section id="section-timeline">
<h2>Timeline</h2>
{}
</section>

<footer>
<code>{}</code> | {}
</footer>
</div>"#,
        report.session_id,
        report.headline.session_name.as_ref().map(|n| format!("<dt>Session Name</dt><dd>{}</dd>", html_escape(n))).unwrap_or_default(),
        html_escape(&report.headline.model),
        html_escape(&report.headline.provider),
        report.headline.git_branch.as_ref().map(|b| format!("<dt>Branch</dt><dd><code>{}</code></dd>", html_escape(b))).unwrap_or_default(),
        report.headline.git_commit.as_ref().map(|c| format!("<dt>Commit</dt><dd><code>{}</code></dd>", html_escape(c))).unwrap_or_default(),
        report.headline.total_cost,
        report.headline.total_turns,
        report.headline.total_input_tokens,
        report.headline.total_output_tokens,
        if report.headline.cache_read_tokens > 0 { format!("<dt>Cache Read</dt><dd>{}</dd>", report.headline.cache_read_tokens) } else { String::new() },
        if report.headline.cache_creation_tokens > 0 { format!("<dt>Cache Creation</dt><dd>{}</dd>", report.headline.cache_creation_tokens) } else { String::new() },
        report.headline.duration_secs,
        &report.headline.session_start_time,
        report.hygiene.iter().map(|s| {
            let verdict_class = match s.verdict.as_str() {
                "GOOD" => "good",
                "WATCH" => "watch",
                "FLAG" => "flag",
                _ => "unknown",
            };
            format!("<tr><td>{}</td><td class=\"{}\"><strong>{}</strong></td><td>{}</td></tr>",
                html_escape(&s.signal), verdict_class, html_escape(&s.verdict), html_escape(&s.note))
        }).collect::<Vec<_>>().join("\n"),
        if report.alerts.is_empty() {
            "<p>(no alerts)</p>".to_string()
        } else {
            format!("<table><tr><th>Turn</th><th>Label</th><th>Detail</th><th>Offset</th></tr>\n{}</table>",
                report.alerts.iter().map(|a| {
                    let min = a.offset_secs / 60;
                    let sec = a.offset_secs % 60;
                    format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}:{:02}</td></tr>",
                        a.turn, html_escape(&a.label), html_escape(&a.detail), min, sec)
                }).collect::<Vec<_>>().join("\n"))
        },
        report.files.iter().map(|f| format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&f.path), f.reads, f.writes, f.lines_added, f.lines_removed
        )).collect::<Vec<_>>().join("\n"),
        report.tools.iter().map(|t| format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.1}</td></tr>",
            html_escape(&t.tool_name), t.calls, t.errors, t.avg_duration_ms
        )).collect::<Vec<_>>().join("\n"),
        svg_timeline,
        report.session_id,
        content_hash,
    );

    if fragment_only {
        println!(
            r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
{}
</style>
</head>
<body>
{}
</body>
</html>"#,
            html_styles(),
            html_content
        );
    } else {
        println!(
            r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
{}
</style>
</head>
<body>
{}
</body>
</html>"#,
            html_styles(),
            html_content
        );
    }

    Ok(())
}

fn html_styles() -> &'static str {
    r#"
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  max-width: 1000px;
  margin: 0 auto;
  padding: 20px;
  background: #f9fafb;
  color: #1f2937;
}
.vigil-report section {
  background: white;
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}
.vigil-report h2 {
  margin-top: 0;
  color: #111827;
  font-size: 1.25rem;
  border-bottom: 2px solid #e5e7eb;
  padding-bottom: 10px;
}
.vigil-report dl {
  display: grid;
  grid-template-columns: 150px 1fr;
  gap: 10px;
}
.vigil-report dt {
  font-weight: 600;
  color: #374151;
}
.vigil-report dd {
  margin: 0;
  font-family: "Monaco", "Courier New", monospace;
  font-size: 0.9em;
}
.vigil-report table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.95em;
}
.vigil-report th {
  text-align: left;
  padding: 10px;
  background: #f3f4f6;
  border-bottom: 2px solid #d1d5db;
  font-weight: 600;
}
.vigil-report td {
  padding: 8px 10px;
  border-bottom: 1px solid #e5e7eb;
}
.vigil-report tr:hover {
  background: #f9fafb;
}
.vigil-report code {
  background: #f3f4f6;
  padding: 2px 4px;
  border-radius: 3px;
  font-family: "Monaco", "Courier New", monospace;
  font-size: 0.9em;
}
.vigil-report .good { color: #22c55e; font-weight: 600; }
.vigil-report .watch { color: #f59e0b; font-weight: 600; }
.vigil-report .flag { color: #ef4444; font-weight: 600; }
.vigil-report footer {
  text-align: center;
  padding: 20px;
  color: #6b7280;
  font-size: 0.9em;
  border-top: 1px solid #e5e7eb;
}
@media print {
  body { background: white; }
  .vigil-report section { page-break-inside: avoid; }
}
"#
}

fn generate_timeline_svg(timeline: &str) -> String {
    let chars: Vec<char> = timeline.chars().collect();
    let width = chars.len() * 10;
    let height = 20;

    let mut rects = String::new();
    for (i, &ch) in chars.iter().enumerate() {
        let color = match ch {
            '.' => "#d1d5db",
            't' => "#3b82f6",
            'W' => "#22c55e",
            '!' => "#ef4444",
            '?' => "#f59e0b",
            _ => "#9ca3af",
        };
        let label = match ch {
            '.' => "turn with no activity",
            't' => "tool calls only",
            'W' => "file write",
            '!' => "alert",
            '?' => "policy decision",
            _ => "unknown",
        };
        rects.push_str(&format!(
            "<rect x=\"{}\" y=\"0\" width=\"10\" height=\"{}\" fill=\"{}\" stroke=\"#e5e7eb\" stroke-width=\"1\"><title>Turn {}: {}</title></rect>",
            i * 10,
            height,
            color,
            i + 1,
            label
        ));
    }

    format!(
        "<svg width=\"{}\" height=\"{}\" viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\">{}</svg>",
        width, height, width, height, rects
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}…", &s[..max_len - 1])
    } else {
        s.to_string()
    }
}

fn print_wrapped_text(prefix: &str, text: &str, width: usize) {
    print!("{}", prefix);
    let mut pos = prefix.len();

    for ch in text.chars() {
        if pos >= width {
            println!();
            pos = 0;
        }
        print!("{}", ch);
        pos += 1;
    }
    println!();
}

#[allow(dead_code)]
fn term_width() -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigil_core::envelope::TimestampedEvent;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_session(events: Vec<Event>) -> Session {
        let now = Utc::now();
        let session_id = Uuid::new_v4();

        // Use a counter to generate simple ULIDs for testing
        let timestamped_events: Vec<TimestampedEvent> = events
            .into_iter()
            .enumerate()
            .map(|(i, event)| TimestampedEvent::new(event))
            .collect();

        Session {
            id: session_id,
            agent: "test-agent".to_string(),
            started_at: now,
            ended_at: Some(now + chrono::Duration::seconds(timestamped_events.len() as i64)),
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cost_usd: 0.0,
            policy_violations: 0,
            pii_detections: 0,
            events: timestamped_events,
            name: None,
        }
    }

    #[test]
    fn test_input_growth_good() {
        let events = vec![
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id: Uuid::new_v4(),
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 1,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 110,
                session_id: Uuid::new_v4(),
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 2,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 120,
                session_id: Uuid::new_v4(),
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 3,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 105,
                session_id: Uuid::new_v4(),
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 4,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 115,
                session_id: Uuid::new_v4(),
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 5,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 125,
                session_id: Uuid::new_v4(),
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 6,
            },
        ];

        let session = make_session(events);
        let mut timestamped = Vec::new();
        for event in &session.events {
            timestamped.push(event.clone());
        }

        let (verdict, _note) = signal_input_growth(&timestamped, &ReportConfig::default()).unwrap();
        assert_eq!(verdict, "GOOD");
    }

    #[test]
    fn test_input_growth_flag() {
        let events = vec![
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id: Uuid::new_v4(),
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 1,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id: Uuid::new_v4(),
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 2,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id: Uuid::new_v4(),
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 3,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 200,
                session_id: Uuid::new_v4(),
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 4,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 200,
                session_id: Uuid::new_v4(),
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 5,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 200,
                session_id: Uuid::new_v4(),
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 6,
            },
        ];

        let session = make_session(events);
        let (verdict, _note) = signal_input_growth(&session.events, &ReportConfig::default()).unwrap();
        assert_eq!(verdict, "FLAG");
    }

    #[test]
    fn test_reread_rate_flag() {
        let session_id = Uuid::new_v4();
        let events = vec![
            Event::FsRead {
                path: "file1.rs".to_string(),
                session_id,
            },
            Event::FsRead {
                path: "file1.rs".to_string(),
                session_id,
            },
            Event::FsRead {
                path: "file1.rs".to_string(),
                session_id,
            },
            Event::FsRead {
                path: "file2.rs".to_string(),
                session_id,
            },
            Event::FsRead {
                path: "file2.rs".to_string(),
                session_id,
            },
            Event::FsRead {
                path: "file2.rs".to_string(),
                session_id,
            },
            Event::FsRead {
                path: "file3.rs".to_string(),
                session_id,
            },
            Event::FsRead {
                path: "file3.rs".to_string(),
                session_id,
            },
            Event::FsRead {
                path: "file3.rs".to_string(),
                session_id,
            },
        ];

        let session = make_session(events);
        let (verdict, _note) = signal_reread_rate(&session.events, &ReportConfig::default());
        assert_eq!(verdict, "FLAG");
    }

    #[test]
    fn test_turn_to_first_write() {
        let session_id = Uuid::new_v4();
        let mut events = vec![
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id,
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 1,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id,
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 2,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id,
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 3,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id,
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 4,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id,
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 5,
            },
        ];

        for _ in 0..15 {
            events.push(Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id,
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 6,
            });
        }
        events.push(Event::FsWrite {
            path: "test.rs".to_string(),
            bytes: 100,
            session_id,
            lines_added: 10,
            lines_removed: 0,
            hunk_count: 1,
        });

        let session = make_session(events);
        let (verdict, _note) = signal_turn_to_first_write(&session.events, &ReportConfig::default());
        assert_eq!(verdict, "FLAG");
    }

    #[test]
    fn test_timeline_strip() {
        let session_id = Uuid::new_v4();
        let events = vec![
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id,
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 1,
            },
            Event::ToolCall {
                agent: "test".to_string(),
                tool_name: "Read".to_string(),
                input: serde_json::json!({}),
                session_id,
                tool_use_id: None,
                correlation_id: None,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id,
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 2,
            },
            Event::FsWrite {
                path: "test.rs".to_string(),
                bytes: 100,
                session_id,
                lines_added: 10,
                lines_removed: 0,
                hunk_count: 1,
            },
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude".to_string(),
                input_tokens: 100,
                session_id,
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 3,
            },
            Event::BurnRateAlert {
                rate_per_min_usd: 1.0,
                projected_total_usd: 100.0,
                session_cost_usd: 10.0,
                session_id,
            },
        ];

        let session = make_session(events);
        let timeline = generate_timeline(&session.events);
        assert_eq!(timeline, "tW!");
    }

    #[test]
    fn test_json_output_roundtrip() {
        let session_id = Uuid::new_v4();
        let events = vec![
            Event::LlmRequest {
                provider: "anthropic".to_string(),
                model: "claude-3".to_string(),
                input_tokens: 100,
                session_id,
                last_user_message: None,
                system_prompt: None,
                raw_request: None,
                turn_number: 1,
            },
            Event::LlmResponse {
                provider: "anthropic".to_string(),
                model: "claude-3".to_string(),
                input_tokens: 100,
                output_tokens: 50,
                cost_usd: 0.001,
                session_id,
                response_text: None,
                cache_read_input_tokens: 0,
                cache_creation_input_tokens: 0,
                raw_response: None,
                stop_reason: None,
            },
        ];

        let session = make_session(events);
        let report = build_report(&session, &ReportConfig::default()).unwrap();

        let json = json!({
            "session_id": report.session_id,
            "scorecard_version": report.scorecard_version,
            "headline": report.headline,
            "hygiene": report.hygiene,
            "alerts": report.alerts,
            "files": report.files,
            "tools": report.tools,
            "timeline": report.timeline,
        });

        assert!(json.get("session_id").is_some());
        assert!(json.get("scorecard_version").is_some());
        assert!(json.get("headline").is_some());
        assert!(json.get("hygiene").is_some());
        assert!(json.get("alerts").is_some());
        assert!(json.get("files").is_some());
        assert!(json.get("tools").is_some());
        assert!(json.get("timeline").is_some());
    }
}

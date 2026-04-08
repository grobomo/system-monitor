use crate::modules::classifier::{Classification, classify_process};
use crate::modules::process_tree::ProcessSnapshot;
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use chrono::Local;
use colored::Colorize;
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Processes that steal focus when launched visible
const FOCUS_STEAL_CANDIDATES: &[&str] = &[
    "cmd.exe",
    "python.exe",
    "python3.exe",
    "pythonw.exe",
    "powershell.exe",
    "pwsh.exe",
    "cscript.exe",
    "wscript.exe",
];

/// Resolved at runtime from $HOME/Documents/ProjectsCL1
fn projects_dir() -> String {
    dirs::home_dir()
        .map(|h| h.join("Documents").join("ProjectsCL1"))
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}
const DASHBOARD_PORT: u16 = 9847;
const MAX_EVENTS: usize = 500;

#[derive(Clone, Serialize)]
struct FocusEvent {
    timestamp: String,
    pid: u32,
    name: String,
    exe_path: Option<String>,
    command_line: Option<String>,
    parent_chain: String,
    classification: String,
    source_project: Option<String>,
}

#[derive(Clone, Serialize)]
struct Stats {
    total: usize,
    safe: usize,
    claude: usize,
    unknown: usize,
    suspicious: usize,
    started_at: String,
}

type EventBuffer = Arc<RwLock<VecDeque<FocusEvent>>>;

#[derive(Clone)]
struct AppState {
    events: EventBuffer,
    iocs: crate::modules::ioc_monitor::IocBuffer,
    started_at: String,
}

/// Check if a process is a child of our own PID (WMI queries, etc.)
fn is_own_child(proc: &crate::modules::process_tree::ProcessInfo, snapshot: &ProcessSnapshot) -> bool {
    let self_pid = std::process::id();
    let chain = snapshot.parent_chain(proc.pid);
    chain.iter().any(|p| p.pid == self_pid)
}

pub async fn run() -> anyhow::Result<()> {
    println!("{}", "=== Focus Guard (Observer) ===".bold());
    println!("Watching for: {}", FOCUS_STEAL_CANDIDATES.join(", ").dimmed());
    println!("Poll interval: 500ms");
    println!("Press Ctrl+C to stop\n");

    let base_dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot find home directory"))?
        .join(".system-monitor");
    std::fs::create_dir_all(&base_dir)?;

    let log_path = base_dir.join("focus-guard.log");
    let events_dir = base_dir.join("events");
    std::fs::create_dir_all(&events_dir)?;

    println!("Log:    {}", log_path.display().to_string().dimmed());
    println!("Events: {}", events_dir.display().to_string().dimmed());

    // Shared state for dashboard
    let events: EventBuffer = Arc::new(RwLock::new(VecDeque::with_capacity(MAX_EVENTS)));
    let iocs = crate::modules::ioc_monitor::new_buffer();
    let started_at = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let state = AppState {
        events: events.clone(),
        iocs: iocs.clone(),
        started_at: started_at.clone(),
    };

    // Start HTTP dashboard server
    let dashboard_state = state.clone();
    tokio::spawn(async move {
        let app = Router::new()
            .route("/", get(dashboard_html))
            .route("/api/events", get(api_events))
            .route("/api/stats", get(api_stats))
            .route("/api/summary", get(api_summary))
            .route("/api/health", get(api_health))
            .route("/api/iocs", get(api_iocs))
            .route("/api/vpn", get(api_vpn))
            .route("/api/claude-sessions", get(api_claude_sessions))
            .route("/api/disk", get(api_disk))
            .route("/api/status", get(api_status))
            .with_state(dashboard_state);

        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", DASHBOARD_PORT))
            .await
            .expect("Failed to bind dashboard port");
        axum::serve(listener, app).await.expect("Dashboard server failed");
    });

    println!(
        "\n{} {}\n",
        "Dashboard:".bold(),
        format!("http://localhost:{}", DASHBOARD_PORT).cyan().underline()
    );

    // Start system tray icon
    let (tray_tx, tray_quit_rx) = crate::modules::tray::spawn_tray();
    println!("{}", "System tray icon active".green());

    // Open dashboard in browser
    let _ = open::that(format!("http://localhost:{}", DASHBOARD_PORT));

    let mut known_pids: HashSet<u32> = HashSet::new();
    let mut known_hidden: HashSet<isize> = HashSet::new();
    let mut total_hidden: usize = 0;
    let mut event_count: usize = 0;
    let mut last_cleanup = std::time::Instant::now();
    let mut last_vpn_check = std::time::Instant::now();
    let mut last_vpn_statuses: Vec<crate::modules::vpn_monitor::VpnStatus> = Vec::new();
    let mut last_collision_check = std::time::Instant::now();

    // Initial snapshot — baseline
    let snapshot = ProcessSnapshot::capture()?;
    for proc in snapshot.all_processes() {
        known_pids.insert(proc.pid);
    }
    println!(
        "Baseline: {} processes tracked\n",
        known_pids.len().to_string().green()
    );

    loop {
        // Check if tray exit was clicked
        if tray_quit_rx.try_recv().is_ok() {
            println!("\n{}", "Tray exit requested, shutting down...".yellow());
            break;
        }

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Active enforcement: hide transient CMD/PS windows
        let hidden = crate::modules::focus_enforcer::enforce_once(&mut known_hidden);
        if hidden > 0 {
            total_hidden += hidden;
            println!(
                "  {} hid {} window(s) ({} total)",
                "SHIELD".green().bold(),
                hidden,
                total_hidden
            );
        }

        let snapshot = ProcessSnapshot::capture()?;

        for proc in snapshot.all_processes() {
            if known_pids.contains(&proc.pid) {
                continue;
            }
            known_pids.insert(proc.pid);

            let name_lower = proc.name.to_lowercase();
            if !FOCUS_STEAL_CANDIDATES.contains(&name_lower.as_str()) {
                continue;
            }

            // Skip our own child processes (WMI queries spawn powershell.exe)
            if is_own_child(proc, &snapshot) {
                continue;
            }

            let classification = classify_process(proc, &snapshot);
            let chain: Vec<String> = snapshot
                .parent_chain(proc.pid)
                .iter()
                .map(|p| format!("{}({})", p.name, p.pid))
                .collect();
            let chain_str = chain.join(" -> ");
            let class_str = format_classification(&classification);
            let source_project = trace_to_project(proc, &snapshot);

            let now = Local::now();
            let timestamp = now.format("%Y-%m-%d %H:%M:%S%.3f").to_string();

            let event = FocusEvent {
                timestamp: timestamp.clone(),
                pid: proc.pid,
                name: proc.name.clone(),
                exe_path: proc.exe_path.clone(),
                command_line: proc.command_line.clone(),
                parent_chain: chain_str.clone(),
                classification: class_str.clone(),
                source_project: source_project.clone(),
            };

            // Push to ring buffer
            {
                let mut buf = events.write().await;
                if buf.len() >= MAX_EVENTS {
                    buf.pop_back();
                }
                buf.push_front(event.clone());
            }

            // Update tray tooltip
            event_count += 1;
            let _ = tray_tx.send(crate::modules::tray::TrayCommand::UpdateTooltip(
                format!("System Monitor - {} events", event_count),
            ));

            // Print to terminal
            print_event(&event);

            // Append to log
            if let Err(e) = append_log(&log_path, &event) {
                eprintln!("  {} log write failed: {}", "!".red(), e);
            }

            // Emit event file for brain
            let brain_event = serde_json::json!({
                "schema_version": 1,
                "type": "focus_steal",
                "timestamp": timestamp,
                "process": {
                    "pid": proc.pid,
                    "name": proc.name,
                    "exe_path": proc.exe_path,
                    "command_line": proc.command_line,
                },
                "parent_chain": chain_str,
                "classification": class_str,
                "source_project": source_project,
            });

            let event_file = events_dir.join(format!(
                "{}-focus-{}.json",
                now.format("%Y%m%d-%H%M%S-%3f"),
                proc.pid
            ));
            if let Err(e) = std::fs::write(&event_file, serde_json::to_string_pretty(&brain_event).unwrap_or_default()) {
                eprintln!("  {} event write failed: {}", "!".red(), e);
            } else {
                println!("    {} event emitted", ">>".green());
            }
        }

        // Clean up dead PIDs
        let current_pids: HashSet<u32> = snapshot.all_processes().map(|p| p.pid).collect();
        known_pids.retain(|pid| current_pids.contains(pid));

        // VPN check (every 60s)
        if last_vpn_check.elapsed() > Duration::from_secs(60) {
            last_vpn_check = std::time::Instant::now();
            let (new_statuses, changes) = crate::modules::vpn_monitor::poll_vpn_changes(&last_vpn_statuses);
            for change in &changes {
                let icon = match change.change.as_str() {
                    "connected" => "▲".green().to_string(),
                    "disconnected" | "tunnel_down" | "process_stopped" => "▼".red().to_string(),
                    _ => "◆".yellow().to_string(),
                };
                println!("  {} VPN {} — {}", icon, change.vpn_name.bright_white(), change.change);

                // Emit brain event
                let brain_event = serde_json::json!({
                    "schema_version": 1,
                    "type": "vpn_change",
                    "timestamp": change.timestamp,
                    "vpn_name": change.vpn_name,
                    "change": change.change,
                });
                let event_file = events_dir.join(format!(
                    "{}-vpn-{}.json",
                    Local::now().format("%Y%m%d-%H%M%S-%3f"),
                    change.change
                ));
                let _ = std::fs::write(&event_file, serde_json::to_string_pretty(&brain_event).unwrap_or_default());
            }
            last_vpn_statuses = new_statuses;
        }

        // Claude tab collision check (every 30s)
        if last_collision_check.elapsed() > Duration::from_secs(30) {
            last_collision_check = std::time::Instant::now();
            let collisions = crate::modules::claude_sessions::check_collisions_for_guard();
            for group in &collisions {
                println!(
                    "  {} Claude tab collision: {} ({} sessions)",
                    "!!".red().bold(),
                    group.project_dir.yellow(),
                    group.sessions.len()
                );

                // Emit brain event
                let brain_event = serde_json::json!({
                    "schema_version": 1,
                    "type": "claude_tab_collision",
                    "timestamp": Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                    "project_dir": group.project_dir,
                    "session_count": group.sessions.len(),
                    "pids": group.sessions.iter().map(|s| s.pid).collect::<Vec<_>>(),
                });
                let event_file = events_dir.join(format!(
                    "{}-collision.json",
                    Local::now().format("%Y%m%d-%H%M%S-%3f"),
                ));
                let _ = std::fs::write(&event_file, serde_json::to_string_pretty(&brain_event).unwrap_or_default());
            }
        }

        // Periodic tasks (every 5 min): cleanup + IOC scan
        if last_cleanup.elapsed() > Duration::from_secs(300) {
            last_cleanup = std::time::Instant::now();
            cleanup_old_events(&events_dir, 7);

            // Disk space check
            let low_drives = crate::modules::disk_monitor::check_disk_for_guard();
            for drive in &low_drives {
                println!(
                    "  {} Drive {} low: {:.1}% used ({:.1} GB free)",
                    "!!".red().bold(),
                    drive.letter.yellow(),
                    drive.used_percent,
                    drive.free_gb
                );
                let brain_event = serde_json::json!({
                    "schema_version": 1,
                    "type": "disk_low",
                    "timestamp": Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                    "drive": drive.letter,
                    "used_percent": drive.used_percent,
                    "free_gb": drive.free_gb,
                    "total_gb": drive.total_gb,
                });
                let event_file = events_dir.join(format!(
                    "{}-disk-low-{}.json",
                    Local::now().format("%Y%m%d-%H%M%S-%3f"),
                    drive.letter.replace(':', ""),
                ));
                let _ = std::fs::write(&event_file, serde_json::to_string_pretty(&brain_event).unwrap_or_default());
            }

            // IOC scan — query last 10 minutes of event logs
            let ioc_events = crate::modules::ioc_monitor::poll_iocs(&iocs, 10);
            if !ioc_events.is_empty() {
                println!("\n  {} {} IOC(s) detected:", "!".red().bold(), ioc_events.len());
                for ioc in &ioc_events {
                    println!("    [{}] EventID:{} {} — {}", ioc.severity, ioc.event_id, ioc.description, ioc.details.chars().take(80).collect::<String>());

                    // Emit brain event
                    let brain_event = serde_json::json!({
                        "schema_version": 1,
                        "type": "ioc",
                        "timestamp": ioc.timestamp,
                        "event_id": ioc.event_id,
                        "log_name": ioc.log_name,
                        "severity": ioc.severity,
                        "description": ioc.description,
                        "details": ioc.details,
                    });
                    let event_file = events_dir.join(format!(
                        "{}-ioc-{}.json",
                        Local::now().format("%Y%m%d-%H%M%S-%3f"),
                        ioc.event_id
                    ));
                    let _ = std::fs::write(&event_file, serde_json::to_string_pretty(&brain_event).unwrap_or_default());
                }

                // Push to IOC ring buffer
                {
                    let mut buf = iocs.write().await;
                    for ioc in ioc_events {
                        if buf.len() >= 500 {
                            buf.pop_back();
                        }
                        buf.push_front(ioc);
                    }
                }
            }
        }
    }

    Ok(())
}

// === HTTP Handlers ===

async fn dashboard_html() -> Html<&'static str> {
    Html(include_str!("../../dashboard.html"))
}

async fn api_events(
    State(state): State<AppState>,
) -> axum::Json<Vec<FocusEvent>> {
    let buf = state.events.read().await;
    axum::Json(buf.iter().cloned().collect())
}

async fn api_stats(
    State(state): State<AppState>,
) -> axum::Json<Stats> {
    let buf = state.events.read().await;
    let mut stats = Stats {
        total: buf.len(),
        safe: 0,
        claude: 0,
        unknown: 0,
        suspicious: 0,
        started_at: state.started_at.clone(),
    };
    for e in buf.iter() {
        match e.classification.as_str() {
            "SAFE" => stats.safe += 1,
            "UNKNOWN" => stats.unknown += 1,
            c if c.starts_with("CLAUDE") => stats.claude += 1,
            c if c.starts_with("SUSPICIOUS") => stats.suspicious += 1,
            _ => {}
        }
    }
    axum::Json(stats)
}

// === Brain Integration API (T023-T025) ===

#[derive(Serialize)]
struct Summary {
    window_minutes: u64,
    total_events: usize,
    repeat_offenders: Vec<RepeatOffender>,
    anomalies: Vec<Anomaly>,
    classification_counts: ClassificationCounts,
}

#[derive(Serialize)]
struct RepeatOffender {
    process: String,
    command_summary: String,
    count: usize,
    frequency_per_min: f64,
    classification: String,
    source_project: Option<String>,
    last_seen: String,
    sample_command_line: Option<String>,
}

#[derive(Serialize)]
struct Anomaly {
    #[serde(rename = "type")]
    anomaly_type: String,
    process: String,
    pid: u32,
    timestamp: String,
    command_line: Option<String>,
    parent_chain: String,
}

#[derive(Serialize)]
struct ClassificationCounts {
    safe: usize,
    claude: usize,
    unknown: usize,
    suspicious: usize,
}

#[derive(Serialize)]
struct Health {
    status: String,
    uptime_seconds: u64,
    events_captured: usize,
    last_event_at: Option<String>,
}

/// T025: Normalize a command line for grouping — strip PIDs, temp paths, quotes, unique IDs
fn normalize_command(cmd: &Option<String>, process_name: &str) -> String {
    let Some(cmd) = cmd else {
        return process_name.to_lowercase();
    };

    let mut s = cmd.clone();
    // Strip quotes
    s = s.replace('"', "");
    // Normalize path separators
    s = s.replace('\\', "/");
    // Strip PID-like numbers in temp filenames (e.g. claude-analyze-args-1775540108755.json)
    s = regex_lite::Regex::new(r"\d{10,}")
        .map(|re| re.replace_all(&s, "<ID>").to_string())
        .unwrap_or(s);
    // Strip temp path prefixes
    s = regex_lite::Regex::new(r"(?i)C:/Users/[^/]+/AppData/Local/Temp/[^ ]*")
        .map(|re| re.replace_all(&s, "<TEMP>").to_string())
        .unwrap_or(s);

    // Extract the key command identity
    let lower = s.to_lowercase();

    // python -IBm azure.cli <cmd> → az <cmd>
    if let Some(caps) = regex_lite::Regex::new(r"(?i)-[IB]*m\s+azure\.cli\s+(.*)")
        .ok()
        .and_then(|re| re.captures(&s))
    {
        return format!("az {}", &caps[1]).chars().take(120).collect();
    }

    // python script.py → script.py
    if lower.contains("python") {
        if let Some(caps) = regex_lite::Regex::new(r"(?i)([^\s/]+\.py)")
            .ok()
            .and_then(|re| re.captures(&s))
        {
            return caps[1].to_string();
        }
    }

    // cmd /c node script.js → node script.js
    if lower.contains("cmd") && lower.contains("/c") {
        if let Some(idx) = lower.find("/c") {
            let after = &s[idx + 2..].trim_start();
            return after.chars().take(120).collect();
        }
    }

    // powershell -Command → PS: <command>
    if lower.contains("powershell") || lower.contains("pwsh") {
        if let Some(caps) = regex_lite::Regex::new(r"(?i)-Command\s+(.*)")
            .ok()
            .and_then(|re| re.captures(&s))
        {
            return format!("PS: {}", &caps[1]).chars().take(120).collect();
        }
    }

    // Fallback: process name
    s.chars().take(120).collect()
}

/// T023: Aggregate repeat offenders and anomalies from ring buffer
async fn api_summary(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::Json<Summary> {
    let events = &state.events;
    let window_minutes: u64 = params
        .get("window")
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    let buf = events.read().await;

    // Filter to window
    let cutoff = chrono::Local::now() - chrono::Duration::minutes(window_minutes as i64);
    let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

    let in_window: Vec<&FocusEvent> = buf
        .iter()
        .filter(|e| e.timestamp.as_str() >= cutoff_str.as_str())
        .collect();

    // Group by normalized command
    let mut groups: std::collections::HashMap<String, Vec<&FocusEvent>> =
        std::collections::HashMap::new();
    for e in &in_window {
        let key = normalize_command(&e.command_line, &e.name);
        groups.entry(key).or_default().push(e);
    }

    // Repeat offenders: 3+ occurrences
    let mut repeat_offenders: Vec<RepeatOffender> = groups
        .iter()
        .filter(|(_, evts)| evts.len() >= 3)
        .map(|(key, evts)| {
            let last = evts.first().unwrap(); // ring buffer is newest-first
            let freq = if window_minutes > 0 {
                evts.len() as f64 / window_minutes as f64
            } else {
                0.0
            };
            RepeatOffender {
                process: last.name.clone(),
                command_summary: key.clone(),
                count: evts.len(),
                frequency_per_min: (freq * 100.0).round() / 100.0,
                classification: last.classification.clone(),
                source_project: last.source_project.clone(),
                last_seen: last.timestamp.clone(),
                sample_command_line: last.command_line.clone(),
            }
        })
        .collect();
    repeat_offenders.sort_by(|a, b| b.count.cmp(&a.count));

    // Anomalies: UNKNOWN or SUSPICIOUS
    let anomalies: Vec<Anomaly> = in_window
        .iter()
        .filter(|e| {
            e.classification == "UNKNOWN" || e.classification.starts_with("SUSPICIOUS")
        })
        .map(|e| {
            let atype = if e.classification.starts_with("SUSPICIOUS") {
                "suspicious_process"
            } else {
                "unknown_process"
            };
            Anomaly {
                anomaly_type: atype.to_string(),
                process: e.name.clone(),
                pid: e.pid,
                timestamp: e.timestamp.clone(),
                command_line: e.command_line.clone(),
                parent_chain: e.parent_chain.clone(),
            }
        })
        .collect();

    // Classification counts
    let mut counts = ClassificationCounts {
        safe: 0,
        claude: 0,
        unknown: 0,
        suspicious: 0,
    };
    for e in &in_window {
        match e.classification.as_str() {
            "SAFE" => counts.safe += 1,
            "UNKNOWN" => counts.unknown += 1,
            c if c.starts_with("CLAUDE") => counts.claude += 1,
            c if c.starts_with("SUSPICIOUS") => counts.suspicious += 1,
            _ => {}
        }
    }

    axum::Json(Summary {
        window_minutes,
        total_events: in_window.len(),
        repeat_offenders,
        anomalies,
        classification_counts: counts,
    })
}

/// T024: Health/liveness endpoint for brain
async fn api_iocs(
    State(state): State<AppState>,
) -> axum::Json<Vec<crate::modules::ioc_monitor::IocEvent>> {
    let buf = state.iocs.read().await;
    axum::Json(buf.iter().cloned().collect())
}

async fn api_vpn() -> axum::Json<Vec<crate::modules::vpn_monitor::VpnStatus>> {
    axum::Json(crate::modules::vpn_monitor::check_vpn_status())
}

async fn api_claude_sessions() -> axum::Json<crate::modules::claude_sessions::SessionReport> {
    axum::Json(crate::modules::claude_sessions::detect_sessions())
}

async fn api_disk() -> axum::Json<crate::modules::disk_monitor::DiskReport> {
    axum::Json(crate::modules::disk_monitor::scan())
}

async fn api_status() -> axum::Json<crate::modules::status::SystemStatus> {
    axum::Json(crate::modules::status::get_status())
}

async fn api_health(
    State(state): State<AppState>,
) -> axum::Json<Health> {
    let buf = state.events.read().await;
    let last_event = buf.front().map(|e| e.timestamp.clone());

    // Parse started_at to compute uptime
    let uptime = chrono::NaiveDateTime::parse_from_str(&state.started_at, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|start| {
            let now = chrono::Local::now().naive_local();
            (now - start).num_seconds().max(0) as u64
        })
        .unwrap_or(0);

    axum::Json(Health {
        status: "ok".to_string(),
        uptime_seconds: uptime,
        events_captured: buf.len(),
        last_event_at: last_event,
    })
}

/// Delete event JSON files older than `days` days
fn cleanup_old_events(events_dir: &std::path::Path, days: u64) {
    let cutoff = std::time::SystemTime::now() - Duration::from_secs(days * 86400);
    let entries = match std::fs::read_dir(events_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(meta) = path.metadata() {
            if let Ok(modified) = meta.modified() {
                if modified < cutoff {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
}

// === Helpers ===

fn trace_to_project(
    proc: &crate::modules::process_tree::ProcessInfo,
    snapshot: &ProcessSnapshot,
) -> Option<String> {
    if let Some(ref cmd) = proc.command_line {
        if let Some(project) = extract_project_from_path(cmd) {
            return Some(project);
        }
    }
    if let Some(ref exe) = proc.exe_path {
        if let Some(project) = extract_project_from_path(exe) {
            return Some(project);
        }
    }
    for ancestor in snapshot.parent_chain(proc.pid) {
        if let Some(ref cmd) = ancestor.command_line {
            if let Some(project) = extract_project_from_path(cmd) {
                return Some(project);
            }
        }
        if let Some(ref exe) = ancestor.exe_path {
            if let Some(project) = extract_project_from_path(exe) {
                return Some(project);
            }
        }
    }
    None
}

fn extract_project_from_path(path: &str) -> Option<String> {
    let path_normalized = path.replace('/', "\\");
    let path_lower = path_normalized.to_lowercase();

    let marker = "projectscl1\\";
    let idx = path_lower.find(marker)?;
    let after = &path_normalized[idx + marker.len()..];
    let parts: Vec<&str> = after.split('\\').collect();
    if parts.is_empty() {
        return None;
    }

    let project_dir = if parts.len() >= 2 && parts[0].starts_with('_') {
        format!("{}\\{}", parts[0], parts[1])
    } else {
        parts[0].to_string()
    };

    let full_path = format!("{}\\{}", &projects_dir(), project_dir);
    if Path::new(&full_path).exists() {
        return Some(project_dir);
    }

    let full_path = format!("{}\\{}", &projects_dir(), parts[0]);
    if Path::new(&full_path).exists() {
        return Some(parts[0].to_string());
    }

    None
}

fn format_classification(c: &Classification) -> String {
    match c {
        Classification::Safe => "SAFE".to_string(),
        Classification::Claude(session) => format!("CLAUDE({})", session),
        Classification::Unknown => "UNKNOWN".to_string(),
        Classification::Suspicious(_, reason) => format!("SUSPICIOUS({})", reason),
    }
}

fn print_event(event: &FocusEvent) {
    let time = &event.timestamp[11..];

    let (icon, name_colored) = match event.classification.as_str() {
        "SAFE" => ("S".green().to_string(), event.name.green().to_string()),
        "UNKNOWN" => ("?".yellow().bold().to_string(), event.name.yellow().to_string()),
        c if c.starts_with("CLAUDE") => ("C".cyan().to_string(), event.name.cyan().to_string()),
        _ => ("!".red().bold().to_string(), event.name.red().bold().to_string()),
    };

    println!(
        "  {} [{}] {} (PID {}) [{}]",
        icon, time, name_colored, event.pid, event.classification
    );
    if let Some(ref project) = event.source_project {
        println!("    project: {}", project.cyan());
    }
    println!("    chain: {}", event.parent_chain.dimmed());
    if let Some(ref cmd) = event.command_line {
        let truncated = if cmd.len() > 200 {
            format!("{}...", &cmd[..200])
        } else {
            cmd.clone()
        };
        println!("    cmd: {}", truncated.dimmed());
    }
}

fn append_log(path: &Path, event: &FocusEvent) -> anyhow::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    writeln!(
        file,
        "{}\t{}\tPID:{}\t{}\tproject:{}\tcmd:{}\tchain:{}",
        event.timestamp,
        event.name,
        event.pid,
        event.classification,
        event.source_project.as_deref().unwrap_or("(unknown)"),
        event.command_line.as_deref().unwrap_or("(none)"),
        event.parent_chain,
    )?;

    Ok(())
}

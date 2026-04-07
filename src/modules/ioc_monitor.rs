use colored::Colorize;
use serde::Serialize;
use std::collections::VecDeque;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::RwLock;

const CREATE_NO_WINDOW: u32 = 0x08000000;
const MAX_IOCS: usize = 500;

// === T015a: Data Structures ===

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IocSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for IocSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocSeverity::Info => write!(f, "INFO"),
            IocSeverity::Low => write!(f, "LOW"),
            IocSeverity::Medium => write!(f, "MEDIUM"),
            IocSeverity::High => write!(f, "HIGH"),
            IocSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IocEvent {
    pub timestamp: String,
    pub event_id: u32,
    pub log_name: String,
    pub severity: IocSeverity,
    pub description: String,
    pub details: String,
    pub computer: String,
}

pub type IocBuffer = Arc<RwLock<VecDeque<IocEvent>>>;

/// Known IOC event IDs and their metadata
struct IocDefinition {
    event_id: u32,
    log_name: &'static str,
    severity: IocSeverity,
    description: &'static str,
}

const IOC_DEFINITIONS: &[IocDefinition] = &[
    IocDefinition { event_id: 4625, log_name: "Security", severity: IocSeverity::Medium, description: "Failed logon attempt" },
    IocDefinition { event_id: 4688, log_name: "Security", severity: IocSeverity::Info, description: "Process created" },
    IocDefinition { event_id: 4697, log_name: "Security", severity: IocSeverity::High, description: "Service installed (Security)" },
    IocDefinition { event_id: 7045, log_name: "System", severity: IocSeverity::High, description: "New service installed" },
    IocDefinition { event_id: 1102, log_name: "Security", severity: IocSeverity::Critical, description: "Audit log cleared" },
    IocDefinition { event_id: 4720, log_name: "Security", severity: IocSeverity::High, description: "User account created" },
    IocDefinition { event_id: 4732, log_name: "Security", severity: IocSeverity::High, description: "Member added to security group" },
];

fn lookup_ioc(event_id: u32) -> Option<&'static IocDefinition> {
    IOC_DEFINITIONS.iter().find(|d| d.event_id == event_id)
}

// === T015b: wevtutil Query Wrapper ===

/// Query Windows Event Log for specific event IDs within a time window
fn query_events(log_name: &str, event_ids: &[u32], last_minutes: u32) -> Vec<IocEvent> {
    // Build XPath filter: *[System[(EventID=4625 or EventID=7045) and TimeCreated[timediff(@SystemTime) <= N]]]
    let id_filter = event_ids
        .iter()
        .map(|id| format!("EventID={}", id))
        .collect::<Vec<_>>()
        .join(" or ");

    let millis = last_minutes as u64 * 60 * 1000;
    let xpath = format!(
        "*[System[({})] and System[TimeCreated[timediff(@SystemTime) <= {}]]]",
        id_filter, millis
    );

    // Use PowerShell to invoke wevtutil — cmd.exe mangles XPath bracket syntax
    let ps_cmd = format!(
        "wevtutil qe {} '/q:{}' /f:text /c:100",
        log_name, xpath
    );

    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let output = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if err.contains("Access is denied") {
                // Security log requires elevation — not an error, just skip
            } else if !err.contains("No events") && !err.is_empty() {
                eprintln!("  wevtutil {} error: {}", log_name, err.trim());
            }
            return Vec::new();
        }
        Err(e) => {
            eprintln!("  wevtutil failed: {}", e);
            return Vec::new();
        }
    };

    parse_wevtutil_text(&output, log_name)
}

/// Parse wevtutil text output into IocEvents
fn parse_wevtutil_text(text: &str, log_name: &str) -> Vec<IocEvent> {
    let mut events = Vec::new();
    let mut current_event_id: Option<u32> = None;
    let mut current_time = String::new();
    let mut current_computer = String::new();
    let mut details_lines: Vec<String> = Vec::new();
    let mut in_description = false;

    // Header fields to skip when collecting details
    const SKIP_PREFIXES: &[&str] = &[
        "Log Name:", "Source:", "Date:", "Event ID:", "Task:", "Level:",
        "Opcode:", "Keyword:", "User:", "User Name:", "Computer:",
    ];

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Event[") {
            // Flush previous event
            flush_event(
                &mut events, &mut current_event_id, &current_time,
                log_name, &current_computer, &details_lines,
            );
            details_lines.clear();
            in_description = false;
            continue;
        }

        if trimmed.is_empty() {
            continue;
        }

        if let Some(val) = trimmed.strip_prefix("Event ID:") {
            current_event_id = val.trim().parse().ok();
            in_description = false;
        } else if let Some(val) = trimmed.strip_prefix("Date:") {
            current_time = val.trim().to_string();
            in_description = false;
        } else if let Some(val) = trimmed.strip_prefix("Computer:") {
            current_computer = val.trim().to_string();
            in_description = false;
        } else if trimmed.starts_with("Description:") {
            in_description = true;
        } else if in_description {
            // Capture everything after Description: as details
            if details_lines.len() < 8 && !trimmed.is_empty() {
                details_lines.push(trimmed.to_string());
            }
        } else if SKIP_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
            // Skip known header fields
        }
    }

    // Flush last event
    flush_event(
        &mut events, &mut current_event_id, &current_time,
        log_name, &current_computer, &details_lines,
    );

    events
}

fn flush_event(
    events: &mut Vec<IocEvent>,
    current_event_id: &mut Option<u32>,
    current_time: &str,
    log_name: &str,
    current_computer: &str,
    details_lines: &[String],
) {
    if let Some(eid) = current_event_id.take() {
        if let Some(def) = lookup_ioc(eid) {
            events.push(IocEvent {
                timestamp: current_time.to_string(),
                event_id: eid,
                log_name: log_name.to_string(),
                severity: def.severity,
                description: def.description.to_string(),
                details: details_lines.join("; "),
                computer: current_computer.to_string(),
            });
        }
    }
}

// === T015c: CLI Command ===

pub async fn show_iocs(last_minutes: u32, min_severity: Option<&str>) -> anyhow::Result<()> {
    println!("{}", "=== IOC Monitor ===".bold());
    println!("Scanning Windows Event Logs (last {} minutes)...\n", last_minutes);

    let min_sev = match min_severity {
        Some("critical") => IocSeverity::Critical,
        Some("high") => IocSeverity::High,
        Some("medium") => IocSeverity::Medium,
        Some("low") => IocSeverity::Low,
        _ => IocSeverity::Info,
    };

    // Query Security log
    let security_ids: Vec<u32> = IOC_DEFINITIONS
        .iter()
        .filter(|d| d.log_name == "Security")
        .map(|d| d.event_id)
        .collect();
    let mut all_events = query_events("Security", &security_ids, last_minutes);

    // Query System log
    let system_ids: Vec<u32> = IOC_DEFINITIONS
        .iter()
        .filter(|d| d.log_name == "System")
        .map(|d| d.event_id)
        .collect();
    all_events.extend(query_events("System", &system_ids, last_minutes));

    // Filter by severity
    all_events.retain(|e| e.severity >= min_sev);

    // Sort by timestamp descending
    all_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    if all_events.is_empty() {
        println!("  {} No IOCs found above {} severity", "✓".green(), min_sev);
        return Ok(());
    }

    // Print
    for event in &all_events {
        let (icon, sev_colored) = match event.severity {
            IocSeverity::Critical => ("!!!".red().bold().to_string(), "CRITICAL".red().bold().to_string()),
            IocSeverity::High => ("!!".red().to_string(), "HIGH".red().to_string()),
            IocSeverity::Medium => ("!".yellow().to_string(), "MEDIUM".yellow().to_string()),
            IocSeverity::Low => ("-".dimmed().to_string(), "LOW".dimmed().to_string()),
            IocSeverity::Info => (".".dimmed().to_string(), "INFO".dimmed().to_string()),
        };

        println!(
            "  {} [{}] EventID:{} [{}] {}",
            icon, event.timestamp, event.event_id, sev_colored, event.description
        );
        if !event.details.is_empty() {
            let truncated = if event.details.len() > 150 {
                format!("{}...", &event.details[..150])
            } else {
                event.details.clone()
            };
            println!("    {}", truncated.dimmed());
        }
    }

    println!(
        "\n  Total: {} IOCs ({} critical, {} high, {} medium)",
        all_events.len(),
        all_events.iter().filter(|e| e.severity == IocSeverity::Critical).count(),
        all_events.iter().filter(|e| e.severity == IocSeverity::High).count(),
        all_events.iter().filter(|e| e.severity == IocSeverity::Medium).count(),
    );

    Ok(())
}

// === T015e: Guard Integration ===

/// Poll for IOCs periodically (called from focus_guard's main loop)
pub fn poll_iocs(_buffer: &IocBuffer, last_minutes: u32) -> Vec<IocEvent> {
    let security_ids: Vec<u32> = IOC_DEFINITIONS
        .iter()
        .filter(|d| d.log_name == "Security")
        .map(|d| d.event_id)
        .collect();
    let mut events = query_events("Security", &security_ids, last_minutes);

    let system_ids: Vec<u32> = IOC_DEFINITIONS
        .iter()
        .filter(|d| d.log_name == "System")
        .map(|d| d.event_id)
        .collect();
    events.extend(query_events("System", &system_ids, last_minutes));

    // Only keep medium+ for guard alerts
    events.retain(|e| e.severity >= IocSeverity::Medium);
    events
}

/// Create a new IOC ring buffer
pub fn new_buffer() -> IocBuffer {
    Arc::new(RwLock::new(VecDeque::with_capacity(MAX_IOCS)))
}

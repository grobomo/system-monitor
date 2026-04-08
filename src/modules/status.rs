use crate::modules::CREATE_NO_WINDOW;
use colored::Colorize;
use serde::Serialize;
use std::os::windows::process::CommandExt;
use std::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct SystemStatus {
    pub cpu_percent: f64,
    pub memory_used_gb: f64,
    pub memory_total_gb: f64,
    pub memory_percent: f64,
    pub uptime_hours: f64,
    pub process_count: u32,
    pub drives: Vec<crate::modules::disk_monitor::DriveInfo>,
    pub vpn: Vec<crate::modules::vpn_monitor::VpnStatus>,
    pub claude_sessions: usize,
    pub claude_collisions: usize,
    pub timestamp: String,
}

/// Show a one-screen system health summary.
pub fn show_status() {
    println!("{}", "=== System Monitor — Status ===".bold());
    println!();

    // System metrics
    let (cpu, mem_used, mem_total) = get_system_metrics();
    let mem_pct = if mem_total > 0.0 {
        mem_used / mem_total * 100.0
    } else {
        0.0
    };

    let uptime = get_uptime_hours();
    let proc_count = get_process_count();

    // CPU
    let cpu_bar = bar(cpu, 100.0);
    let cpu_color = color_for_pct(cpu);
    println!(
        "  {} {} {}",
        "CPU:".bold(),
        cpu_bar,
        format!("{:.1}%", cpu).color(cpu_color)
    );

    // Memory
    let mem_bar = bar(mem_pct, 100.0);
    let mem_color = color_for_pct(mem_pct);
    println!(
        "  {} {} {} ({:.1} / {:.1} GB)",
        "MEM:".bold(),
        mem_bar,
        format!("{:.1}%", mem_pct).color(mem_color),
        mem_used,
        mem_total
    );

    // Disk (from disk_monitor)
    let low_drives = crate::modules::disk_monitor::check_disk_for_guard();
    let all_drives = get_drive_info();
    for d in &all_drives {
        let d_bar = bar(d.used_percent, 100.0);
        let d_color = color_for_pct(d.used_percent);
        println!(
            "  {} {} {} ({:.1} GB free)",
            format!("{}:", d.letter).bold(),
            d_bar,
            format!("{:.1}%", d.used_percent).color(d_color),
            d.free_gb
        );
    }

    println!();

    // Uptime & processes
    println!(
        "  {} {:.1}h   {} {}",
        "Uptime:".bold(),
        uptime,
        "Processes:".bold(),
        proc_count
    );

    println!();

    // VPN
    let vpn = crate::modules::vpn_monitor::check_vpn_status();
    if vpn.is_empty() {
        println!("  {} {}", "VPN:".bold(), "No VPN clients detected".dimmed());
    } else {
        for v in &vpn {
            let verified = v.tunnel_verified.unwrap_or(false);
            let icon = if verified {
                "UP".green().bold().to_string()
            } else if v.running {
                "PROC".yellow().to_string()
            } else {
                "DOWN".red().to_string()
            };
            println!(
                "  {} {} [{}] {}",
                "VPN:".bold(),
                v.name.cyan(),
                icon,
                if verified {
                    "tunnel verified"
                } else if v.running {
                    "process running, tunnel unverified"
                } else {
                    "disconnected"
                }
                .dimmed()
            );
        }
    }

    // Claude sessions
    let sessions = crate::modules::claude_sessions::detect_sessions();
    let total_sessions = sessions.collisions.iter().map(|c| c.sessions.len()).sum::<usize>()
        + sessions.safe.len()
        + sessions.headless.len()
        + sessions.unknown.len();
    let collision_count = sessions.collisions.len();

    if collision_count > 0 {
        println!(
            "  {} {} active ({} {})",
            "Claude:".bold(),
            total_sessions,
            collision_count.to_string().red().bold(),
            "collisions!".red().bold()
        );
    } else {
        println!(
            "  {} {} active, {} collisions",
            "Claude:".bold(),
            total_sessions.to_string().green(),
            "0".green()
        );
    }

    // Disk warnings
    if !low_drives.is_empty() {
        println!();
        for d in &low_drives {
            println!(
                "  {} Drive {} critically low: {:.1} GB free",
                "WARNING".red().bold(),
                d.letter.yellow(),
                d.free_gb
            );
        }
    }

    println!();
}

/// Generate status report for API consumption.
pub fn get_status() -> SystemStatus {
    let (cpu, mem_used, mem_total) = get_system_metrics();
    let mem_pct = if mem_total > 0.0 {
        mem_used / mem_total * 100.0
    } else {
        0.0
    };
    let uptime = get_uptime_hours();
    let proc_count = get_process_count();
    let drives = get_drive_info();
    let vpn = crate::modules::vpn_monitor::check_vpn_status();
    let sessions = crate::modules::claude_sessions::detect_sessions();
    let total_sessions = sessions.collisions.iter().map(|c| c.sessions.len()).sum::<usize>()
        + sessions.safe.len()
        + sessions.headless.len()
        + sessions.unknown.len();

    SystemStatus {
        cpu_percent: cpu,
        memory_used_gb: mem_used,
        memory_total_gb: mem_total,
        memory_percent: (mem_pct * 10.0).round() / 10.0,
        uptime_hours: (uptime * 10.0).round() / 10.0,
        process_count: proc_count,
        drives,
        vpn,
        claude_sessions: total_sessions,
        claude_collisions: sessions.collisions.len(),
        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
    }
}

fn bar(value: f64, max: f64) -> String {
    let pct = (value / max * 100.0).min(100.0);
    let filled = (pct / 5.0).round() as usize;
    let empty = 20usize.saturating_sub(filled);
    let bar_str = format!("[{}{}]", "#".repeat(filled), "-".repeat(empty));
    let color = color_for_pct(pct);
    bar_str.color(color).to_string()
}

fn color_for_pct(pct: f64) -> colored::Color {
    if pct > 90.0 {
        colored::Color::Red
    } else if pct > 75.0 {
        colored::Color::Yellow
    } else {
        colored::Color::Green
    }
}

fn get_drive_info() -> Vec<crate::modules::disk_monitor::DriveInfo> {
    let report = crate::modules::disk_monitor::scan();
    report.drives
}

/// Get CPU usage and memory via PowerShell (single call).
fn get_system_metrics() -> (f64, f64, f64) {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            r#"$os = Get-CimInstance Win32_OperatingSystem; $cpu = (Get-CimInstance Win32_Processor).LoadPercentage; Write-Output "$cpu $($os.TotalVisibleMemorySize) $($os.FreePhysicalMemory)""#,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = stdout.trim().split_whitespace().collect();
            if parts.len() >= 3 {
                let cpu = parts[0].parse::<f64>().unwrap_or(0.0);
                let total_kb = parts[1].parse::<f64>().unwrap_or(0.0);
                let free_kb = parts[2].parse::<f64>().unwrap_or(0.0);
                let total_gb = total_kb / (1024.0 * 1024.0);
                let used_gb = (total_kb - free_kb) / (1024.0 * 1024.0);
                return (cpu, (used_gb * 10.0).round() / 10.0, (total_gb * 10.0).round() / 10.0);
            }
        }
    }
    (0.0, 0.0, 0.0)
}

fn get_uptime_hours() -> f64 {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime | ForEach-Object { ((Get-Date) - $_).TotalHours }",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout.trim().parse::<f64>().unwrap_or(0.0);
        }
    }
    0.0
}

fn get_process_count() -> u32 {
    let snapshot = crate::modules::process_tree::ProcessSnapshot::capture();
    match snapshot {
        Ok(s) => s.all_processes().count() as u32,
        Err(_) => 0,
    }
}

//! Diagnose and fix focus-stealing CMD/PowerShell popups.
//!
//! Queries Windows Task Scheduler for tasks that spawn visible cmd.exe,
//! powershell.exe, or script hosts. Monitors spawn rates in real-time
//! to verify fixes.

use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use super::CREATE_NO_WINDOW;

/// A scheduled task that might cause visible CMD windows
#[derive(Debug, Clone, Serialize)]
pub struct SuspectTask {
    pub name: String,
    pub path: String,
    pub action: String,
    pub arguments: String,
    pub schedule_type: String,
    pub repeat_interval: String,
    pub status: String,
    pub last_run: String,
    pub next_run: String,
    /// True if the task runs cmd.exe, powershell.exe, or a .bat/.cmd/.ps1 script
    pub spawns_cmd: bool,
    /// True if task has no /WindowStyle Hidden or CREATE_NO_WINDOW
    pub likely_visible: bool,
}

/// Snapshot of cmd.exe process counts for monitoring
#[derive(Debug, Clone, Serialize)]
pub struct SpawnSnapshot {
    pub timestamp: String,
    pub cmd_count: usize,
    pub powershell_count: usize,
    pub total_focus_stealers: usize,
    pub new_since_last: usize,
}

/// Query all scheduled tasks and filter for ones that spawn CMD/PS windows
pub fn find_suspect_tasks() -> Vec<SuspectTask> {
    // Use schtasks XML output for reliable parsing
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-WindowStyle", "Hidden",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            r#"
$tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
$results = @()
foreach ($task in $tasks) {
    foreach ($action in $task.Actions) {
        if ($action.Execute) {
            $exe = $action.Execute.ToLower()
            $args = if ($action.Arguments) { $action.Arguments } else { '' }
            $isCmdLike = $exe -match '(cmd|cmd\.exe|powershell|pwsh|cscript|wscript|bash)' -or
                         $exe -match '\.(bat|cmd|ps1|vbs|js)$' -or
                         $args -match '(cmd|powershell|pwsh)'
            if ($isCmdLike) {
                $info = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                $triggers = $task.Triggers | ForEach-Object {
                    $rep = if ($_.Repetition.Interval) { $_.Repetition.Interval } else { 'none' }
                    @{ Type = $_.CimClass.CimClassName; Repeat = $rep }
                }
                $trigType = if ($triggers.Count -gt 0) { ($triggers | ForEach-Object { $_.Type }) -join ',' } else { 'Unknown' }
                $repInt = if ($triggers.Count -gt 0) { ($triggers | ForEach-Object { $_.Repeat }) -join ',' } else { 'none' }
                $isHidden = $args -match '(-WindowStyle\s+Hidden|-NoNewWindow|/B\s)' -or $exe -match 'pythonw'
                $results += [PSCustomObject]@{
                    Name = $task.TaskName
                    Path = $task.TaskPath
                    Execute = $action.Execute
                    Arguments = $args
                    ScheduleType = $trigType
                    RepeatInterval = $repInt
                    Status = $task.State.ToString()
                    LastRun = if ($info) { $info.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
                    NextRun = if ($info) { $info.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
                    IsHidden = $isHidden
                }
            }
        }
    }
}
$results | ConvertTo-Json -Compress
"#,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            eprintln!("{} PowerShell error: {}", "!".red(), stderr.trim());
            return Vec::new();
        }
        Err(e) => {
            eprintln!("{} Failed to run PowerShell: {}", "!".red(), e);
            return Vec::new();
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    if stdout.is_empty() {
        return Vec::new();
    }

    // Parse JSON — could be single object or array
    let entries: Vec<SchtaskEntry> = if stdout.starts_with('[') {
        serde_json::from_str(stdout).unwrap_or_default()
    } else {
        serde_json::from_str::<SchtaskEntry>(stdout)
            .map(|e| vec![e])
            .unwrap_or_default()
    };

    entries
        .into_iter()
        .map(|e| {
            let action_lower = e.execute.to_lowercase();
            let args_lower = e.arguments.to_lowercase();
            let spawns_cmd = action_lower.contains("cmd")
                || action_lower.contains("powershell")
                || action_lower.contains("pwsh")
                || action_lower.contains("cscript")
                || action_lower.contains("wscript")
                || action_lower.ends_with(".bat")
                || action_lower.ends_with(".cmd")
                || action_lower.ends_with(".ps1")
                || args_lower.contains("cmd")
                || args_lower.contains("powershell");

            SuspectTask {
                name: e.name,
                path: e.path,
                action: e.execute,
                arguments: e.arguments,
                schedule_type: e.schedule_type,
                repeat_interval: e.repeat_interval,
                status: e.status,
                last_run: e.last_run,
                next_run: e.next_run,
                spawns_cmd,
                likely_visible: !e.is_hidden,
            }
        })
        .collect()
}

/// Disable a scheduled task by full path + name
pub fn disable_task(task_path: &str, task_name: &str) -> Result<String, String> {
    let full_path = format!("{}{}", task_path, task_name);
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-WindowStyle", "Hidden",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            &format!(
                "Disable-ScheduledTask -TaskPath '{}' -TaskName '{}' -ErrorAction Stop | Select-Object TaskName, State | ConvertTo-Json -Compress",
                task_path, task_name
            ),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {}", e))?;

    if output.status.success() {
        Ok(format!("Disabled task: {}", full_path))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to disable {}: {}", full_path, stderr.trim()))
    }
}

/// Enable a previously disabled scheduled task
pub fn enable_task(task_path: &str, task_name: &str) -> Result<String, String> {
    let full_path = format!("{}{}", task_path, task_name);
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-WindowStyle", "Hidden",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            &format!(
                "Enable-ScheduledTask -TaskPath '{}' -TaskName '{}' -ErrorAction Stop | Select-Object TaskName, State | ConvertTo-Json -Compress",
                task_path, task_name
            ),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {}", e))?;

    if output.status.success() {
        Ok(format!("Re-enabled task: {}", full_path))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to enable {}: {}", full_path, stderr.trim()))
    }
}

/// Fast snapshot of cmd/ps processes using ToolHelp32 (same as focus_guard).
/// Returns: (pid, name, ppid, parent_name)
fn get_focus_stealer_snapshot() -> Vec<(u32, String, u32, String)> {
    use crate::modules::process_tree::ProcessSnapshot;

    let snapshot = match ProcessSnapshot::capture() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let targets = ["cmd.exe", "powershell.exe", "pwsh.exe"];
    let self_pid = std::process::id();

    snapshot
        .all_processes()
        .filter(|p| {
            let name_lower = p.name.to_lowercase();
            targets.contains(&name_lower.as_str())
        })
        .filter(|p| {
            // Skip our own children (WMI queries from ProcessSnapshot::capture)
            let chain = snapshot.parent_chain(p.pid);
            !chain.iter().any(|c| c.pid == self_pid)
        })
        .map(|p| {
            let parent_name = snapshot
                .get(p.ppid)
                .map(|pp| format!("{}({})", pp.name, pp.pid))
                .unwrap_or_else(|| format!("(dead:{})", p.ppid));
            let detail = format!(
                "parent={} cmd=[{}]",
                parent_name,
                p.command_line.as_deref().unwrap_or("(none)")
            );
            (p.pid, p.name.clone(), p.ppid, detail)
        })
        .collect()
}

/// Monitor CMD/PS spawn rate using PID tracking (catches short-lived processes).
/// Returns the list of snapshots taken.
pub fn monitor_spawn_rate(duration_secs: u64, interval_secs: u64) -> Vec<SpawnSnapshot> {
    use std::collections::{HashSet, HashMap};

    let mut snapshots = Vec::new();
    let start = Instant::now();
    let mut known_pids: HashSet<u32> = HashSet::new();
    let mut total_new_spawns: usize = 0;
    let mut parent_counts: HashMap<String, usize> = HashMap::new();

    // Initial baseline
    for (pid, _, _, _) in get_focus_stealer_snapshot() {
        known_pids.insert(pid);
    }

    println!(
        "\n{} Monitoring CMD/PowerShell spawns for {}s (polling every {}s)...\n",
        "▶".cyan(),
        duration_secs,
        interval_secs
    );
    println!(
        "  {:>8}  {:>5}  {:>5}  {:>5}  {}",
        "Time", "Alive", "New", "Total", "Details"
    );
    println!("  {}", "─".repeat(80));

    loop {
        if start.elapsed() >= Duration::from_secs(duration_secs) {
            break;
        }

        // Poll fast (500ms) for catching short-lived processes, but only print on interval
        let sub_start = Instant::now();
        let mut current = Vec::new();
        let mut new_this_round = 0;
        let mut new_details = Vec::new();

        while sub_start.elapsed() < Duration::from_secs(interval_secs) {
            std::thread::sleep(Duration::from_millis(500));
            let snap = get_focus_stealer_snapshot();
            for (pid, name, _ppid, detail) in &snap {
                if !known_pids.contains(pid) {
                    known_pids.insert(*pid);
                    new_this_round += 1;
                    total_new_spawns += 1;
                    new_details.push(format!("{}({}): {}", name, pid, detail));
                    let parent_key = detail.split(" cmd=").next().unwrap_or(detail).to_string();
                    *parent_counts.entry(parent_key).or_insert(0) += 1;
                }
            }
            // Remove dead PIDs
            let snap_pids: HashSet<u32> = snap.iter().map(|(pid, _, _, _)| *pid).collect();
            known_pids.retain(|pid| snap_pids.contains(pid));
            current = snap;
        }

        let ts = chrono::Local::now().format("%H:%M:%S").to_string();

        let new_str = if new_this_round > 0 {
            format!("+{}", new_this_round).red().bold().to_string()
        } else {
            "0".green().to_string()
        };

        let detail_str = if new_details.is_empty() {
            String::new()
        } else {
            new_details[0].chars().take(50).collect::<String>()
        };

        println!(
            "  {:>8}  {:>5}  {:>5}  {:>5}  {}",
            ts,
            current.len(),
            new_str,
            total_new_spawns,
            detail_str.dimmed()
        );

        // Print full details for new processes
        if new_details.len() > 1 {
            for detail in &new_details[1..] {
                println!("                                        {}", detail.dimmed());
            }
        }

        snapshots.push(SpawnSnapshot {
            timestamp: ts,
            cmd_count: current.iter().filter(|(_, n, _, _)| n == "cmd.exe").count(),
            powershell_count: current.iter().filter(|(_, n, _, _)| n.contains("powershell") || n.contains("pwsh")).count(),
            total_focus_stealers: current.len(),
            new_since_last: new_this_round,
        });
    }

    // Summary
    let elapsed = start.elapsed().as_secs().max(1);
    let rate_per_min = (total_new_spawns as f64 / elapsed as f64) * 60.0;

    println!("\n  {}", "─".repeat(80));
    println!(
        "  {} new CMD/PS spawns in {}s ({:.1}/min)",
        if total_new_spawns > 0 {
            total_new_spawns.to_string().red().bold().to_string()
        } else {
            "0".green().bold().to_string()
        },
        elapsed,
        rate_per_min
    );

    if !parent_counts.is_empty() {
        println!("\n  {} Spawn sources:", ">>>".yellow());
        let mut sorted: Vec<_> = parent_counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (parent, count) in sorted {
            println!("    {}x  {}", count.to_string().yellow(), parent);
        }
    }

    if total_new_spawns == 0 {
        println!("\n  {} No focus-stealing CMD/PS windows detected!", "✓".green().bold());
    } else {
        println!(
            "\n  {} Still seeing {} new CMD/PS processes",
            "✗".red().bold(),
            total_new_spawns
        );
    }

    snapshots
}

/// CLI: run full diagnosis
pub fn show_diagnosis() {
    println!("{}", "=== CMD Popup Diagnosis ===".bold());
    println!();

    // Step 1: Find suspect scheduled tasks
    println!("{}", "Scanning scheduled tasks...".dimmed());
    let tasks = find_suspect_tasks();

    if tasks.is_empty() {
        println!("  {} No scheduled tasks found that spawn CMD/PowerShell", "✓".green());
    } else {
        // Sort: likely visible + repeating first
        let mut sorted = tasks.clone();
        sorted.sort_by(|a, b| {
            let a_score = score_task(a);
            let b_score = score_task(b);
            b_score.cmp(&a_score)
        });

        println!(
            "\n  Found {} tasks that spawn CMD/PowerShell:\n",
            sorted.len().to_string().yellow()
        );

        for (i, task) in sorted.iter().enumerate() {
            let visibility = if task.likely_visible {
                "VISIBLE".red().bold().to_string()
            } else {
                "hidden".green().to_string()
            };

            let repeat = if task.repeat_interval != "none" && !task.repeat_interval.is_empty() {
                task.repeat_interval.yellow().to_string()
            } else {
                "no repeat".dimmed().to_string()
            };

            println!(
                "  {}. {} [{}] [{}]",
                (i + 1).to_string().bold(),
                task.name.bright_white(),
                visibility,
                repeat
            );
            println!("     Path: {}", task.path.dimmed());
            println!("     Action: {}", task.action.cyan());
            if !task.arguments.is_empty() {
                let args_display = if task.arguments.len() > 120 {
                    format!("{}...", &task.arguments[..120])
                } else {
                    task.arguments.clone()
                };
                println!("     Args: {}", args_display.dimmed());
            }
            println!(
                "     Schedule: {} | Last: {} | Next: {}",
                task.schedule_type.dimmed(),
                task.last_run.dimmed(),
                task.next_run.dimmed()
            );
            println!();
        }

        // Highlight the most likely culprits
        let culprits: Vec<&SuspectTask> = sorted
            .iter()
            .filter(|t| t.likely_visible && t.repeat_interval != "none" && !t.repeat_interval.is_empty())
            .collect();

        if !culprits.is_empty() {
            println!(
                "  {} Most likely culprits (visible + repeating):",
                ">>>".red().bold()
            );
            for t in &culprits {
                println!(
                    "      {} (every {})",
                    t.name.red().bold(),
                    t.repeat_interval.yellow()
                );
            }
            println!();
            println!(
                "  Use {} to disable a task",
                "system-monitor fix --disable <task-name>".cyan()
            );
        }
    }

    // Step 2: Quick spawn rate check
    println!();
    monitor_spawn_rate(30, 5);
}

/// CLI: fix by disabling tasks
pub fn fix_tasks(disable: &[String], enable: &[String]) {
    // Need to look up full paths for task names
    let tasks = find_suspect_tasks();

    for name in disable {
        if let Some(task) = tasks.iter().find(|t| t.name.eq_ignore_ascii_case(name)) {
            println!("  Disabling {}{}...", task.path, task.name);
            match disable_task(&task.path, &task.name) {
                Ok(msg) => println!("  {} {}", "✓".green(), msg),
                Err(msg) => println!("  {} {}", "✗".red(), msg),
            }
        } else {
            // Try as a full path
            println!("  Disabling {} (by path)...", name);
            // Extract path and name from full path like \Microsoft\Windows\Foo\BarTask
            let (path, task_name) = split_task_path(name);
            match disable_task(&path, &task_name) {
                Ok(msg) => println!("  {} {}", "✓".green(), msg),
                Err(msg) => println!("  {} {}", "✗".red(), msg),
            }
        }
    }

    for name in enable {
        if let Some(task) = tasks.iter().find(|t| t.name.eq_ignore_ascii_case(name)) {
            println!("  Re-enabling {}{}...", task.path, task.name);
            match enable_task(&task.path, &task.name) {
                Ok(msg) => println!("  {} {}", "✓".green(), msg),
                Err(msg) => println!("  {} {}", "✗".red(), msg),
            }
        } else {
            let (path, task_name) = split_task_path(name);
            match enable_task(&path, &task_name) {
                Ok(msg) => println!("  {} {}", "✓".green(), msg),
                Err(msg) => println!("  {} {}", "✗".red(), msg),
            }
        }
    }
}

/// Monitor spawn rate for verification
pub fn verify_fix(duration_secs: u64) {
    println!("{}", "=== Verifying Fix ===".bold());
    monitor_spawn_rate(duration_secs, 5);
}

/// Score a task for sorting — higher = more likely culprit
fn score_task(task: &SuspectTask) -> u32 {
    let mut score = 0;
    if task.likely_visible {
        score += 10;
    }
    if task.repeat_interval != "none" && !task.repeat_interval.is_empty() {
        score += 5;
        // Shorter intervals = more suspicious
        if task.repeat_interval.contains("PT1M") || task.repeat_interval.contains("PT2M") {
            score += 10; // every 1-2 minutes
        } else if task.repeat_interval.contains("PT5M") || task.repeat_interval.contains("PT10M") {
            score += 5; // every 5-10 minutes
        }
    }
    if task.spawns_cmd {
        score += 3;
    }
    // Recently ran
    if task.last_run != "N/A" && !task.last_run.is_empty() {
        score += 2;
    }
    score
}

/// Split "\Path\To\TaskName" into ("\Path\To\", "TaskName")
fn split_task_path(full: &str) -> (String, String) {
    let normalized = full.replace('/', "\\");
    if let Some(idx) = normalized.rfind('\\') {
        let path = &normalized[..=idx];
        let name = &normalized[idx + 1..];
        (path.to_string(), name.to_string())
    } else {
        ("\\".to_string(), normalized)
    }
}

#[derive(Deserialize)]
struct SchtaskEntry {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Execute")]
    execute: String,
    #[serde(rename = "Arguments", default)]
    arguments: String,
    #[serde(rename = "ScheduleType", default)]
    schedule_type: String,
    #[serde(rename = "RepeatInterval", default)]
    repeat_interval: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "LastRun", default)]
    last_run: String,
    #[serde(rename = "NextRun", default)]
    next_run: String,
    #[serde(rename = "IsHidden", default)]
    is_hidden: bool,
}

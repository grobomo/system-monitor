use crate::modules::classifier::{Classification, classify_process};
use crate::modules::process_tree::ProcessSnapshot;
use colored::Colorize;
use std::collections::HashSet;
use std::time::Duration;

pub async fn run() -> anyhow::Result<()> {
    println!("{}", "=== System Monitor Daemon ===".bold());
    println!("Monitoring process creation events...");
    println!("Press Ctrl+C to stop\n");

    let mut known_pids: HashSet<u32> = HashSet::new();

    // Initial snapshot — mark all current processes as known
    let snapshot = ProcessSnapshot::capture()?;
    for proc in snapshot.all_processes() {
        known_pids.insert(proc.pid);
    }
    println!(
        "Baseline: {} processes tracked",
        known_pids.len().to_string().green()
    );

    // Save baseline to ~/.system-monitor/baseline.json
    save_baseline(&snapshot)?;

    // Poll loop (TODO T006: replace with ETW for real-time events)
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;

        let snapshot = ProcessSnapshot::capture()?;
        let mut new_count = 0;

        for proc in snapshot.all_processes() {
            if known_pids.contains(&proc.pid) {
                continue;
            }
            known_pids.insert(proc.pid);
            new_count += 1;

            let classification = classify_process(proc, &snapshot);
            match &classification {
                Classification::Safe => {} // silent for safe
                Classification::Claude(session) => {
                    println!(
                        "  {} {} (PID {}) [{}]",
                        "→".cyan(),
                        proc.name.cyan(),
                        proc.pid,
                        session.cyan()
                    );
                }
                Classification::Unknown => {
                    let chain: Vec<String> = snapshot
                        .parent_chain(proc.pid)
                        .iter()
                        .map(|p| format!("{}({})", p.name, p.pid))
                        .collect();
                    println!(
                        "  {} {} (PID {}) [UNKNOWN]",
                        "?".yellow().bold(),
                        proc.name.yellow(),
                        proc.pid,
                    );
                    println!("    chain: {}", chain.join(" → ").dimmed());
                    if let Some(ref cmd) = proc.command_line {
                        println!("    cmd: {}", cmd.dimmed());
                    }
                }
                Classification::Suspicious(_, reason) => {
                    println!(
                        "  {} {} (PID {}) [{}]",
                        "!!!".red().bold(),
                        proc.name.red().bold(),
                        proc.pid,
                        reason.red()
                    );
                    let chain: Vec<String> = snapshot
                        .parent_chain(proc.pid)
                        .iter()
                        .map(|p| format!("{}({})", p.name, p.pid))
                        .collect();
                    println!("    chain: {}", chain.join(" → "));
                    if let Some(ref cmd) = proc.command_line {
                        println!("    cmd: {}", cmd);
                    }
                    if let Some(ref path) = proc.exe_path {
                        println!("    path: {}", path);
                    }
                }
            }
        }

        // Clean up PIDs that no longer exist
        let current_pids: HashSet<u32> = snapshot.all_processes().map(|p| p.pid).collect();
        known_pids.retain(|pid| current_pids.contains(pid));

        if new_count > 0 {
            // Only print if there were non-safe new processes worth mentioning
        }
    }
}

fn save_baseline(snapshot: &ProcessSnapshot) -> anyhow::Result<()> {
    let dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot find home directory"))?
        .join(".system-monitor");
    std::fs::create_dir_all(&dir)?;

    let baseline: Vec<serde_json::Value> = snapshot
        .all_processes()
        .map(|p| {
            serde_json::json!({
                "pid": p.pid,
                "ppid": p.ppid,
                "name": p.name,
                "exe_path": p.exe_path,
                "command_line": p.command_line,
            })
        })
        .collect();

    let path = dir.join("baseline.json");
    std::fs::write(&path, serde_json::to_string_pretty(&baseline)?)?;
    Ok(())
}

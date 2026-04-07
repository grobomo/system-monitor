use crate::modules::classifier::{Classification, classify_process};
use crate::modules::process_tree::ProcessSnapshot;
use colored::Colorize;

pub async fn show_process_tree(threats_only: bool) -> anyhow::Result<()> {
    let snapshot = ProcessSnapshot::capture()?;
    let roots = snapshot.roots();

    println!("{}", "=== Process Tree ===".bold());
    println!(
        "  {} {} {} {}",
        "SAFE".green(),
        "CLAUDE".cyan(),
        "UNKNOWN".yellow(),
        "SUSPICIOUS".red()
    );
    println!();

    for root_pid in &roots {
        print_tree(&snapshot, *root_pid, 0, threats_only);
    }

    // Summary
    let mut counts = [0u32; 4]; // safe, claude, unknown, suspicious
    for proc in snapshot.all_processes() {
        match classify_process(proc, &snapshot) {
            Classification::Safe => counts[0] += 1,
            Classification::Claude(_) => counts[1] += 1,
            Classification::Unknown => counts[2] += 1,
            Classification::Suspicious(_, _) => counts[3] += 1,
        }
    }
    println!();
    println!(
        "Total: {} processes — {} safe, {} claude, {} unknown, {} suspicious",
        counts.iter().sum::<u32>(),
        counts[0].to_string().green(),
        counts[1].to_string().cyan(),
        counts[2].to_string().yellow(),
        counts[3].to_string().red(),
    );

    Ok(())
}

fn print_tree(snapshot: &ProcessSnapshot, pid: u32, depth: usize, threats_only: bool) {
    // Prevent excessive depth (guards against cycles)
    if depth > 30 {
        return;
    }

    let Some(proc) = snapshot.get(pid) else { return };
    let classification = classify_process(proc, snapshot);

    if threats_only {
        match &classification {
            Classification::Safe | Classification::Claude(_) => {
                // Still recurse into children — a safe parent might have suspicious children
                for child_pid in snapshot.children_of(pid) {
                    if child_pid != pid {
                        print_tree(snapshot, child_pid, depth, threats_only);
                    }
                }
                return;
            }
            _ => {}
        }
    }

    let indent = "  ".repeat(depth);
    let exe_name = proc.exe_name();
    let pid_str = format!("({})", pid);

    let line = match &classification {
        Classification::Safe => {
            format!("{}{} {} {}", indent, "●".green(), exe_name, pid_str.dimmed())
        }
        Classification::Claude(session) => {
            format!(
                "{}{} {} {} [{}]",
                indent,
                "●".cyan(),
                exe_name.cyan(),
                pid_str.dimmed(),
                session.cyan()
            )
        }
        Classification::Unknown => {
            format!(
                "{}{} {} {} [UNKNOWN]",
                indent,
                "?".yellow().bold(),
                exe_name.yellow(),
                pid_str.dimmed()
            )
        }
        Classification::Suspicious(_, reason) => {
            format!(
                "{}{} {} {} [{}]",
                indent,
                "!".red().bold(),
                exe_name.red().bold(),
                pid_str.dimmed(),
                reason.red()
            )
        }
    };

    println!("{}", line);

    // Print command line for unknown/suspicious
    if matches!(classification, Classification::Unknown | Classification::Suspicious(_, _)) {
        if let Some(ref cmd) = proc.command_line {
            let truncated = if cmd.len() > 120 {
                format!("{}...", &cmd[..120])
            } else {
                cmd.clone()
            };
            println!("{}  cmd: {}", indent, truncated.dimmed());
        }
    }

    for child_pid in snapshot.children_of(pid) {
        if child_pid != pid {
            print_tree(snapshot, child_pid, depth + 1, threats_only);
        }
    }
}

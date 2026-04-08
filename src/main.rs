mod modules;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "system-monitor")]
#[command(about = "Real-time system security agent — process monitoring, UAC tracking, threat classification")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Show running processes as a classified tree
    Procs {
        /// Only show unknown/suspicious/malicious
        #[arg(short, long)]
        threats_only: bool,
    },
    /// Show recent UAC/elevation events with attribution
    Uac {
        /// Minutes to look back
        #[arg(short, long, default_value = "60")]
        last: u32,
    },
    /// One-screen system health summary
    Status,
    /// Run as continuous monitoring daemon
    Daemon,
    /// Watch for cmd/python windows stealing focus — log and emit events to brain
    Guard,
    /// Show VPN connectivity status
    Vpn,
    /// Scan Windows Event Logs for indicators of compromise
    Ioc {
        /// Minutes to look back (default: 1440 = 24h)
        #[arg(short, long, default_value = "1440")]
        last: u32,
        /// Minimum severity: info, low, medium, high, critical
        #[arg(short, long)]
        severity: Option<String>,
    },
    /// List active Claude Code sessions — detect project directory collisions
    ClaudeTabs,
    /// Diagnose focus-stealing CMD/PowerShell popup windows
    Diagnose,
    /// Fix focus-stealing popups by disabling/enabling scheduled tasks
    Fix {
        /// Task names to disable (can specify multiple)
        #[arg(long, num_args = 1..)]
        disable: Vec<String>,
        /// Task names to re-enable (can specify multiple)
        #[arg(long, num_args = 1..)]
        enable: Vec<String>,
    },
    /// Monitor CMD/PS spawn rate to verify a fix worked
    Verify {
        /// Duration to monitor in seconds (default: 120)
        #[arg(short, long, default_value = "120")]
        duration: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Procs { threats_only }) => {
            modules::process_monitor::show_process_tree(threats_only).await?;
        }
        Some(Commands::Uac { last }) => {
            modules::uac_tracker::show_uac_events(last).await?;
        }
        Some(Commands::Status) => {
            println!("system-monitor status — not yet implemented (T012)");
        }
        Some(Commands::Daemon) => {
            modules::daemon::run().await?;
        }
        Some(Commands::Guard) => {
            modules::focus_guard::run().await?;
        }
        Some(Commands::Vpn) => {
            modules::vpn_monitor::show_vpn_status();
        }
        Some(Commands::Ioc { last, severity }) => {
            modules::ioc_monitor::show_iocs(last, severity.as_deref()).await?;
        }
        Some(Commands::ClaudeTabs) => {
            modules::claude_sessions::show_sessions();
        }
        Some(Commands::Diagnose) => {
            modules::cmd_diagnosis::show_diagnosis();
        }
        Some(Commands::Fix { disable, enable }) => {
            modules::cmd_diagnosis::fix_tasks(&disable, &enable);
        }
        Some(Commands::Verify { duration }) => {
            modules::cmd_diagnosis::verify_fix(duration);
        }
        None => {
            // Default: show quick status
            modules::process_monitor::show_process_tree(true).await?;
        }
    }

    Ok(())
}

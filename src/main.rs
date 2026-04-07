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
        None => {
            // Default: show quick status
            modules::process_monitor::show_process_tree(true).await?;
        }
    }

    Ok(())
}

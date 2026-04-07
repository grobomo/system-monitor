use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct UacEvent {
    pub timestamp: String,
    pub pid: u32,
    pub exe: String,
    pub command_line: Option<String>,
    pub parent_pid: u32,
    pub attributed_to: Option<String>,
    pub elevated: bool,
}

pub async fn show_uac_events(_last_minutes: u32) -> anyhow::Result<()> {
    // TODO T007: Implement via Windows Event Log API
    // For now, use PowerShell as a bridge
    println!("UAC event tracking — implementation in progress (T007)");
    println!("Will monitor Security Event Log 4688 for elevation events");
    Ok(())
}

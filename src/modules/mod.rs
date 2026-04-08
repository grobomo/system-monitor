pub mod classifier;
pub mod claude_sessions;
pub mod cmd_diagnosis;
pub mod daemon;
pub mod disk_monitor;
pub mod focus_guard;
pub mod ioc_monitor;
pub mod process_monitor;
pub mod process_tree;
pub mod tray;
pub mod uac_tracker;
pub mod vpn_monitor;

/// Windows process creation flag — prevents spawning a visible console window.
/// Used by all modules that shell out to powershell/cmd.
pub const CREATE_NO_WINDOW: u32 = 0x08000000;

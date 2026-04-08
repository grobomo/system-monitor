//! Disk monitoring — re-exports from standalone sm-disk-monitor crate.
//!
//! This module delegates to the `sm_disk_monitor` crate, which can also
//! be installed standalone: `cargo install sm-disk-monitor`

pub use sm_disk_monitor::DiskReport;
pub use sm_disk_monitor::DriveInfo;

pub fn scan() -> DiskReport {
    sm_disk_monitor::scan()
}

pub fn show_disk_status() {
    sm_disk_monitor::show_disk_status()
}

pub fn check_disk_for_guard() -> Vec<DriveInfo> {
    sm_disk_monitor::check_disk_for_guard()
}

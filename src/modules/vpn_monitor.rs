//! VPN monitoring — re-exports from standalone sm-vpn-monitor crate.
//!
//! This module delegates to the `sm_vpn_monitor` crate, which can also
//! be installed standalone: `cargo install sm-vpn-monitor`

pub use sm_vpn_monitor::VpnStateChange;
pub use sm_vpn_monitor::VpnStatus;

pub fn check_vpn_status() -> Vec<VpnStatus> {
    sm_vpn_monitor::check_vpn_status()
}

pub fn poll_vpn_changes(last: &[VpnStatus]) -> (Vec<VpnStatus>, Vec<VpnStateChange>) {
    sm_vpn_monitor::poll_vpn_changes(last)
}

pub fn show_vpn_status() {
    sm_vpn_monitor::show_vpn_status()
}

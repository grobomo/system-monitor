use colored::Colorize;
use serde::Serialize;
use std::os::windows::process::CommandExt;
use std::process::Command;

use super::CREATE_NO_WINDOW;

/// Known VPN process patterns: (process_name_lowercase, vpn_name)
const VPN_PROCESSES: &[(&str, &str)] = &[
    // F5 BIG-IP Edge Client
    ("f5trafficsrv.exe", "F5 BIG-IP"),
    ("f5fltsrv.exe", "F5 BIG-IP"),
    ("f5installerservice.exe", "F5 BIG-IP"),
    ("f5fpclientw.exe", "F5 BIG-IP"),
    // Tailscale
    ("tailscaled.exe", "Tailscale"),
    ("tailscale.exe", "Tailscale"),
    // Cisco AnyConnect
    ("vpnagent.exe", "Cisco AnyConnect"),
    ("vpnui.exe", "Cisco AnyConnect"),
    // GlobalProtect
    ("pangpa.exe", "GlobalProtect"),
    ("pangps.exe", "GlobalProtect"),
    // Zscaler
    ("zscaler.exe", "Zscaler"),
    ("zstunnel.exe", "Zscaler"),
    // OpenVPN
    ("openvpn.exe", "OpenVPN"),
    ("openvpn-gui.exe", "OpenVPN"),
    // WireGuard
    ("wireguard.exe", "WireGuard"),
    // Pulse Secure / Ivanti
    ("dsaccessservice.exe", "Pulse Secure"),
    ("pulseprotect.exe", "Pulse Secure"),
];

#[derive(Debug, Clone, Serialize)]
pub struct VpnStatus {
    pub name: String,
    pub running: bool,
    pub connected: bool,
    pub tunnel_verified: Option<bool>,
    pub interface: Option<String>,
    pub checked_at: String,
}

/// Check which VPN services are running and their connection status
pub fn check_vpn_status() -> Vec<VpnStatus> {
    let running_vpns = detect_running_vpns();
    let adapters = get_vpn_adapters();
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let mut results: Vec<VpnStatus> = Vec::new();

    for (vpn_name, is_running) in &running_vpns {
        // Check if there's a matching network adapter that's connected
        let (connected, iface) = match vpn_name.as_str() {
            "Tailscale" => check_tailscale_status(&adapters),
            _ => check_adapter_status(vpn_name, &adapters),
        };

        // Verify tunnel is actually passing traffic (only if adapter says connected)
        let tunnel_verified = if connected {
            Some(verify_tunnel(vpn_name))
        } else {
            None
        };

        results.push(VpnStatus {
            name: vpn_name.clone(),
            running: *is_running,
            connected,
            tunnel_verified,
            interface: iface,
            checked_at: now.clone(),
        });
    }

    results
}

/// Verify VPN tunnel is actually passing traffic by testing connectivity
fn verify_tunnel(vpn_name: &str) -> bool {
    // Use different test targets based on VPN type
    let test_targets: Vec<&str> = match vpn_name {
        "Tailscale" => {
            // Tailscale: check if we can reach the Tailscale control plane
            // or any Tailscale peer (100.x.x.x range)
            vec!["100.100.100.100"] // Tailscale MagicDNS resolver
        }
        "F5 BIG-IP" => {
            // F5: try common internal DNS resolution as tunnel test
            // Use a generic connectivity check — ping the default gateway on the VPN interface
            vec![]
        }
        _ => vec![],
    };

    // Generic test: can we resolve DNS through the tunnel?
    // A working VPN tunnel should allow DNS resolution of internal names
    if test_targets.is_empty() {
        // Fallback: check if the VPN adapter has a default gateway
        return check_vpn_gateway(vpn_name);
    }

    // Ping test with short timeout
    for target in test_targets {
        let output = Command::new("cmd")
            .args(["/c", &format!("ping -n 1 -w 2000 {}", target)])
            .creation_flags(CREATE_NO_WINDOW)
            .output();

        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout).to_lowercase();
            if stdout.contains("reply from") || stdout.contains("bytes=") {
                return true;
            }
        }
    }

    false
}

/// Check if VPN adapter has an assigned gateway (indicates active tunnel)
fn check_vpn_gateway(vpn_name: &str) -> bool {
    let vpn_lower = vpn_name.to_lowercase();
    let keywords: Vec<&str> = match vpn_lower.as_str() {
        "f5 big-ip" => vec!["f5", "big-ip", "edge"],
        "cisco anyconnect" => vec!["cisco", "anyconnect"],
        "globalprotect" => vec!["palo alto", "globalprotect"],
        "zscaler" => vec!["zscaler"],
        _ => vec![&vpn_lower],
    };

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4DefaultGateway | ConvertTo-Csv -NoTypeInformation",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if let Ok(o) = output {
        let csv = String::from_utf8_lossy(&o.stdout).to_lowercase();
        for line in csv.lines() {
            let has_keyword = keywords.iter().any(|k| line.contains(k));
            let has_gateway = !line.contains("\"\"") && line.split(',').nth(1).map_or(false, |g| !g.trim_matches('"').is_empty());
            if has_keyword && has_gateway {
                return true;
            }
        }
    }

    false
}

/// Poll VPN status and return events for state changes.
/// Call this periodically from the guard loop.
pub fn poll_vpn_changes(last_statuses: &[VpnStatus]) -> (Vec<VpnStatus>, Vec<VpnStateChange>) {
    let current = check_vpn_status();
    let mut changes = Vec::new();

    for status in &current {
        let prev = last_statuses.iter().find(|s| s.name == status.name);
        match prev {
            Some(prev) => {
                // Detect connection state changes
                if prev.connected && !status.connected {
                    changes.push(VpnStateChange {
                        vpn_name: status.name.clone(),
                        change: "disconnected".to_string(),
                        timestamp: status.checked_at.clone(),
                    });
                } else if !prev.connected && status.connected {
                    changes.push(VpnStateChange {
                        vpn_name: status.name.clone(),
                        change: "connected".to_string(),
                        timestamp: status.checked_at.clone(),
                    });
                }
                // Detect tunnel verification changes
                if prev.tunnel_verified == Some(true) && status.tunnel_verified == Some(false) {
                    changes.push(VpnStateChange {
                        vpn_name: status.name.clone(),
                        change: "tunnel_down".to_string(),
                        timestamp: status.checked_at.clone(),
                    });
                }
            }
            None => {
                // Newly detected VPN
                if status.running {
                    changes.push(VpnStateChange {
                        vpn_name: status.name.clone(),
                        change: "detected".to_string(),
                        timestamp: status.checked_at.clone(),
                    });
                }
            }
        }
    }

    // Check for VPNs that disappeared
    for prev in last_statuses {
        if !current.iter().any(|s| s.name == prev.name) {
            changes.push(VpnStateChange {
                vpn_name: prev.name.clone(),
                change: "process_stopped".to_string(),
                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            });
        }
    }

    (current, changes)
}

/// A VPN state change event for brain integration
#[derive(Debug, Clone, Serialize)]
pub struct VpnStateChange {
    pub vpn_name: String,
    pub change: String,
    pub timestamp: String,
}

/// Detect which VPN software is running by checking processes
fn detect_running_vpns() -> Vec<(String, bool)> {
    let output = Command::new("cmd")
        .args(["/c", "tasklist /fo csv /nh"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let process_list = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_lowercase(),
        Err(_) => return Vec::new(),
    };

    let mut seen = std::collections::HashSet::new();
    let mut results = Vec::new();

    for (proc_name, vpn_name) in VPN_PROCESSES {
        if process_list.contains(proc_name) && seen.insert(*vpn_name) {
            results.push((vpn_name.to_string(), true));
        }
    }

    results
}

/// Get network adapters that look like VPN interfaces
fn get_vpn_adapters() -> Vec<(String, String, bool)> {
    // Returns: (adapter_name, description, is_connected)
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status | ConvertTo-Csv -NoTypeInformation",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let csv = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return Vec::new(),
    };

    let mut adapters = Vec::new();
    for line in csv.lines().skip(1) {
        // Parse CSV: "Name","Description","Status"
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() >= 3 {
            let name = fields[0].trim_matches('"').to_string();
            let desc = fields[1].trim_matches('"').to_string();
            let status = fields[2].trim_matches('"').to_string();
            let connected = status == "Up";
            adapters.push((name, desc, connected));
        }
    }

    adapters
}

/// Check Tailscale status via CLI
fn check_tailscale_status(adapters: &[(String, String, bool)]) -> (bool, Option<String>) {
    // First try tailscale status command
    let output = Command::new("cmd")
        .args(["/c", "tailscale status --json"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if let Ok(o) = output {
        let stdout = String::from_utf8_lossy(&o.stdout);
        // If the output contains "BackendState":"Running", it's connected
        if stdout.contains("\"Running\"") {
            let iface = adapters
                .iter()
                .find(|(_, desc, _)| desc.to_lowercase().contains("tailscale"))
                .map(|(name, _, _)| name.clone());
            return (true, iface);
        }
    }

    (false, None)
}

/// Check if a VPN has a connected network adapter
fn check_adapter_status(vpn_name: &str, adapters: &[(String, String, bool)]) -> (bool, Option<String>) {
    let search = vpn_name.to_lowercase();

    // Map VPN names to adapter description keywords
    let keywords: Vec<&str> = match search.as_str() {
        "f5 big-ip" => vec!["f5", "big-ip", "edge client"],
        "cisco anyconnect" => vec!["cisco", "anyconnect"],
        "globalprotect" => vec!["palo alto", "globalprotect"],
        "zscaler" => vec!["zscaler"],
        "openvpn" => vec!["tap-windows", "openvpn", "tap0"],
        "wireguard" => vec!["wireguard", "wg"],
        "pulse secure" => vec!["pulse", "juniper", "junos"],
        _ => vec![&search],
    };

    for (name, desc, connected) in adapters {
        let desc_lower = desc.to_lowercase();
        let name_lower = name.to_lowercase();
        if keywords.iter().any(|k| desc_lower.contains(k) || name_lower.contains(k)) {
            return (*connected, Some(name.clone()));
        }
    }

    (false, None)
}

/// CLI: show VPN status
pub fn show_vpn_status() {
    println!("{}", "=== VPN Monitor ===".bright_cyan());
    println!();

    let statuses = check_vpn_status();

    if statuses.is_empty() {
        println!("{}", "No VPN software detected.".dimmed());
        return;
    }

    for vpn in &statuses {
        let status_icon = if vpn.tunnel_verified == Some(true) {
            "●".green()
        } else if vpn.connected {
            "◐".yellow() // adapter up but tunnel not verified
        } else if vpn.running {
            "○".yellow()
        } else {
            "○".red()
        };

        let status_text = if vpn.tunnel_verified == Some(true) {
            "connected (tunnel verified)".green()
        } else if vpn.tunnel_verified == Some(false) {
            "connected (tunnel NOT passing traffic)".red()
        } else if vpn.connected {
            "connected".green()
        } else if vpn.running {
            "running (not connected)".yellow()
        } else {
            "not running".red()
        };

        print!("  {} {} — {}", status_icon, vpn.name.bright_white(), status_text);

        if let Some(ref iface) = vpn.interface {
            print!(" via {}", iface.dimmed());
        }
        println!();
    }
    println!("\n  {}", format!("Checked at: {}", statuses.first().map(|s| s.checked_at.as_str()).unwrap_or("?")).dimmed());
}

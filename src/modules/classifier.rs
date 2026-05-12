use crate::modules::process_tree::{ProcessInfo, ProcessSnapshot};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Classification {
    /// Known-safe: signed system binary from expected parent
    Safe,
    /// Attributed to a Claude Code session
    Claude(String),
    /// Not in known-good list, but not suspicious either
    Unknown,
    /// Matches suspicious patterns (level used by brain integration for severity routing)
    Suspicious(#[allow(dead_code)] SuspicionLevel, String),
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum SuspicionLevel {
    Low,
    Medium,
    High,
}

/// Known-safe Windows system processes
const SAFE_SYSTEM_PROCESSES: &[&str] = &[
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
    "dwm.exe", "explorer.exe", "taskhostw.exe", "runtimebroker.exe",
    "shellexperiencehost.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "textinputhost.exe", "sihost.exe", "ctfmon.exe", "fontdrvhost.exe",
    "dllhost.exe", "conhost.exe", "audiodg.exe", "spoolsv.exe",
    "wudfhost.exe", "dashost.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "msmpeng.exe", "nissrv.exe",
    "mpcmdrun.exe", "sgrmbroker.exe", "microsoftedgeupdate.exe",
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "widgetservice.exe", "widgets.exe", "phoneexperiencehost.exe",
    "gameinputsvc.exe", "backgroundtaskhost.exe", "applicationframehost.exe",
    "[system process]", "secure system", "memory compression",
    "shellhost.exe", "crossdeviceservice.exe", "crossdeviceresume.exe",
    "useroobbroker.exe", "smartscreen.exe", "filecoauth.exe",
    "appactions.exe",
];

/// Known enterprise/IT management software
const SAFE_ENTERPRISE: &[&str] = &[
    // VPN / network
    "f5trafficsrv.exe", "f5fltsrv.exe", "f5installerservice.exe",
    "tailscaled.exe",
    // Intel
    "igfxcuiservicen.exe", "igfxemn.exe", "intelaudioservice.exe",
    "jhi_service.exe", "lms.exe", "intelcphdcpsvc.exe",
    "intelgraphicssoftware.service.exe", "presentmonservice.exe",
    // Broadcom / wireless
    "bcmhoststorageservice.exe", "bcmhostcontrolservice.exe",
    "bcmushupgradeservice.exe", "wlanext.exe",
    // Enterprise management
    "azuremonitoragentservice.exe", "monagentlauncher.exe",
    "monagenthost.exe", "monagentmanager.exe", "monagentcore.exe",
    "cloudendpointservice.exe", "endpointbasecamp.exe",
    "inventoryservice.exe", "omadmclient.exe", "dsagent.exe",
    "microsoft.management.services.intunewindowsagent.exe",
    // Microsoft Office / enterprise
    "officeclicktorun.exe", "msoia.exe", "officec2rclient.exe",
    "pacjsworker.exe", "filesynchhelper.exe", "filesynchelper.exe",
    // WMI
    "wmiprvse.exe", "unsecapp.exe", "wmiregistrationservice.exe",
    // VS Build Tools
    "mspdbsrv.exe", "vctip.exe", "vs_setup_bootstrapper.exe",
    "setup.exe",
    // PowerToys
    "powertoys.exe",
    // Edge
    "msedgewebview2.exe", "msedge.exe",
    // Aggregator
    "aggregatorhost.exe",
    // Virtual memory / containers
    "vmmemczygote", "vmmemcmzygote", "vmcompute.exe", "wslservice.exe",
    // Endpoint security agent
    "ntrtscan.exe", "tmwscsvc.exe", "tmlisten.exe", "cntaosmgr.exe",
    "tmssclient.exe", "tmcoreframeworkhost.exe", "tmbmsrv.exe",
    "tmccsf.exe", "tm_netsrv.exe", "tmpfw.exe", "dsa-wrs-app.exe",
    // Realtek audio
    "rtkauduservice64.exe",
    // Waves audio
    "wavesaudioservice.exe", "wavessyssvc64.exe",
    // Thunderbolt
    "tbtp2pshortcutservice.exe",
    // Printer management
    "printerinstallerclientlauncher.exe", "printerinstallerclient.exe",
    // SurfaceThunder / SupportAssist
    "stdispatch.exe", "stdownloader.exe", "stagent.exe",
    "serviceshell.exe",
    // Zero-trust network agent
    "ztsamonitorservice.exe", "ztsawinservice.exe", "ztsawinengine.exe",
    // iVP / VPN
    "ivpagent.exe",
    // Adobe
    "armsvc.exe",
    // Windows misc
    "appidcertstorecheck.exe", "msiexec.exe", "ngciso.exe",
    "lsaiso.exe", "ssh-agent.exe", "esif_uf.exe",
    "tiworker.exe", "trustedinstaller.exe", "sppsvc.exe",
    // Self
    "system-monitor.exe",
    // User apps
    "greenshot.exe", "flux.exe",
];

/// Known development tools
const SAFE_DEV_TOOLS: &[&str] = &[
    "node.exe", "npm.cmd", "npx.cmd", "git.exe", "ssh.exe",
    "code.exe", "code-insiders.exe", "windowsterminal.exe",
    "powershell.exe", "pwsh.exe", "bash.exe", "wsl.exe",
    "python.exe", "python3.exe", "pythonw.exe", "pip.exe",
    "cargo.exe", "rustc.exe", "rustup.exe",
    "notepad++.exe", "notepad.exe",
    "cmd.exe", "rundll32.exe",
];

/// Suspicious patterns in command lines
const SUSPICIOUS_PATTERNS: &[(&str, &str, SuspicionLevel)] = &[
    // Encoded commands
    ("-encodedcommand", "encoded PowerShell command", SuspicionLevel::High),
    ("-enc ", "encoded PowerShell command", SuspicionLevel::High),
    ("frombase64string", "base64 decoding in command", SuspicionLevel::High),
    // LOLBins abuse
    ("certutil -urlcache", "certutil download (LOLBin)", SuspicionLevel::High),
    ("bitsadmin /transfer", "bitsadmin download (LOLBin)", SuspicionLevel::Medium),
    ("mshta ", "mshta execution (LOLBin)", SuspicionLevel::High),
    ("regsvr32 /s /n /u /i:", "regsvr32 proxy execution", SuspicionLevel::High),
    ("rundll32 javascript:", "rundll32 script execution", SuspicionLevel::High),
    // Recon
    ("net user /domain", "domain user enumeration", SuspicionLevel::Medium),
    ("net group /domain", "domain group enumeration", SuspicionLevel::Medium),
    ("nltest /dclist", "domain controller enumeration", SuspicionLevel::Medium),
    ("whoami /priv", "privilege enumeration", SuspicionLevel::Low),
    // Persistence
    ("schtasks /create", "scheduled task creation", SuspicionLevel::Medium),
    ("reg add.*\\run ", "registry run key modification", SuspicionLevel::High),
    // Data exfil
    ("invoke-webrequest", "web request from PowerShell", SuspicionLevel::Low),
    ("downloadstring", "download string (possible dropper)", SuspicionLevel::High),
    ("invoke-expression", "invoke-expression (code execution)", SuspicionLevel::Medium),
    ("iex(", "iex shorthand (code execution)", SuspicionLevel::High),
];

pub fn classify_process(proc: &ProcessInfo, snapshot: &ProcessSnapshot) -> Classification {
    let name_lower = proc.name.to_lowercase();

    // Check Claude attribution first
    if let Some(session) = snapshot.claude_attribution(proc.pid) {
        // Even Claude-attributed processes can be suspicious
        if let Some(ref cmd) = proc.command_line {
            if let Some(suspicion) = check_suspicious_command(cmd) {
                return suspicion;
            }
        }
        return Classification::Claude(session);
    }

    // Check command line for suspicious patterns
    if let Some(ref cmd) = proc.command_line {
        if let Some(suspicion) = check_suspicious_command(cmd) {
            return suspicion;
        }
    }

    // Known system processes
    if SAFE_SYSTEM_PROCESSES.contains(&name_lower.as_str()) {
        return Classification::Safe;
    }

    // Known enterprise software
    if SAFE_ENTERPRISE.contains(&name_lower.as_str()) {
        return Classification::Safe;
    }

    // PowerToys subprocesses (PowerToys.*.exe pattern)
    if name_lower.starts_with("powertoys.") && name_lower.ends_with(".exe") {
        return Classification::Safe;
    }

    // Known dev tools
    if SAFE_DEV_TOOLS.contains(&name_lower.as_str()) {
        return Classification::Safe;
    }

    // Check if exe is in standard system directories
    if let Some(ref path) = proc.exe_path {
        let path_lower = path.to_lowercase();
        if path_lower.starts_with("c:\\windows\\")
            || path_lower.starts_with("c:\\program files\\")
            || path_lower.starts_with("c:\\program files (x86)\\")
        {
            return Classification::Safe;
        }
    }

    Classification::Unknown
}

fn check_suspicious_command(cmd: &str) -> Option<Classification> {
    let cmd_lower = cmd.to_lowercase();
    for (pattern, reason, level) in SUSPICIOUS_PATTERNS {
        if cmd_lower.contains(&pattern.to_lowercase()) {
            return Some(Classification::Suspicious(
                *level,
                reason.to_string(),
            ));
        }
    }
    None
}

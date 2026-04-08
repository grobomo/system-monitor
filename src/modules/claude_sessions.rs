use crate::modules::CREATE_NO_WINDOW;
use colored::Colorize;
use serde::Serialize;
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::process::Command;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::*;

#[derive(Debug, Clone, Serialize)]
pub struct ClaudeSession {
    pub pid: u32,
    pub parent_pid: u32,
    pub project_dir: Option<String>,
    pub command_line: Option<String>,
    pub is_headless: bool, // -p flag (non-interactive)
}

#[derive(Debug, Clone, Serialize)]
pub struct CollisionGroup {
    pub project_dir: String,
    pub sessions: Vec<ClaudeSession>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionReport {
    pub collisions: Vec<CollisionGroup>,
    pub safe: Vec<ClaudeSession>,
    pub headless: Vec<ClaudeSession>,
    pub unknown: Vec<ClaudeSession>, // couldn't determine project dir
}

/// Discover all active Claude Code sessions and detect collisions.
pub fn detect_sessions() -> SessionReport {
    let mut sessions = Vec::new();

    // Step 1: Get all claude.exe processes with command lines from WMI
    let wmi_data = fetch_claude_processes_wmi();

    // Step 2: For each claude.exe, try to get its CWD via PEB reading
    for (pid, ppid, cmd) in &wmi_data {
        let is_headless = cmd
            .as_ref()
            .map(|c| c.contains(" -p ") || c.ends_with(" -p") || c.contains(" -p\t"))
            .unwrap_or(false);

        let project_dir = get_process_cwd(*pid).map(|d| normalize_path(&d));

        sessions.push(ClaudeSession {
            pid: *pid,
            parent_pid: *ppid,
            project_dir,
            command_line: cmd.clone(),
            is_headless,
        });
    }

    // Step 3: Group interactive sessions by project directory
    let mut by_dir: HashMap<String, Vec<ClaudeSession>> = HashMap::new();
    let mut headless = Vec::new();
    let mut unknown = Vec::new();

    for session in sessions {
        if session.is_headless {
            headless.push(session);
        } else if let Some(ref dir) = session.project_dir {
            by_dir.entry(dir.clone()).or_default().push(session);
        } else {
            unknown.push(session);
        }
    }

    let mut collisions = Vec::new();
    let mut safe = Vec::new();

    for (dir, group) in by_dir {
        if group.len() >= 2 {
            collisions.push(CollisionGroup {
                project_dir: dir,
                sessions: group,
            });
        } else {
            safe.extend(group);
        }
    }

    SessionReport {
        collisions,
        safe,
        headless,
        unknown,
    }
}

/// Display Claude sessions with collision warnings.
pub fn show_sessions() {
    let report = detect_sessions();

    let total = report.collisions.iter().map(|c| c.sessions.len()).sum::<usize>()
        + report.safe.len()
        + report.headless.len()
        + report.unknown.len();

    println!(
        "{}",
        format!("=== Claude Code Sessions ({} total) ===", total).bold()
    );
    println!();

    // Collisions first (danger)
    if !report.collisions.is_empty() {
        println!(
            "{}",
            format!(
                "COLLISIONS DETECTED ({} project dirs with multiple sessions)",
                report.collisions.len()
            )
            .red()
            .bold()
        );
        for group in &report.collisions {
            println!(
                "  {} {} ({} sessions)",
                "COLLISION".red().bold(),
                group.project_dir.yellow(),
                group.sessions.len()
            );
            for s in &group.sessions {
                println!(
                    "    PID {} (parent {})",
                    s.pid.to_string().white(),
                    s.parent_pid
                );
            }
        }
        println!();
    } else {
        println!("{}", "No collisions detected".green());
        println!();
    }

    // Safe sessions
    if !report.safe.is_empty() {
        println!("{}", "Active sessions:".bold());
        for s in &report.safe {
            let dir = s.project_dir.as_deref().unwrap_or("(unknown)");
            println!(
                "  {} PID {} -> {}",
                "OK".green(),
                s.pid.to_string().white(),
                dir.cyan()
            );
        }
        println!();
    }

    // Headless
    if !report.headless.is_empty() {
        println!(
            "{}",
            format!("Headless (-p) sessions: {}", report.headless.len()).dimmed()
        );
        for s in &report.headless {
            let dir = s.project_dir.as_deref().unwrap_or("(unknown)");
            println!(
                "  {} PID {} -> {}",
                "API".dimmed(),
                s.pid.to_string().dimmed(),
                dir.dimmed()
            );
        }
        println!();
    }

    // Unknown
    if !report.unknown.is_empty() {
        println!(
            "{}",
            format!(
                "Sessions with unknown project dir: {}",
                report.unknown.len()
            )
            .yellow()
        );
        for s in &report.unknown {
            println!(
                "  {} PID {} (parent {})",
                "?".yellow(),
                s.pid,
                s.parent_pid
            );
        }
    }
}

// ─── Process discovery ────────────────────────────────────────────────

/// Get all claude.exe processes via WMI (returns PID, ParentPID, CommandLine).
fn fetch_claude_processes_wmi() -> Vec<(u32, u32, Option<String>)> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'claude.exe' } | Select-Object ProcessId, ParentProcessId, CommandLine | ConvertTo-Json -Compress",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let mut results = Vec::new();
    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Could be a single object or an array
            if let Ok(entries) = serde_json::from_str::<Vec<WmiClaudeEntry>>(&stdout) {
                for e in entries {
                    results.push((e.process_id, e.parent_process_id, e.command_line));
                }
            } else if let Ok(entry) = serde_json::from_str::<WmiClaudeEntry>(&stdout) {
                results.push((
                    entry.process_id,
                    entry.parent_process_id,
                    entry.command_line,
                ));
            }
        }
    }
    results
}

#[derive(serde::Deserialize)]
struct WmiClaudeEntry {
    #[serde(rename = "ProcessId")]
    process_id: u32,
    #[serde(rename = "ParentProcessId")]
    parent_process_id: u32,
    #[serde(rename = "CommandLine")]
    command_line: Option<String>,
}

// ─── PEB reading for CWD ─────────────────────────────────────────────

/// Read the current working directory of a process by reading its PEB.
/// Returns None if we can't access the process or read its memory.
fn get_process_cwd(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
        .ok()?;

        let result = read_cwd_from_peb(handle);
        let _ = CloseHandle(handle);
        result
    }
}

/// NtQueryInformationProcess function type (not in windows crate directly).
#[allow(non_snake_case)]
type FnNtQueryInformationProcess = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    ProcessInformationClass: u32,
    ProcessInformation: *mut std::ffi::c_void,
    ProcessInformationLength: u32,
    ReturnLength: *mut u32,
) -> i32; // NTSTATUS

const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;

#[repr(C)]
struct ProcessBasicInformation {
    reserved1: usize,
    peb_base_address: usize,
    reserved2: [usize; 2],
    unique_process_id: usize,
    reserved3: usize,
}

/// Read CWD from a process's PEB via NtQueryInformationProcess + ReadProcessMemory.
unsafe fn read_cwd_from_peb(handle: HANDLE) -> Option<String> {
    // Load NtQueryInformationProcess from ntdll.dll
    let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleA(
        windows::core::s!("ntdll.dll"),
    )
    .ok()?;

    let proc_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
        ntdll,
        windows::core::s!("NtQueryInformationProcess"),
    )?;

    let nt_query: FnNtQueryInformationProcess = std::mem::transmute(proc_addr);

    // Step 1: Get PEB address
    let mut pbi = std::mem::zeroed::<ProcessBasicInformation>();
    let status = nt_query(
        handle,
        PROCESS_BASIC_INFORMATION_CLASS,
        &mut pbi as *mut _ as *mut std::ffi::c_void,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        std::ptr::null_mut(),
    );
    if status != 0 {
        return None;
    }

    let peb_addr = pbi.peb_base_address;
    if peb_addr == 0 {
        return None;
    }

    // Step 2: Read ProcessParameters pointer from PEB
    // PEB layout on x64: offset 0x20 is RTL_USER_PROCESS_PARAMETERS*
    let params_ptr_offset = 0x20usize;
    let mut params_ptr: usize = 0;
    if ReadProcessMemory(
        handle,
        (peb_addr + params_ptr_offset) as *const std::ffi::c_void,
        &mut params_ptr as *mut _ as *mut std::ffi::c_void,
        std::mem::size_of::<usize>(),
        None,
    )
    .is_err()
        || params_ptr == 0
    {
        return None;
    }

    // Step 3: Read CurrentDirectory from RTL_USER_PROCESS_PARAMETERS
    // CurrentDirectory is a CURDIR at offset 0x38 (x64)
    // CURDIR = { UNICODE_STRING DosPath; HANDLE Handle; }
    // UNICODE_STRING = { USHORT Length; USHORT MaximumLength; <4 bytes padding on x64>; PWSTR Buffer; }
    let curdir_offset = 0x38usize;

    // Read UNICODE_STRING Length (2 bytes)
    let mut length: u16 = 0;
    if ReadProcessMemory(
        handle,
        (params_ptr + curdir_offset) as *const std::ffi::c_void,
        &mut length as *mut _ as *mut std::ffi::c_void,
        2,
        None,
    )
    .is_err()
    {
        return None;
    }

    // Read Buffer pointer (8 bytes at offset +8 on x64: 2+2+4 padding)
    let mut buffer_ptr: usize = 0;
    if ReadProcessMemory(
        handle,
        (params_ptr + curdir_offset + 8) as *const std::ffi::c_void,
        &mut buffer_ptr as *mut _ as *mut std::ffi::c_void,
        std::mem::size_of::<usize>(),
        None,
    )
    .is_err()
    {
        return None;
    }

    if buffer_ptr == 0 || length == 0 {
        return None;
    }

    // Step 4: Read the actual directory string (UTF-16)
    let char_count = (length as usize) / 2;
    let mut buf = vec![0u16; char_count];
    if ReadProcessMemory(
        handle,
        buffer_ptr as *const std::ffi::c_void,
        buf.as_mut_ptr() as *mut std::ffi::c_void,
        length as usize,
        None,
    )
    .is_err()
    {
        return None;
    }

    let path = String::from_utf16_lossy(&buf);
    // Remove trailing backslash if present
    let path = path.trim_end_matches('\\').to_string();
    Some(path)
}

/// Normalize a Windows path for consistent comparison.
fn normalize_path(path: &str) -> String {
    let mut p = path.replace('/', "\\");
    // Lowercase the drive letter for consistent grouping
    if p.len() >= 2 && p.as_bytes()[1] == b':' {
        let mut chars: Vec<char> = p.chars().collect();
        chars[0] = chars[0].to_lowercase().next().unwrap_or(chars[0]);
        p = chars.into_iter().collect();
    }
    p.trim_end_matches('\\').to_string()
}

// ─── Guard integration ────────────────────────────────────────────────

/// Check for collisions and emit brain events. Called from guard loop.
pub fn check_collisions_for_guard() -> Vec<CollisionGroup> {
    let report = detect_sessions();
    report.collisions
}

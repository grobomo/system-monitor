use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::process::Command;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::*;

use super::CREATE_NO_WINDOW;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub creation_time: Option<String>,
    pub is_signed: Option<bool>,
}

impl ProcessInfo {
    pub fn exe_name(&self) -> &str {
        &self.name
    }
}

pub struct ProcessSnapshot {
    processes: HashMap<u32, ProcessInfo>,
    children: HashMap<u32, Vec<u32>>,
}

impl ProcessSnapshot {
    pub fn capture() -> anyhow::Result<Self> {
        let mut processes = HashMap::new();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(
                        &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())]
                    );
                    let pid = entry.th32ProcessID;
                    let ppid = entry.th32ParentProcessID;

                    // Try to get full exe path and command line
                    let (exe_path, command_line) = get_process_details(pid);

                    let info = ProcessInfo {
                        pid,
                        ppid,
                        name,
                        exe_path,
                        command_line,
                        creation_time: None, // TODO: get from process handle
                        is_signed: None,     // TODO: check digital signature
                    };

                    children.entry(ppid).or_default().push(pid);
                    processes.insert(pid, info);

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        // Enrich with command lines from WMI (catches elevated processes)
        let cmd_lines = fetch_command_lines_wmi();
        for (pid, info) in processes.iter_mut() {
            if info.command_line.is_none() {
                if let Some(cmd) = cmd_lines.get(pid) {
                    info.command_line = Some(cmd.clone());
                }
            }
        }

        Ok(Self { processes, children })
    }

    pub fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.processes.get(&pid)
    }

    pub fn all_processes(&self) -> impl Iterator<Item = &ProcessInfo> {
        self.processes.values()
    }

    pub fn children_of(&self, pid: u32) -> Vec<u32> {
        self.children.get(&pid).cloned().unwrap_or_default()
    }

    pub fn roots(&self) -> Vec<u32> {
        // Processes whose parent doesn't exist in the snapshot, or PID 0/4 (System)
        self.processes
            .values()
            .filter(|p| {
                p.pid == 0
                    || p.pid == 4
                    || !self.processes.contains_key(&p.ppid)
                    || p.ppid == p.pid
            })
            .map(|p| p.pid)
            .collect()
    }

    pub fn parent_chain(&self, pid: u32) -> Vec<&ProcessInfo> {
        let mut chain = Vec::new();
        let mut current = pid;
        let mut visited = std::collections::HashSet::new();

        loop {
            if visited.contains(&current) {
                break; // cycle guard
            }
            visited.insert(current);

            if let Some(proc) = self.processes.get(&current) {
                chain.push(proc);
                if proc.ppid == 0 || proc.ppid == proc.pid {
                    break;
                }
                current = proc.ppid;
            } else {
                break;
            }
        }

        chain
    }

    /// Find if this PID is under a Claude Code process tree
    pub fn claude_attribution(&self, pid: u32) -> Option<String> {
        let chain = self.parent_chain(pid);
        for proc in &chain {
            let name_lower = proc.name.to_lowercase();
            if name_lower.contains("claude") || name_lower == "claude.exe" {
                return Some(format!("claude-pid-{}", proc.pid));
            }
            // Claude Code runs as node.exe with claude in the path
            if name_lower == "node.exe" {
                if let Some(ref cmd) = proc.command_line {
                    if cmd.to_lowercase().contains("claude") {
                        return Some(format!("claude-pid-{}", proc.pid));
                    }
                }
            }
        }
        None
    }
}

unsafe fn get_process_details(pid: u32) -> (Option<String>, Option<String>) {
    let mut exe_path = None;
    let command_line = None;

    // Try to open process for query
    if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
        // Get exe path
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        let pwstr = windows::core::PWSTR(buf.as_mut_ptr());
        if QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, pwstr, &mut size).is_ok() {
            exe_path = Some(String::from_utf16_lossy(&buf[..size as usize]));
        }
        let _ = CloseHandle(handle);
    }

    (exe_path, command_line)
}

/// Bulk-fetch command lines for all processes via WMI (PowerShell).
/// This is more reliable than per-process OpenProcess since WMI can read
/// command lines for elevated processes that we can't open directly.
fn fetch_command_lines_wmi() -> HashMap<u32, String> {
    let mut map = HashMap::new();

    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-WindowStyle", "Hidden",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            "Get-CimInstance Win32_Process | Select-Object ProcessId, CommandLine | ConvertTo-Json -Compress",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Parse JSON array of {ProcessId, CommandLine}
            if let Ok(entries) = serde_json::from_str::<Vec<WmiProcessEntry>>(&stdout) {
                for entry in entries {
                    if let Some(cmd) = entry.command_line {
                        if !cmd.is_empty() {
                            map.insert(entry.process_id, cmd);
                        }
                    }
                }
            }
        }
    }

    map
}

#[derive(Deserialize)]
struct WmiProcessEntry {
    #[serde(rename = "ProcessId")]
    process_id: u32,
    #[serde(rename = "CommandLine")]
    command_line: Option<String>,
}

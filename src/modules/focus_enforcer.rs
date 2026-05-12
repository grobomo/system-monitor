//! Active focus-steal prevention.
//!
//! Three-layer defense:
//! 1. Registry: ForegroundLockTimeout set to MAX
//! 2. Event hooks: SetWinEventHook for real-time interception (CREATE + SHOW + FOREGROUND)
//! 3. Polling backup: hides visible console windows from transient processes
//!
//! Key insight: EVENT_OBJECT_CREATE fires BEFORE the window renders,
//! giving us a chance to hide it before the user sees it.

use colored::Colorize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
use windows::Win32::UI::Accessibility::*;
use windows::Win32::UI::WindowsAndMessaging::*;

/// Process names that spawn transient windows (parent chain)
const TRANSIENT_PARENTS: &[&str] = &[
    "claude.exe",
    "node.exe",
    "wscript.exe",
    "cscript.exe",
    "terraform.exe",
    "terraform-provider-azurerm",
    "python.exe",
    "pythonw.exe",
    "go.exe",
];

/// Process names whose windows we intercept
const INTERCEPT_TARGETS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "conhost.exe",
    "bash.exe",
    "openconsole.exe",
];

static HIDDEN_COUNT: AtomicUsize = AtomicUsize::new(0);
static RESTORED_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_GOOD_HWND: AtomicIsize = AtomicIsize::new(0);

/// Run the focus enforcer standalone.
pub fn run_enforcer() -> anyhow::Result<()> {
    println!("{}", "=== Focus Steal Shield ===".bold().green());
    println!("Intercepting transient CMD/bash/PS windows in real-time");
    println!("Press Ctrl+C to stop\n");

    install_event_hooks();
    set_foreground_lock_timeout(0xFFFFFFFF);

    let mut known_hidden: HashSet<isize> = HashSet::new();
    let mut stats_interval = Instant::now();

    ctrlc::set_handler(move || {
        set_foreground_lock_timeout(200000);
        println!("\n{}", "  Foreground lock timeout restored. Exiting.".yellow());
        std::process::exit(0);
    })
    .ok();

    loop {
        // Pump messages — CRITICAL: hooks only fire if we pump
        pump_messages();

        // Backup polling
        let hidden = enforce_once(&mut known_hidden);
        if hidden > 0 {
            let total = HIDDEN_COUNT.load(Ordering::Relaxed);
            println!(
                "  {} hid {} window(s) ({} total)",
                "HIDE".yellow().bold(),
                hidden,
                total
            );
        }

        if stats_interval.elapsed() > Duration::from_secs(30) {
            stats_interval = Instant::now();
            let restored = RESTORED_COUNT.load(Ordering::Relaxed);
            let hidden_total = HIDDEN_COUNT.load(Ordering::Relaxed);
            known_hidden.retain(|h| unsafe { IsWindow(HWND(*h as *mut _)).as_bool() });
            println!(
                "  {} focus restored: {}, windows hidden: {}, tracked: {}",
                "STATS".cyan(),
                restored,
                hidden_total,
                known_hidden.len()
            );
        }

        // Tight loop — 50ms for faster interception
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Restore default ForegroundLockTimeout and exit.
pub fn restore_defaults() {
    set_foreground_lock_timeout(200000);
    println!(
        "{}",
        "Foreground lock timeout restored to default (200000ms)".green()
    );
}

/// Install event hooks for window interception.
fn install_event_hooks() {
    unsafe {
        let fg = GetForegroundWindow();
        if !fg.0.is_null() {
            LAST_GOOD_HWND.store(fg.0 as isize, Ordering::SeqCst);
        }

        // EVENT_OBJECT_CREATE: fires BEFORE window is shown — earliest interception point
        let _hook_create = SetWinEventHook(
            EVENT_OBJECT_CREATE,
            EVENT_OBJECT_CREATE,
            None,
            Some(create_callback),
            0,
            0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        );

        // EVENT_OBJECT_SHOW: fires when window becomes visible
        let _hook_show = SetWinEventHook(
            EVENT_OBJECT_SHOW,
            EVENT_OBJECT_SHOW,
            None,
            Some(show_callback),
            0,
            0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        );

        // EVENT_SYSTEM_FOREGROUND: fires when window takes focus
        let _hook_fg = SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            None,
            Some(foreground_callback),
            0,
            0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        );
    }

    println!("{}", "  Event hooks installed (CREATE + SHOW + FOREGROUND)".green());
}

/// Fires when ANY window is created — hide transient console windows immediately.
unsafe extern "system" fn create_callback(
    _hook: HWINEVENTHOOK,
    _event: u32,
    hwnd: HWND,
    id_object: i32,
    _id_child: i32,
    _id_event_thread: u32,
    _dwms_event_time: u32,
) {
    // Only handle OBJID_WINDOW (0) — not child objects
    if hwnd.0.is_null() || id_object != 0 {
        return;
    }

    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid == 0 || pid == std::process::id() {
        return;
    }

    if is_transient_stealer(pid) {
        // Hide immediately — before it renders
        let _ = ShowWindow(hwnd, SW_HIDE);
        HIDDEN_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Fires when a window becomes visible.
unsafe extern "system" fn show_callback(
    _hook: HWINEVENTHOOK,
    _event: u32,
    hwnd: HWND,
    id_object: i32,
    _id_child: i32,
    _id_event_thread: u32,
    _dwms_event_time: u32,
) {
    if hwnd.0.is_null() || id_object != 0 {
        return;
    }

    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid == 0 || pid == std::process::id() {
        return;
    }

    if is_transient_stealer(pid) {
        let _ = ShowWindow(hwnd, SW_HIDE);
        HIDDEN_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Fires when a window takes foreground — restore focus if stolen.
unsafe extern "system" fn foreground_callback(
    _hook: HWINEVENTHOOK,
    _event: u32,
    hwnd: HWND,
    _id_object: i32,
    _id_child: i32,
    _id_event_thread: u32,
    _dwms_event_time: u32,
) {
    if hwnd.0.is_null() {
        return;
    }

    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid == 0 || pid == std::process::id() {
        return;
    }

    if is_transient_stealer(pid) {
        let _ = ShowWindow(hwnd, SW_HIDE);
        HIDDEN_COUNT.fetch_add(1, Ordering::Relaxed);

        let last_good = LAST_GOOD_HWND.load(Ordering::SeqCst);
        if last_good != 0 {
            let restore = HWND(last_good as *mut _);
            if IsWindow(restore).as_bool() {
                let _ = SetForegroundWindow(restore);
                RESTORED_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
    } else {
        LAST_GOOD_HWND.store(hwnd.0 as isize, Ordering::SeqCst);
    }
}

/// Check if a PID is a transient CMD/bash/PS spawned by Claude/node/terraform.
fn is_transient_stealer(pid: u32) -> bool {
    let (proc_name, ppid) = match get_process_info(pid) {
        Some(info) => info,
        None => return false,
    };

    let proc_lower = proc_name.to_lowercase();

    if !INTERCEPT_TARGETS.iter().any(|t| proc_lower == *t) {
        return false;
    }

    let mut current_pid = ppid;
    let mut visited = HashSet::new();
    visited.insert(pid);

    for _ in 0..10 {
        if current_pid == 0 || visited.contains(&current_pid) {
            break;
        }
        visited.insert(current_pid);

        if let Some((parent_name, grandparent_pid)) = get_process_info(current_pid) {
            let parent_lower = parent_name.to_lowercase();

            if is_terminal_emulator(&parent_lower) {
                return false;
            }

            if TRANSIENT_PARENTS
                .iter()
                .any(|t| parent_lower == *t || parent_lower.starts_with(t))
            {
                return true;
            }

            current_pid = grandparent_pid;
        } else {
            break;
        }
    }

    false
}

fn is_terminal_emulator(name: &str) -> bool {
    matches!(
        name,
        "windowsterminal.exe"
            | "wt.exe"
            | "alacritty.exe"
            | "hyper.exe"
            | "terminus.exe"
            | "mintty.exe"
            | "conemu64.exe"
            | "conemu.exe"
            | "cmder.exe"
            | "wezterm-gui.exe"
            | "explorer.exe"
    )
}

fn pump_messages() {
    unsafe {
        let mut msg = std::mem::zeroed::<MSG>();
        while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

/// Polling backup — hide visible console windows from transient processes.
pub fn enforce_once(known_hidden: &mut HashSet<isize>) -> usize {
    let mut hidden_this_cycle = 0;

    unsafe {
        let mut results: Vec<(isize, u32)> = Vec::new();
        let _ = EnumWindows(
            Some(enum_callback),
            LPARAM(&mut results as *mut _ as isize),
        );

        for (hwnd_val, pid) in &results {
            if known_hidden.contains(hwnd_val) {
                continue;
            }
            if is_transient_stealer(*pid) {
                let _ = ShowWindow(HWND(*hwnd_val as *mut _), SW_HIDE);
                known_hidden.insert(*hwnd_val);
                hidden_this_cycle += 1;
                HIDDEN_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    if known_hidden.len() > 100 {
        known_hidden.retain(|h| unsafe { IsWindow(HWND(*h as *mut _)).as_bool() });
    }

    hidden_this_cycle
}

unsafe extern "system" fn enum_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let results = &mut *(lparam.0 as *mut Vec<(isize, u32)>);

    if !IsWindowVisible(hwnd).as_bool() {
        return BOOL(1);
    }

    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid == 0 {
        return BOOL(1);
    }

    results.push((hwnd.0 as isize, pid));
    BOOL(1)
}

/// Set ForegroundLockTimeout via registry.
fn set_foreground_lock_timeout(timeout_ms: u32) {
    use std::os::windows::process::CommandExt;

    let cmd = format!(
        "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name ForegroundLockTimeout -Value {}",
        timeout_ms
    );
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &cmd])
        .creation_flags(super::CREATE_NO_WINDOW)
        .output();

    match output {
        Ok(o) if o.status.success() => {
            if timeout_ms == 0xFFFFFFFF {
                println!(
                    "{}",
                    "  Foreground lock timeout set to MAX".green().bold()
                );
                println!(
                    "{}",
                    "  (Alt+Tab / clicking still works normally)".dimmed()
                );
            }
        }
        _ => {
            println!(
                "{}",
                "  Warning: could not set ForegroundLockTimeout".yellow()
            );
        }
    }

    unsafe {
        let _ = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            windows::Win32::Foundation::WPARAM(0),
            windows::Win32::Foundation::LPARAM(0),
            SMTO_ABORTIFHUNG,
            1000,
            None,
        );
    }
}

fn get_process_info(pid: u32) -> Option<(String, u32)> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    let name = String::from_utf16_lossy(
                        &entry.szExeFile[..entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len())],
                    );
                    let _ = windows::Win32::Foundation::CloseHandle(snapshot);
                    return Some((name, entry.th32ParentProcessID));
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
    }

    None
}

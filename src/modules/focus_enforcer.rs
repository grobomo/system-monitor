//! Active focus-steal prevention.
//!
//! Two-pronged approach:
//! 1. SetWinEventHook: intercepts FOREGROUND events and restores focus if stolen
//!    by a transient CMD/bash/PS process from Claude Code
//! 2. Backup polling: hides visible console windows owned by transient processes

use colored::Colorize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
use windows::Win32::UI::Accessibility::*;
use windows::Win32::UI::WindowsAndMessaging::*;

/// Process names that spawn transient windows (the parent chain)
const TRANSIENT_PARENTS: &[&str] = &[
    "claude.exe",
    "node.exe",
    "wscript.exe",
    "cscript.exe",
    "terraform.exe",
    "terraform-provider-azurerm", // prefix match — version suffix varies
    "python.exe",
    "pythonw.exe",
    "go.exe",
];

/// Process names whose focus-stealing we intercept
const INTERCEPT_TARGETS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "conhost.exe",
    "bash.exe",
    "openconsole.exe",
];

/// Window class names for console windows
const CONSOLE_CLASSES: &[&str] = &[
    "ConsoleWindowClass",
    "CASCADIA_HOSTING_WINDOW_CLASS",
    "PseudoConsoleWindow",
    "mintty",
];

static RESTORED_COUNT: AtomicUsize = AtomicUsize::new(0);
static HIDDEN_COUNT: AtomicUsize = AtomicUsize::new(0);
/// The HWND that had focus before a steal — we restore focus here
static LAST_GOOD_HWND: AtomicIsize = AtomicIsize::new(0);

/// Run the focus enforcer standalone.
pub fn run_enforcer() -> anyhow::Result<()> {
    println!("{}", "=== Focus Steal Shield ===".bold().green());
    println!("Protecting against focus theft by transient CMD/bash/PS windows");
    println!("Strategy: intercept focus changes + hide transient console windows");
    println!("Press Ctrl+C to stop\n");

    install_event_hooks();

    // Set ForegroundLockTimeout via registry — prevents background windows from stealing focus
    // They'll flash in the taskbar instead. User can still Alt+Tab / click normally.
    set_foreground_lock_timeout(0xFFFFFFFF);

    let mut known_hidden: HashSet<isize> = HashSet::new();
    let mut stats_interval = Instant::now();

    // Set up Ctrl+C handler to restore default timeout on exit
    ctrlc::set_handler(move || {
        set_foreground_lock_timeout(200000); // restore default
        println!("\n{}", "  Foreground lock timeout restored to default. Exiting.".yellow());
        std::process::exit(0);
    })
    .ok();

    loop {
        pump_messages();

        // Backup: hide any visible transient console windows
        let hidden = enforce_once(&mut known_hidden);
        if hidden > 0 {
            let total = HIDDEN_COUNT.load(Ordering::Relaxed);
            println!(
                "  {} hid {} window(s) ({} total hidden)",
                "HIDE".yellow().bold(),
                hidden,
                total
            );
        }

        if stats_interval.elapsed() > Duration::from_secs(30) {
            stats_interval = Instant::now();
            let restored = RESTORED_COUNT.load(Ordering::Relaxed);
            let hidden_total = HIDDEN_COUNT.load(Ordering::Relaxed);
            known_hidden.retain(|h| {
                let hwnd = HWND(*h as *mut _);
                unsafe { IsWindow(hwnd).as_bool() }
            });
            println!(
                "  {} focus restored: {}, windows hidden: {}, handles tracked: {}",
                "STATS".cyan(),
                restored,
                hidden_total,
                known_hidden.len()
            );
        }

        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Restore default ForegroundLockTimeout and exit.
pub fn restore_defaults() {
    set_foreground_lock_timeout(200000);
    println!("{}", "Foreground lock timeout restored to default (200000ms)".green());
}

/// Install event hooks for real-time focus-steal interception.
fn install_event_hooks() {
    unsafe {
        // Track the current foreground window as "last good"
        let fg = GetForegroundWindow();
        if !fg.0.is_null() {
            LAST_GOOD_HWND.store(fg.0 as isize, Ordering::SeqCst);
        }

        // Hook foreground changes — fires when any window takes focus
        let _hook = SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            None,
            Some(foreground_callback),
            0,
            0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        );

        // Hook window show events
        let _hook2 = SetWinEventHook(
            EVENT_OBJECT_SHOW,
            EVENT_OBJECT_SHOW,
            None,
            Some(show_callback),
            0,
            0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        );
    }

    println!("{}", "  Event hooks installed".green());
}

/// Called when a window takes foreground focus.
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

    // Is this a transient process stealing focus?
    if is_transient_stealer(pid) {
        // Hide the offending window
        let _ = ShowWindow(hwnd, SW_HIDE);
        HIDDEN_COUNT.fetch_add(1, Ordering::Relaxed);

        // Restore focus to the last good window
        let last_good = LAST_GOOD_HWND.load(Ordering::SeqCst);
        if last_good != 0 {
            let restore_hwnd = HWND(last_good as *mut _);
            if IsWindow(restore_hwnd).as_bool() {
                let _ = SetForegroundWindow(restore_hwnd);
                RESTORED_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
    } else {
        // This is a legitimate focus change — update last good
        LAST_GOOD_HWND.store(hwnd.0 as isize, Ordering::SeqCst);
    }
}

/// Called when a window becomes visible.
unsafe extern "system" fn show_callback(
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

    // Quick class check
    let mut class_buf = [0u16; 256];
    let class_len = GetClassNameW(hwnd, &mut class_buf);
    if class_len == 0 {
        return;
    }
    let class_name = String::from_utf16_lossy(&class_buf[..class_len as usize]);
    let is_console = CONSOLE_CLASSES
        .iter()
        .any(|c| class_name.eq_ignore_ascii_case(c));
    if !is_console {
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

/// Check if a PID is a transient CMD/bash/PS spawned by Claude/node.
fn is_transient_stealer(pid: u32) -> bool {
    let (proc_name, ppid) = match get_process_info(pid) {
        Some(info) => info,
        None => return false,
    };

    let proc_lower = proc_name.to_lowercase();

    if !INTERCEPT_TARGETS.iter().any(|t| proc_lower == *t) {
        return false;
    }

    // Walk parent chain
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

            // User terminal — not transient, don't intercept
            if is_terminal_emulator(&parent_lower) {
                return false;
            }

            // Transient spawner — intercept (prefix match for versioned names)
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

/// Process Windows messages (required for SetWinEventHook callbacks).
fn pump_messages() {
    unsafe {
        let mut msg = std::mem::zeroed::<MSG>();
        while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

/// Polling backup: hide visible console windows owned by transient processes.
pub fn enforce_once(known_hidden: &mut HashSet<isize>) -> usize {
    let windows = find_visible_console_windows();
    let mut hidden_this_cycle = 0;

    for (hwnd_val, pid, _title) in &windows {
        if known_hidden.contains(hwnd_val) {
            continue;
        }

        if is_transient_stealer(*pid) {
            let hwnd = HWND(*hwnd_val as *mut _);
            unsafe {
                let _ = ShowWindow(hwnd, SW_HIDE);
            }
            known_hidden.insert(*hwnd_val);
            hidden_this_cycle += 1;
            HIDDEN_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }

    if known_hidden.len() > 100 {
        known_hidden.retain(|h| {
            let hwnd = HWND(*h as *mut _);
            unsafe { IsWindow(hwnd).as_bool() }
        });
    }

    hidden_this_cycle
}

fn find_visible_console_windows() -> Vec<(isize, u32, String)> {
    let mut results: Vec<(isize, u32, String)> = Vec::new();

    unsafe {
        let _ = EnumWindows(
            Some(enum_windows_callback),
            LPARAM(&mut results as *mut _ as isize),
        );
    }

    results
}

unsafe extern "system" fn enum_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let results = &mut *(lparam.0 as *mut Vec<(isize, u32, String)>);

    if !IsWindowVisible(hwnd).as_bool() {
        return BOOL(1);
    }

    let mut class_buf = [0u16; 256];
    let class_len = GetClassNameW(hwnd, &mut class_buf);
    if class_len == 0 {
        return BOOL(1);
    }
    let class_name = String::from_utf16_lossy(&class_buf[..class_len as usize]);

    let is_console = CONSOLE_CLASSES
        .iter()
        .any(|c| class_name.eq_ignore_ascii_case(c));
    if !is_console {
        return BOOL(1);
    }

    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid == 0 {
        return BOOL(1);
    }

    let mut title_buf = [0u16; 256];
    let title_len = GetWindowTextW(hwnd, &mut title_buf);
    let title = if title_len > 0 {
        String::from_utf16_lossy(&title_buf[..title_len as usize])
    } else {
        String::new()
    };

    results.push((hwnd.0 as isize, pid, title));

    BOOL(1)
}

/// Set ForegroundLockTimeout registry value and broadcast the change.
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
                    "  Foreground lock timeout set to MAX — background windows cannot steal focus"
                        .green()
                        .bold()
                );
                println!(
                    "{}",
                    "  (You can still switch windows with Alt+Tab / clicking)".dimmed()
                );
            }
        }
        _ => {
            println!(
                "{}",
                "  Warning: could not set ForegroundLockTimeout registry value".yellow()
            );
        }
    }

    // Broadcast WM_SETTINGCHANGE so the setting takes effect immediately
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

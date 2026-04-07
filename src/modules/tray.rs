use std::sync::mpsc;
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIconBuilder};

const DASHBOARD_URL: &str = "http://localhost:9847";

pub enum TrayCommand {
    UpdateTooltip(String),
}

/// Spawn the system tray icon on a dedicated OS thread.
/// Returns a sender to update tooltip text and a receiver for quit signals.
pub fn spawn_tray() -> (mpsc::Sender<TrayCommand>, mpsc::Receiver<()>) {
    let (cmd_tx, cmd_rx) = mpsc::channel::<TrayCommand>();
    let (quit_tx, quit_rx) = mpsc::channel::<()>();

    std::thread::spawn(move || {
        run_tray_loop(cmd_rx, quit_tx);
    });

    (cmd_tx, quit_rx)
}

fn run_tray_loop(cmd_rx: mpsc::Receiver<TrayCommand>, quit_tx: mpsc::Sender<()>) {
    let menu = Menu::new();
    let open_item = MenuItem::new("Open Dashboard", true, None);
    let quit_item = MenuItem::new("Exit", true, None);
    let _ = menu.append(&open_item);
    let _ = menu.append(&quit_item);

    let open_id = open_item.id().clone();
    let quit_id = quit_item.id().clone();

    let icon = create_icon();

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("System Monitor - Focus Guard")
        .with_icon(icon)
        .build();

    let _tray = match tray {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to create tray icon: {}", e);
            return;
        }
    };

    let menu_rx = MenuEvent::receiver();

    loop {
        // Process menu events
        if let Ok(event) = menu_rx.try_recv() {
            if event.id == open_id {
                let _ = open::that(DASHBOARD_URL);
            } else if event.id == quit_id {
                let _ = quit_tx.send(());
                break;
            }
        }

        // Process commands from main thread
        if let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                TrayCommand::UpdateTooltip(text) => {
                    let _ = _tray.set_tooltip(Some(&text));
                }
            }
        }

        // Pump Windows messages
        unsafe {
            let mut msg: windows::Win32::UI::WindowsAndMessaging::MSG = std::mem::zeroed();
            while windows::Win32::UI::WindowsAndMessaging::PeekMessageW(
                &mut msg,
                None,
                0,
                0,
                windows::Win32::UI::WindowsAndMessaging::PM_REMOVE,
            )
            .as_bool()
            {
                let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&msg);
                windows::Win32::UI::WindowsAndMessaging::DispatchMessageW(&msg);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Create a 16x16 RGBA icon (green circle)
fn create_icon() -> Icon {
    let size = 16u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];

    let center = size as f32 / 2.0;
    let radius = 6.0f32;

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center + 0.5;
            let dy = y as f32 - center + 0.5;
            let dist = (dx * dx + dy * dy).sqrt();
            let idx = ((y * size + x) * 4) as usize;

            if dist <= radius {
                rgba[idx] = 0x4a;     // R
                rgba[idx + 1] = 0xde; // G
                rgba[idx + 2] = 0x80; // B
                rgba[idx + 3] = 0xff; // A
            }
        }
    }

    Icon::from_rgba(rgba, size, size).expect("Failed to create icon")
}

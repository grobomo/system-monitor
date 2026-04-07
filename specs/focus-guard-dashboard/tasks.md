# Tasks: Focus Guard Dashboard

## T101: Add axum + tray-icon dependencies to Cargo.toml
- axum 0.7, tower-http (cors)
- tray-icon, tao (event loop)
- Add Win32_UI_WindowsAndMessaging back to windows features (tray needs it)

## T102: In-memory event ring buffer
- Shared `Arc<RwLock<VecDeque<FocusEvent>>>` capped at 500 events
- FocusEvent gets Serialize derive
- Polling loop pushes events to buffer (in addition to file + log)

## T103: Embedded HTTP server
- Spawn axum on `127.0.0.1:9847` in a tokio task
- `GET /` — serve embedded HTML dashboard (include_str!)
- `GET /api/events` — return ring buffer as JSON array (newest first)
- `GET /api/stats` — return `{ total, safe, unknown, suspicious, claude, uptime_secs }`

## T104: Dashboard HTML
- Single HTML file with inline CSS + JS
- Dark theme, monospace
- Auto-refresh every 2s via fetch(/api/events)
- Table: Time | Process | PID | Classification | Source | Command | Chain
- Color-coded rows by classification
- Top stats bar with counts
- Filter buttons: All / Unknown / Suspicious / Safe

## T105: System tray icon
- tray-icon with a simple icon (can use a built-in Windows icon or embedded PNG)
- Left-click → open http://localhost:9847 in default browser
- Right-click menu: "Open Dashboard" / "Exit"
- Tray tooltip: "System Monitor — N events"

## T106: Integration — wire everything into guard command
- guard command starts: polling loop + HTTP server + tray icon
- Graceful shutdown on Ctrl+C or tray Exit
- Print "Dashboard: http://localhost:9847" on startup

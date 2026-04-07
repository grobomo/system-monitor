# Spec: Focus Guard Dashboard

## Problem
Phantom cmd.exe and python.exe windows steal focus every few minutes. The focus guard module detects and logs these events, but there's no way to review them without reading log files. The user needs a persistent, always-available GUI to see what's happening.

## Solution
Extend the `system-monitor guard` command to include:
1. **Embedded HTTP server** on localhost serving a dashboard
2. **System tray icon** — clicking opens dashboard in default browser
3. **Dashboard HTML** — single-page app showing recent focus events with:
   - Process name, PID, timestamp
   - Parent chain (what started it)
   - Command line (what it's doing)
   - Classification (safe/claude/unknown/suspicious)
   - Source project (if traced)
   - Brain actions (events sent, dispatches triggered)

## Architecture
```
system-monitor guard
├── Process polling loop (existing, 500ms)
├── Event emitter (existing, writes JSON to ~/.system-monitor/events/)
├── HTTP server (new, localhost:9847)
│   ├── GET /           → serves dashboard HTML (embedded in binary)
│   ├── GET /api/events → returns recent events as JSON array
│   └── GET /api/stats  → summary counts by classification
└── System tray icon (new)
    └── Left-click → opens http://localhost:9847 in browser
```

## Dashboard UI
- Dark theme, monospace font
- Auto-refreshes every 2 seconds
- Table with columns: Time | Process | PID | Classification | Source | Command | Chain
- Color-coded rows: green=safe, yellow=unknown, red=suspicious, cyan=claude
- Top bar: total events, counts per classification, uptime
- Filter buttons: All / Unknown / Suspicious / Safe

## Dependencies
- `axum` — lightweight HTTP framework (already using tokio)
- `tray-icon` + `tao` — system tray icon (Windows native)

## Non-goals
- No enforcement (hiding windows, killing processes) — passive observer only
- No persistent storage beyond JSON event files
- No authentication (localhost only)

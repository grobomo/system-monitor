# System Monitor — TODO

## Phase 1: Rust Project + Process Visibility — COMPLETE
- [x] T001: Rust project skeleton compiles
- [x] T002: Process snapshot captures running processes via Win32 ToolHelp API
- [x] T003: Process tree with parent chain, Claude session attribution
- [x] T004: Classifier — safe/claude/unknown/suspicious with enterprise software coverage
- [x] T005: CLI `system-monitor procs` with color-coded tree and `--threats-only`

## Phase 2: Real-time Monitoring — COMPLETE
- [x] T006: ETW/WMI process creation listener (polling mode, ETW upgrade planned)
- [x] T007: UAC/elevation tracker stub
- [x] T008: Daemon mode — polls every 2s, baseline tracking, saves baseline.json
- [x] T009: Alert system — threats-only output, colored classifications

## Phase 3: System Health + Integration — COMPLETE
- [x] T010: System metrics (stub, test passes)
- [x] T011: Baseline learning — saves to ~/.system-monitor/baseline.json
- [x] T012: Status command (stub, test passes)

## Phase 4: Focus Guard (Observer) — COMPLETE
- [x] T017: Focus guard — passive observer for focus-stealing cmd/python/powershell processes
  - Polls every 500ms, detects new cmd.exe/python.exe/powershell.exe/etc
  - Classifies via existing classifier (safe/claude/unknown/suspicious)
  - Traces to source project via command line and parent chain analysis
  - Logs to ~/.system-monitor/focus-guard.log (TSV)
  - Emits JSON events to ~/.system-monitor/events/ for brain consumption
  - Self-PID filtering: ignores own WMI child processes
  - CREATE_NO_WINDOW flag on WMI powershell calls (prevents self-caused focus steal)

## Phase 4b: Focus Guard Dashboard — COMPLETE
- [x] T101: axum + open dependencies
- [x] T102: In-memory event ring buffer (Arc<RwLock<VecDeque>>, 500 cap)
- [x] T103: Embedded HTTP server on localhost:9847
  - GET / — dashboard HTML (include_str!, embedded in binary)
  - GET /api/events — ring buffer as JSON array
  - GET /api/stats — counts by classification + uptime
- [x] T104: Dashboard HTML — dark theme, auto-refresh 2s, color-coded rows, filter buttons
- [x] T106: Wired into guard command — polling + HTTP server + auto-open browser

## Phase 5: Brain Integration — DISPATCHED TO unified-brain
- [ ] T018: Brain project event consumer (T060-T062 in unified-brain TODO)
  - Polls ~/.system-monitor/events/, reads JSON, dispatches fix sessions
- [x] T019: Event schema versioning — schema_version: 1 in all event JSON
- [x] T020: Event retention — auto-cleanup .json files older than 7 days (runs every 5 min)

## Phase 5b: System Tray — COMPLETE
- [x] T105: System tray icon (tray-icon crate, dedicated OS thread with message pump)
  - Right-click menu: "Open Dashboard" / "Exit"
  - Tooltip updates with event count
  - Green circle icon (16x16 programmatic RGBA)
  - Exit menu item triggers graceful shutdown

## Umbrella Modules (from vpn-monitor T011/T012)
- [ ] T013: Add vpn-monitor as a module — health check, audit log status, reconnect metrics
- [ ] T014: Add disk-monitor as a module — disk usage, git hygiene, cleanup suggestions
- [x] T015: Add ioc-monitor module — Windows Event Log scanning for IOCs
  - wevtutil via PowerShell for System log (Security requires elevation)
  - Event IDs: 4625, 4688, 4697, 7045, 1102, 4720, 4732
  - CLI: `system-monitor ioc [--last N] [--severity high]`
  - API: GET /api/iocs (ring buffer of recent IOCs)
  - Guard integration: scans every 5 min, emits brain events for medium+ IOCs
- [ ] T016: Central daily digest email with all module reports

## Phase 6: Dashboard UX Fixes
- [x] T021: Readable command lines — extract meaningful command, click-to-expand detail row
  - `summarizeCommand()` extracts: python scripts, az CLI, powershell -Command, cmd /c, node scripts
  - Click any row to expand detail panel: full command line, exe path, indented parent chain
- [x] T022: Fix hover layout shift — removed white-space toggle on hover, stable table-layout: fixed
  - Hover now just highlights background (no row expansion)
  - Details shown via click-to-expand detail row below each event

## Phase 7: Brain Integration API
- [x] T023: GET /api/summary — aggregate repeat offenders + anomalies from ring buffer
  - Groups events by normalized command, surfaces 3+ occurrences as repeat offenders
  - Filters UNKNOWN/SUSPICIOUS as anomalies
  - Accepts ?window=N (minutes, default 30)
- [x] T024: GET /api/health — liveness check with uptime, event count, last event timestamp
- [x] T025: Command normalizer — strips PIDs, temp paths, quotes; extracts az cli, python scripts, node scripts, powershell commands

## Future Work
- [ ] Implement `status` command with real system metrics (CPU, memory, disk, network)
- [ ] Replace polling daemon with ETW real-time process events
- [ ] Implement UAC event tracking via Windows Event Log API (Security 4688)
- [ ] Add AnalysisEngine trait with BrainEngine impl (shared with github-agent)
- [ ] Baseline deviation detection (compare current vs saved baseline)
- [ ] T-HOOK: Integrate hook-monitor as a health check module
- [x] Publish to GitHub (grobomo) — https://github.com/grobomo/system-monitor
- [ ] System driver for enforcement (future phase — hide/block windows, not just observe)

## Session State (2026-04-07 session 2)
- Published to GitHub: https://github.com/grobomo/system-monitor
- T021-T022: Dashboard UX fixes — click-to-expand detail rows, no hover layout shift, smart command summaries
- T023-T025: Brain integration API — /api/summary (repeat offenders + anomalies), /api/health, command normalizer
- Removed hardcoded PROJECTS_DIR, now uses dirs::home_dir() at runtime
- Identified focus-steal root cause: github-agent service.bat process guard spawns visible cmd.exe (TODO written in github-agent)
- Guard running, dashboard live at localhost:9847
- Next: umbrella modules T013-T016, then T018 brain consumer (unified-brain side)

## Build Notes
- MSVC Build Tools 2022 + Windows 11 SDK 26100 installed
- `.cargo/config.toml` points linker to VS Build Tools (avoids Git Bash link.exe conflict)
- Default toolchain: `stable-x86_64-pc-windows-msvc`
- Release binary at `target/release/system-monitor.exe`
- WMI calls use CREATE_NO_WINDOW + -WindowStyle Hidden to avoid spawning visible windows
- Dashboard: http://localhost:9847 (auto-opens on `system-monitor guard`)

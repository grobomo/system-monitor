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
- [x] T013: Add vpn-monitor as a module — health check, tunnel verification, guard integration
  - Process detection for F5, Tailscale, Cisco, GlobalProtect, Zscaler, OpenVPN, WireGuard, Pulse
  - Adapter status via Get-NetAdapter
  - Tunnel verification: ping test (Tailscale→100.100.100.100), gateway check (others)
  - CLI: `system-monitor vpn` with verified/unverified/disconnected indicators
  - API: GET /api/vpn
  - Guard integration: polls every 60s, emits brain events on connect/disconnect/tunnel_down
- [x] T014: Add disk-monitor as a module — drive space, project sizes, cleanup suggestions (PR #5)
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

## Phase 8: Code Quality
- [x] T026: Fix all compiler warnings — unused imports, unused variables, dead code fields

## Claude Tab Collision Detection
- [x] T027: Detect multiple Claude Code sessions on the same project directory (PR #4)
  - Enumerates claude.exe processes via WMI, reads CWD from PEB (NtQueryInformationProcess + ReadProcessMemory)
  - Groups sessions by normalized project directory path
  - CLI: `system-monitor claude-tabs` — lists all sessions, highlights collisions
  - API: GET /api/claude-sessions — full session report as JSON
  - Guard integration: polls every 30s, emits brain events on collision detection
  - Classifies sessions as interactive vs headless (-p flag)

## Phase 9: CMD Popup Diagnosis
- [x] T028: `diagnose` command — scans scheduled tasks for CMD/PS spawners, identifies visible + repeating tasks
  - PowerShell query of Get-ScheduledTask with action/trigger analysis
  - Scores tasks by visibility, repeat interval, recency
  - Fast ToolHelp32-based spawn rate monitor (500ms polling, PID tracking)
  - Parent chain tracing for each new CMD/PS process
- [x] T029: `fix` command — disable/enable scheduled tasks by name
  - `system-monitor fix --disable <task1> <task2>` / `--enable <task>`
- [x] T030: `verify` command — monitor spawn rate for configurable duration to confirm fix
- [x] T031: Diagnosed and fixed focus-stealing CMD popups
  - Root cause: `github-agent-service` scheduled task (PT1M repeat) → wscript.exe → service.bat → cmd.exe
  - Also: 8 orphaned wscript.exe instances accumulated (guard check failed due to hidden window)
  - Fix: disabled task, killed orphaned processes
  - Residual CMD spawns (~4/min) all from Claude Code sessions — expected behavior, not focus-stealing

## Phase 10: Status Command
- [x] T032: Implement `status` command with real system metrics (CPU, memory, disk, VPN, Claude sessions) (PR #6)
  - CPU load via Win32_Processor, memory via Win32_OperatingSystem
  - Drive space from disk_monitor, VPN from vpn_monitor, Claude sessions from claude_sessions
  - One-screen summary with color-coded bars
  - API: GET /api/status for programmatic access

## Phase 11: Bundle Architecture
- [x] T033: Document bundle architecture — ARCHITECTURE.md (PR #7)
- [x] T034: Extract vpn-monitor crate — grobomo/sm-vpn-monitor (PR #7)
- [x] T035: Extract disk-monitor crate — grobomo/sm-disk-monitor (PR #7)
- [ ] T036: Extract process-monitor crate — standalone CLI + library for process tree/classification
- [ ] T037: Extract ioc-monitor crate — standalone CLI + library for Windows Event Log IOC scanning
- [ ] T038: Extract claude-sessions crate — standalone CLI + library for Claude tab collision detection
- [ ] T039: Integrate standalone vpn-monitor (Python reconnect) as managed service

## Phase 12: Focus Steal Prevention (Enforcement)
- [ ] T040: Active focus-steal prevention — hide/close CMD popups in real-time
  - Diagnose current sources of focus-stealing CMD/PS windows
  - Extend focus-guard from observer to enforcer: detect + hide visible CMD windows
  - Use Win32 ShowWindow(SW_HIDE) on newly spawned CMD/PS windows that aren't from terminals
  - Whitelist: windows inside terminal emulators (conpty), user-launched terminals
  - Must not hide legitimate user terminals — only transient script-spawned windows

## Future Work
- [ ] Replace polling daemon with ETW real-time process events
- [ ] Implement UAC event tracking via Windows Event Log API (Security 4688)
- [ ] Add AnalysisEngine trait with BrainEngine impl (shared with github-agent)
- [ ] Baseline deviation detection (compare current vs saved baseline)
- [ ] T-HOOK: Integrate hook-monitor as a health check module
- [x] Publish to GitHub (grobomo) — https://github.com/grobomo/system-monitor
- [ ] System driver for enforcement (future phase — hide/block windows, not just observe)

## Session State (2026-04-08 session 2)
- T027: Claude tab collision detection (PR #4)
- T014: Disk monitor (PR #5)
- T032: Status command (PR #6)
- T033-T035: Bundle architecture + extracted sm-vpn-monitor, sm-disk-monitor (PR #7)
- Next: T036 (process-monitor), T037 (ioc-monitor), T038 (claude-sessions) extractions
- Remaining non-extraction: T016 (daily digest), T018 (brain consumer), T039 (Python vpn-monitor integration)

## Build Notes
- MSVC Build Tools 2022 + Windows 11 SDK 26100 installed
- `.cargo/config.toml` points linker to VS Build Tools (avoids Git Bash link.exe conflict)
- Default toolchain: `stable-x86_64-pc-windows-msvc`
- Release binary at `target/release/system-monitor.exe`
- WMI calls use CREATE_NO_WINDOW + -WindowStyle Hidden to avoid spawning visible windows
- Dashboard: http://localhost:9847 (auto-opens on `system-monitor guard`)

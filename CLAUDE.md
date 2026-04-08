# System Monitor

Bundle of independent system management tools for Windows. Each module can be installed standalone or run together via the orchestrator. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full vision.

## Purpose

The user runs multiple Claude Code sessions simultaneously. Each spawns shell commands, PowerShell scripts, and child processes. Mystery windows appear with no attribution. UAC prompts fire with unknown origin. This agent provides real-time visibility, threat classification, and system health monitoring.

## Modules

| Command | Module | Description |
|---------|--------|-------------|
| `system-monitor status` | status | One-screen health: CPU, memory, disk, VPN, Claude sessions |
| `system-monitor procs` | process-monitor | Process tree with classifications |
| `system-monitor vpn` | vpn-monitor | VPN detection + tunnel verification |
| `system-monitor disk` | disk-monitor | Drive space, project sizes, cleanup suggestions |
| `system-monitor ioc` | ioc-monitor | Windows Event Log IOC scanning |
| `system-monitor claude-tabs` | claude-sessions | Claude Code tab collision detection |
| `system-monitor diagnose` | cmd-diagnosis | Find focus-stealing CMD popups |
| `system-monitor guard` | focus-guard | Dashboard + tray + all modules polling |

## Usage

```bash
# Quick health check
system-monitor status

# Full dashboard with all modules
system-monitor guard

# Individual modules
system-monitor vpn
system-monitor disk
system-monitor claude-tabs
system-monitor ioc --last 60 --severity high
system-monitor diagnose
```

## Build

```bash
cargo build --release
# Binary: target/release/system-monitor.exe
```

## Bundle Architecture

Each module is being extracted to its own `sm-*` crate (see ARCHITECTURE.md):
- Standalone install: `cargo install sm-vpn-monitor`
- Bundle install: `cargo install system-monitor` (includes all modules)
- Library use: `sm_vpn_monitor::check_vpn_status()` in your own code

## Dashboard

`system-monitor guard` starts:
- HTTP dashboard at `http://localhost:9847`
- System tray icon with right-click menu
- Polling loop: focus events (500ms), VPN (60s), Claude tabs (30s), IOCs + disk (5min)
- Brain events emitted to `~/.system-monitor/events/` for external consumers

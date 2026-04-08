# System Monitor — Bundle Architecture

## Vision

`system-monitor` is a **bundle of independent system management tools** for Windows.
Each tool can be:

1. **Used standalone** — install just the tool you need (`cargo install sm-vpn-monitor`)
2. **Used as a library** — import the crate into your own Rust project
3. **Run as part of the bundle** — `system-monitor` orchestrates all tools with a unified CLI, dashboard, and brain event system

Think of it like `coreutils` — individual tools (`ls`, `cat`, `grep`) that also ship together.

## Component Map

```
system-monitor (orchestrator)
├── sm-vpn-monitor      — VPN detection, tunnel verification, reconnect management
├── sm-disk-monitor     — Drive space, project sizes, cleanup suggestions
├── sm-process-monitor  — Process tree, classification (safe/claude/unknown/suspicious)
├── sm-ioc-monitor      — Windows Event Log scanning for security IOCs
├── sm-claude-sessions  — Claude Code tab collision detection (PEB-based CWD)
├── sm-cmd-diagnosis    — Diagnose/fix focus-stealing CMD popups
├── sm-focus-guard      — Real-time process watcher with dashboard + tray icon
└── sm-status           — Aggregated system health summary
```

## Repository Structure

Each component lives in its own repo under `grobomo/`:

| Repo | Type | Description |
|------|------|-------------|
| `grobomo/system-monitor` | Rust binary | Orchestrator — depends on all `sm-*` crates |
| `grobomo/sm-vpn-monitor` | Rust crate + binary | VPN process detection, adapter status, tunnel verification |
| `grobomo/sm-disk-monitor` | Rust crate + binary | Drive space, project scanning, cleanup suggestions |
| `grobomo/sm-process-monitor` | Rust crate + binary | ToolHelp32 process tree, WMI enrichment, classifier |
| `grobomo/sm-ioc-monitor` | Rust crate + binary | Windows Event Log IOC scanning |
| `grobomo/sm-claude-sessions` | Rust crate + binary | Claude Code session discovery via PEB reading |
| `grobomo/sm-cmd-diagnosis` | Rust crate + binary | Scheduled task analysis, spawn rate monitoring |

### Related but separate

| Repo | Type | Description |
|------|------|-------------|
| `vpn-monitor` (tmemu, private) | Python | F5 VPN auto-reconnect with MFA email. Managed by `sm-vpn-monitor` as a service |

## Crate Design

Each `sm-*` crate exposes:

```rust
// Library API (for use by system-monitor or other projects)
pub fn check_vpn_status() -> Vec<VpnStatus>;
pub fn poll_vpn_changes(prev: &[VpnStatus]) -> (Vec<VpnStatus>, Vec<VpnStateChange>);

// CLI entry point (for standalone use)
pub fn cli_main();
```

The orchestrator (`system-monitor`) imports the library APIs and wires them into:
- **Unified CLI** — `system-monitor vpn`, `system-monitor disk`, etc.
- **Dashboard** — single HTTP server at `:9847` with all module data
- **Guard loop** — periodic polling of all modules, brain event emission
- **System tray** — single tray icon for the whole bundle

## Standalone vs Bundle

### Standalone install
```bash
cargo install sm-vpn-monitor
sm-vpn-monitor          # Show VPN status
sm-vpn-monitor --json   # JSON output for scripting
```

### Bundle install
```bash
cargo install system-monitor
system-monitor vpn      # Same output, via orchestrator
system-monitor status   # Aggregated health from ALL modules
system-monitor guard    # Dashboard + tray + all monitors polling
```

## Dependency Flow

```
system-monitor
├── Cargo.toml dependencies:
│   ├── sm-vpn-monitor = { git = "https://github.com/grobomo/sm-vpn-monitor" }
│   ├── sm-disk-monitor = { git = "https://github.com/grobomo/sm-disk-monitor" }
│   ├── sm-process-monitor = { git = "https://github.com/grobomo/sm-process-monitor" }
│   ├── sm-ioc-monitor = { git = "https://github.com/grobomo/sm-ioc-monitor" }
│   ├── sm-claude-sessions = { git = "https://github.com/grobomo/sm-claude-sessions" }
│   └── sm-cmd-diagnosis = { git = "https://github.com/grobomo/sm-cmd-diagnosis" }
└── src/
    ├── main.rs          — CLI routing (clap)
    ├── focus_guard.rs   — Dashboard, guard loop, brain events (orchestrator-only)
    ├── status.rs        — Aggregated status (orchestrator-only)
    └── tray.rs          — System tray (orchestrator-only)
```

## VPN Monitor Integration

The `sm-vpn-monitor` crate handles **detection and status**:
- Which VPN clients are running (F5, Tailscale, Cisco, etc.)
- Network adapter status (connected/disconnected)
- Tunnel verification (ping tests, gateway checks)

The standalone `vpn-monitor` (Python, tmemu) handles **reconnection**:
- F5 BIG-IP auto-reconnect with SSO automation
- MFA number extraction and email notification
- Scheduled task management

`sm-vpn-monitor` can optionally manage the Python reconnect service:
- Check if the scheduled task is installed and running
- Trigger a reconnect when tunnel is detected as down
- Surface reconnect status in the dashboard

## Extraction Order

1. **T033**: Document this architecture (this file)
2. **T034**: `sm-vpn-monitor` — most standalone-ready, clear boundary
3. **T035**: `sm-disk-monitor` — no dependencies on other modules
4. **T036**: `sm-process-monitor` — foundational (classifier + tree)
5. **T037**: `sm-ioc-monitor` — clean boundary, no deps on process tree
6. **T038**: `sm-claude-sessions` — depends on process tree for PEB reading
7. **T039**: Wire Python vpn-monitor as managed service in sm-vpn-monitor

## Design Principles

- **Zero mandatory dependencies between modules** — each crate compiles alone
- **Shared types via `sm-common`** if needed (e.g., brain event schema)
- **No runtime coordination** — modules don't talk to each other, only to the orchestrator
- **Advisory only** — no module deletes files, kills processes, or changes config without explicit user action
- **Windows-first** — all modules target Windows, macOS/Linux support is future work

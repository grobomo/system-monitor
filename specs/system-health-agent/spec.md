# System Monitor Agent — Spec

## Problem

The user runs multiple Claude Code sessions simultaneously, each spawning shell commands, PowerShell scripts, and child processes. UAC prompts appear with unknown origin. Mystery cmd.exe and powershell.exe windows show "Access denied" errors with no attribution. The user has zero visibility into what's running on their PC, who started it, and whether it's safe.

This is fundamentally an AV/EDR agent problem: real-time process monitoring, threat classification, and alerting.

## Solution: Rust-based Security Agent

A lightweight Rust daemon that continuously monitors the system and classifies activity as **safe / unknown / suspicious / malicious** in real time.

## Core Capabilities

### 1. Process Monitor (Priority 1)
- **Real-time process creation tracking** via Windows ETW (Event Tracing for Windows) or WMI event subscriptions
- For every new process: PID, PPID, full command line, executable path, digital signature status, user, start time
- **Parent chain resolution**: trace any process back to its root (explorer.exe, services.exe, claude.exe, etc.)
- **Claude session attribution**: identify which Claude Code tab spawned a process by walking the process tree
- **Classification engine**:
  - `safe`: signed Microsoft/known vendor binary, launched from expected parent chain
  - `claude`: attributed to a Claude Code session (show which tab)
  - `unknown`: unsigned or unusual parent chain, not in baseline
  - `suspicious`: access denied patterns, privilege escalation attempts, unusual network activity
  - `malicious`: matches known bad patterns (LOLBins abuse, encoded PowerShell, etc.)

### 2. UAC/Elevation Tracking
- Monitor Security Event Log (4688) and Sysmon (1) for elevation events
- Attribute each elevation to a source (Claude session, user action, scheduled task, service, unknown)
- Alert immediately on unattributed elevation requests

### 3. System Health Metrics
- CPU, memory, disk usage on intervals
- Network connections with process attribution
- Service status monitoring
- Anomaly detection against a learned baseline

### 4. Real-time Alerting
- Console output (colored, structured)
- JSON log to `~/.system-monitor/`
- Future: desktop toast notifications

## Architecture

```
system-monitor (Rust binary)
├── daemon mode     — runs continuously, monitors events
├── cli mode        — query current state, recent alerts
│   ├── status      — system health summary
│   ├── procs       — process tree with classifications
│   ├── uac         — recent elevation events
│   └── alerts      — recent alerts
└── modules
    ├── process_monitor   — ETW/WMI process creation events
    ├── process_tree      — PID→parent chain mapping
    ├── classifier        — safe/unknown/suspicious/malicious
    ├── uac_tracker       — elevation event monitoring
    ├── metrics           — CPU/mem/disk/net collection
    ├── baseline          — learned normal state
    └── alerter           — log + notify
```

## Tech Choices
- **Rust**: Safe, fast, no runtime, direct Win32/ETW access
- **windows-rs**: Windows API bindings
- **ETW (Event Tracing for Windows)**: Real-time kernel-level process events without polling
- **tokio**: Async runtime for concurrent monitoring
- **serde/serde_json**: Structured output

## Analysis Engine Architecture

The classifier is designed as a pluggable trait:

```rust
trait AnalysisEngine: Send + Sync {
    fn classify(&self, context: &ProcessContext) -> Classification;
    fn update_baseline(&mut self, snapshot: &SystemSnapshot);
}
```

### Implementations
1. **RuleBasedEngine** (v1, built-in): Static rules for known-good processes, LOLBin detection, suspicious patterns. Fast, no external deps.
2. **BaselineEngine** (v1.1): Learns normal activity over time. Processes that deviate from historical baseline get flagged.
3. **BrainEngine** (future): Calls shared analysis engine from `github-agent` project via local API. Provides full environmental context (what Claude sessions are doing, what's expected vs unexpected).

### Baseline Learning
- On first run: snapshot all processes, services, listening ports, scheduled tasks as "known good"
- Store in `~/.system-monitor/baseline.json`
- Over time: track frequency, timing, parent relationships
- Flag deviations: new processes never seen before, unusual parent chains, new listening ports

### Proactive Behavior
The daemon does NOT wait for queries. It:
1. Logs every process creation with full context
2. Immediately classifies against baseline + rules
3. Alerts on unknown/suspicious to console AND log file
4. Periodically summarizes: "Last hour: 47 safe, 3 claude, 2 unknown, 0 suspicious"

## Non-goals (v1)
- No GUI (CLI + JSON only)
- No kernel driver (user-mode only)
- No file scanning (that's ioc-monitor's job)
- No network packet inspection (just connection tracking)
- No Windows service registration yet (manual start, runs in background)

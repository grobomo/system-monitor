# System Monitor

Rust-based real-time security agent for Windows. Monitors processes, UAC events, and system health — classifying activity as safe/claude/unknown/suspicious/malicious like an AV/EDR agent.

## Purpose

The user runs multiple Claude Code sessions simultaneously. Each spawns shell commands, PowerShell scripts, and child processes. Mystery windows appear with no attribution. UAC prompts fire with unknown origin. This agent provides real-time visibility and threat classification.

## Architecture

- **Rust binary** — single executable, no runtime dependencies
- **Process monitor** — enumerates all processes via Win32 ToolHelp API
- **Process tree** — maps PIDs to parent chains, identifies Claude session trees
- **Classifier** — categorizes each process: safe / claude / unknown / suspicious / malicious
- **Daemon mode** — continuous polling (future: ETW real-time events)
- **CLI** — `system-monitor procs`, `uac`, `status`, `daemon`

## Usage

```bash
# Show all processes with classifications
system-monitor procs

# Show only unknown/suspicious/malicious
system-monitor procs --threats-only

# Run as continuous daemon
system-monitor daemon

# Show UAC events (TODO)
system-monitor uac
```

## Build

```bash
cargo build --release
```

## Integration Points

- `vpn-monitor` — VPN connectivity status
- `disk-monitor` — Disk usage and cleanup recommendations
- `ioc-monitor` (planned) — Windows events, file events, network connections

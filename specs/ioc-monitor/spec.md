# Spec: IOC Monitor Module (T015)

## Problem
The system-monitor watches for focus-stealing processes but has no visibility into Windows security events — failed logins, new services installed, suspicious process creation with unusual parents. These are standard IOCs that any EDR would monitor.

## Solution
Add an `ioc` subcommand and background module that reads Windows Event Logs via `wevtutil` and surfaces IOCs.

### Event IDs to Monitor
| Event ID | Log | Meaning | Severity |
|----------|-----|---------|----------|
| 4625 | Security | Failed logon attempt | Medium |
| 4688 | Security | New process created (with command line) | Low (info) |
| 4697 | Security | Service installed | High |
| 7045 | System | New service installed | High |
| 1102 | Security | Audit log cleared | Critical |
| 4720 | Security | User account created | High |
| 4732 | Security | Member added to security group | High |
| 1 | Sysmon | Process creation (if Sysmon installed) | Low (info) |

### Architecture
- `wevtutil qe` subprocess to query event logs (no extra dependencies)
- XML parsing via `quick-xml` crate (lightweight)
- IOC struct: event_id, timestamp, severity, description, raw_data
- Ring buffer for recent IOCs (same pattern as focus_guard)
- Dashboard integration: new `/api/iocs` endpoint + IOC tab in dashboard

### CLI
```
system-monitor ioc              # Show IOCs from last 24h
system-monitor ioc --last 60    # Last 60 minutes
system-monitor ioc --severity high  # Filter by severity
```

### Integration with Guard
When running `system-monitor guard`, IOC monitor runs as a background task alongside focus-steal detection. IOC events emit to `~/.system-monitor/events/` with type `ioc` for brain consumption.

## Non-goals
- Full SIEM functionality (correlation, alerting rules engine)
- Sysmon installation or configuration
- Event log forwarding to external systems

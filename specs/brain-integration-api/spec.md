# Spec: Brain Integration API

## Problem
Brain needs to consume system-monitor data to analyze patterns (repeat offenders, anomalies, frequency spikes) and dispatch Claude sessions to fix issues. Current API only exposes raw events — brain would need to re-derive patterns each time.

## Solution
Add summary/aggregation endpoints that pre-compute patterns from the event ring buffer. Brain calls these periodically and decides what action to take.

### New Endpoints

**GET /api/summary** — Aggregated view for brain consumption
```json
{
  "window_minutes": 30,
  "total_events": 42,
  "repeat_offenders": [
    {
      "process": "cmd.exe",
      "command_summary": "node self-analyze-loop.js",
      "count": 15,
      "frequency_per_min": 0.5,
      "classification": "SAFE",
      "source_project": null,
      "last_seen": "2026-04-07 00:44:25",
      "sample_command_line": "cmd.exe /c node \"C:\\Users\\...\\self-analyze-loop.js\" ..."
    }
  ],
  "anomalies": [
    {
      "type": "unknown_process",
      "process": "wscript.exe",
      "pid": 29588,
      "timestamp": "2026-04-07 00:42:41",
      "command_line": null,
      "parent_chain": "wscript.exe(29588)"
    }
  ],
  "classification_counts": { "safe": 30, "claude": 10, "unknown": 1, "suspicious": 1 }
}
```

- `repeat_offenders`: processes that appeared 3+ times, grouped by normalized command
- `anomalies`: UNKNOWN or SUSPICIOUS events
- Brain reads this, decides if action is needed, dispatches fix sessions

**GET /api/health** — Simple liveness check for brain
```json
{
  "status": "ok",
  "uptime_seconds": 3600,
  "events_captured": 500,
  "last_event_at": "2026-04-07 00:44:44"
}
```

## Architecture
- Summary computation runs in-process from the existing ring buffer (no new storage)
- Normalization: group commands by extracting script/binary name, ignoring PIDs and temp paths
- No changes to event collection or classification logic

## Non-goals
- Brain dispatch logic (that's unified-brain's job)
- Persistent event storage beyond the ring buffer + event files
- Authentication (localhost only)

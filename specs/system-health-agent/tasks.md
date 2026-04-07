# System Monitor Agent — Tasks

## Phase 1: Rust Project + Process Visibility (urgent)

**Checkpoint**: `bash scripts/test/test-T001-rust-skeleton.sh && bash scripts/test/test-T002-process-snapshot.sh && bash scripts/test/test-T003-process-tree.sh && bash scripts/test/test-T004-classifier.sh && bash scripts/test/test-T005-cli-procs.sh` exits 0

- [ ] T001: Initialize Rust project — Cargo.toml with windows-rs, tokio, serde, clap dependencies. Build and run hello world.
- [ ] T002: Process snapshot module — enumerate all running processes via Win32 API (CreateToolhelp32Snapshot), get PID, PPID, exe path, command line, creation time, signature status
- [ ] T003: Process tree module — build parent chain from snapshot, identify Claude Code session roots (node.exe/claude.exe → bash.exe → children)
- [ ] T004: Process classifier — classify each process as safe/claude/unknown/suspicious based on signature, parent chain, known-good baseline
- [ ] T005: CLI `system-monitor procs` — show running processes as a tree with color-coded classifications

## Phase 2: Real-time Monitoring

**Checkpoint**: `bash scripts/test/test-T006-etw-listener.sh && bash scripts/test/test-T007-uac-tracker.sh && bash scripts/test/test-T008-daemon.sh && bash scripts/test/test-T009-alerts.sh` exits 0

- [ ] T006: ETW process creation listener — subscribe to kernel process events for real-time new process detection (or WMI fallback)
- [ ] T007: UAC/elevation tracker — monitor Security Event Log 4688 for token elevation, attribute to source
- [ ] T008: Daemon mode — continuous monitoring loop, process events as they arrive, maintain live process tree
- [ ] T009: Alert system — log suspicious/unknown processes to `~/.system-monitor/alerts.json`, colored console output

## Phase 3: System Health + Integration

**Checkpoint**: `bash scripts/test/test-T010-metrics.sh && bash scripts/test/test-T011-baseline.sh && bash scripts/test/test-T012-status.sh` exits 0

- [ ] T010: System metrics collector — CPU, memory, disk, network connections via Win32 API
- [ ] T011: Baseline learning — snapshot current state as "known good", detect deviations
- [ ] T012: CLI `system-monitor status` — one-screen health dashboard with alerts

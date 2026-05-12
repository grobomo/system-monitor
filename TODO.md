# System Monitor — TODO

## From Publishable Audit (2026-05-11)

- [x] T-STRIP: PUBLIC REPO — Reworded secret-scan.yml "Vision One / Trend" → "JWT / Bearer tokens". Generalized classifier.rs vendor comments. SESSION_STATE.md already gitignored + untracked (safe).

<!-- See TODO-COMPLETED.md for history -->

## Phase 5: Brain Integration — DISPATCHED TO unified-brain
- [ ] T018: Brain project event consumer (T060-T062 in unified-brain TODO)
  - Polls ~/.system-monitor/events/, reads JSON, dispatches fix sessions

## Umbrella Modules (from vpn-monitor T011/T012)
- [ ] T016: Central daily digest email with all module reports

## Phase 11: Bundle Architecture
- [ ] T036: Extract process-monitor crate — DISPATCHED to sm-process-monitor session (2026-05-11)
- [ ] T037: Extract ioc-monitor crate — standalone CLI + library for Windows Event Log IOC scanning
- [ ] T038: Extract claude-sessions crate — standalone CLI + library for Claude tab collision detection
- [ ] T039: Integrate standalone vpn-monitor (Python reconnect) as managed service

## Phase 12: Focus Steal Prevention (Enforcement)
- [ ] T040: Fix focus-stealing CMD popups at the source
  - ROOT CAUSE IDENTIFIED: Claude Code spawns cmd.exe without CREATE_NO_WINDOW.
    Windows 11 default terminal = Windows Terminal, so orphan consoles open as WT tabs,
    stealing focus. The shield (PR #8) catches some but has latency.
  - AUDIT RESULTS (2026-05-11):
    1. ✅ ~/.claude/hooks/ audit COMPLETE — only ONE offender found:
       - haiku-client.js:85 — execSync('curl ...') missing windowsHide: true
       - All other spawns (12 call sites) already have windowsHide: true
       - Fix dispatched as T657 to the hooks project
    2. ⏳ Hooks project fix — T657 pending
    3. ✅ Claude Code settings — NO configurable shell spawn flags exist
    4. ⏳ Claude Code's built-in Bash tool — spawns cmd.exe inherently;
       run-hidden.js wrapper (already deployed) mitigates this for hooks.
       For the Bash tool itself, the shield (focus_enforcer.rs) is the only mitigation.
  - Shield (focus_enforcer.rs) is a mitigation, not the fix — keeps running as backup
  - DO NOT change default terminal app or Windows Terminal settings
  - REMAINING: Wait for T657 fix, then close T040

## Future Work
- [ ] Replace polling daemon with ETW real-time process events
- [ ] Implement UAC event tracking via Windows Event Log API (Security 4688)
- [ ] Add AnalysisEngine trait with BrainEngine impl (shared with github-agent)
- [ ] Baseline deviation detection (compare current vs saved baseline)
- [ ] T-HOOK: Integrate hook-monitor as a health check module
- [ ] System driver for enforcement (future phase — hide/block windows, not just observe)

## Session State (2026-05-11 session 4)
- T-STRIP: Complete — stripped brand refs from secret-scan.yml + classifier.rs
- T040: Hooks audit complete. 12/13 spawn sites already had windowsHide. One fix (haiku-client.js)
  dispatched as T657 to hook-runner project. Claude Code Bash tool has no configurable flags.
- T036: Dispatched to sm-process-monitor session (TODO.md written with full extraction spec)
- NEXT: T037 (ioc-monitor extraction), T038 (claude-sessions extraction), T016 (daily digest)
- BLOCKED: T040 final close waiting on T657 in hook-runner

## Build Notes
- MSVC Build Tools 2022 + Windows 11 SDK 26100 installed
- `.cargo/config.toml` points linker to VS Build Tools (avoids Git Bash link.exe conflict)
- Default toolchain: `stable-x86_64-pc-windows-msvc`
- Release binary at `target/release/system-monitor.exe`
- WMI calls use CREATE_NO_WINDOW + -WindowStyle Hidden to avoid spawning visible windows
- Dashboard: http://localhost:9847 (auto-opens on `system-monitor guard`)

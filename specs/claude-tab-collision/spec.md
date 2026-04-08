# Claude Tab Collision Detection

## Goal
Detect when multiple Claude Code sessions target the same project directory.
This causes git branch switching, index.lock contention, and parallel commits
that stomp each other. Detection must be fast enough to warn at SessionStart.

## Approach
- Enumerate running processes via ToolHelp32 (already in process_tree)
- Find claude.exe processes — these are the Electron shell for Claude Code
- For each claude.exe, find child node.exe processes with `--project-dir` in args
- Group sessions by project directory
- Flag directories with 2+ active sessions as collisions

## Discovery: How to get project directory
Claude Code runs as: `claude.exe` → `node.exe ...claude... --project-dir <path>`
The `--project-dir` argument in the node.exe command line gives us the project path.
Fallback: check CLAUDE_PROJECT_DIR environment variable via WMI Win32_Process.

## Data Model
```rust
struct ClaudeSession {
    pid: u32,           // claude.exe PID
    node_pid: u32,      // child node.exe PID
    project_dir: String,
    command_line: Option<String>,
}

struct CollisionReport {
    collisions: Vec<CollisionGroup>,
    safe: Vec<ClaudeSession>,
}

struct CollisionGroup {
    project_dir: String,
    sessions: Vec<ClaudeSession>,
}
```

## CLI
- `system-monitor claude-tabs` — list active Claude sessions, highlight collisions

## API
- `GET /api/claude-sessions` — JSON list of sessions with collision flags

## Guard integration
- Poll every 30s in guard loop
- Emit brain event when collision detected
- Event type: `claude_tab_collision`

## Non-goals
- Killing duplicate sessions (user decides)
- Git lock resolution (separate concern)

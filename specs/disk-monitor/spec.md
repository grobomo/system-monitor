# Disk Monitor Module

## Goal
Add disk usage monitoring to system-monitor. Report drive space, identify large
directories in the projects folder, check git hygiene (untracked large files,
stale branches), and suggest safe cleanup actions.

## Approach
- Query disk space per drive via Win32 API (GetDiskFreeSpaceExW)
- Scan projects directory for disk usage per project (dir size)
- Check git repos for: large untracked files, stale local branches, node_modules size
- Categorize findings as safe-to-clean vs review-needed
- Advisory only — never delete without explicit user approval

## Data Model
```rust
struct DiskReport {
    drives: Vec<DriveInfo>,
    projects: Vec<ProjectDiskUsage>,
    suggestions: Vec<CleanupSuggestion>,
    scanned_at: String,
}

struct DriveInfo {
    letter: String,
    total_gb: f64,
    free_gb: f64,
    used_percent: f64,
}

struct ProjectDiskUsage {
    name: String,
    path: String,
    size_mb: f64,
    has_git: bool,
    node_modules_mb: Option<f64>,
    target_mb: Option<f64>, // Rust target/
}

struct CleanupSuggestion {
    path: String,
    size_mb: f64,
    category: String, // "safe" | "review"
    reason: String,
}
```

## CLI
- `system-monitor disk` — drive space + top projects by size + cleanup suggestions

## API
- `GET /api/disk` — full disk report as JSON

## Guard integration
- Poll every 10 min
- Emit brain event when any drive drops below 10% free

## Non-goals
- Automated deletion (advisory only)
- Deep file-level analysis (too slow for polling)

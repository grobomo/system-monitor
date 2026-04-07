# Spec: Dashboard UX Fixes

## Problem
1. Dashboard shows process chains like `python.exe(33216) -> bash.exe(34708) -> ...` but doesn't clearly show what the process is actually doing (the full command line). The command column is truncated to 300px with ellipsis, making it unreadable.
2. Hovering over rows changes `white-space: nowrap` to `normal`, causing layout shift — the entire table jumps as rows expand/collapse.

## Solution

### T021: Readable command lines
- Show the **leaf process command line** prominently — this is the most important info
- For python.exe, extract the script name/path from the command line (e.g. `context_reset.py --project-dir ...`)
- For the parent chain, show command lines in a tooltip or expandable detail row, not inline
- Add a click-to-expand detail panel per row showing full command line, full chain with each process's command, exe path

### T022: Fix hover layout shift
- Remove the `white-space: normal` hover rule entirely
- Use a fixed table layout or stable row heights
- Move expanded details to a click-to-expand panel below the row (not hover)

## Non-goals
- No changes to the Rust backend — event data already includes command_line
- No changes to polling or classification logic

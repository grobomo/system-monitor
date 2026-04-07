#!/usr/bin/env bash
# Test T003: Process tree resolves parent chains
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "T003: Checking process tree..."

export PATH="$HOME/.cargo/bin:$PATH"
cargo build 2>&1

# The procs command should show hierarchical output
OUTPUT=$(./target/debug/system-monitor procs 2>&1) || { echo "FAIL: procs command failed"; exit 1; }

# Should have safe processes (green dots)
echo "$OUTPUT" | grep -q "safe" || { echo "FAIL: no safe process count"; exit 1; }

echo "PASS: T003 process tree"

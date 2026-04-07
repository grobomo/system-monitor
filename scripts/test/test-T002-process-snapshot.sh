#!/usr/bin/env bash
# Test T002: Process snapshot captures running processes
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "T002: Checking process snapshot..."

export PATH="$HOME/.cargo/bin:$PATH"
cargo build 2>&1

# Run procs command — should list processes without error
OUTPUT=$(./target/debug/system-monitor procs 2>&1) || { echo "FAIL: procs command failed"; exit 1; }

# Should contain "Process Tree" header and at least some processes
echo "$OUTPUT" | grep -q "Process Tree" || { echo "FAIL: missing Process Tree header"; exit 1; }
echo "$OUTPUT" | grep -q "processes" || { echo "FAIL: missing process count"; exit 1; }

echo "PASS: T002 process snapshot"

#!/usr/bin/env bash
# Test T004: Process classifier categorizes processes
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "T004: Checking classifier..."

export PATH="$HOME/.cargo/bin:$PATH"
cargo build 2>&1

OUTPUT=$(./target/debug/system-monitor procs 2>&1) || { echo "FAIL: procs command failed"; exit 1; }

# Should classify svchost, explorer etc as safe
echo "$OUTPUT" | grep -qE "safe" || { echo "FAIL: no safe classifications"; exit 1; }

# Total line should show counts
echo "$OUTPUT" | grep -qE "Total:" || { echo "FAIL: no Total summary line"; exit 1; }

echo "PASS: T004 classifier"

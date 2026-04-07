#!/usr/bin/env bash
# Test T005: CLI procs command works with --threats-only flag
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "T005: Checking CLI procs command..."

export PATH="$HOME/.cargo/bin:$PATH"
cargo build 2>&1

# Full tree
OUTPUT=$(./target/debug/system-monitor procs 2>&1) || { echo "FAIL: procs command failed"; exit 1; }
echo "$OUTPUT" | grep -q "Process Tree" || { echo "FAIL: missing header"; exit 1; }

# Threats only (should still work, may have fewer lines)
OUTPUT2=$(./target/debug/system-monitor procs --threats-only 2>&1) || { echo "FAIL: procs --threats-only failed"; exit 1; }

echo "PASS: T005 CLI procs"

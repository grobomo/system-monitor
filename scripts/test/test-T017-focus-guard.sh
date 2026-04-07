#!/usr/bin/env bash
# Test T017: Focus guard starts, captures baseline, emits events dir
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "T017: Checking focus guard..."
cargo build --release 2>&1

# Run guard for 15 seconds — WMI command-line fetch takes a few seconds
timeout 15 ./target/release/system-monitor guard 2>&1 | tee /tmp/guard-out.txt || true

grep -q "Focus Guard" /tmp/guard-out.txt || { echo "FAIL: guard didn't print header"; exit 1; }
grep -q "Baseline" /tmp/guard-out.txt || { echo "FAIL: guard didn't report baseline"; exit 1; }
grep -q "events" /tmp/guard-out.txt || { echo "FAIL: guard didn't show events dir"; exit 1; }

# Verify events directory was created
if [ ! -d "$HOME/.system-monitor/events" ]; then
    echo "FAIL: events directory not created"
    exit 1
fi

echo "PASS: T017 focus-guard"

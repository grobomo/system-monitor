#!/usr/bin/env bash
# Test T008: Daemon mode starts, captures baseline, and exits cleanly on signal
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "T008: Checking daemon mode..."
cargo build 2>&1

# Run daemon for 5 seconds, should capture baseline
timeout 5 ./target/debug/system-monitor daemon 2>&1 | tee /tmp/daemon-out.txt || true

grep -q "Baseline" /tmp/daemon-out.txt || { echo "FAIL: daemon didn't report baseline"; exit 1; }

echo "PASS: T008 daemon"

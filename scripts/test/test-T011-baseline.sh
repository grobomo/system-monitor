#!/usr/bin/env bash
# Test T011: Baseline learning captures and persists system state
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "T011: Checking baseline learning..."
cargo build 2>&1

# After daemon run, baseline should be saved
timeout 5 ./target/debug/system-monitor daemon 2>&1 || true

BASELINE="$HOME/.system-monitor/baseline.json"
[ -f "$BASELINE" ] || { echo "FAIL: baseline.json not created"; exit 1; }

# Validate JSON using python with Windows-style path
WIN_BASELINE=$(cygpath -w "$BASELINE")
python -c "import json, sys; json.load(open(sys.argv[1]))" "$WIN_BASELINE" 2>/dev/null || { echo "FAIL: invalid baseline JSON"; exit 1; }

echo "PASS: T011 baseline"

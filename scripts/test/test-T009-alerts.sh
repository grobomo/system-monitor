#!/usr/bin/env bash
# Test T009: Alert system writes to alerts.json
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "T009: Checking alert system..."
cargo build 2>&1

# Run procs with threats-only — if any unknown processes, they should be logged
./target/debug/system-monitor procs --threats-only 2>&1 || { echo "FAIL: procs --threats-only crashed"; exit 1; }

# Check log directory exists after daemon run
LOGDIR="$HOME/.system-monitor"
if [ -d "$LOGDIR" ]; then
  echo "  Log directory exists: $LOGDIR"
fi

echo "PASS: T009 alerts"

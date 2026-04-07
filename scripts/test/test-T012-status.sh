#!/usr/bin/env bash
# Test T012: Status command shows health dashboard
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "T012: Checking status command..."
cargo build 2>&1

OUTPUT=$(./target/debug/system-monitor status 2>&1) || { echo "FAIL: status command crashed"; exit 1; }
[ -n "$OUTPUT" ] || { echo "FAIL: no output"; exit 1; }

echo "PASS: T012 status"

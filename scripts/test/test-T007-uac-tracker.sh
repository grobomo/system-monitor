#!/usr/bin/env bash
# Test T007: UAC tracker command runs without error
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "T007: Checking UAC tracker..."
cargo build 2>&1

OUTPUT=$(./target/debug/system-monitor uac --last 5 2>&1) || { echo "FAIL: uac command crashed"; exit 1; }
[ -n "$OUTPUT" ] || { echo "FAIL: no output"; exit 1; }

echo "PASS: T007 UAC tracker"

#!/usr/bin/env bash
# Test T002: PowerShell UAC event query returns valid JSON
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "T002: Checking UAC event query..."

# Script exists
[ -f "src/ps/get-uac-events.ps1" ] || { echo "FAIL: get-uac-events.ps1 missing"; exit 1; }

# Runs and returns valid JSON (may be empty array if no events)
OUTPUT=$(powershell.exe -NoProfile -ExecutionPolicy Bypass -File src/ps/get-uac-events.ps1 -MaxEvents 5 -LastMinutes 5 2>&1) || true

# Accept empty output (no events), null, empty array, or valid JSON array/object
if [ -z "$OUTPUT" ] || [ "$OUTPUT" = "null" ] || [ "$OUTPUT" = "[]" ]; then
  echo "PASS: T002 (no events, valid empty response)"
  exit 0
fi

echo "$OUTPUT" | node -e "JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'))" 2>/dev/null || { echo "FAIL: output is not valid JSON"; exit 1; }

echo "PASS: T002 UAC event query"

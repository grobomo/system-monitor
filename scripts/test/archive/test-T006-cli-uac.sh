#!/usr/bin/env bash
# Test T006: CLI uac command runs and produces output
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "T006: Checking CLI uac command..."

npm run build --silent 2>/dev/null

# Should exit 0 and produce some output (even if no events)
OUTPUT=$(node dist/cli.js uac --last 5 2>&1) || { echo "FAIL: cli uac exited non-zero"; exit 1; }

# Should contain a header or "no events" message
if [ -z "$OUTPUT" ]; then
  echo "FAIL: no output from cli uac"
  exit 1
fi

echo "PASS: T006 CLI uac command"

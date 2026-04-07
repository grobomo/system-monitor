#!/usr/bin/env bash
# Test T007: JSON log writer writes and rotates UAC events
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "T007: Checking JSON log writer..."

npm run build --silent 2>/dev/null

# Use a temp dir to avoid polluting real config
TMPDIR=$(mktemp -d)
node -e "
const { UacLogWriter } = require('./dist/collectors/log-writer');
const path = require('path');
const fs = require('fs');
const logDir = '$TMPDIR'.replace(/\\\\/g, '/');
const writer = new UacLogWriter(logDir, 5); // max 5 entries for test

// Write 7 events
for (let i = 0; i < 7; i++) {
  writer.write({ timestamp: new Date().toISOString(), pid: i, exe: 'test.exe', commandLine: 'test', parentPid: 0, parentChain: [], attributedTo: null, elevated: true });
}

const data = JSON.parse(fs.readFileSync(path.join(logDir, 'uac-events.json'), 'utf8'));
if (data.length > 5) {
  console.error('FAIL: rotation failed, got ' + data.length + ' entries (max 5)');
  process.exit(1);
}
console.log('PASS: T007 JSON log writer (' + data.length + ' entries after rotation)');
"

rm -rf "$TMPDIR"

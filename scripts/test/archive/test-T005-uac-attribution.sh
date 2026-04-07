#!/usr/bin/env bash
# Test T005: UAC attribution traces elevation to Claude session or unknown
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "T005: Checking UAC attribution module..."

npm run build --silent 2>/dev/null

node -e "
const { attributeUacEvent } = require('./dist/collectors/uac-attribution');
// Mock: cmd.exe (elevated) spawned by bash.exe spawned by claude.exe
const processMap = new Map([
  [300, { pid: 300, ppid: 200, name: 'cmd.exe', commandLine: 'cmd /c net user', user: 'USER', startTime: '' }],
  [200, { pid: 200, ppid: 100, name: 'bash.exe', commandLine: 'bash', user: 'USER', startTime: '' }],
  [100, { pid: 100, ppid: 1, name: 'claude.exe', commandLine: 'claude --session-3', user: 'USER', startTime: '' }],
  [1, { pid: 1, ppid: 0, name: 'System', commandLine: '', user: 'SYSTEM', startTime: '' }],
]);
const result = attributeUacEvent({ pid: 300, parentPid: 200, exe: 'cmd.exe' }, processMap);
if (!result.attributedTo || !result.attributedTo.includes('claude')) {
  console.error('FAIL: should attribute to claude, got: ' + result.attributedTo);
  process.exit(1);
}

// Mock: unknown process not in Claude tree
const processMap2 = new Map([
  [999, { pid: 999, ppid: 500, name: 'malware.exe', commandLine: 'malware', user: 'USER', startTime: '' }],
  [500, { pid: 500, ppid: 1, name: 'explorer.exe', commandLine: 'explorer', user: 'USER', startTime: '' }],
]);
const result2 = attributeUacEvent({ pid: 999, parentPid: 500, exe: 'malware.exe' }, processMap2);
if (result2.attributedTo !== null) {
  console.error('FAIL: should be null (unattributed), got: ' + result2.attributedTo);
  process.exit(1);
}
console.log('PASS: T005 UAC attribution');
"

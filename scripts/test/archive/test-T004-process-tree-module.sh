#!/usr/bin/env bash
# Test T004: Process tree module maps PIDs to parent chains
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "T004: Checking process tree module..."

npm run build --silent 2>/dev/null

node -e "
const { buildProcessTree, getParentChain } = require('./dist/collectors/process-tree');
// Test with mock data
const procs = [
  { pid: 1, ppid: 0, name: 'System', commandLine: '', user: 'SYSTEM', startTime: '' },
  { pid: 100, ppid: 1, name: 'claude.exe', commandLine: 'claude', user: 'USER', startTime: '' },
  { pid: 200, ppid: 100, name: 'bash.exe', commandLine: 'bash', user: 'USER', startTime: '' },
  { pid: 300, ppid: 200, name: 'cmd.exe', commandLine: 'cmd /c something', user: 'USER', startTime: '' },
];
const tree = buildProcessTree(procs);
const chain = getParentChain(tree, 300);
if (chain.length < 3) { console.error('FAIL: parent chain too short'); process.exit(1); }
if (chain[0].name !== 'cmd.exe') { console.error('FAIL: chain[0] should be cmd.exe'); process.exit(1); }
console.log('PASS: T004 process tree module');
"

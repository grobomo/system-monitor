#!/usr/bin/env bash
# Test T001: Project skeleton exists and compiles
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "T001: Checking project skeleton..."

# Required files exist
for f in package.json tsconfig.json src/types/index.ts; do
  [ -f "$f" ] || { echo "FAIL: $f missing"; exit 1; }
done

# Required directories exist
for d in src src/collectors src/cli src/ps src/types tests scripts/test; do
  [ -d "$d" ] || { echo "FAIL: directory $d missing"; exit 1; }
done

# TypeScript compiles
npm install --silent 2>/dev/null
npx tsc --noEmit || { echo "FAIL: TypeScript compilation failed"; exit 1; }

echo "PASS: T001 project skeleton"

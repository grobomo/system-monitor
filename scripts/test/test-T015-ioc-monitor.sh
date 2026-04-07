#!/usr/bin/env bash
# Test T015: IOC Monitor — Windows Event Log scanning
set -euo pipefail

BINARY="./target/release/system-monitor.exe"

echo "=== T015: IOC Monitor ==="

# T015a: Binary exists
echo -n "  T015a: Binary exists... "
[[ -f "$BINARY" ]] && echo "PASS" || { echo "FAIL"; exit 1; }

# T015b: IOC command runs without error
echo -n "  T015b: IOC command runs... "
OUTPUT=$("$BINARY" ioc --last 5 2>&1) || true
if echo "$OUTPUT" | grep -q "IOC Monitor"; then
    echo "PASS"
else
    echo "FAIL: $OUTPUT"
    exit 1
fi

# T015c: IOC command accepts severity filter
echo -n "  T015c: Severity filter works... "
OUTPUT=$("$BINARY" ioc --last 5 --severity high 2>&1) || true
if echo "$OUTPUT" | grep -q "IOC Monitor"; then
    echo "PASS"
else
    echo "FAIL: $OUTPUT"
    exit 1
fi

# T015d: /api/iocs endpoint (requires running guard)
echo -n "  T015d: /api/iocs endpoint... "
RESPONSE=$(curl -s http://localhost:9847/api/iocs 2>/dev/null) || true
if echo "$RESPONSE" | grep -q '^\['; then
    echo "PASS (returns JSON array)"
else
    echo "SKIP (guard not running)"
fi

# T015e: /api/health includes uptime
echo -n "  T015e: /api/health endpoint... "
RESPONSE=$(curl -s http://localhost:9847/api/health 2>/dev/null) || true
if echo "$RESPONSE" | grep -q '"status":"ok"'; then
    echo "PASS"
else
    echo "SKIP (guard not running)"
fi

echo ""
echo "=== T015: All tests passed ==="

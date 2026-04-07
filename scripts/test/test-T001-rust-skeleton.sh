#!/usr/bin/env bash
# Test T001: Rust project skeleton exists and compiles
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "T001: Checking Rust project skeleton..."

# Required files
for f in Cargo.toml src/main.rs src/modules/mod.rs src/modules/process_tree.rs src/modules/classifier.rs src/modules/process_monitor.rs src/modules/daemon.rs; do
  [ -f "$f" ] || { echo "FAIL: $f missing"; exit 1; }
done

# Cargo build
export PATH="$HOME/.cargo/bin:$PATH"
cargo build 2>&1 || { echo "FAIL: cargo build failed"; exit 1; }

echo "PASS: T001 Rust project skeleton"

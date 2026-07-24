#!/usr/bin/env bash
set -euo pipefail

echo "=== Sentinel AI Test Script ==="
echo "Running workspace tests..."

cargo test --workspace 2>&1

echo "Done."

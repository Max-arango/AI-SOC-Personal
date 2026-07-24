#!/usr/bin/env bash
set -euo pipefail

echo "=== Sentinel AI Lint Script ==="
echo "Running clippy..."

cargo clippy --workspace -- -D warnings 2>&1

echo "Running fmt check..."
cargo fmt --all -- --check 2>&1

echo "Done."

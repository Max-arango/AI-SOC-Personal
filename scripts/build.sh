#!/usr/bin/env bash
set -euo pipefail

echo "=== Sentinel AI Build Script ==="
echo "Building release binaries..."

cargo build --release --workspace

echo "Done. Binaries in target/release/"
ls -lh target/release/sentinel-*

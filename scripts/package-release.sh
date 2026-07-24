#!/usr/bin/env bash
set -euo pipefail

echo "=== Sentinel AI Package Script ==="
echo "Packaging release artifacts..."

VERSION="${1:-0.1.0}"
RELEASE_DIR="target/release"
PACKAGE_DIR="dist/sentinel-ai-${VERSION}"

mkdir -p "$PACKAGE_DIR"

cp "$RELEASE_DIR/sentinel-core-service" "$PACKAGE_DIR/"
cp "$RELEASE_DIR/sentinel-cli" "$PACKAGE_DIR/" 2>/dev/null || true
cp docker/docker-compose.yml "$PACKAGE_DIR/"
cp docker/sentinel.toml "$PACKAGE_DIR/config.toml.default"
cp README.md "$PACKAGE_DIR/"

tar czf "dist/sentinel-ai-${VERSION}-linux-x86_64.tar.gz" -C dist "sentinel-ai-${VERSION}"

echo "Package created: dist/sentinel-ai-${VERSION}-linux-x86_64.tar.gz"

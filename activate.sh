#!/bin/bash
# ┌──────────────────────────────────────────────────────────────┐
# │          SENTINEL AI v0.2 — ACTIVATION SCRIPT               │
# │          One command to build, configure, and run.           │
# └──────────────────────────────────────────────────────────────┘
set -euo pipefail

SENTINEL_HOME="${SENTINEL_HOME:-$HOME/.config/sentinel}"
SENTINEL_DATA="${SENTINEL_DATA:-$HOME/.local/share/sentinel}"
SENTINEL_PORT="${SENTINEL_PORT:-50051}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           SENTINEL AI — System Activation                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Create directories ────────────────────────────
echo "[1/5] Creating directories..."
mkdir -p "$SENTINEL_HOME"
mkdir -p "$SENTINEL_HOME/rules/builtin"
mkdir -p "$SENTINEL_HOME/rules/custom"
mkdir -p "$SENTINEL_DATA"

# ── Step 2: Generate config ───────────────────────────────
echo "[2/5] Generating configuration..."
cat > "$SENTINEL_HOME/config.toml" << 'EOF'
[core]
host_id = "sentinel-local"
instance_name = "Sentinel AI"

[storage.sqlite]
path = "data/sentinel.db"
wal_mode = true

[grpc]
enabled = true
address = "127.0.0.1:50051"

[rule_engine]
rules_directories = ["rules/builtin", "rules/custom"]
worker_threads = 2

[ai_engine]
enabled = true
provider = "ollama"
model = "llama3.2:3b"
host = "localhost"
port = 11434

[collectors.process]
enabled = true
include_command_line = true
monitor_injection = true

[collectors.network]
enabled = true
capture_dns = true

[collectors.file]
enabled = true

[collectors.browser]
enabled = true

[collectors.usb]
enabled = true

[collectors.startup]
enabled = true

[privacy]
ai_local_only = true
telemetry_enabled = false
EOF

# ── Step 3: Copy rules ────────────────────────────────────
echo "[3/5] Copying SigmaHQ rules..."
if [ -d "rules" ] && [ "$(ls -A rules/*.yaml 2>/dev/null)" ]; then
    cp rules/*.yaml "$SENTINEL_HOME/rules/builtin/" 2>/dev/null || true
    echo "   Copied $(ls "$SENTINEL_HOME/rules/builtin/" | wc -l) rules"
else
    echo "   No rules directory found (run from project root)"
fi

# ── Step 4: Build (if needed) ─────────────────────────────
echo "[4/5] Building binary..."
if [ ! -f "target/release/sentinel-core-service" ]; then
    echo "   Building release (3-5 min)..."
    cargo build --release -p sentinel-core-service -p sentinel-cli
else
    echo "   Binary exists: $(ls -lh target/release/sentinel-core-service | awk '{print $5}')"
fi

# ── Step 5: Start daemon ──────────────────────────────────
echo "[5/5] Starting Sentinel AI daemon..."
echo ""
echo "   gRPC API:  127.0.0.1:$SENTINEL_PORT"
echo "   Config:    $SENTINEL_HOME/config.toml"
echo "   Rules:     $SENTINEL_HOME/rules/"
echo "   Data:      $SENTINEL_DATA/"
echo ""
echo "   Press Ctrl+C to stop."
echo ""

cd "$SENTINEL_HOME"
exec target/release/sentinel-core-service --config "$SENTINEL_HOME/config.toml" "$@" 2>&1 | head -200

# Getting Started — Sentinel AI

## Prerequisites

- **Linux** (Ubuntu 22.04+, Debian 12+, Arch/Artix)
- **Rust** 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **Node.js** 20+ (`curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install nodejs`)
- **Tauri system deps**: `webkit2gtk-4.1`, `libsoup3`, `gtk3`, `librsvg2` (see [Tauri docs](https://v2.tauri.app/start/prerequisites/))
- **Ollama** (optional, for AI features): `curl -fsSL https://ollama.ai/install.sh | sh`
- **sqlite3** CLI (for browser collector): already installed on most Linux distros

## Quick Install

```bash
git clone https://github.com/sentinel-ai/sentinel-ai
cd sentinel-ai
```

## Build & Run (Backend Daemon)

```bash
cargo build --release --workspace
cargo run --release --bin sentinel-core-service
```

The daemon starts on `127.0.0.1:7777` (gRPC API) and begins monitoring immediately.

## Build & Run (Desktop UI)

```bash
cd ui/tauri-app
npm install
npm run tauri dev
```

The desktop UI connects to the backend via Tauri IPC. If the daemon is running separately, data is read from the shared SQLite database.

## Your First Alert

1. Start the daemon: `cargo run --bin sentinel-core-service`
2. The process collector immediately starts monitoring processes (5s interval)
3. Other collectors start: network (30s), file (60s), startup (1h), browser (120s)
4. If any of the 50 rules fire, an alert is generated and persisted
5. Check the Dashboard (UI) or the SQLite database:

```bash
sqlite3 ~/.local/share/sentinel/sentinel.db "SELECT * FROM alerts LIMIT 5;"
```

## Enable AI Explanations

```bash
# Option 1: Local Ollama (default)
ollama pull llama3.2:3b
export SENTINEL_AI_PROVIDER=ollama
cargo run --bin sentinel-core-service

# Option 2: OpenRouter (free tier available)
export SENTINEL_AI_PROVIDER=openrouter
export SENTINEL_AI_API_KEY=sk-or-v1-your-key
cargo run --bin sentinel-core-service

# Option 3: OpenAI
export SENTINEL_AI_PROVIDER=openai
export SENTINEL_AI_API_KEY=sk-your-key
cargo run --bin sentinel-core-service
```

## Enable Threat Intel

```bash
# All are optional and free-tier
export SENTINEL_ABUSEIPDB_API_KEY=your-key
export SENTINEL_SHODAN_API_KEY=your-key
export SENTINEL_VIRUSTOTAL_API_KEY=your-key
export SENTINEL_OTX_API_KEY=your-key
```

## Enable Notifications

```bash
export SENTINEL_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
export SENTINEL_TELEGRAM_BOT_TOKEN=123:abc
export SENTINEL_TELEGRAM_CHAT_ID=-100123
export SENTINEL_SLACK_WEBHOOK=https://hooks.slack.com/...
export SENTINEL_EMAIL_TO=admin@example.com
```

## Docker Quick Start

```bash
docker compose -f docker/docker-compose.yml up -d
```

Starts 6 services:
- `sentinel-core`: daemon with hot-reload
- `ollama`: local LLM (GPU accelerated if NVIDIA available)
- `prometheus`: metrics collection
- `grafana`: dashboards (default admin/admin)
- `loki`: log aggregation
- `promtail`: log shipping

## Directory Layout

| Path | Purpose |
|---|---|
| `~/.local/share/sentinel/sentinel.db` | SQLite database |
| `~/.config/sentinel/config.toml` | Configuration |
| `~/.config/sentinel/geoip/` | MaxMind GeoIP databases |
| `~/.config/sentinel/iocs/` | Custom IOC files (.csv, .json) |
| `rules/` | Detection rules (YAML) |
| `logs/` | Application logs (JSON) |

## Next Steps

- [Configuration](configuration.md) — full config reference
- [Collectors](collectors.md) — how each collector works
- [Rules](rules.md) — write custom detection rules
- [Plugins](plugins.md) — create new plugins

# Sentinel AI

[![CI](https://github.com/Max-arango/AI-SOC-Personal/actions/workflows/ci.yml/badge.svg)](https://github.com/Max-arango/AI-SOC-Personal/actions/workflows/ci.yml)

A local-first, privacy-preserving AI Security Assistant for personal computers.

## Demo

[![asciicast](https://asciinema.org/a/EdR50d7JtGf2lmtM.svg)](https://asciinema.org/a/EdR50d7JtGf2lmtM)

> Watch: architecture walkthrough, collectors, plugins, tests, and quick start in 30 seconds.

Or replay locally:
```bash
asciinema play docs/demo.cast
```

## Architecture

Sentinel AI follows a modular, event-driven architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Sentinel AI                               │
├─────────────────────────────────────────────────────────────────┤
│  Tauri UI (React)  ◄─── gRPC/IPC ───►  Core Service (Rust)      │
│                                                            │      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Event Bus (Tokio channels, zero-copy, backpressure)       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                    ▲                    ▲                         │
│          ┌─────────┴─────────┐   ┌───────┴────────┐             │
│          ▼                   ▼   ▼                ▼             │
│   ┌──────────┐         ┌──────────┐       ┌──────────┐         │
│   │ Collectors│        │Rule Engine│       │AI Engine │         │
│   │(7 types) │         │  (CEL)    │       │(Ollama)  │         │
│   └──────────┘         └──────────┘       └──────────┘         │
│          ▲                   ▲                   ▲              │
│          └───────────────────┼───────────────────┘              │
│                              ▼                                  │
│                    ┌──────────────────┐                         │
│                    │ Correlation Eng. │                         │
│                    └──────────────────┘                         │
│                              ▲                                  │
│                              ▼                                  │
│                    ┌──────────────────┐                         │
│                    │   Risk Engine    │                         │
│                    └──────────────────┘                         │
│                              ▲                                  │
│                              ▼                                  │
│                    ┌──────────────────┐                         │
│                    │  Plugin Manager  │                         │
│                    └──────────────────┘                         │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### Core Crates
- **sentinel-core** - Shared types, traits, errors, metrics, health
- **sentinel-events** - Protocol Buffers event definitions
- **sentinel-config** - TOML configuration with validation, hot-reload, secrets
- **sentinel-storage** - SQLite (metadata) + DuckDB (analytics)
- **sentinel-event-bus** - High-performance in-memory pub/sub
- **sentinel-rule-engine** - CEL-based rule evaluation
- **sentinel-correlation** - Causal, flow, behavioral correlation
- **sentinel-risk** - SIEM-grade risk scoring with temporal decay
- **sentinel-ai** - Local LLM integration (Ollama/llama.cpp)
- **sentinel-plugins** - Process-isolated plugin system
- **sentinel-collectors** - 7 OS telemetry collectors

### Collectors
1. **Process** - ETW/auditd/EndpointSecurity
2. **Network** - ETW/eBPF/EndpointSecurity + JA3
3. **File** - USN/fanotify/FSEvents + hashes/entropy
4. **Registry** - Windows callbacks (Windows only)
5. **USB** - udev/IOKit/WM_DEVICECHANGE
6. **Browser** - Native messaging + SQLite
7. **Startup** - systemd/launchd/cron/registry

### UI (Tauri + React)
- Real-time dashboard with risk timeline
- Events explorer with advanced filtering
- Alert management with AI explanations
- Process tree visualization
- Network connection map
- File activity timeline
- MITRE ATT&CK heatmap
- AI chat assistant
- Plugin management
- Settings editor with validation

## Quick Start

### Prerequisites
- Rust 1.75+
- Node.js 20+
- Tauri CLI (`cargo install tauri-cli`)
- Ollama (for AI features): `curl -fsSL https://ollama.ai/install.sh | sh`

### Build
```bash
# Clone
git clone https://github.com/Max-arango/AI-SOC-Personal
cd sentinel-ai

# Build core (Rust)
cargo build --release --workspace

# Build UI
cd ui/tauri-app
npm install
npm run tauri build
```

### Development
```bash
# Terminal 1: Rust backend
cargo run --bin sentinel-core-service

# Terminal 2: Frontend
cd ui/tauri-app
npm run dev
```

## Configuration

Main config at `/etc/sentinel/config.toml` (system) or `~/.config/sentinel/config.toml` (user):

```toml
[core]
host_id = ""           # Auto-generated
instance_name = "Sentinel AI"

[grpc]
enabled = true
address = "127.0.0.1:50051"

[ai_engine]
enabled = true
provider = "ollama"
model = "llama-3.2-3b-instruct"

[collectors.process]
enabled = true
monitor_injection = true

[collectors.network]
enabled = true
capture_tls_fingerprints = true

[privacy]
ai_local_only = true
telemetry_enabled = false
```

## Plugin System

Plugins run in isolated processes with capability-based permissions:

```yaml
# plugin.yaml
plugin:
  id: "virustotal"
  name: "VirusTotal Integration"
  capabilities:
    - "event:read"
    - "network:http"
    - "secret:read"
  config_schema:
    api_key:
      type: "string"
      format: "password"
```

Built-in plugins: VirusTotal, AbuseIPDB, Shodan, OTX, GreyNoise, URLhaus,
GeoIP, IOC, Discord, Telegram, Slack, Email, Home Assistant.

## API

gRPC API on `127.0.0.1:50051` with 35 endpoints:
- Health, version, status
- Events: query, get, list processes
- Alerts: list, get, update state, stream
- Rules: CRUD + test
- Attack chains: list, detail
- Configuration: get, update
- Plugins: list, get, configure
- Collectors: list, status, restart

## Security

- **Local-first**: No data leaves your machine without explicit consent
- **Process isolation**: Plugins run in separate processes with seccomp/AppContainer
- **Capability model**: Fine-grained permissions per plugin
- **Encrypted secrets**: Age encryption for API keys
- **Signed binaries**: All releases signed and notarized
- **Reproducible builds**: Verifiable build artifacts

## License

MIT OR Apache-2.0
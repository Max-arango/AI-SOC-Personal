# Architecture — Sentinel AI

## System Overview

Sentinel AI follows a modular, event-driven architecture within a single process (with optional Management Server for multi-host). All data flows from collectors through a processing pipeline, stored in SQLite/DuckDB, and exposed via gRPC API and Tauri UI.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Sentinel AI System                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │   Tauri UI   │◄───│  gRPC/IPC    │◄───│   Core Service       │   │
│  │  (React/TS)  │    │   Layer      │    │   (Orchestrator)     │   │
│  └──────────────┘    └──────────────┘    └──────────┬───────────┘   │
│                                                      │               │
│                          ┌───────────────────────────┼──────────┐   │
│                          ▼                           ▼          ▼   │
│                 ┌────────────────┐      ┌────────────────┐        │
│                 │  Event Bus     │      │  Rule Engine   │        │
│                 │  (tokio mpsc)  │      │  (CEL)         │        │
│                 └───────┬────────┘      └───────┬────────┘        │
│                         │                       │                  │
│         ┌───────────────┼───────────────┐       │                  │
│         ▼               ▼               ▼       ▼                  │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐      │
│  │  Process   │ │  Network   │ │   File     │ │  Browser   │      │
│  │ Collector  │ │ Collector  │ │ Collector  │ │ Collector  │      │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘      │
│         │               │               │               │          │
│         └───────────────┼───────────────┼───────────────┘          │
│                         ▼               ▼                           │
│                 ┌────────────┐ ┌────────────┐                      │
│                 │  Startup   │ │  Threat    │                      │
│                 │ Collector  │ │  Intel     │                      │
│                 └────────────┘ └────────────┘                      │
│                          │                │                         │
│                          └────────────────┘                         │
│                                   ▼                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Processing Pipeline                       │   │
│  │                                                              │   │
│  │  Event → Threat Intel → Correlation → Rules → Risk → Alerts  │   │
│  │    │          │              │          │       │      │      │   │
│  │    │    AbuseIPDB       Causal     CEL eval  Score  Notify  │   │
│  │    │    Shodan          Temporal   Match     Decay  Store   │   │
│  │    │    OTX             Flow                 Alert   AI     │   │
│  │    │    GeoIP                                 Dedup  Explain│   │
│  │    │    IOC                                                   │   │
│  │    │    VirusTotal                                              │   │
│  │    ▼                                                           │   │
│  │  ┌──────────────────┐    ┌──────────────────┐                  │   │
│  │  │  SQLite          │    │  DuckDB          │                  │   │
│  │  │  (metadata)      │    │  (analytics)     │                  │   │
│  │  └──────────────────┘    └──────────────────┘                  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Collection

Collectors gather telemetry from the operating system:

| Collector | Source | Interval | Events |
|---|---|---|---|
| Process | `/proc` (Linux) / sysinfo (cross-platform) | 5s | `sentinel.process.create`, `.terminate` |
| Network | `/proc/net/tcp`, `/proc/net/udp` | 30s | `sentinel.network.connect` |
| File | Filesystem polling (`/etc`, `/tmp`, `/var/log`) | 60s | `sentinel.file.create`, `.modify` |
| Startup | systemd, cron, shell profiles, XDG autostart | 1h | `sentinel.startup.add` |
| Browser | Chrome/Firefox SQLite databases | 120s | `sentinel.browser.navigation`, `.download`, `.extension_install` |

### 2. Event Bus

Events are published to an in-memory pub/sub bus via `tokio::mpsc` channels:

```
Collector → event_tx → Topic Router → Subscribers
                                     ├── Rule Engine
                                     ├── Correlation Engine
                                     └── Storage Writer
```

### 3. Threat Intel Enrichment

Before entering the processing pipeline, events are enriched with external threat intelligence:

- **Network events**: AbuseIPDB, Shodan, OTX, GeoIP, IOC lookups (parallel via `tokio::join!`)
- **Process events**: VirusTotal hash lookup (if SHA256 available)
- **All events**: IOC local database check

Enrichment modifies the event's `risk_score` and adds `tags`.

### 4. Privacy Filter

The `PrivacyEngine` sanitizes events before they enter correlation/rules/storage:

- Command lines: redacted (passwords, tokens, API keys removed)
- File paths: anonymized (`$HOME` prefix)
- Usernames: hashed (SHA256)
- IPs: anonymized (last octets masked) in enterprise mode

Configurable per field: Full, Redacted, Anonymized, Hashed, None.

### 5. Processing Pipeline

```
sanitized_event
  → Correlation Engine (causal/temporal/flow chains)
  → Rule Engine (CEL evaluation, 50 rules)
  → Risk Engine (scoring, decay, dedup, threshold alerts)
  → Alert Manager (persist to SQLite)
  → AI Engine (Ollama/OpenRouter/OpenAI explanation)
  → Notification Plugins (Discord, Telegram, Email, Slack, HA)
```

### 6. Storage

| Database | Purpose | Format |
|---|---|---|
| **SQLite** | Metadata: events, alerts, rules, config | WAL mode, row-based |
| **DuckDB** | Analytics: aggregations, timelines, stats | Columnar, embedded |

### 7. API Layer

- **gRPC API** (`sentinel-api`): 30+ RPCs for health, events, processes, network, alerts, rules, config, plugins
- **Tauri IPC**: Direct Rust→React communication for the desktop UI

### 8. UI

- **Tauri v2** desktop app with React/TypeScript
- **Dashboard**: real-time stats, process tree, risk timeline, MITRE heatmap, network map
- **Events**: infinite virtual scroll with filtering
- **Alerts**: CRUD with state management
- **AI Chat**: conversational security assistant

## Repository Structure

```
sentinel-ai/
├── apps/
│   ├── sentinel-core-service/   # Main daemon binary
│   ├── sentinel-cli/            # CLI tool (import-sigma, health)
│   └── sentinel-mgmt/           # Management Server (multi-host)
├── crates/
│   ├── sentinel-core/           # Shared types, traits, errors
│   ├── sentinel-events/         # Protobuf event definitions
│   ├── sentinel-config/         # TOML config, validation, hot-reload
│   ├── sentinel-storage/        # SQLite + DuckDB
│   ├── sentinel-event-bus/      # In-memory pub/sub
│   ├── sentinel-rule-engine/    # CEL-based rule evaluation
│   ├── sentinel-correlation/    # Causal/temporal/flow chains
│   ├── sentinel-risk/           # SIEM-grade risk scoring
│   ├── sentinel-ai/             # Ollama/OpenRouter/OpenAI
│   ├── sentinel-plugins/        # Plugin framework
│   ├── sentinel-api/            # gRPC server
│   ├── sentinel-privacy/        # PrivacyFilter + anonymization
│   ├── sentinel-sigma/          # Sigma rule importer
│   ├── sentinel-os-common/      # OS abstraction (stub)
│   ├── sentinel-os-linux/       # Linux abstraction (stub)
│   ├── sentinel-os-windows/     # Windows abstraction (stub)
│   ├── sentinel-os-macos/       # macOS abstraction (stub)
│   └── sentinel-test-utils/     # Test utilities (stub)
├── collectors/
│   └── src/
│       ├── framework/           # CollectorManager
│       ├── process/             # Process collector (sysinfo)
│       ├── network/             # Network collector (/proc/net)
│       ├── file/                # File collector (polling)
│       ├── startup/             # Startup collector (systemd/cron)
│       └── browser/             # Browser collector (SQLite)
├── plugins/
│   ├── discord/                 # Webhook notifications
│   ├── telegram/                # Bot notifications
│   ├── email/                   # sendmail SMTP
│   ├── slack/                   # Webhook Block Kit
│   ├── home-assistant/          # REST API + sensor
│   ├── virustotal/              # Hash/URL lookup
│   ├── abuseipdb/               # IP reputation
│   ├── shodan/                  # Host scan
│   ├── otx/                     # AlienVault pulses
│   ├── geoip/                   # MaxMind local
│   └── ioc/                     # CSV/STIX local indicators
├── proto/                       # Protocol Buffers
├── rules/                       # 50 YAML detection rules
├── ui/tauri-app/                # Tauri + React frontend
├── docker/                      # Docker Compose (6 services)
├── scripts/                     # Build, test, lint, package
├── docs/                        # Documentation
└── tests/                       # Integration tests
```

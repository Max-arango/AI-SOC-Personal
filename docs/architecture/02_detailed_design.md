let mut errors = ValidationErrors::new();
        
        if self.graceful_shutdown_timeout == 0 {
            errors.add("graceful_shutdown_timeout", ValidationError::new("must be > 0"));
        }
        if self.max_memory_mb < 64 {
            errors.add("max_memory_mb", ValidationError::new("minimum 64 MB"));
        }
        if self.max_cpu_percent == 0 || self.max_cpu_percent > 100 {
            errors.add("max_cpu_percent", ValidationError::new("must be 1-100"));
        }
        
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(())
    }
}

// Hot-reload with validation
impl ConfigManager {
    async fn reload(&self) -> Result<(), ConfigError> {
        let new_config = self.load_and_validate().await?;
        
        // Validate against current running state
        self.validate_transition(&self.current_config, &new_config).await?;
        
        // Atomic swap
        let old = self.current_config.swap(Arc::new(new_config));
        
        // Notify all modules
        self.notify_modules(&*self.current_config.load()).await;
        
        Ok(())
    }
}
```

---

## 13. Repository Organization

### 13.1 Monorepo Structure (Cargo Workspace)

```
sentinel-ai/
├── Cargo.toml                    # Workspace root
├── Cargo.lock
├── rust-toolchain.toml           # Pinned toolchain
├── .github/
│   ├── workflows/                # CI/CD
│   └── actions/                  # Custom actions
├── docs/
│   ├── architecture/             # This documentation
│   ├── api/                      # API reference (generated)
│   ├── user-guide/
│   └── developer-guide/
├── crates/                       # Internal libraries (published optionally)
│   ├── sentinel-core/            # Core types, traits, errors
│   ├── sentinel-events/          # Event definitions (Protobuf + Rust)
│   ├── sentinel-config/          # Config loading, validation, schemas
│   ├── sentinel-storage/         # Storage abstractions, repositories
│   ├── sentinel-event-bus/       # Event bus implementation
│   ├── sentinel-rule-engine/     # Rule engine (CEL-based)
│   ├── sentinel-correlation/     # Correlation engine
│   ├── sentinel-risk/            # Risk engine
│   ├── sentinel-ai/              # AI engine, context building
│   ├── sentinel-plugins/         # Plugin SDK, host, manager
│   ├── sentinel-collectors/      # Collector framework + base traits
│   ├── sentinel-os-windows/      # Windows OS abstractions
│   ├── sentinel-os-linux/        # Linux OS abstractions
│   ├── sentinel-os-macos/        # macOS OS abstractions
│   ├── sentinel-os-common/       # Cross-platform abstractions
│   ├── sentinel-api/             # gRPC service definitions + server
│   ├── sentinel-tui/             # Terminal UI (optional)
│   └── sentinel-test-utils/      # Testing utilities, fixtures
├── apps/
│   ├── sentinel-core-service/    # Main daemon binary
│   ├── sentinel-cli/             # CLI tool (control, query, debug)
│   └── sentinel-installer/       # Installer builder
├── collectors/                   # Collector implementations (separate crates)
│   ├── process-collector/
│   ├── network-collector/
│   ├── file-collector/
│   ├── registry-collector/
│   ├── usb-collector/
│   ├── browser-collector/
│   └── startup-collector/
├── plugins/                      # Official plugins
│   ├── virustotal/
│   ├── abuseipdb/
│   ├── shodan/
│   ├── discord/
│   ├── telegram/
│   ├── slack/
│   ├── email/
│   └── home-assistant/
├── ui/
│   ├── tauri-app/                # Tauri + React frontend
│   │   ├── src/
│   │   ├── src-tauri/
│   │   └── package.json
│   └── shared-components/        # Shared React components
├── scripts/
│   ├── build.sh
│   ├── test.sh
│   ├── lint.sh
│   ├── fmt.sh
│   ├── generate-proto.sh
│   ├── generate-docs.sh
│   ├── package-deb.sh
│   ├── package-rpm.sh
│   ├── package-msi.sh
│   └── release.sh
├── tests/
│   ├── integration/              # End-to-end tests
│   ├── fixtures/                 # Test data (pcaps, event logs)
│   ├── mocks/                    # Mock implementations
│   └── benchmarks/               # Performance benchmarks
├── docker/
│   ├── Dockerfile.dev
│   ├── Dockerfile.prod
│   └── docker-compose.yml
├── packaging/
│   ├── debian/
│   ├── rpm/
│   ├── msi/
│   ├── dmg/
│   └── arch/
├── .cargo/
│   └── config.toml               # Cargo configuration
├── clippy.toml                   # Clippy lints
├── rustfmt.toml                  # Rustfmt config
├── deny.toml                     # Cargo deny (license, security)
└── README.md
```

### 13.2 Crate Dependency Graph

```
sentinel-core-service (binary)
    │
    ├── sentinel-api (gRPC server)
    │       │
    │       ├── sentinel-core
    │       ├── sentinel-events
    │       ├── sentinel-config
    │       ├── sentinel-storage
    │       ├── sentinel-event-bus
    │       ├── sentinel-rule-engine
    │       ├── sentinel-correlation
    │       ├── sentinel-risk
    │       ├── sentinel-ai
    │       ├── sentinel-plugins
    │       └── sentinel-collectors
    │
    ├── sentinel-cli (binary)
    │       │
    │       ├── sentinel-api (client)
    │       └── sentinel-core
    │
    └── collectors/* (dynamic libraries loaded at runtime)
            │
            ├── sentinel-collectors (framework)
            ├── sentinel-events
            ├── sentinel-core
            └── sentinel-os-{windows,linux,macos}
```

### 13.3 Cargo Workspace Configuration

```toml
# Cargo.toml (workspace root)
[workspace]
resolver = "2"
members = [
    "crates/*",
    "apps/*",
    "collectors/*",
    "plugins/*",
    "ui/tauri-app",
]
exclude = [
    "target",
    "ui/tauri-app/node_modules",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT OR Apache-2.0"
repository = "https://github.com/sentinel-ai/sentinel-ai"
authors = ["Sentinel AI Team <team@sentinel-ai.dev>"]
categories = ["security", "system-tools", "monitoring"]
keywords = ["security", "edr", "siem", "monitoring", "ai"]

[workspace.dependencies]
# Core
tokio = { version = "1.38", features = ["full", "tracing"] }
tracing = { version = "0.1", features = ["std"] }
tracing-subscriber = { version = "0.3", features = ["env-filter", "json", "fmt"] }
anyhow = "1.0"
thiserror = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_toml = "0.8"
config = { version = "0.14", features = ["toml", "watch"] }
notify = "6.1"

# gRPC/Protobuf
tonic = "0.10"
prost = "0.12"
prost-types = "0.12"
tonic-reflection = "0.10"

# CEL (Rule Engine)
cel = { version = "0.3", features = ["rust"] }

# Storage
sqlx = { version = "0.7", features = ["runtime-tokio", "sqlite", "chrono", "uuid"] }
duckdb = { version = "0.9", features = ["bundled"] }

# OS Abstraction
windows = { version = "0.58", features = ["Win32_Foundation", "Win32_System_Threading", "Win32_System_Diagnostics", "Win32_Security", "Win32_Storage_FileSystem"], target = "cfg(windows)" }
libc = { version = "0.2", target = "cfg(not(windows))" }
nix = { version = "0.27", target = "cfg(target_os = 'linux')" }

# Crypto/Hashing
blake3 = "1.5"
sha2 = "0.10"
ring = "0.17"

# AI
ollama-rs = "0.5"
tokenizers = "0.15"

# Plugin System
libloading = "0.8"
capnp = "0.18"  # For capability tokens

# Testing
tempfile = "3.5"
mockall = "0.12"
proptest = "1.0"

[workspace.lints.rust]
unused_crate_dependencies = "warn"
unused_imports = "warn"
dead_code = "warn"

[workspace.lints.clippy]
all = "warn"
pedantic = "warn"
nursery = "warn"
cargo = "warn"
```

### 13.4 Build & Release Pipeline

```yaml
# .github/workflows/ci.yml (simplified)
name: CI

on: [push, pull_request]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Check formatting
        run: cargo fmt --all -- --check
      - name: Lint
        run: cargo clippy --all-targets --all-features -- -D warnings
      - name: Check docs
        run: cargo doc --all --no-deps --document-private-items

  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Install dependencies
        run: |
          # OS-specific deps (llvm, protobuf, etc.)
      - name: Test
        run: cargo test --all --locked
      - name: Test integration
        run: cargo test --test integration --locked

  build:
    needs: [check, test]
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Build release
        run: cargo build --release --locked --bins
      - name: Build UI
        run: |
          cd ui/tauri-app
          npm ci
          npm run build
      - name: Package
        run: ./scripts/package-${{ runner.os }}.sh
      - name: Upload artifacts
        uses: actions/upload-artifact@v4

  release:
    needs: build
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Download artifacts
      - name: Create release
        uses: softprops/action-gh-release@v1
      - name: Publish to crates.io (optional)
        run: cargo publish --all
```

---

## 14. Roadmap

### 14.1 Version Strategy

| Version | Focus | Stability | Timeline |
|---------|-------|-----------|----------|
| **v0.1** | Foundation: Core, Process Collector, Rule Engine, Basic UI | Alpha | Month 1-2 |
| **v0.2** | Network, File Collectors, Correlation, Risk Engine | Alpha | Month 3-4 |
| **v0.3** | Registry, USB, Startup Collectors, AI Engine, Plugins | Beta | Month 5-6 |
| **v0.5** | Browser Collector, Threat Intel, Full Plugin SDK, Performance | Beta | Month 7-9 |
| **v1.0** | Production Ready: Stability, Docs, Packaging, Migration | Stable | Month 10-12 |
| **v2.0** | Multi-host, Cloud Sync (optional), Advanced ML, Enterprise | Stable | Year 2 |

### 14.2 Detailed Milestones

#### v0.1 - Foundation (Months 1-2)
**Goal:** Running daemon collecting process events, evaluating rules, showing alerts in UI.

| Task | Owner | Deliverable |
|------|-------|-------------|
| Workspace setup, CI/CD | Platform | Building monorepo |
| Core service lifecycle | Backend | Start/stop/health |
| Event bus (tokio channels) | Backend | Pub/sub with backpressure |
| Process Collector (Windows) | Backend | ETW-based process create/terminate |
| Process Collector (Linux) | Backend | auditd/netlink process events |
| Process Collector (macOS) | Backend | Endpoint Security process events |
| Protocol Buffers event schema | Backend | Generated Rust/TS/Go |
| SQLite + DuckDB storage | Backend | Persistence layer |
| Rule Engine (CEL) | Backend | Load YAML, evaluate, hot-reload |
| Basic rules (10 built-in) | Security | PowerShell, WMI, Scheduled Tasks |
| gRPC API (core methods) | Backend | Health, Events, Processes, Rules |
| Tauri app shell | Frontend | Window, navigation, theme |
| Dashboard (events, alerts) | Frontend | Real-time table, filters |
| Settings page | Frontend | Config editor, validation |
| Installer (MSI, DEB, DMG) | Platform | Signed packages |

**Exit Criteria:** Daemon runs as service, UI connects, shows process events, rules fire, alerts appear.

#### v0.2 - Telemetry Expansion (Months 3-4)
**Goal:** Network + File visibility, correlation, risk scoring.

| Task | Owner | Deliverable |
|------|-------|-------------|
| Network Collector (all OS) | Backend | Connections, DNS, HTTP, TLS JA3 |
| File Collector (all OS) | Backend | Create/modify/delete/execute, hashes |
| Correlation Engine | Backend | Causal, temporal, flow correlation |
| Attack Chain detection | Backend | MITRE tactic chaining |
| Risk Engine | Backend | Scoring, decay, thresholds, alerts |
| Alert management API | Backend | List, acknowledge, investigate |
| Risk dashboard | Frontend | Timeline, top risks, MITRE heatmap |
| Process tree view | Frontend | Interactive graph |
| Network connections view | Frontend | Map, geoip, JA3 |
| File activity timeline | Frontend | Hash lookup, entropy |
| 30 built-in rules | Security | MITRE-covered detection rules |
| Integration tests | QA | E2E scenarios |

**Exit Criteria:** Full process/network/file visibility, correlated chains, risk scores, alert workflow.

#### v0.3 - Completeness & AI (Months 5-6)
**Goal:** All collectors, AI explanations, plugin system.

| Task | Owner | Deliverable |
|------|-------|-------------|
| Registry Collector (Windows) | Backend | Run keys, services, BHO |
| USB Collector (all OS) | Backend | Device connect, mass storage, HID |
| Startup Collector (all OS) | Backend | systemd, launchd, cron, registry |
| AI Engine integration | Backend | Ollama/llama.cpp client |
| Context builder | Backend | Anonymized summaries |
| Alert explanation | AI | Plain English, actions, investigation |
| Chat interface | Frontend | Conversational security assistant |
| Plugin Manager | Backend | Load, configure, sandbox |
| Plugin SDK (Rust) | Platform | Host SDK, examples |
| VirusTotal plugin | Security | Hash/URL reputation |
| Discord/Telegram/Slack plugins | Community | Notifications |
| Email plugin | Community | SMTP alerts |
| Home Assistant plugin | Community | Entity integration |
| Performance optimization | Backend | <5% CPU, <100MB RAM |
| Resource monitoring | Backend | Self-metrics, backpressure |

**Exit Criteria:** Feature-complete collectors, AI explains alerts, plugins work, resource targets met.

#### v0.5 - Hardening & Extensibility (Months 7-9)
**Goal:** Browser collector, threat intel, production hardening.

| Task | Owner | Deliverable |
|------|-------|-------------|
| Browser Collector | Backend | History, downloads, extensions |
| Native messaging hosts | Backend | Chrome, Firefox, Edge |
| Threat Intelligence framework | Backend | Local IOCs, API providers |
| AbuseIPDB/Shodan/OTX plugins | Security | IP reputation, host intel |
| Sigma rule importer | Security | Convert Sigma → CEL |
| Rule testing framework | Platform | Unit tests for rules |
| Migration system | Backend | Config/schema migrations |
| Backup/restore | Backend | Encrypted export/import |
| Offline mode | Backend | Full operation without network |
| Accessibility (a11y) | Frontend | WCAG 2.1 AA |
| Localization (i18n) | Frontend | EN, ES, FR, DE, PT, JA |
| Comprehensive docs | Docs | User, admin, developer guides |
| Security audit | Security | Third-party review |
| Fuzzing harness | QA | Continuous fuzzing |

**Exit Criteria:** Browser telemetry, threat intel, production-grade reliability, documented.

#### v1.0 - Production Release (Months 10-12)
**Goal:** Stable API, long-term support, enterprise readiness.

| Task | Owner | Deliverable |
|------|-------|-------------|
| API stability guarantee | Platform | v1 API frozen |
| Semantic versioning policy | Platform | Documented |
| LTS branch | Platform | 2-year support |
| Windows service hardening | Backend | Recovery, watchdog |
| Linux systemd hardening | Backend | Capabilities, seccomp |
| macOS launchd hardening | Backend | Sandbox, notarization |
| Code signing (all binaries) | Platform | EV certificates |
| Reproducible builds | Platform | Verifiable artifacts |
| SBOM generation | Security | CycloneDX/SPDX |
| Vulnerability scanning | Security | CI integration |
| Performance benchmarks | Backend | Published baselines |
| Upgrade testing | QA | v0.x → v1.0 migration |
| Enterprise features | Backend | Multi-user, RBAC (planning) |

**Exit Criteria:** Signed, notarized, reproducible, documented, supported.

#### v2.0 - Platform Evolution (Year 2)
**Goal:** Multi-host, advanced analytics, enterprise.

| Area | Vision |
|------|--------|
| **Multi-Host** | Central management console, fleet queries, cross-host correlation |
| **Cloud Sync (Optional)** | Encrypted backup, shared threat intel, remote UI (user-controlled) |
| **Advanced ML** | On-device anomaly detection (isolation forests, autoencoders) |
| **EDR Features** | Response actions (kill, quarantine, isolate), remote shell |
| **Compliance** | CIS benchmarks, STIG, GDPR reporting |
| **Integration** | SIEM connectors (Splunk, Elastic, Sentinel), SOAR |
| **Plugin Marketplace** | Signed, reviewed, auto-update |
| **Mobile Companion** | Read-only dashboard, push alerts |

---

## Appendix A: Technology Decisions Log

| Decision | Options Considered | Choice | Rationale |
|----------|-------------------|--------|-----------|
| **Language** | Rust, Go, C++, Zig | Rust | Memory safety, performance, ecosystem, no runtime |
| **Async Runtime** | tokio, async-std, smol | tokio | Ecosystem, performance, maturity |
| **Event Bus** | tokio channels, crossbeam, ZeroMQ, NATS | tokio channels | Zero-copy, in-process, backpressure, no deps |
| **Serialization** | JSON, CBOR, MessagePack, Protobuf | Protobuf | Schema-first, versioning, zero-copy, performance |
| **Rule Language** | CEL, YARA, Sigma, Custom DSL, Rust | CEL | Safe, fast, expressive, tooling, Google-backed |
| **Config Format** | TOML, YAML, JSON, HCL | TOML | Human-readable, typed, comments, Rust-native |
| **Primary DB** | SQLite, RocksDB, Sled, Redb | SQLite | Mature, SQL, WAL, backup, tooling |
| **Analytics DB** | DuckDB, ClickHouse, Apache Arrow | DuckDB | Embedded, OLAP, SQL, Parquet, no server |
| **UI Framework** | Tauri, Electron, Wry, Dioxus | Tauri | Small, native, Rust backend, WebView2/WebKit |
| **Frontend** | React, Svelte, Solid, Leptos | React | Ecosystem, hiring, Tauri integration |
| **AI Runtime** | Ollama, llama.cpp, ONNX, custom | Ollama + llama.cpp | Local-first, model management, hardware accel |
| **Plugin Isolation** | In-proc (dlopen), WASM, Process | Process | Security, language-agnostic, crash isolation |
| **Plugin Protocol** | gRPC, JSON-RPC, Cap'n Proto | gRPC | Schema, streaming, auth, ecosystem |
| **OS Abstraction** | Custom, custody, pelite | Custom traits | Control, testability, no-op mocks |
| **Logging** | tracing, log, slog | tracing | Structured, spans, OpenTelemetry ready |
| **Metrics** | Prometheus, statsd, custom | Prometheus | Standard, exposition format, Grafana |
| **Packaging** | cargo-deb, cargo-msi, cargo-bundle | Custom scripts | Control, signing, multi-platform |

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **Collector** | Independent module that gathers telemetry from OS and publishes events |
| **Event Bus** | In-memory pub/sub system routing events from collectors to engines |
| **Rule Engine** | Evaluates CEL expressions against events to detect patterns |
| **Correlation Engine** | Builds causal/temporal/flow/behavioral links between events |
| **Risk Engine** | Aggregates rule matches into scored risk with temporal decay |
| **Attack Chain** | Correlated sequence of events mapping to MITRE ATT&CK tactics |
| **AI Engine** | Local LLM integration for explanation, summarization, recommendation |
| **Plugin** | External process extending functionality via gRPC protocol |
| **Capability** | Fine-grained permission granted to plugins (event:read, network:http, etc.) |
| **Sandbox** | OS-level isolation for plugin processes |
| **MITRE ATT&CK** | Adversary tactic/technique framework used for classification |
| **JA3/JA3S** | TLS client/server fingerprinting for threat identification |
| **ULID** | Universally Unique Lexicographically Sortable Identifier (timestamp + entropy) |
| **CEL** | Common Expression Language - safe, fast expression evaluation |
| **WAL** | Write-Ahead Log - SQLite durability mechanism |
| **mTLS** | Mutual TLS - certificate-based authentication for gRPC |

---

*End of Architecture Specification*  
*Document Version: 1.0*  
*Last Updated: 2026-07-16*
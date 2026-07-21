# Sentinel AI - Implementation Plan

**Version:** 1.0  
**Status:** Draft for Review  
**Based on:** Architecture Specification v1.0  
**Date:** 2026-07-16

---

## Overview

This plan translates the architecture specification into an actionable implementation roadmap. It assumes a small team (2-4 engineers) and prioritizes **vertical slices** - delivering working end-to-end functionality early rather than completing all infrastructure first.

---

## Phase 0: Foundation (Weeks 1-2)

**Goal:** Build the monorepo, CI/CD, and core infrastructure so all subsequent work has a solid base.

### Tasks

| ID | Task | Description | Dependencies | Estimate |
|----|------|-------------|--------------|----------|
| F01 | Initialize Cargo workspace | Create workspace structure, Cargo.toml, rust-toolchain.toml | - | 2 days |
| F02 | Setup CI/CD pipeline | GitHub Actions: fmt, clippy, test, build, doc | F01 | 2 days |
| F03 | Protobuf codegen setup | Generate Rust/TS from `.proto` files, publish to workspace | F01 | 1 day |
| F04 | Core crate scaffolding | `sentinel-core`, `sentinel-events`, `sentinel-config` with basic types | F01 | 2 days |
| F05 | Logging & metrics infra | `tracing` setup, Prometheus metrics, structured JSON logs | F01 | 1 day |
| F06 | Config system | TOML loading with `config-rs`, validation, hot-reload, secrets (age) | F04 | 2 days |
| F07 | Storage layer | SQLite + DuckDB connections, migrations, repository traits | F04 | 2 days |
| F08 | Event bus implementation | Tokio channels with backpressure, topic routing, broadcast/mpsc | F04 | 2 days |

### Deliverables
- Building monorepo with passing CI
- Generated Protobuf code in `sentinel-events`
- Working config system with validation
- Event bus publishing/subscribing in tests
- Basic SQLite/DuckDB read/write

### Exit Criteria
```bash
cargo test --workspace --all-targets  # All pass
cargo clippy --workspace --all-targets -- -D warnings  # Clean
cargo fmt --all -- --check  # Clean
```

---

## Phase 1: Core Service & Process Collector (Weeks 3-5)

**Goal:** Running daemon collecting process events on all platforms, evaluating rules, exposing gRPC API.

### Tasks

| ID | Task | Description | Dependencies | Estimate |
|----|------|-------------|--------------|----------|
| P1.1 | Core service lifecycle | Module registry, topological start/stop, health aggregation | F04, F08 | 3 days |
| P1.2 | gRPC server skeleton | Tonic server with reflection, health check, version endpoint | F03 | 2 days |
| P1.3 | Process Collector - Windows | ETW (Kernel-Process) + WMI fallback, process create/terminate | F08 | 5 days |
| P1.4 | Process Collector - Linux | auditd + netlink (CN_PROC) + eBPF option, process events | F08 | 5 days |
| P1.5 | Process Collector - macOS | Endpoint Security Framework (ES_EVENT_TYPE_NOTIFY_EXEC) | F08 | 4 days |
| P1.6 | Collector framework | Shared trait, context, backpressure handling, metrics | F08 | 3 days |
| P1.7 | Rule Engine - CEL integration | Load YAML, parse CEL, compile, evaluate, hot-reload | F04, F06 | 4 days |
| P1.8 | Built-in rules (10) | PowerShell, WMI, Scheduled Tasks, LOLBins, etc. | P1.7 | 2 days |
| P1.9 | gRPC API - Events/Processes/Rules | QueryEvents, StreamEvents, ListProcesses, ListRules | P1.2 | 3 days |
| P1.10 | Tauri app shell | Window, routing, theme, gRPC-web/grpc-web client | F03 | 3 days |
| P1.11 | Dashboard - Events table | Real-time event stream, filters, pagination | P1.9, P1.10 | 3 days |
| P1.12 | Dashboard - Alerts panel | Alert list, severity, acknowledge | P1.9, P1.10 | 2 days |
| P1.13 | Settings page | Config editor with validation, rule enable/disable | P1.9, P1.10 | 2 days |
| P1.14 | Installer packaging | MSI (Windows), DEB (Linux), DMG (macOS) - unsigned | P1.1 | 2 days |
| P1.15 | Integration tests | End-to-end: collector → bus → rule → storage → API → UI | All above | 3 days |

### Deliverables
- `sentinel-core-service` binary running as daemon
- Process events flowing on Windows/Linux/macOS
- Rules firing and generating alerts
- gRPC API responding to queries
- Tauri UI showing events and alerts
- Installers for all platforms

### Exit Criteria
- Daemon starts/stops cleanly on all 3 OSes
- Process create/terminate events visible in UI within 1s
- Rule matches generate alerts visible in UI
- `cargo test --test integration` passes

---

## Phase 2: Network, File Collectors & Correlation (Weeks 6-9)

**Goal:** Network + file visibility, correlation engine, risk scoring.

### Tasks

| ID | Task | Description | Dependencies | Estimate |
|----|------|-------------|--------------|----------|
| P2.1 | Network Collector - Windows | ETW (TCPIP, WFP), WFP callouts for connect/listen/DNS/HTTP | P1.6 | 5 days |
| P2.2 | Network Collector - Linux | eBPF (tc/sockops) + netlink fallback, TLS parsing, JA3 | P1.6 | 6 days |
| P2.3 | Network Collector - macOS | Endpoint Security (network) + pf fallback | P1.6 | 4 days |
| P2.4 | File Collector - Windows | USN Journal + Minifilter (kernel) for create/modify/delete/execute | P1.6 | 5 days |
| P2.5 | File Collector - Linux | fanotify (FAN_CLASS_CONTENT) + eBPF, hash/entropy calculation | P1.6 | 5 days |
| P2.6 | File Collector - macOS | FSEvents + Endpoint Security (file ops) | P1.6 | 4 days |
| P2.7 | Hash/entropy pipeline | Async thread pool, streaming SHA256, Shannon entropy | P2.4 | 2 days |
| P2.8 | Correlation Engine - Causal | Process tree, parent-child, cause_event_id linking | P1.1 | 3 days |
| P2.9 | Correlation Engine - Flow | File→process→network data flow tracking | P2.8 | 3 days |
| P2.10 | Correlation Engine - Behavioral | MITRE tactic chaining, attack chain detection | P2.8 | 4 days |
| P2.11 | Risk Engine | Scoring, temporal decay, asset criticality, threat intel boost | P1.7 | 4 days |
| P2.12 | Alert Generator | Threshold crossing, escalation, flapping suppression | P2.11 | 2 days |
| P2.13 | gRPC API - Network/Files/Risk | Connections, file activity, risk summary, timeline | P1.9 | 3 days |
| P2.14 | Dashboard - Network view | Connection map, geoip, JA3, process linkage | P2.13 | 3 days |
| P2.15 | Dashboard - File timeline | Hash lookup, entropy, sensitive path alerts | P2.13 | 2 days |
| P2.16 | Dashboard - Risk/Attack chains | Risk timeline, MITRE heatmap, chain graph | P2.13 | 3 days |
| P2.17 | Extended rules (30 total) | Network, file, registry, MITRE-mapped rules | P1.8 | 3 days |
| P2.18 | Performance optimization | <5% CPU, <100MB RAM, backpressure tuning | All above | 3 days |

### Deliverables
- Network connections with DNS/HTTP/TLS metadata
- File activity with hashes and entropy
- Correlated attack chains (causal + flow + behavioral)
- Risk scores with temporal decay
- Alerts with escalation
- Rich dashboards for all telemetry

### Exit Criteria
- All collectors running on all platforms
- Attack chain detection working (PowerShell → download → execute → persist)
- Risk scores correlate with threat severity
- Dashboard shows meaningful visualizations
- Resource targets met

---

## Phase 3: Registry, USB, Startup, Browser & AI (Weeks 10-14)

**Goal:** Complete collector coverage, AI explanations, plugin system.

### Tasks

| ID | Task | Description | Dependencies | Estimate |
|----|------|-------------|--------------|----------|
| P3.1 | Registry Collector (Windows) | Registry callbacks, Run keys, services, Winlogon, BHO | P1.6 | 4 days |
| P3.2 | USB Collector - all OS | udev/IOKit/WM_DEVICECHANGE, HID detection, mass storage scan | P1.6 | 4 days |
| P3.3 | Startup Collector - all OS | systemd, launchd, cron, registry, shell profiles, browser ext | P1.6 | 4 days |
| P3.4 | Browser Collector - Chrome/Edge | Native messaging + SQLite (History, Cookies, Downloads) | P1.6 | 5 days |
| P3.5 | Browser Collector - Firefox | Native messaging + SQLite (places.sqlite, cookies.sqlite) | P1.6 | 4 days |
| P3.6 | Native messaging hosts | Chrome/Edge/Firefox manifests, Rust host process | P3.4 | 3 days |
| P3.7 | AI Engine - Ollama client | HTTP client, model management, streaming, fallback | F04 | 3 days |
| P3.8 | AI Engine - llama.cpp | Direct FFI binding, model loading, GPU/CPU config | P3.7 | 3 days |
| P3.9 | Context Builder | Anonymization, summarization, process tree, network summary | P2.10 | 4 days |
| P3.10 | Alert Explanation | Prompt templates, guardrails, structured response | P3.9 | 3 days |
| P3.11 | Chat Interface | Conversation history, context continuity, streaming | P3.10 | 3 days |
| P3.12 | Plugin Manager | Process isolation, gRPC protocol, capability enforcement | P1.1 | 5 days |
| P3.13 | Plugin SDK (Rust) | Host SDK, capability macros, config, logging, examples | P3.12 | 4 days |
| P3.14 | VirusTotal Plugin | Hash/URL reputation, auto-submit on risk, report viewing | P3.13 | 3 days |
| P3.15 | Notification Plugins | Discord, Telegram, Slack, Email (webhook/SMTP) | P3.13 | 3 days |
| P3.16 | Home Assistant Plugin | Entity mapping, automation triggers | P3.13 | 2 days |
| P3.17 | gRPC API - AI/Plugins | ExplainAlert, Chat, StreamChat, Plugin management | P3.10 | 2 days |
| P3.18 | UI - AI Chat panel | Conversation view, streaming responses, alert explain button | P3.11 | 3 days |
| P3.19 | UI - Plugin management | Install/configure/enable/disable, capability review | P3.12 | 3 days |

### Deliverables
- Complete collector coverage (all 7 types)
- AI explaining alerts in plain language
- Chat assistant for security questions
- Plugin system with 6 built-in plugins
- UI for plugin management

### Exit Criteria
- All collectors functional on all platforms
- AI explains alerts with actions/investigation steps
- Chat answers questions using current context
- Plugins install/configure/run in isolation
- No regressions in Phases 1-2

---

## Phase 4: Hardening & Production Readiness (Weeks 15-18)

**Goal:** Threat intel, browser collector polish, security, packaging, documentation.

### Tasks

| ID | Task | Description | Dependencies | Estimate |
|----|------|-------------|--------------|----------|
| P4.1 | Threat Intelligence Framework | Local IOC files, API providers (AbuseIPDB, OTX, Shodan) | P2.11 | 3 days |
| P4.2 | Threat Intel Plugins | AbuseIPDB, Shodan, OTX, Hybrid Analysis plugins | P3.13, P4.1 | 3 days |
| P4.3 | Sigma Rule Importer | Convert Sigma YAML → CEL rules | P1.7 | 3 days |
| P4.4 | Rule Testing Framework | Unit tests for rules, test fixtures, CI integration | P1.8 | 2 days |
| P4.5 | Config Migration System | Versioned config, automatic migration on upgrade | P0.6 | 2 days |
| P4.6 | Backup/Restore | Encrypted export/import of config, rules, plugins | P0.6 | 2 days |
| P4.7 | Offline Mode | Full operation without network, model caching | P3.7 | 2 days |
| P4.8 | Accessibility (WCAG 2.1 AA) | Keyboard nav, screen readers, contrast, focus | P1.10 | 3 days |
| P4.9 | Localization (i18n) | EN, ES, FR, DE, PT, JA - react-i18next | P1.10 | 3 days |
| P4.10 | Windows Service Hardening | Recovery actions, watchdog, Event Log integration | P1.1 | 2 days |
| P4.11 | Linux systemd Hardening | Capabilities, seccomp, ProtectSystem, PrivateTmp | P1.1 | 2 days |
| P4.12 | macOS Launchd Hardening | Sandbox, hardened runtime, notarization prep | P1.1 | 2 days |
| P4.13 | Code Signing | EV certificates, Windows Authenticode, Apple notary | P4.10 | 2 days |
| P4.14 | Reproducible Builds | Deterministic builds, pinned deps, build verification | P0.2 | 2 days |
| P4.15 | SBOM Generation | CycloneDX/SPDX in CI, vulnerability scanning | P0.2 | 1 day |
| P4.16 | Documentation | User guide, admin guide, developer guide, API reference | All | 5 days |
| P4.17 | Security Audit Prep | Threat model, attack surface, dependency audit | All | 2 days |
| P4.18 | Fuzzing Harness | libFuzzer for event parsing, rule engine, protobuf | P0.2 | 2 days |
| P4.19 | Load/Soak Testing | 72h soak, 10k events/sec, memory leak detection | P2.18 | 3 days |
| P4.20 | Upgrade Testing | v0.x → v1.0 migration, config/data compatibility | P4.5 | 2 days |

### Deliverables
- Threat intelligence integration
- Production-grade service hardening
- Signed, notarized, reproducible builds
- Complete documentation
- Security audit ready

### Exit Criteria
- All services hardened per platform best practices
- Binaries signed and notarized
- Reproducible builds verified
- Documentation published
- 72h soak test passes with no leaks
- Upgrade from v0.x works

---

## Phase 5: v1.0 Release & LTS (Weeks 19-20)

**Goal:** Stable API, LTS branch, release process.

### Tasks

| ID | Task | Description | Dependencies | Estimate |
|----|------|-------------|--------------|----------|
| P5.1 | API Stability Review | Finalize v1 API, mark deprecated, generate docs | P4.16 | 2 days |
| P5.2 | LTS Branch Strategy | Branch protection, backport policy, 2-year support | P5.1 | 1 day |
| P5.3 | Release Automation | Tag → build → sign → package → GitHub Release | P4.13 | 2 days |
| P5.4 | Release Notes | Changelog, migration guide, known issues | P5.3 | 1 day |
| P5.5 | Community Prep | Issue templates, contributing guide, security policy | P4.16 | 1 day |
| P5.6 | v1.0 Tag & Release | Final validation, publish, announce | All | 1 day |

---

## Resource Allocation (Suggested)

| Role | Phase 0 | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Phase 5 |
|------|---------|---------|---------|---------|---------|---------|
| Backend Engineer 1 | Core, Config, Storage | Core Service, Rule Engine | Correlation, Risk | AI Engine, Plugin Manager | Threat Intel, Hardening | Release |
| Backend Engineer 2 | Event Bus, Protobuf | Process Collector (Win) | Network Collector (Lin) | Browser Collector, Plugins | systemd/launchd, Signing | Release |
| Backend Engineer 3 | CI/CD, Testing | Process Collector (Lin/macOS) | File Collector (all) | Registry/USB/Startup | Windows Hardening, SBOM | Release |
| Frontend Engineer | - | Tauri Shell, Dashboard | Network/File/Risk UI | AI Chat, Plugin UI | a11y, i18n, Polish | Release |
| Security Engineer | - | Rules (10) | Rules (30), MITRE | Threat Intel, Plugins | Audit, Fuzzing, Signing | Release |

*With 2 engineers: Combine backend roles, extend timeline by ~40%*

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| eBPF complexity on Linux | High | High | Start with auditd/netlink, eBPF as enhancement |
| Endpoint Security (macOS) entitlements | Medium | High | Early prototype, Apple Developer account ready |
| AI model quality on consumer hardware | Medium | Medium | Multiple model fallbacks, quantized models (Q4_K_M) |
| Plugin sandbox escape | Low | Critical | Process isolation, seccomp/AppContainer, capability model |
| Resource usage > targets | Medium | High | Continuous benchmarking in CI, backpressure tuning |
| Windows driver signing for Minifilter | Low | Medium | USN Journal first, Minifilter as v1.1 |
| Browser native messaging complexity | Medium | Medium | Prototype early, fallback to polling |
| Dependency supply chain | Low | High | cargo-deny, pinned versions, vendoring option |

---

## Testing Strategy

| Layer | Tools | Coverage Target |
|-------|-------|-----------------|
| Unit | `cargo test`, `mockall`, `proptest` | 80% for core crates |
| Integration | `cargo test --test integration`, temp dirs | All API endpoints |
| Contract | Protobuf conformance, gRPC reflection | All services |
| E2E | Playwright (UI), custom scenarios | Critical user flows |
| Performance | `criterion`, custom soak tests | <5% CPU, <100MB RAM |
| Security | `cargo-audit`, `cargo-deny`, fuzzing | Zero high/critical |
| Chaos | Simulated collector crashes, network partition | Graceful degradation |

---

## Definition of Done (Per Task)

- [ ] Code compiles with `cargo clippy -D warnings`
- [ ] Unit tests pass (`cargo test`)
- [ ] Integration tests pass (if applicable)
- [ ] Documentation updated (doc comments + architecture docs)
- [ ] Metrics/tracing added for observability
- [ ] Config schema updated (if new settings)
- [ ] Protobuf version bumped (if API change)
- [ ] CHANGELOG entry added
- [ ] Reviewed by at least one other engineer

---

## Questions for Clarification

Before finalizing, I'd like your input on:

1. **Team size**: How many engineers will work on this? (Affects parallelization)
2. **Platform priority**: Windows first, or all three simultaneously?
3. **AI model preference**: Ollama (easier) vs llama.cpp (more control)?
4. **Plugin sandbox**: Process isolation (secure, heavier) vs WASM (lighter, less mature)?
5. **Distribution**: Open source from start, or closed beta first?
6. **Telemetry**: Any desire for anonymous usage stats (opt-in)?
7. **v1.0 timeline**: Hard deadline or quality-gated?

---

## Next Steps

Once you review and confirm:
1. I'll create detailed task breakdowns for Phase 0-1 (sprint-ready)
2. Set up the monorepo with all tooling
3. Begin implementation with daily/weekly checkpoints

---

*Plan Version: 1.0*  
*Ready for stakeholder review*

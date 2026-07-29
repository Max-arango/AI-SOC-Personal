# Sentinel AI — Documentation

> Local-first, privacy-preserving AI Security Assistant for personal computers.

## Quick Links

- [Getting Started](getting-started.md) — Install, run, first alerts
- [Architecture](architecture.md) — Full system design and data flow
- [Configuration](configuration.md) — All config options (TOML + env vars)
- [Collectors](collectors.md) — Process, network, file, browser, startup, registry, USB
- [Rules](rules.md) — Rule engine, CEL expressions, 50 built-in rules
- [Plugins](plugins.md) — Discord, Telegram, Email, Slack, VirusTotal, AbuseIPDB, Shodan, OTX, GeoIP, IOC, Home Assistant
- [API](api.md) — gRPC API reference (30+ RPCs)
- [Development](development.md) — Build, test, contribute, project structure
- [Security](security.md) — Security model, privacy, threat model

## What is Sentinel AI?

Sentinel AI monitors your computer in real-time, detects suspicious behavior, correlates events into attack chains, scores risk, and explains threats in plain language using local AI. It does NOT replace an antivirus — it's an additional layer of observability and assistance.

### Core Principles

- **Local-first**: All processing happens on your machine. No data leaves without explicit consent.
- **Privacy-preserving**: Events are anonymized before any sharing. AI runs locally via Ollama.
- **Explainable**: Security alerts come with natural language explanations.
- **Modular**: Every component (collectors, rules, plugins, storage) is independently configurable.
- **Open-source**: MIT + Apache 2.0 dual license. All dependencies are open-source.

## Project Stats

| Metric | Value |
|---|---|
| Stars | — |
| License | MIT OR Apache 2.0 |
| Language | Rust (backend) + TypeScript/React (frontend) |
| Framework | Tauri v2 |
| Min Rust | 1.75+ |
| Min Node | 20+ |
| Rules | 50 YAML (12 MITRE ATT&CK tactics, 38+ techniques) |
| Plugins | 12 (notifications + threat intel + automation) |
| Collectors | 5 implemented (process, network, file, startup, browser) |
| Tests | 41+ (unit + integration) |
| Binary size | ~15 MB (release, with DuckDB embedded) |

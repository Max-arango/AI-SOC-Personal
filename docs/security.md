# Security Model — Sentinel AI

## Design Principles

| Principle | Implementation |
|---|---|
| **Local-first** | All processing runs on the user's machine. No telemetry. No cloud dependency. |
| **Privacy by default** | Events are anonymized before any sharing. AI runs locally. |
| **Opt-in sharing** | Every feature that sends data off-machine is individually configurable. |
| **Defense in depth** | Multiple security layers: mTLS, encryption at rest, sandboxing, input validation. |
| **Open-source** | All code is auditable. No backdoors. No hidden telemetry. |

## Data Flow Security

### 1. Collection → Processing

```
OS Telemetry → Collector → Event Bus → PrivacyFilter → Pipeline
```

- Collectors run with minimal privileges (user-level, no root)
- Events are processed in memory before any persistence
- PrivacyFilter redacts PII before the event enters the pipeline
- No raw command lines, paths, or usernames survive the privacy filter

### 2. Storage Security

- **SQLite**: Database file at `~/.local/share/sentinel/sentinel.db` with standard Unix permissions (0600)
- **DuckDB**: Analytics database with same permissions
- No encryption at rest currently (planned for v2.0)
- WAL mode provides crash safety

### 3. API Security

- **gRPC**: Binds to `127.0.0.1:7777` by default (localhost only)
- **Tauri IPC**: Direct in-process communication, no network exposure
- **mTLS**: Optional for multi-host deployments

### 4. Network Communication

All external API calls are:
- **User-initiated**: The user provides API keys via environment variables
- **HTTPS only**: All HTTP calls use TLS
- **Rate-limited**: Free API tiers have built-in rate limits
- **Opt-in**: No external calls happen unless the user configures the corresponding plugin

## Threat Model

### Attacker Profiles

| Profile | Capability | Mitigation |
|---|---|---|
| **External attacker** | Network access, exploits | gRPC binds localhost only, input validation |
| **Malicious admin** (enterprise) | Fleet query abuse, EDR commands | Audit log, human-in-the-loop, quorum |
| **Supply chain** | Plugin/update compromise | Sandboxing, reproducible builds, checksums |
| **Passive observer** | Network traffic analysis | mTLS, silent push, traffic padding |

### Attack Surface

| Component | Surface | Hardening |
|---|---|---|
| gRPC server | TCP 7777 | localhost-only, input validation, proto fuzzing |
| SQLite DB | Filesystem | Unix permissions 0600 |
| Collectors | OS APIs | User-level privileges, no kernel modules |
| AI Engine | Unix socket (Ollama) or HTTPS (OpenRouter) | Local-only or TLS |
| Plugins | Process isolation | Capability-based sandboxing |
| UI (Tauri) | IPC, WebView | CSP headers, no eval, no inline scripts |

## Privacy Guarantees

### What Sentinel AI NEVER accesses

- ❌ Browser cookies, form data, localStorage
- ❌ Email contents, chat messages
- ❌ Keystrokes, clipboard data
- ❌ Microphone, camera, screen capture (without explicit opt-in)
- ❌ File contents (only metadata: path, size, hash)
- ❌ Full HTTP payloads (only metadata: method, URL, status)

### What Sentinel AI stores (with redaction)

- Process names, PIDs, parent-child relationships
- Network connection metadata (IPs, ports, protocols)
- File paths (anonymized)
- Command lines (redacted: passwords, tokens removed)
- Browser URLs (no query parameters, no POST data)

### Data retention

- Events: 30 days by default (configurable)
- Alerts: Indefinite (configurable)
- Config/rules: Indefinite

### Right to deletion

All data is local. Delete the database to remove all records:

```bash
rm ~/.local/share/sentinel/sentinel.db
rm ~/.local/share/sentinel/sentinel.duckdb
```

## Security Recommendations

### Production Deployment

```bash
# 1. Run as non-root user
useradd --system sentinel
sudo -u sentinel sentinel-core-service

# 2. Use systemd with hardening
# See docker/sentinel.toml for example

# 3. Enable mTLS for multi-host
[grpc]
address = "0.0.0.0:7777"
mtls_enabled = true
```

### API Key Management

```bash
# Never hardcode keys in config files
# Use environment variables or a secrets manager
export SENTINEL_VIRUSTOTAL_API_KEY=$(cat /run/secrets/vt_key)
export SENTINEL_ABUSEIPDB_API_KEY=$(cat /run/secrets/abuseipdb_key)
```

### Audit

```bash
# Check what data is stored
sqlite3 ~/.local/share/sentinel/sentinel.db "SELECT type, source, COUNT(*) FROM events GROUP BY type, source;"

# Check plugin activity
grep -i "discord\|telegram\|email" logs/sentinel.log
```

## Vulnerability Reporting

Report security issues to: `security@sentinel-ai.dev`

Do NOT open a public GitHub issue for security vulnerabilities.

# Collectors — Sentinel AI

Collectors gather telemetry from the operating system and publish events to the Event Bus.

## Architecture

Every collector follows the same pattern:

```
┌──────────────┐     ┌──────────┐     ┌───────────┐     ┌──────────┐
│ OS Telemetry │────►│ Collector│────►│ Event Bus │────►│ Pipeline │
│ (sysinfo,    │     │ (poll)   │     │ (mpsc)    │     │          │
│  /proc, etc) │     └──────────┘     └───────────┘     └──────────┘
└──────────────┘
```

Each collector:
- Runs on its own interval (configurable)
- Publishes `Arc<Event>` to the Event Bus
- Handles backpressure (throttles or drops events)
- Is independently configurable and restartable

---

## 1. Process Collector

**Source:** `collectors/src/process/process_collector.rs`

| Property | Value |
|---|---|
| Platform | Linux (sysinfo), Windows/macOS (stubs) |
| Interval | 5 seconds |
| Events | `sentinel.process.create`, `sentinel.process.terminate` |

**How it works:**
1. Takes a snapshot of all running PIDs via `sysinfo::System::refresh_all()`
2. Compares current PIDs against previous (`known_pids` HashSet)
3. New PIDs → `process.create` events
4. Missing PIDs → `process.terminate` events
5. Each event includes: PID, PPID, name, path, command line, user, CPU%, memory

**Privacy:** Command lines are redacted via PrivacyEngine before storage.

---

## 2. Network Collector

**Source:** `collectors/src/network/mod.rs`

| Property | Value |
|---|---|
| Platform | Linux |
| Interval | 30 seconds |
| Events | `sentinel.network.connect` |

**How it works:**
1. Reads `/proc/net/tcp`, `/proc/net/udp`, `/proc/net/tcp6`, `/proc/net/udp6`
2. Parses hex addresses/ports (network byte order → human readable)
3. Detects new connections not in the `known` HashMap
4. Events include: local_addr, local_port, remote_addr, remote_port, protocol

**Threat intel enrichment:** Each remote IP is checked against AbuseIPDB, Shodan, OTX, GeoIP, and IOC database (parallel via `tokio::join!`).

---

## 3. File Collector

**Source:** `collectors/src/file/mod.rs`

| Property | Value |
|---|---|
| Platform | Cross-platform |
| Interval | 60 seconds |
| Events | `sentinel.file.create`, `sentinel.file.modify` |

**How it works:**
1. Scans `/etc`, `/tmp`, `/var/log` directories
2. Reads file metadata (mtime, size)
3. Compares against known files (path → mtime)
4. New files → `file.create`, modified files → `file.modify`
5. Files in sensitive paths get `is_sensitive_path = true` and risk boost

---

## 4. Startup Collector

**Source:** `collectors/src/startup/mod.rs`

| Property | Value |
|---|---|
| Platform | Linux |
| Interval | 1 hour |
| Events | `sentinel.startup.add` |

**What it scans:**
- **systemd services** (`/etc/systemd/system`, `/usr/lib/systemd/system`)
- **cron jobs** (`/etc/crontab`, `/etc/cron.d`, user crontabs)
- **Shell profiles** (`.bashrc`, `.bash_profile`, `.zshrc`, `.profile`)
- **XDG autostart** (`~/.config/autostart/*.desktop`)

Each entry is published as a persistence event with tags:
- `persistence`, `startup:systemd`, `startup:cron`, `startup:profile`

---

## 5. Browser Collector

**Source:** `collectors/src/browser/mod.rs`

| Property | Value |
|---|---|
| Platform | Cross-platform |
| Interval | 120 seconds |
| Events | `sentinel.browser.navigation`, `.download_complete`, `.extension_install` |

**Supported browsers:**
- Google Chrome / Chromium
- Mozilla Firefox
- Microsoft Edge
- Brave
- Vivaldi

**What it monitors:**
1. **History** — Reads `urls` table from browser SQLite databases (last 50 entries)
2. **Downloads** — Reads download records with paths, URLs, timestamps
3. **Extensions** — Detects new extension directories

**Privacy:** Only metadata (URLs, paths, timestamps). No cookies, form data, passwords, or localStorage. SHA256 of downloaded files is computed without reading content.

**Deduplication:** Entries are deduplicated by `URL|timestamp` key in a persistent HashSet.

---

## Future Collectors (stubs)

| Collector | Status | Platform |
|---|---|---|
| Registry | Stub | Windows only |
| USB | Stub | Cross-platform |
| Browser (real-time) | Stub | Native messaging |

# Collectors — Sentinel AI

Collectors gather telemetry from the operating system and publish events to the Event Bus.

## Architecture

Every collector follows the same pattern:

```
OS Telemetry ──► Collector ──► Event Bus ──► Pipeline
(netlink,         (async)       (mpsc)
 fanotify,
 /proc, etc)
```

Each collector:
- Uses OS-native APIs where available (netlink, fanotify, inotify)
- Falls back to polling when kernel interfaces unavailable
- Publishes `Arc<Event>` to the Event Bus
- Handles backpressure (throttles or drops events)
- Is independently configurable and restartable

---

## 1. Process Collector

**Source:** `collectors/src/process/`

| Property | Value |
|---|---|
| Platform | Linux (CN_PROC netlink), Windows/macOS (stubs) |
| Mechanism | Kernel CN_PROC connector — real-time fork/exec/exit |
| Events | `sentinel.process.create`, `sentinel.process.terminate`, `sentinel.process.inject` |

**How it works:**
1. Opens `AF_NETLINK` socket with `NETLINK_CONNECTOR` protocol
2. Subscribes to `CN_IDX_PROC` multicast events from the kernel
3. Receives real-time: `PROC_EVENT_FORK`, `PROC_EVENT_EXEC`, `PROC_EVENT_EXIT`
4. Enriches with `/proc/<pid>/cmdline`, `exe`, `status` — SHA256 of binary, UID
5. Detects ptrace (injection) and coredump events
6. Parent context resolved recursively

**Fallback:** `/proc` polling every 5 seconds when netlink unavailable.

---

## 2. Network Collector

**Source:** `collectors/src/network/`

| Property | Value |
|---|---|
| Platform | Linux (/proc/net), other (stub) |
| Interval | 5 seconds |
| Events | `sentinel.network.connect`, `sentinel.network.close` |

**How it works:**
1. Polls `/proc/net/tcp`, `/proc/net/udp`, `/proc/net/tcp6`, `/proc/net/udp6`
2. Maps connections to PIDs via inode→pid lookup in `/proc/<pid>/fd/*`
3. Tracks connection lifecycle: NEW (first seen), CLOSE (disappeared)
4. Enriches with DNS reverse lookup (PTR) for remote addresses
5. Detects port scans (>10 ports to same host in 30s)

**Privacy:** Local connections (127.x, 10.x, 192.168.x) filtered.

---

## 3. File Collector

**Source:** `collectors/src/file/`

| Property | Value |
|---|---|
| Platform | Linux (fanotify), other (polling fallback) |
| Mechanism | Kernel fanotify — real-time file events |
| Events | `sentinel.file.create`, `sentinel.file.modify`, `sentinel.file.delete`, `sentinel.file.read` |

**How it works:**
1. Uses `fanotify_init` + `fanotify_mark` to watch `/etc`, `/tmp`, `/var/log`
2. Receives: `FAN_OPEN`, `FAN_MODIFY`, `FAN_CLOSE_WRITE`, `FAN_DELETE`, `FAN_OPEN_EXEC`
3. Computes SHA256 and Shannon entropy for suspicious files
4. Detects ransomware: ≥3 CLOSE_WRITE with entropy >7.5 in 10s window

**Fallback:** Directory polling every 30s when fanotify unavailable.

---

## 4. Browser Collector

**Source:** `collectors/src/browser/`

| Property | Value |
|---|---|
| Platform | All (reads browser SQLite databases) |
| Interval | 120 seconds (incremental) |
| Events | `sentinel.browser.navigation`, `sentinel.browser.download_complete`, `sentinel.browser.extension_install` |

**How it works:**
1. Scans Chrome, Firefox, Edge, Brave, Opera, Vivaldi profiles
2. Incremental scan via `WHERE last_visit_time > max_ts`
3. Detects malicious extensions (7 known IDs)
4. Flags URLs with IP addresses (phishing) and suspicious TLDs
5. Detects download bursts (≥3 .exe/.sh in 5 min)

---

## 5. USB Collector

**Source:** `collectors/src/usb/`

| Property | Value |
|---|---|
| Platform | Linux (/sys/bus/usb/devices), other (stub) |
| Interval | 5 seconds |
| Events | `sentinel.usb.connect`, `sentinel.usb.disconnect` |

**How it works:**
1. Polls `/sys/bus/usb/devices/` for vendor_id, product_id, serial
2. Tracks known devices via HashSet diff
3. Emits connect/disconnect events with device metadata

---

## 6. Registry Collector

**Source:** `collectors/src/registry/`

| Property | Value |
|---|---|
| Platform | Linux (systemd user services), other (stub) |
| Interval | 1 hour |
| Events | `sentinel.registry.persistence` |

**How it works:**
1. Scans `~/.config/systemd/user/` for new `.service` files
2. Emits persistence events with MITRE T1543 tags

---

## 7. Startup Collector

**Source:** `collectors/src/startup/`

| Property | Value |
|---|---|
| Platform | Linux (systemd, cron, shell profiles), other (stub) |
| Interval | 1 hour |
| Events | `sentinel.startup.add` |

**How it works:**
1. Scans cron jobs, systemd services, shell profiles, XDG autostart
2. Detects new persistence entries
3. Emits events with persistence and MITRE tags

//! Network Collector — Connection monitoring via /proc/net polling.
//!
//! Architecture:
//! ```text
//! /proc/net/{tcp,udp,tcp6,udp6}  ──► parser ──► RawConn { inode, addr, port, state, uid }
//! /proc/<pid>/fd/*                 ──► inode→PID map
//!                                           │
//!                                           ▼
//!                                    Enriched connections
//!                                           │
//!                         ┌─────────────────┼───────────────────┐
//!                         ▼                 ▼                    ▼
//!                   conn_tracker      dns_resolver        scan_detector
//!                   (new/close)       (hostname)          (alerts)
//!                         │                 │                    │
//!                         └─────────────────┼────────────────────┘
//!                                           ▼
//!                                    EventBus.publish()
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sentinel_core::traits::EventBus;
use sentinel_events::network_event::{Action, Direction, Protocol};
use sentinel_events::{Event, NetworkEvent};
use tracing::{debug, info, warn};

mod conn_tracker;
mod dns_resolver;
mod scan_detector;

use conn_tracker::{ConnTracker, ConnectionEvent, ConnectionKey, ConnectionMeta};
use dns_resolver::DnsResolver;
use scan_detector::ScanDetector;

// ── Raw parsed connection from /proc/net ──────────────────────────

struct RawConn {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    protocol: Protocol,
    inode: u64,
    uid: u32,
}

// ── /proc/net parser ──────────────────────────────────────────────

fn parse_ip_port(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip = if parts[0].len() == 8 {
        // IPv4: 8 hex chars, little-endian bytes
        let mut bytes = [0u8; 4];
        for i in 0..4 {
            bytes[3 - i] = u8::from_str_radix(&parts[0][i * 2..i * 2 + 2], 16).ok()?;
        }
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else if parts[0].len() == 32 {
        // IPv6: 32 hex chars, 4-char groups
        let mut groups = Vec::new();
        for i in 0..8 {
            let hi = u8::from_str_radix(&parts[0][i * 4..i * 4 + 2], 16).ok()?;
            let lo = u8::from_str_radix(&parts[0][i * 4 + 2..i * 4 + 4], 16).ok()?;
            groups.push(format!("{:02x}{:02x}", hi, lo));
        }
        groups.join(":")
    } else {
        return None;
    };

    let port = u16::from_str_radix(parts[1], 16).ok()?;
    Some((ip, port))
}

fn parse_proc_net(path: &str, protocol: Protocol) -> Vec<RawConn> {
    let mut connections = Vec::new();
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return connections,
    };

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let local = parse_ip_port(fields[1]);
        let remote = parse_ip_port(fields[2]);

        if let (Some((local_addr, local_port)), Some((remote_addr, remote_port))) = (local, remote)
        {
            let inode = u64::from_str_radix(fields[9], 10).unwrap_or(0);
            let uid = u32::from_str_radix(fields[7], 10).unwrap_or(0);
            connections.push(RawConn {
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                protocol,
                inode,
                uid,
            });
        }
    }
    connections
}

// ── Inode → PID resolver ─────────────────────────────────────────

/// Scan `/proc/<pid>/fd/` to build an inode → PID lookup map.
///
/// Each fd is a symlink like `socket:[12345]`. We parse the inode
/// number and map it back to the owning PID and process name.
fn build_inode_pid_map() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();

    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };

    for entry in proc_dir.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let pid = match pid_str.parse::<u32>() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = match std::fs::read_dir(format!("/proc/{}/fd", pid)) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_entry in fd_dir.filter_map(|e| e.ok()) {
            let link = match std::fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };

            let target = link.to_string_lossy();
            if target.starts_with("socket:[") && target.ends_with(']') {
                let inode_str = &target[8..target.len() - 1];
                if let Ok(inode) = inode_str.parse::<u64>() {
                    let proc_name = read_process_name(pid);
                    map.insert(inode, (pid, proc_name));
                }
            }
        }
    }

    map
}

fn read_process_name(pid: u32) -> String {
    let comm = format!("/proc/{}/comm", pid);
    std::fs::read_to_string(&comm)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".to_string())
}

// ── Main monitor ──────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub async fn start_network_monitor(bus: Arc<dyn EventBus>, registry: Arc<sentinel_core::CollectorRegistry>) {
    registry.register(sentinel_core::CollectorStatus::new("network", "Network Monitor", "/proc/net polling + DNS + scan detection"));
    tokio::spawn(async move {
        let reg = registry;
        // Initial scan: populate tracker with existing connections
        // without emitting NEW events (only track them).
        let mut tracker = ConnTracker::new();
        {
            let raw_conns = poll_all_connections();
            let inode_map = build_inode_pid_map();
            let enriched: Vec<(ConnectionKey, ConnectionMeta)> = raw_conns
                .into_iter()
                .filter_map(|rc| {
                    let (pid, proc_name) =
                        inode_map.get(&rc.inode).cloned().unwrap_or((0, "?".to_string()));
                    Some((raw_to_key(&rc), ConnectionMeta {
                        pid,
                        process_name: proc_name,
                        uid: rc.uid,
                        inode: rc.inode,
                    }))
                })
                .collect();
            // Seed tracker silently (no events for existing connections)
            let _ = tracker.update(enriched);
        }

        info!(
            "Network collector started (5s interval, {} active connections)",
            tracker.active_count()
        );

        let mut dns = DnsResolver::new(Duration::from_secs(900)); // 15 min cache
        let mut scan = ScanDetector::new(Duration::from_secs(30));
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.tick().await;

        loop {
            tick.tick().await;

            let raw_conns = poll_all_connections();
            let inode_map = build_inode_pid_map();

            let enriched: Vec<(ConnectionKey, ConnectionMeta)> = raw_conns
                .into_iter()
                .filter_map(|rc| {
                    let (pid, proc_name) =
                        inode_map.get(&rc.inode).cloned().unwrap_or((0, "?".to_string()));
                    Some((raw_to_key(&rc), ConnectionMeta {
                        pid,
                        process_name: proc_name,
                        uid: rc.uid,
                        inode: rc.inode,
                    }))
                })
                .collect();

            let events = tracker.update(enriched);

            for event in events {
                match event {
                    ConnectionEvent::New { key, meta } => {
                        // DNS enrichment
                        let hostname = dns.reverse_lookup(&key.remote_addr).await;

                        // Scan detection
                        let scan_alert = scan.record(&key.remote_addr, key.remote_port, meta.pid);

                        let mut tags = Vec::new();
                        let severity;
                        let risk;
                        let action;

                        if let Some(ref s) = scan_alert {
                            action = Action::Connect as i32;
                            match s {
                                scan_detector::ScanType::VerticalScan { host, port_count } => {
                                    severity = sentinel_events::Severity::Warning as i32;
                                    risk = 50u32;
                                    tags.push(format!("vertical_scan:{}:{}", host, port_count));
                                }
                                scan_detector::ScanType::HorizontalScan { port, host_count } => {
                                    severity = sentinel_events::Severity::Warning as i32;
                                    risk = 40u32;
                                    tags.push(format!("horizontal_scan:{}:{}", port, host_count));
                                }
                                scan_detector::ScanType::ConnectionStorm { pid, count } => {
                                    severity = sentinel_events::Severity::Warning as i32;
                                    risk = 60u32;
                                    tags.push(format!("connection_storm:{}:{}", pid, count));
                                }
                            }
                        } else {
                            severity = sentinel_events::Severity::Info as i32;
                            risk = 5u32;
                            action = Action::Connect as i32;
                        }

                        tags.push("new_connection".to_string());

                        let net_event = Arc::new(Event {
                            id: sentinel_core::Ulid::new().to_string(),
                            r#type: "sentinel.network.connect".into(),
                            source: "network".into(),
                            timestamp: sentinel_core::now_proto_ts(),
                            ingest_timestamp: sentinel_core::now_proto_ts(),
                            severity,
                            risk_score: risk,
                            host_id: String::new(),
                            schema_version: 1,
                            process: if meta.pid > 0 {
                                Some(sentinel_events::ProcessContext {
                                    pid: meta.pid,
                                    name: meta.process_name.clone(),
                                    ..Default::default()
                                })
                            } else {
                                None
                            },
                            payload: Some(sentinel_events::event::Payload::NetworkEvent(
                                NetworkEvent {
                                    direction: Direction::Outbound as i32,
                                    protocol: key.protocol as i32,
                                    action,
                                    local_addr: key.local_addr.clone(),
                                    local_port: key.local_port as u32,
                                    remote_addr: key.remote_addr.clone(),
                                    remote_port: key.remote_port as u32,
                                    hostname,
                                    ..Default::default()
                                },
                            )),
                            tags,
                            ..Default::default()
                        });

                        if let Err(e) = bus.publish(net_event).await {
                            warn!("Network collector publish failed: {e}");
                        } else {
                            reg.increment_events("network", 1);
                            debug!(
                                "New connection: {} (pid={}, {})",
                                key.display(),
                                meta.pid,
                                meta.process_name,
                            );
                        }

                        // Prune DNS cache periodically
                        if dns.cache_size() > 1000 {
                            dns.prune();
                        }
                    }

                    ConnectionEvent::Close { key, duration, meta } => {
                        let net_event = Arc::new(Event {
                            id: sentinel_core::Ulid::new().to_string(),
                            r#type: "sentinel.network.close".into(),
                            source: "network".into(),
                            timestamp: sentinel_core::now_proto_ts(),
                            ingest_timestamp: sentinel_core::now_proto_ts(),
                            severity: sentinel_events::Severity::Info as i32,
                            risk_score: 1,
                            host_id: String::new(),
                            schema_version: 1,
                            process: if meta.pid > 0 {
                                Some(sentinel_events::ProcessContext {
                                    pid: meta.pid,
                                    name: meta.process_name.clone(),
                                    ..Default::default()
                                })
                            } else {
                                None
                            },
                            payload: Some(sentinel_events::event::Payload::NetworkEvent(
                                NetworkEvent {
                                    direction: Direction::Outbound as i32,
                                    protocol: key.protocol as i32,
                                    action: Action::Close as i32,
                                    local_addr: key.local_addr.clone(),
                                    local_port: key.local_port as u32,
                                    remote_addr: key.remote_addr.clone(),
                                    remote_port: key.remote_port as u32,
                                    ..Default::default()
                                },
                            )),
                            tags: vec![
                                "closed_connection".to_string(),
                                format!("duration_secs:{}", duration.as_secs()),
                            ],
                            ..Default::default()
                        });

                        let _ = bus.publish(net_event).await;
                        reg.increment_events("network", 1);
                    }
                }
            }
        }
    });
}

#[cfg(not(target_os = "linux"))]
pub async fn start_network_monitor(_bus: Arc<dyn EventBus>) {
    tracing::info!("Network collector: not supported on this platform");
}

fn poll_all_connections() -> Vec<RawConn> {
    let mut all = Vec::new();
    for (path, proto) in [
        ("/proc/net/tcp", Protocol::Tcp),
        ("/proc/net/udp", Protocol::Udp),
        ("/proc/net/tcp6", Protocol::Tcp),
        ("/proc/net/udp6", Protocol::Udp),
    ] {
        all.extend(parse_proc_net(path, proto));
    }
    all
}

fn raw_to_key(rc: &RawConn) -> ConnectionKey {
    ConnectionKey {
        local_addr: rc.local_addr.clone(),
        local_port: rc.local_port,
        remote_addr: rc.remote_addr.clone(),
        remote_port: rc.remote_port,
        protocol: rc.protocol,
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let result = parse_ip_port("0100007F:0050").unwrap();
        assert_eq!(result.0, "127.0.0.1");
        assert_eq!(result.1, 80);
    }

    #[test]
    fn test_parse_ipv6() {
        let result = parse_ip_port(
            "00000000000000000000000000000001:1F90",
        )
        .unwrap();
        assert_eq!(result.0, "0000:0000:0000:0000:0000:0000:0000:0001");
        assert_eq!(result.1, 8080);
    }

    #[test]
    fn test_parse_empty_port() {
        let result = parse_ip_port("00000000:0000").unwrap();
        assert_eq!(result.0, "0.0.0.0");
        assert_eq!(result.1, 0);
    }

    #[test]
    fn test_parse_bogus_rejected() {
        assert!(parse_ip_port("nothex").is_none());
        assert!(parse_ip_port("1234:xyz").is_none());
    }

    #[test]
    fn test_read_process_name() {
        // PID 1 should exist on any Linux system
        let name = read_process_name(1);
        assert!(!name.is_empty());
    }
}

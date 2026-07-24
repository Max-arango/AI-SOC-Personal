#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use sentinel_core::traits::EventBus;
use sentinel_events::network_event::{Action, Direction, Protocol};
use sentinel_events::{Event, NetworkEvent};
use tracing::{debug, info, warn};

struct ConnectionKey {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    protocol: Protocol,
}

impl ConnectionKey {
    fn to_key(&self) -> String {
        format!(
            "{}:{}->{}:{}:{}",
            self.local_addr,
            self.local_port,
            self.remote_addr,
            self.remote_port,
            self.protocol as i32
        )
    }
}

fn parse_ip_port(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip = if parts[0].len() == 8 {
        let mut bytes = [0u8; 4];
        for i in 0..4 {
            let byte = u8::from_str_radix(&parts[0][i * 2..i * 2 + 2], 16).ok()?;
            bytes[3 - i] = byte;
        }
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else if parts[0].len() == 32 {
        let mut groups = Vec::new();
        for i in 0..8 {
            let byte_hi = u8::from_str_radix(&parts[0][i * 4..i * 4 + 2], 16).ok()?;
            let byte_lo = u8::from_str_radix(&parts[0][i * 4 + 2..i * 4 + 4], 16).ok()?;
            if byte_hi == 0 && byte_lo == 0 && groups.is_empty() {
                continue;
            }
            groups.push(format!("{:x}{:02x}", byte_hi, byte_lo));
        }
        groups.join(":")
    } else {
        return None;
    };

    let port = u16::from_str_radix(parts[1], 16).ok()?;
    Some((ip, port))
}

fn parse_proc_net_tcp(path: &str, protocol: Protocol) -> Vec<ConnectionKey> {
    let mut connections = Vec::new();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return connections,
    };

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let local = parse_ip_port(fields[1]);
        let remote = parse_ip_port(fields[2]);

        if let (Some((local_addr, local_port)), Some((remote_addr, remote_port))) = (local, remote)
        {
            connections.push(ConnectionKey {
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                protocol,
            });
        }
    }

    connections
}

#[cfg(target_os = "linux")]
pub async fn start_network_monitor(bus: Arc<dyn EventBus>) {
    tokio::spawn(async move {
        let mut known: HashMap<String, bool> = HashMap::new();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        tick.tick().await;

        info!("Network collector started (30s interval)");

        loop {
            tick.tick().await;

            let mut current_keys = HashMap::new();

            for (path, proto) in [
                ("/proc/net/tcp", Protocol::Tcp),
                ("/proc/net/udp", Protocol::Udp),
                ("/proc/net/tcp6", Protocol::Tcp),
                ("/proc/net/udp6", Protocol::Udp),
            ] {
                for conn in parse_proc_net_tcp(path, proto) {
                    let key = conn.to_key();
                    if !known.contains_key(&key) {
                        let event = Arc::new(Event {
                            id: sentinel_core::Ulid::new().to_string(),
                            r#type: "sentinel.network.connect".into(),
                            source: "network".into(),
                            severity: 3,
                            risk_score: 5,
                            host_id: String::new(),
                            schema_version: 1,
                            payload: Some(sentinel_events::event::Payload::NetworkEvent(
                                NetworkEvent {
                                    direction: Direction::Outbound as i32,
                                    protocol: conn.protocol as i32,
                                    action: Action::Connect as i32,
                                    local_addr: conn.local_addr.clone(),
                                    local_port: conn.local_port as u32,
                                    remote_addr: conn.remote_addr.clone(),
                                    remote_port: conn.remote_port as u32,
                                    ..Default::default()
                                },
                            )),
                            ..Default::default()
                        });

                        if let Err(e) = bus.publish(event).await {
                            warn!("Network collector publish failed: {e}");
                        } else {
                            debug!(
                                "New connection: {} -> {}:{} ({})",
                                conn.local_addr,
                                conn.remote_addr,
                                conn.remote_port,
                                if conn.protocol == Protocol::Tcp { "tcp" } else { "udp" }
                            );
                        }
                    }
                    current_keys.insert(key, true);
                }
            }

            known = current_keys;
        }
    });
}

#[cfg(not(target_os = "linux"))]
pub async fn start_network_monitor(_bus: Arc<dyn EventBus>) {
    tracing::info!("Network collector: not supported on this platform");
}

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
    fn test_parse_empty_port() {
        let result = parse_ip_port("00000000:0000").unwrap();
        assert_eq!(result.0, "0.0.0.0");
        assert_eq!(result.1, 0);
    }
}

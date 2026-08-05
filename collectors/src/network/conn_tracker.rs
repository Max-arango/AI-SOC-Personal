//! Connection tracker — state machine for network connections.
//!
//! Tracks every connection seen on the host: marks them as
//! Established when first observed, detects Close when they
//! disappear from /proc/net, and deduplicates by connection key.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use sentinel_events::network_event::Protocol;

/// Unique identifier for a network connection
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ConnectionKey {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: Protocol,
}

impl ConnectionKey {
    pub fn display(&self) -> String {
        let proto = if self.protocol == Protocol::Tcp { "tcp" } else { "udp" };
        format!(
            "{}:{} → {}:{} ({})",
            self.local_addr, self.local_port,
            self.remote_addr, self.remote_port,
            proto,
        )
    }
}

/// Enriched connection data
#[derive(Debug, Clone)]
pub struct ConnectionMeta {
    pub pid: u32,
    pub process_name: String,
    #[allow(dead_code)]
    pub uid: u32,
    #[allow(dead_code)]
    pub inode: u64,
}

/// State of a tracked connection
#[derive(Debug, Clone)]
pub enum ConnState {
    Established {
        first_seen: Instant,
        #[allow(dead_code)]
        tx_bytes: u64,
        #[allow(dead_code)]
        rx_bytes: u64,
        meta: ConnectionMeta,
    },
}

/// Result of processing a poll cycle
#[derive(Debug)]
pub enum ConnectionEvent {
    New {
        key: ConnectionKey,
        meta: ConnectionMeta,
    },
    Close {
        key: ConnectionKey,
        duration: Duration,
        meta: ConnectionMeta,
    },
}

/// Tracks the lifecycle of all observed connections
pub struct ConnTracker {
    connections: HashMap<ConnectionKey, ConnState>,
}

impl ConnTracker {
    pub fn new() -> Self {
        Self {
            connections: HashMap::with_capacity(256),
        }
    }

    /// Feed the tracker with the current set of connections observed
    /// in this poll cycle. Returns New and Close events.
    pub fn update(
        &mut self,
        current: Vec<(ConnectionKey, ConnectionMeta)>,
    ) -> Vec<ConnectionEvent> {
        let mut events = Vec::new();
        let now = Instant::now();

        // Mark all current keys as "seen" for close detection
        let current_keys: std::collections::HashSet<ConnectionKey> =
            current.iter().map(|(k, _)| k.clone()).collect();

        // Detect CLOSED: connections we knew about but not in current
        let mut closed: Vec<ConnectionKey> = Vec::new();
        for key in self.connections.keys() {
            if !current_keys.contains(key) {
                closed.push(key.clone());
            }
        }

        for key in &closed {
            if let Some(ConnState::Established { first_seen, meta, .. }) =
                self.connections.remove(key)
            {
                let duration = now.duration_since(first_seen);
                events.push(ConnectionEvent::Close {
                    key: key.clone(),
                    duration,
                    meta,
                });
            }
        }

        // Detect NEW: connections not yet tracked
        for (key, meta) in current {
            if !self.connections.contains_key(&key) {
                events.push(ConnectionEvent::New {
                    key: key.clone(),
                    meta: meta.clone(),
                });

                self.connections.insert(
                    key,
                    ConnState::Established {
                        first_seen: now,
                        tx_bytes: 0,
                        rx_bytes: 0,
                        meta,
                    },
                );
            }
            // Already-tracked connections: nothing to do (would update
            // tx_bytes/rx_bytes if we had byte counters)
        }

        events
    }

    /// Number of currently tracked connections
    pub fn active_count(&self) -> usize {
        self.connections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(remote_port: u16) -> ConnectionKey {
        ConnectionKey {
            local_addr: "10.0.0.1".into(),
            local_port: 12345,
            remote_addr: "93.184.216.34".into(),
            remote_port,
            protocol: Protocol::Tcp,
        }
    }

    fn make_meta(pid: u32) -> ConnectionMeta {
        ConnectionMeta {
            pid,
            process_name: "test".into(),
            uid: 1000,
            inode: 10000 + pid as u64,
        }
    }

    #[test]
    fn detects_new_connection() {
        let mut tracker = ConnTracker::new();
        let key = make_key(443);
        let meta = make_meta(100);

        let events = tracker.update(vec![(key.clone(), meta.clone())]);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], ConnectionEvent::New { .. }));
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn detects_closed_connection() {
        let mut tracker = ConnTracker::new();
        let key = make_key(443);
        let meta = make_meta(100);

        // First poll: NEW
        tracker.update(vec![(key.clone(), meta.clone())]);
        // Second poll: connection gone → CLOSE
        let events = tracker.update(vec![]);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], ConnectionEvent::Close { .. }));
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn deduplicates_existing_connections() {
        let mut tracker = ConnTracker::new();
        let key = make_key(443);
        let meta = make_meta(100);

        // First poll
        let events = tracker.update(vec![(key.clone(), meta.clone())]);
        assert_eq!(events.len(), 1);
        // Second poll, same connection still present
        let events = tracker.update(vec![(key.clone(), meta.clone())]);
        assert_eq!(events.len(), 0); // No events for unchanged connection
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn tracks_multiple_connections() {
        let mut tracker = ConnTracker::new();
        let current: Vec<_> = (1..=5)
            .map(|i| (make_key(100 + i), make_meta(1000 + i as u32)))
            .collect();

        let events = tracker.update(current.clone());
        assert_eq!(events.len(), 5);
        assert_eq!(tracker.active_count(), 5);

        // Keep 2, close 3
        let subset = current.into_iter().take(2).collect();
        let events = tracker.update(subset);
        assert_eq!(events.len(), 3); // 3 CLOSE events
        assert_eq!(tracker.active_count(), 2);
    }

    #[test]
    fn handles_empty_poll() {
        let mut tracker = ConnTracker::new();
        let events = tracker.update(vec![]);
        assert!(events.is_empty());
        assert_eq!(tracker.active_count(), 0);
    }
}

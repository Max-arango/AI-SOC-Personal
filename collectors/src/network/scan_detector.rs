//! Port-scan / brute-force detector.
//!
//! Tracks connection patterns over a sliding window to detect:
//! - **Port scans**: > N unique destination ports to the same remote
//!   host in the window (default: >10 ports in 30s).
//! - **Horizontal scans**: > N unique remote hosts on the same port
//!   in the window (default: >20 hosts in 30s).
//! - **Connection storms**: > N total new connections in the window
//!   from a single local process.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// What kind of suspicious activity was detected
#[derive(Debug, Clone, PartialEq)]
pub enum ScanType {
    VerticalScan {
        host: String,
        port_count: usize,
    },
    HorizontalScan {
        port: u16,
        host_count: usize,
    },
    ConnectionStorm {
        pid: u32,
        count: usize,
    },
}

/// A recorded connection observation for scan analysis
#[derive(Debug, Clone)]
struct ConnObservation {
    remote_host: String,
    remote_port: u16,
    pid: u32,
    timestamp: Instant,
}

/// Sliding-window scan detector
pub struct ScanDetector {
    observations: VecDeque<ConnObservation>,
    window: Duration,
    vertical_threshold: usize,
    horizontal_threshold: usize,
    storm_threshold: usize,
}

impl ScanDetector {
    pub fn new(window: Duration) -> Self {
        Self {
            observations: VecDeque::new(),
            window,
            vertical_threshold: 10,
            horizontal_threshold: 20,
            storm_threshold: 100,
        }
    }

    /// Record a new connection and check for scan patterns.
    ///
    /// Returns `Some(ScanType)` if a scan is detected, `None` otherwise.
    pub fn record(&mut self, remote_host: &str, remote_port: u16, pid: u32) -> Option<ScanType> {
        let now = Instant::now();

        // Prune old observations outside the window
        while let Some(front) = self.observations.front() {
            if now.duration_since(front.timestamp) > self.window {
                self.observations.pop_front();
            } else {
                break;
            }
        }

        // Record the new observation
        self.observations.push_back(ConnObservation {
            remote_host: remote_host.to_string(),
            remote_port,
            pid,
            timestamp: now,
        });

        // Check for vertical scan (many ports to one host)
        if let Some(scan) = self.check_vertical_scan(remote_host) {
            return Some(scan);
        }

        // Check for horizontal scan (many hosts on same port)
        if let Some(scan) = self.check_horizontal_scan(remote_port) {
            return Some(scan);
        }

        // Check for connection storm from this process
        if let Some(scan) = self.check_storm(pid) {
            return Some(scan);
        }

        None
    }

    fn check_vertical_scan(&self, host: &str) -> Option<ScanType> {
        let unique_ports: std::collections::HashSet<u16> = self
            .observations
            .iter()
            .filter(|o| o.remote_host == host)
            .map(|o| o.remote_port)
            .collect();

        if unique_ports.len() >= self.vertical_threshold {
            Some(ScanType::VerticalScan { host: host.to_string(), port_count: unique_ports.len() })
        } else {
            None
        }
    }

    fn check_horizontal_scan(&self, port: u16) -> Option<ScanType> {
        let unique_hosts: std::collections::HashSet<&str> = self
            .observations
            .iter()
            .filter(|o| o.remote_port == port)
            .map(|o| o.remote_host.as_str())
            .collect();

        if unique_hosts.len() >= self.horizontal_threshold {
            Some(ScanType::HorizontalScan { port, host_count: unique_hosts.len() })
        } else {
            None
        }
    }

    fn check_storm(&self, pid: u32) -> Option<ScanType> {
        let count = self.observations.iter().filter(|o| o.pid == pid).count();

        if count >= self.storm_threshold {
            Some(ScanType::ConnectionStorm { pid, count })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_scan_with_few_connections() {
        let mut detector = ScanDetector::new(Duration::from_secs(30));
        for port in 1..=5 {
            assert!(detector.record("8.8.8.8", port, 1000).is_none());
        }
    }

    #[test]
    fn detects_vertical_scan() {
        let mut detector = ScanDetector::new(Duration::from_secs(3600));
        let mut result = None;
        for port in 1..=15 {
            result = detector.record("10.0.0.5", port, 1000);
        }
        assert!(matches!(result, Some(ScanType::VerticalScan { port_count: 15, .. })));
    }

    #[test]
    fn detects_horizontal_scan() {
        let mut detector = ScanDetector::new(Duration::from_secs(3600));
        let mut result = None;
        for i in 1..=25 {
            let host = format!("192.168.1.{}", i);
            result = detector.record(&host, 22, 1000);
        }
        assert!(matches!(result, Some(ScanType::HorizontalScan { port: 22, host_count: 25 })));
    }

    #[test]
    fn window_prunes_old_observations() {
        let mut detector = ScanDetector::new(Duration::from_millis(1));
        for port in 1..=15 {
            detector.record("10.0.0.5", port, 1000);
        }
        std::thread::sleep(Duration::from_millis(2));
        // After window expires, new connections should not trigger scan
        let result = detector.record("10.0.0.5", 99, 1000);
        assert!(result.is_none());
    }

    #[test]
    fn ignores_same_port_repeatedly() {
        let mut detector = ScanDetector::new(Duration::from_secs(30));
        for _ in 0..50 {
            let result = detector.record("8.8.8.8", 443, 1000);
            assert!(result.is_none(), "Single port repeated should not trigger scan");
        }
    }
}

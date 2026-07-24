//! Health monitoring for Sentinel AI components

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Overall system health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Component health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub details: HashMap<String, String>,
    pub last_check: DateTime<Utc>,
    pub metrics: Option<ComponentMetrics>,
}

impl ComponentHealth {
    pub fn healthy(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Healthy,
            message: None,
            details: HashMap::new(),
            last_check: Utc::now(),
            metrics: None,
        }
    }

    pub fn degraded(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Degraded,
            message: Some(message.into()),
            details: HashMap::new(),
            last_check: Utc::now(),
            metrics: None,
        }
    }

    pub fn unhealthy(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Unhealthy,
            message: Some(message.into()),
            details: HashMap::new(),
            last_check: Utc::now(),
            metrics: None,
        }
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    pub fn with_metrics(mut self, metrics: ComponentMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }
}

/// Component-specific metrics for health reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentMetrics {
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
    pub queue_depth: Option<usize>,
    pub events_per_second: Option<f64>,
    pub error_rate: Option<f64>,
    pub latency_p99_ms: Option<f64>,
}

/// Aggregated health status for the entire system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub status: HealthStatus,
    pub components: Vec<ComponentHealth>,
    pub timestamp: DateTime<Utc>,
    pub uptime_seconds: u64,
}

impl SystemHealth {
    pub fn new(components: Vec<ComponentHealth>, uptime_seconds: u64) -> Self {
        let status = if components
            .iter()
            .any(|c| c.status == HealthStatus::Unhealthy)
        {
            HealthStatus::Unhealthy
        } else if components
            .iter()
            .any(|c| c.status == HealthStatus::Degraded)
        {
            HealthStatus::Degraded
        } else if components.iter().all(|c| c.status == HealthStatus::Healthy) {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unknown
        };

        Self { status, components, timestamp: Utc::now(), uptime_seconds }
    }

    pub fn unhealthy_components(&self) -> Vec<&ComponentHealth> {
        self.components
            .iter()
            .filter(|c| c.status == HealthStatus::Unhealthy)
            .collect()
    }

    pub fn degraded_components(&self) -> Vec<&ComponentHealth> {
        self.components
            .iter()
            .filter(|c| c.status == HealthStatus::Degraded)
            .collect()
    }
}

/// Health check trait for components
#[async_trait::async_trait]
pub trait HealthCheck: Send + Sync {
    async fn check(&self) -> ComponentHealth;

    fn name(&self) -> &'static str;
}

/// Composite health check that runs multiple checks
pub struct CompositeHealthCheck {
    checks: Vec<Box<dyn HealthCheck>>,
}

impl CompositeHealthCheck {
    pub fn new(checks: Vec<Box<dyn HealthCheck>>) -> Self {
        Self { checks }
    }
}

#[async_trait::async_trait]
impl HealthCheck for CompositeHealthCheck {
    async fn check(&self) -> ComponentHealth {
        let mut results = Vec::new();

        for check in &self.checks {
            results.push(check.check().await);
        }

        let overall = if results.iter().any(|r| r.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if results.iter().any(|r| r.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        ComponentHealth {
            name: "composite".to_string(),
            status: overall,
            message: None,
            details: results
                .into_iter()
                .map(|r| (r.name, format!("{:?}", r.status)))
                .collect(),
            last_check: Utc::now(),
            metrics: None,
        }
    }

    fn name(&self) -> &'static str {
        "composite"
    }
}

/// Resource usage tracker
pub struct ResourceTracker {
    process_start: DateTime<Utc>,
    #[cfg(target_os = "linux")]
    pid: u32,
}

impl ResourceTracker {
    pub fn new() -> Self {
        Self {
            process_start: Utc::now(),
            #[cfg(target_os = "linux")]
            pid: std::process::id(),
        }
    }

    pub fn uptime_seconds(&self) -> u64 {
        (Utc::now() - self.process_start).num_seconds() as u64
    }

    pub fn memory_bytes(&self) -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            let content = fs::read_to_string(format!("/proc/{}/status", self.pid)).ok()?;
            for line in content.lines() {
                if line.starts_with("VmRSS:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(kb) = parts[1].parse::<u64>() {
                            return Some(kb * 1024);
                        }
                    }
                }
            }
            None
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            let output = Command::new("ps")
                .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()
                .ok()?;
            let rss = String::from_utf8(output.stdout)
                .ok()?
                .trim()
                .parse::<u64>()
                .ok()?;
            Some(rss * 1024)
        }

        #[cfg(target_os = "windows")]
        {
            use std::mem;
            use windows::Win32::System::Memory::GetProcessMemoryInfo;
            use windows::Win32::System::Memory::PROCESS_MEMORY_COUNTERS;
            use windows::Win32::System::Threading::GetCurrentProcess;

            unsafe {
                let mut counters: PROCESS_MEMORY_COUNTERS = mem::zeroed();
                counters.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                if GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb).is_ok() {
                    Some(counters.WorkingSetSize)
                } else {
                    None
                }
            }
        }

        #[cfg(
            not(
                any(
                    target_os = "linux",
                    target_os = "macos",
                    target_os = "windows"
                )
            )
        )]
        {
            None
        }
    }

    pub fn cpu_percent(&self) -> Option<f64> {
        // Simplified - would need more sophisticated tracking for real CPU%
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            let content = fs::read_to_string(format!("/proc/{}/stat", self.pid)).ok()?;
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 17 {
                let utime = parts[13].parse::<u64>().ok()?;
                let stime = parts[14].parse::<u64>().ok()?;
                let total_time = utime + stime;
                let clock_ticks = 100; // sysconf(_SC_CLK_TCK)
                let elapsed = self.uptime_seconds() as f64;
                if elapsed > 0.0 {
                    return Some((total_time as f64 / clock_ticks as f64) / elapsed * 100.0);
                }
            }
            None
        }

        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

impl Default for ResourceTracker {
    fn default() -> Self {
        Self::new()
    }
}

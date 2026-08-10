//! Sentinel AI Core Library
//!
//! Shared types, traits, and utilities for the Sentinel AI security platform.

pub mod errors;
pub mod health;
pub mod metrics;
pub mod response;
pub mod traits;

// Re-export commonly used types at the crate root so downstream crates can
// import them as `sentinel_core::ConfigProvider`, etc.
pub use errors::{CollectorError, ConfigError, EventBusError, SentinelError, StorageError};
pub use health::{ComponentHealth, ComponentMetrics, HealthCheck, HealthStatus, SystemHealth};
pub use metrics::{MetricsRegistry, MetricsSnapshot};
pub use traits::{
    Alert, AlertQuery, AlertRepository, AlertState, AttackChain, BrowserData, BrowserDownload,
    BrowserExtension, BrowserHistoryEntry, BrowserType, ChainQuery, ChainRepository, ChainStatus,
    Collector, CollectorContext, CollectorHealth, CollectorMetrics, CollectorState, ConfigProvider,
    ConfigRepository, ConfigSchema, ConfigWatcher, ConnectionInfo, EventBus, EventBusStats,
    EventCursor, EventFilter, EventQuery, EventRepository, EventSubscription, FileAction,
    FileEvent, FileWatcher, MitreMapping, Module, OsAbstraction, PluginInfo, PluginManager,
    PluginState, ProcessInfo, RegistryAction, RegistryEvent, RegistryWatcher, RetentionPolicy,
    RiskConfig, RiskMultiplier, Rule, RuleAction, RuleActionType, RuleRepository, RuleTest,
    StartupItem, StartupLocation, SuppressionRule, UsbAction, UsbDeviceInfo, UsbEvent, UsbWatcher,
    UserInfo,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

/// Unique identifier for events (ULID - timestamp + entropy)
pub type EventId = Ulid;

/// Unique identifier for rules
pub type RuleId = String;

/// Unique identifier for alerts
pub type AlertId = Ulid;

/// Unique identifier for correlation chains
pub type CorrelationId = Ulid;

/// Unique identifier for hosts
pub type HostId = String;

/// Unique identifier for collectors
pub type CollectorId = String;

/// Unique identifier for plugins
pub type PluginId = String;

/// ULID-based identifier.
///
/// `ulid::Ulid` does not ship a working `serde` feature in current releases, so
/// we wrap it in a newtype that serializes through the canonical 26-char string
/// representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ulid(ulid::Ulid);

impl Ulid {
    pub fn new() -> Self {
        Ulid(ulid::Ulid::new())
    }

    pub fn from_string(s: &str) -> crate::Result<Self> {
        ulid::Ulid::from_string(s)
            .map(Ulid)
            .map_err(|e| crate::errors::SentinelError::Parse(format!("invalid ULID: {e}")))
    }

    pub fn inner(&self) -> ulid::Ulid {
        self.0
    }
}

impl Default for Ulid {
    fn default() -> Self {
        Ulid::new()
    }
}

impl fmt::Display for Ulid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Ulid {
    type Err = crate::errors::SentinelError;
    fn from_str(s: &str) -> crate::Result<Self> {
        Ulid::from_string(s)
    }
}

impl Serialize for Ulid {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Ulid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ulid::from_string(&s).map_err(serde::de::Error::custom)
    }
}

/// A configuration value, transparently wrapping a `serde_json::Value`.
///
/// Defined here (rather than in `sentinel-config`) to avoid a crate cycle:
/// `sentinel-config` depends on `sentinel-core` for this type.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ConfigValue(pub serde_json::Value);

impl ConfigValue {
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl From<serde_json::Value> for ConfigValue {
    fn from(value: serde_json::Value) -> Self {
        ConfigValue(value)
    }
}

impl From<ConfigValue> for serde_json::Value {
    fn from(value: ConfigValue) -> Self {
        value.0
    }
}

/// Current host identifier (generated at first run)
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct HostIdentity {
    pub id: HostId,
    pub created_at: DateTime<Utc>,
    pub platform: String,
    pub hostname: String,
}

impl HostIdentity {
    pub fn new(platform: String, hostname: String) -> Self {
        Self { id: Uuid::new_v4().to_string(), created_at: Utc::now(), platform, hostname }
    }
}

/// Severity levels matching syslog/RFC5424.
///
/// The discriminants mirror the `sentinel_events::Severity` protobuf enum
/// so the two representations are interchangeable without conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, Default)]
#[repr(u8)]
pub enum Severity {
    Debug = 1,
    #[default]
    Info = 2,
    Notice = 3,
    Warning = 4,
    Error = 5,
    Critical = 6,
    Alert = 7,
    Emergency = 8,
}

impl<'de> serde::Deserialize<'de> for Severity {
    /// Accepts case-insensitive syslog names ("warning", "ERROR", ...) plus the
    /// alert-level vocabulary used in rule files ("LOW", "MEDIUM", "HIGH",
    /// "CRITICAL"), mapped onto the syslog scale.
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_ascii_uppercase().as_str() {
            "DEBUG" => Ok(Severity::Debug),
            "INFO" | "LOW" => Ok(Severity::Info),
            "NOTICE" => Ok(Severity::Notice),
            "WARNING" | "MEDIUM" => Ok(Severity::Warning),
            "ERROR" | "HIGH" => Ok(Severity::Error),
            "CRITICAL" => Ok(Severity::Critical),
            "ALERT" => Ok(Severity::Alert),
            "EMERGENCY" => Ok(Severity::Emergency),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &[
                    "DEBUG",
                    "INFO",
                    "NOTICE",
                    "WARNING",
                    "ERROR",
                    "CRITICAL",
                    "ALERT",
                    "EMERGENCY",
                    "LOW",
                    "MEDIUM",
                    "HIGH",
                ],
            )),
        }
    }
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Debug => "DEBUG",
            Severity::Info => "INFO",
            Severity::Notice => "NOTICE",
            Severity::Warning => "WARNING",
            Severity::Error => "ERROR",
            Severity::Critical => "CRITICAL",
            Severity::Alert => "ALERT",
            Severity::Emergency => "EMERGENCY",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// System lifecycle states
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SystemState {
    Initializing,
    Starting,
    Running,
    Degraded,
    Stopping,
    Stopped,
    Crashed,
}

/// Backpressure signal levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BackpressureSignal {
    Normal,
    Elevated,
    High,
    Critical,
    Overflow,
}

/// Configuration for channel capacities
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChannelConfig {
    pub ingest: usize,
    pub broadcast: usize,
    pub storage: usize,
    pub plugin: usize,
    pub ipc: usize,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self { ingest: 10_000, broadcast: 1_000, storage: 5_000, plugin: 2_000, ipc: 500 }
    }
}

/// Backpressure thresholds (percentage of channel capacity)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackpressureConfig {
    pub elevated: u8,
    pub high: u8,
    pub critical: u8,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self { elevated: 50, high: 75, critical: 90 }
    }
}

/// Result type for fallible operations
pub type Result<T> = std::result::Result<T, errors::SentinelError>;

/// Trait for types that can be serialized to bytes for storage/transport
pub trait Serializable: Send + Sync {
    fn to_bytes(&self) -> Result<Vec<u8>>;
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// Trait for components that can report health
pub trait HealthReporter: Send + Sync {
    fn health(&self) -> health::ComponentHealth;
}

/// Trait for components that expose metrics
pub trait MetricsReporter: Send + Sync {
    fn metrics(&self) -> metrics::MetricsSnapshot;
}

/// Shutdown signal for graceful termination
#[derive(Debug, Clone)]
pub struct ShutdownSignal(pub tokio::sync::watch::Receiver<bool>);

impl ShutdownSignal {
    pub fn new() -> (Self, tokio::sync::watch::Sender<bool>) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (Self(rx), tx)
    }

    pub async fn wait(&self) {
        let mut rx = self.0.clone();
        let _ = rx.changed().await;
    }

    pub fn is_shutdown(&self) -> bool {
        *self.0.borrow()
    }
}


/// Module context provided to each subsystem
#[derive(Clone)]
pub struct ModuleContext {
    pub event_bus: Arc<dyn traits::EventBus>,
    pub storage: Arc<dyn traits::Storage>,
    pub config: Arc<dyn traits::ConfigProvider>,
    pub metrics: Arc<metrics::MetricsRegistry>,
    pub plugin_manager: Arc<dyn traits::PluginManager>,
    pub shutdown: ShutdownSignal,
}



#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CollectorStatus {
    pub id: String,
    pub name: String,
    pub description: String,
    pub state: String,
    pub events_produced: u64,
    pub errors: u64,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_event_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl CollectorStatus {
    pub fn new(id: &str, name: &str, description: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            state: "running".to_string(),
            events_produced: 0,
            errors: 0,
            started_at: Some(chrono::Utc::now()),
            last_event_at: None,
        }
    }
}

pub struct CollectorRegistry {
    collectors: parking_lot::RwLock<std::collections::HashMap<String, CollectorStatus>>,
}

impl CollectorRegistry {
    pub fn new() -> Self {
        Self {
            collectors: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub fn register(&self, status: CollectorStatus) {
        self.collectors.write().insert(status.id.clone(), status);
    }

    pub fn list(&self) -> Vec<CollectorStatus> {
        self.collectors.read().values().cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<CollectorStatus> {
        self.collectors.read().get(id).cloned()
    }

    pub fn update_state(&self, id: &str, state: &str) {
        let mut c = self.collectors.write();
        if let Some(s) = c.get_mut(id) {
            s.state = state.to_string();
        }
    }

    pub fn increment_events(&self, id: &str, count: u64) {
        let mut c = self.collectors.write();
        if let Some(s) = c.get_mut(id) {
            s.events_produced += count;
            s.last_event_at = Some(chrono::Utc::now());
        }
    }
}

impl Default for CollectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleContext {
    pub fn new(
        event_bus: Arc<dyn traits::EventBus>,
        storage: Arc<dyn traits::Storage>,
        config: Arc<dyn traits::ConfigProvider>,
        metrics: Arc<metrics::MetricsRegistry>,
        plugin_manager: Arc<dyn traits::PluginManager>,
        shutdown: ShutdownSignal,
    ) -> Self {
        Self { event_bus, storage, config, metrics, plugin_manager, shutdown }
    }
}

/// Convert a `chrono` UTC datetime into a proto `Timestamp`.
pub fn chrono_to_proto_ts(dt: chrono::DateTime<chrono::Utc>) -> Option<prost_types::Timestamp> {
    Some(prost_types::Timestamp::from(std::time::SystemTime::from(dt)))
}

/// Current time as a proto `Timestamp`.
pub fn now_proto_ts() -> Option<prost_types::Timestamp> {
    Some(prost_types::Timestamp::from(std::time::SystemTime::now()))
}

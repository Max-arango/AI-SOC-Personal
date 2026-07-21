//! Core traits and type definitions for Sentinel AI modules

use std::sync::Arc;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use crate::{ConfigValue, EventId, ModuleContext, Result};

pub use sentinel_events::Event;

/// Module lifecycle trait - all subsystems implement this
#[async_trait]
pub trait Module: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn dependencies(&self) -> Vec<&'static str> { vec![] }
    
    async fn initialize(&mut self, ctx: &ModuleContext) -> Result<()>;
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self, graceful: bool) -> Result<()>;
    async fn restart(&mut self) -> Result<()> {
        self.stop(true).await?;
        self.start().await
    }
    
    fn health(&self) -> super::health::ComponentHealth;
    fn config_schema(&self) -> ConfigSchema;
}

/// Configuration schema for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSchema {
    pub module: String,
    pub version: u32,
    pub schema: serde_json::Value, // JSON Schema
}

/// Event bus trait for publishing/subscribing to events
#[async_trait]
pub trait EventBus: Send + Sync {
    /// Publish an event to the bus
    async fn publish(&self, event: Arc<Event>) -> Result<()>;
    
    /// Subscribe to events matching a filter
    async fn subscribe(&self, filter: EventFilter) -> Result<EventSubscription>;
    
    /// Subscribe to all events of a specific type
    async fn subscribe_type(&self, event_type: &str) -> Result<EventSubscription>;
    
    /// Get current backpressure signal
    fn backpressure(&self) -> crate::BackpressureSignal;
    
    /// Get channel statistics
    fn stats(&self) -> EventBusStats;
}

/// Event subscription handle
pub struct EventSubscription {
    pub receiver: tokio::sync::mpsc::Receiver<Arc<Event>>,
    pub filter: EventFilter,
}

/// Filter for event subscriptions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    pub event_types: Option<Vec<String>>,
    pub sources: Option<Vec<String>>,
    pub min_severity: Option<crate::Severity>,
    pub process_names: Option<Vec<String>>,
    pub correlation_id: Option<String>,
    pub flow_id: Option<String>,
    pub min_risk_score: Option<u32>,
}

impl Default for EventFilter {
    fn default() -> Self {
        Self {
            event_types: None,
            sources: None,
            min_severity: None,
            process_names: None,
            correlation_id: None,
            flow_id: None,
            min_risk_score: None,
        }
    }
}

/// Event bus statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBusStats {
    pub ingest_queue_depth: usize,
    pub broadcast_queue_depths: Vec<usize>,
    pub storage_queue_depth: usize,
    pub plugin_queue_depth: usize,
    pub ipc_queue_depth: usize,
    pub events_published: u64,
    pub events_dropped: u64,
}

/// Storage abstraction for persistence
#[async_trait]
pub trait Storage: Send + Sync {
    /// Event repository
    async fn events(&self) -> Arc<dyn EventRepository>;
    
    /// Rule repository
    async fn rules(&self) -> Arc<dyn RuleRepository>;
    
    /// Alert repository
    async fn alerts(&self) -> Arc<dyn AlertRepository>;
    
    /// Configuration repository
    async fn config(&self) -> Arc<dyn ConfigRepository>;
    
    /// Run migrations
    async fn migrate(&self) -> Result<()>;
    
    /// Health check
    async fn health(&self) -> Result<()>;
}

/// Event repository trait
#[async_trait]
pub trait EventRepository: Send + Sync {
    async fn append(&self, events: &[Arc<Event>]) -> Result<()>;
    async fn query(&self, query: EventQuery) -> Result<Arc<dyn EventCursor>>;
    async fn get(&self, id: &EventId) -> Result<Option<Arc<Event>>>;
    async fn count(&self, query: &EventQuery) -> Result<u64>;
    async fn aggregate(&self, agg: AggregationQuery) -> Result<AggregationResult>;
    async fn retention(&self, policy: RetentionPolicy) -> Result<u64>;
}

/// Query for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventQuery {
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub event_types: Vec<String>,
    pub sources: Vec<String>,
    pub severities: Vec<crate::Severity>,
    pub process_names: Vec<String>,
    pub pids: Vec<u32>,
    pub correlation_id: Option<String>,
    pub flow_id: Option<String>,
    pub min_risk_score: Option<u32>,
    pub tags: Vec<String>,
    pub free_text: Option<String>,
    pub limit: usize,
    pub offset: usize,
    pub sort_by: Option<String>,
    pub sort_desc: bool,
}

impl Default for EventQuery {
    fn default() -> Self {
        Self {
            start_time: None,
            end_time: None,
            event_types: vec![],
            sources: vec![],
            severities: vec![],
            process_names: vec![],
            pids: vec![],
            correlation_id: None,
            flow_id: None,
            min_risk_score: None,
            tags: vec![],
            free_text: None,
            limit: 100,
            offset: 0,
            sort_by: Some("timestamp".to_string()),
            sort_desc: true,
        }
    }
}

/// Cursor for iterating query results
#[async_trait]
pub trait EventCursor: Send + Sync {
    async fn next(&mut self) -> Result<Option<Arc<Event>>>;
    async fn collect(&mut self, limit: usize) -> Result<Vec<Arc<Event>>>;
    fn total_count(&self) -> u64;
}

/// Aggregation query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationQuery {
    pub group_by: String, // "hour", "day", "type", "source", "severity"
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub filters: EventQuery,
}

/// Aggregation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationResult {
    pub buckets: Vec<AggregationBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationBucket {
    pub key: String,
    pub count: u64,
    pub avg_risk: Option<f64>,
    pub min_risk: Option<u32>,
    pub max_risk: Option<u32>,
}

/// Retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub event_type_pattern: String,
    pub max_age_days: u32,
    pub max_count: u64,
}

/// Rule repository trait
#[async_trait]
pub trait RuleRepository: Send + Sync {
    async fn load_all(&self) -> Result<Vec<Rule>>;
    async fn get(&self, id: &str) -> Result<Option<Rule>>;
    async fn upsert(&self, rule: &Rule) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
    async fn enable(&self, id: &str, enabled: bool) -> Result<()>;
}

/// Rule definition (matches YAML schema)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub version: u32,
    pub name: String,
    pub description: String,
    pub author: String,
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,
    pub enabled: bool,
    pub category: String,
    pub subcategory: Option<String>,
    pub mitre: Vec<MitreMapping>,
    pub severity: crate::Severity,
    pub risk: RiskConfig,
    pub condition: String, // CEL expression
    pub and_conditions: Vec<String>,
    pub or_conditions: Vec<String>,
    pub not_conditions: Vec<String>,
    pub actions: Vec<RuleAction>,
    pub suppressions: Vec<SuppressionRule>,
    pub tests: Vec<RuleTest>,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            id: String::new(),
            version: 0,
            name: String::new(),
            description: String::new(),
            author: String::new(),
            created: chrono::Utc::now(),
            modified: chrono::Utc::now(),
            enabled: false,
            category: String::new(),
            subcategory: None,
            mitre: Vec::new(),
            severity: crate::Severity::default(),
            risk: RiskConfig::default(),
            condition: String::new(),
            and_conditions: Vec::new(),
            or_conditions: Vec::new(),
            not_conditions: Vec::new(),
            actions: Vec::new(),
            suppressions: Vec::new(),
            tests: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique: String,
    pub name: String,
    pub tactic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskConfig {
    pub base_score: u32,
    pub confidence: f64,
    pub multipliers: Vec<RiskMultiplier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskMultiplier {
    pub condition: String, // CEL expression
    pub factor: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAction {
    pub action_type: RuleActionType,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleActionType {
    Alert,
    Enrich,
    Correlate,
    Snapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRule {
    pub id: String,
    pub condition: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTest {
    pub name: String,
    pub event: serde_json::Value, // Event as JSON
    pub expected_match: bool,
}

/// Alert repository trait
#[async_trait]
pub trait AlertRepository: Send + Sync {
    async fn create(&self, alert: &Alert) -> Result<()>;
    async fn get(&self, id: &crate::AlertId) -> Result<Option<Alert>>;
    async fn update_state(&self, id: &crate::AlertId, state: AlertState, comment: Option<String>) -> Result<()>;
    async fn query(&self, query: AlertQuery) -> Result<Vec<Alert>>;
    async fn count(&self, query: &AlertQuery) -> Result<u64>;
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Alert {
    pub id: crate::AlertId,
    pub rule_id: String,
    pub correlation_id: crate::CorrelationId,
    pub risk_score: u32,
    pub severity: crate::Severity,
    pub state: AlertState,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    pub events: Vec<EventId>,
    pub context: serde_json::Value,
    pub ai_summary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    #[default]
    New,
    Acknowledged,
    Investigating,
    ResolvedTruePositive,
    ResolvedFalsePositive,
    Suppressed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertQuery {
    pub state: Option<AlertState>,
    pub min_severity: Option<crate::Severity>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: usize,
    pub offset: usize,
}

impl Default for AlertQuery {
    fn default() -> Self {
        Self {
            state: None,
            min_severity: None,
            start_time: None,
            end_time: None,
            limit: 100,
            offset: 0,
        }
    }
}

/// Config repository trait
#[async_trait]
pub trait ConfigRepository: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<ConfigValue>>;
    async fn set(&self, key: &str, value: &ConfigValue) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn list(&self, prefix: &str) -> Result<Vec<(String, ConfigValue)>>;
}

/// Configuration provider trait (for hot-reload)
#[async_trait]
pub trait ConfigProvider: Send + Sync {
    async fn get(&self, path: &str) -> Result<Option<ConfigValue>>;
    async fn watch(&self, path: &str) -> Result<ConfigWatcher>;
    fn schema(&self) -> &ConfigSchema;
}

/// Configuration watcher for hot-reload
pub struct ConfigWatcher {
    pub receiver: tokio::sync::watch::Receiver<ConfigValue>,
}

/// Plugin manager trait
#[async_trait]
pub trait PluginManager: Send + Sync {
    async fn load(&self, plugin_id: &str) -> Result<()>;
    async fn unload(&self, plugin_id: &str) -> Result<()>;
    async fn configure(&self, plugin_id: &str, config: serde_json::Value) -> Result<()>;
    async fn execute_action(&self, plugin_id: &str, action: &str, params: serde_json::Value) -> Result<serde_json::Value>;
    fn list(&self) -> Vec<PluginInfo>;
    fn get(&self, plugin_id: &str) -> Option<PluginInfo>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub state: PluginState,
    pub capabilities: Vec<String>,
    pub config_schema: serde_json::Value,
    pub installed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginState {
    Installed,
    Loaded,
    Running,
    Error,
    Disabled,
}

/// Collector trait
#[async_trait]
pub trait Collector: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn event_types(&self) -> Vec<&str>;
    fn required_capabilities(&self) -> Vec<String>;
    fn config_schema(&self) -> ConfigSchema;
    
    async fn start(&mut self, ctx: CollectorContext) -> Result<()>;
    async fn stop(&mut self, graceful: bool) -> Result<()>;
    async fn health(&self) -> CollectorHealth;
    async fn reconfigure(&mut self, config: serde_json::Value) -> Result<()>;
}

#[derive(Clone)]
pub struct CollectorContext {
    pub event_tx: tokio::sync::mpsc::Sender<Arc<Event>>,
    pub backpressure_rx: tokio::sync::watch::Receiver<crate::BackpressureSignal>,
    pub config: Arc<dyn ConfigProvider>,
    pub os: Arc<dyn OsAbstraction>,
    pub metrics: CollectorMetrics,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollectorHealth {
    pub state: CollectorState,
    pub message: Option<String>,
    pub last_event: Option<chrono::DateTime<chrono::Utc>>,
    pub events_per_sec: f64,
    pub error_rate: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorState {
    #[default]
    Stopped,
    Starting,
    Running,
    Degraded,
    Error,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CollectorMetrics {
    pub events_produced: u64,
    pub events_dropped: u64,
    pub errors: u64,
    pub avg_latency_ms: f64,
    pub cpu_percent: f64,
    pub memory_bytes: u64,
}

/// OS abstraction layer trait
#[async_trait]
pub trait OsAbstraction: Send + Sync {
    fn platform(&self) -> &'static str;
    
    // Process enumeration
    async fn list_processes(&self) -> Result<Vec<ProcessInfo>>;
    async fn get_process(&self, pid: u32) -> Result<Option<ProcessInfo>>;
    
    // Network
    async fn list_connections(&self) -> Result<Vec<ConnectionInfo>>;
    
    // File system
    async fn watch_path(&self, path: &str, recursive: bool) -> Result<Arc<dyn FileWatcher>>;

    // Registry (Windows only)
    #[cfg(windows)]
    async fn watch_registry(&self, hive: &str, path: &str) -> Result<Arc<dyn RegistryWatcher>>;

    // USB
    async fn list_usb_devices(&self) -> Result<Vec<UsbDeviceInfo>>;
    async fn watch_usb(&self) -> Result<Arc<dyn UsbWatcher>>;
    
    // Browser
    async fn get_browser_data(&self, browser: BrowserType) -> Result<BrowserData>;
    
    // Startup
    async fn list_startup_items(&self) -> Result<Vec<StartupItem>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub cwd: String,
    pub user: UserInfo,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub integrity_level: Option<String>,
    pub signing: Option<CodeSigningInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub sid: String,
    pub username: String,
    pub domain: String,
    pub is_elevated: bool,
    pub is_system: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSigningInfo {
    pub is_signed: bool,
    pub is_trusted: bool,
    pub publisher: Option<String>,
    pub issuer: Option<String>,
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub pid: u32,
    pub process_name: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceInfo {
    pub device_id: String,
    pub vendor_id: String,
    pub product_id: String,
    pub serial_number: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub is_mass_storage: bool,
    pub is_hid_keyboard: bool,
    pub is_hid_mouse: bool,
    pub mount_point: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserData {
    pub history: Vec<BrowserHistoryEntry>,
    pub downloads: Vec<BrowserDownload>,
    pub extensions: Vec<BrowserExtension>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserHistoryEntry {
    pub url: String,
    pub title: String,
    pub visit_time: chrono::DateTime<chrono::Utc>,
    pub visit_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDownload {
    pub url: String,
    pub path: String,
    pub hash: Option<String>,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserExtension {
    pub id: String,
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub install_time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserType {
    Chrome,
    Firefox,
    Edge,
    Safari,
    Brave,
    Vivaldi,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupItem {
    pub location: StartupLocation,
    pub name: String,
    pub command: String,
    pub arguments: String,
    pub user: String,
    pub enabled: bool,
    pub is_signed: bool,
    pub publisher: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupLocation {
    RunKey,
    RunOnceKey,
    ScheduledTask,
    Service,
    StartupFolder,
    Winlogon,
    BrowserExtension,
    Systemd,
    Launchd,
    Cron,
    RcLocal,
    ProfileScript,
}

// Placeholder traits for watchers
#[async_trait]
pub trait FileWatcher: Send + Sync {
    async fn next_event(&mut self) -> Result<FileEvent>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub path: String,
    pub action: FileAction,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAction {
    Created,
    Modified,
    Deleted,
    Renamed,
    Accessed,
}

#[async_trait]
pub trait RegistryWatcher: Send + Sync {
    async fn next_event(&mut self) -> Result<RegistryEvent>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub hive: String,
    pub key_path: String,
    pub value_name: Option<String>,
    pub action: RegistryAction,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryAction {
    Created,
    Deleted,
    Modified,
    Renamed,
}

#[async_trait]
pub trait UsbWatcher: Send + Sync {
    async fn next_event(&mut self) -> Result<UsbEvent>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbEvent {
    pub device: UsbDeviceInfo,
    pub action: UsbAction,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsbAction {
    Connected,
    Disconnected,
    Mounted,
    Unmounted,
}
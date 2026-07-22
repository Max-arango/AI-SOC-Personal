//! Process Collector Implementation

use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::framework::*;
use sentinel_config::ProcessCollectorConfig;
use sentinel_core::{
    CollectorError, CollectorHealth, CollectorMetrics, CollectorState, EventId,
};
use sentinel_core::traits::{Collector, CollectorContext, ConfigSchema, ProcessInfo};
use sentinel_events::{Event, Severity, ProcessContext, ProcessEvent, UserContext, CodeSigningInfo};

/// Process collector implementation
#[allow(dead_code)]
pub struct ProcessCollector {
    id: String,
    name: String,
    description: String,
    state: parking_lot::RwLock<CollectorState>,
    health: parking_lot::RwLock<CollectorHealth>,
    config: ProcessCollectorConfig,
    platform: Arc<tokio::sync::Mutex<dyn OsProcessCollector>>,
    event_tx: Option<mpsc::Sender<Arc<Event>>>,
    backpressure_rx: Option<tokio::sync::watch::Receiver<sentinel_core::BackpressureSignal>>,
    metrics: CollectorMetrics,
}

impl ProcessCollector {
    /// Create new process collector
    pub async fn new(config: ProcessCollectorConfig) -> Result<Self, CollectorError> {
        let platform = create_platform_collector(&config).await?;
        
        Ok(Self {
            id: "process".to_string(),
            name: "Process Monitor".to_string(),
            description: "Monitors process creation, termination, and suspicious behavior".to_string(),
            state: parking_lot::RwLock::new(CollectorState::Stopped),
            health: parking_lot::RwLock::new(CollectorHealth::default()),
            config,
            platform,
            event_tx: None,
            backpressure_rx: None,
            metrics: CollectorMetrics::default(),
        })
    }
    
    async fn do_start_inner(&mut self) -> Result<(), CollectorError> {
        info!("Starting process collector");
        self.platform.lock().await.start().await
            .map_err(|e| CollectorError::StartFailed(e.to_string()))?;
        
        // Spawn event processing loop
        let event_tx = self.event_tx.clone().unwrap();
        let platform = self.platform.clone();
        let backpressure_rx = self.backpressure_rx.clone();
        let _config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
            
            loop {
                interval.tick().await;
                
                // Check backpressure
                if let Some(ref bp) = backpressure_rx {
                    if matches!(*bp.borrow(), sentinel_core::BackpressureSignal::Critical | sentinel_core::BackpressureSignal::Overflow) {
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        continue;
                    }
                }
                
                // Poll for events
                if let Ok(events) = platform.lock().await.poll().await {
                    for event in events {
                        if let Err(e) = event_tx.send(event).await {
                            error!("Failed to send event: {}", e);
                            break;
                        }
                    }
                }
            }
        });
        
        Ok(())
    }
    
    async fn do_stop_inner(&mut self, graceful: bool) -> Result<(), CollectorError> {
        info!("Stopping process collector (graceful={})", graceful);
        self.platform.lock().await.stop().await
            .map_err(|e| CollectorError::StopFailed(e.to_string()))?;
        Ok(())
    }
    
    async fn do_reconfigure_inner(&mut self, config: serde_json::Value) -> Result<(), CollectorError> {
        let new_config: ProcessCollectorConfig = serde_json::from_value(config)
            .map_err(|e| CollectorError::Configuration(e.to_string()))?;
        self.config = new_config;
        Ok(())
    }
}

#[async_trait]
impl Collector for ProcessCollector {
    fn id(&self) -> &str {
        &self.id
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn description(&self) -> &str {
        &self.description
    }
    
    fn event_types(&self) -> Vec<&str> {
        vec![
            "sentinel.process.create",
            "sentinel.process.terminate",
            "sentinel.process.open",
            "sentinel.process.access",
            "sentinel.process.inject",
            "sentinel.process.hollow",
            "sentinel.process.dump",
        ]
    }
    
    fn required_capabilities(&self) -> Vec<String> {
        vec!["process:read".to_string(), "process:enumerate".to_string()]
    }
    
    fn config_schema(&self) -> ConfigSchema {
        ConfigSchema {
            module: "process_collector".to_string(),
            version: 1,
            schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean", "default": true },
                    "sample_rate": { "type": "number", "minimum": 0, "maximum": 1, "default": 1.0 },
                    "include_command_line": { "type": "boolean", "default": true },
                    "include_environment": { "type": "boolean", "default": false },
                    "resolve_signatures": { "type": "boolean", "default": true },
                    "track_ancestry_depth": { "type": "integer", "minimum": 1, "maximum": 50, "default": 10 },
                    "monitor_injection": { "type": "boolean", "default": true },
                    "monitor_hollowing": { "type": "boolean", "default": true },
                    "monitor_dumps": { "type": "boolean", "default": true },
                    "exclude_paths": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["enabled"]
            }),
        }
    }
    
    async fn start(&mut self, ctx: CollectorContext) -> sentinel_core::Result<()> {
        self.event_tx = Some(ctx.event_tx);
        self.backpressure_rx = Some(ctx.backpressure_rx);
        self.do_start_inner().await?;
        Ok(())
    }
    
    async fn stop(&mut self, graceful: bool) -> sentinel_core::Result<()> {
        self.do_stop_inner(graceful).await?;
        Ok(())
    }
    
    async fn health(&self) -> CollectorHealth {
        self.health.read().clone()
    }
    
    async fn reconfigure(&mut self, config: serde_json::Value) -> sentinel_core::Result<()> {
        self.do_reconfigure_inner(config).await?;
        Ok(())
    }
}

#[async_trait]
impl CollectorImpl for ProcessCollector {
    async fn do_start(&mut self) -> sentinel_core::Result<()> {
        self.do_start_inner().await?;
        Ok(())
    }
    
    async fn do_stop(&mut self, graceful: bool) -> sentinel_core::Result<()> {
        self.do_stop_inner(graceful).await?;
        Ok(())
    }
    
    async fn do_reconfigure(&mut self, config: serde_json::Value) -> sentinel_core::Result<()> {
        self.do_reconfigure_inner(config).await?;
        Ok(())
    }
}

/// Platform-specific process collector trait
#[async_trait]
pub trait OsProcessCollector: Send + Sync {
    async fn start(&mut self) -> Result<(), CollectorError>;
    async fn stop(&mut self) -> Result<(), CollectorError>;
    async fn poll(&mut self) -> Result<Vec<Arc<Event>>, CollectorError>;
}

/// Create platform-specific collector
async fn create_platform_collector(config: &ProcessCollectorConfig) -> Result<Arc<tokio::sync::Mutex<dyn OsProcessCollector>>, CollectorError> {
    #[cfg(target_os = "windows")]
    {
        Ok(Arc::new(tokio::sync::Mutex::new(windows::WindowsProcessCollector::new(config).await?)))
    }
    
    #[cfg(target_os = "linux")]
    {
        Ok(Arc::new(tokio::sync::Mutex::new(linux::LinuxProcessCollector::new(config).await?)))
    }
    
    #[cfg(target_os = "macos")]
    {
        Ok(Arc::new(tokio::sync::Mutex::new(macos::MacosProcessCollector::new(config).await?)))
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err(CollectorError::UnsupportedPlatform)
    }
}

/// Convert platform process info to Sentinel Event
pub fn process_info_to_event(
    process: ProcessInfo,
    action: ProcessEventAction,
    config: &ProcessCollectorConfig,
) -> Event {
    let mut event = Event {
        id: EventId::new().to_string(),
        r#type: format!("sentinel.process.{:?}", action).to_lowercase(),
        source: "process".to_string(),
        timestamp: sentinel_core::now_proto_ts(),
        ingest_timestamp: sentinel_core::now_proto_ts(),
        severity: Severity::Info as i32,
        process: Some(ProcessContext {
            pid: process.pid,
            ppid: process.ppid,
            name: process.name.clone(),
            path: process.path.clone(),
            command_line: if config.include_command_line { process.command_line } else { String::new() },
            cwd: process.cwd,
            user: Some(UserContext {
                sid: process.user.sid,
                username: process.user.username,
                domain: process.user.domain,
                is_elevated: process.user.is_elevated,
                is_system: process.user.is_system,
            }),
            integrity_level: process.integrity_level.clone().unwrap_or_default(),
            signing: process.signing.map(|s| CodeSigningInfo {
                is_signed: s.is_signed,
                is_trusted: s.is_trusted,
                publisher: s.publisher.unwrap_or_default(),
                issuer: s.issuer.unwrap_or_default(),
                timestamp: s.timestamp.and_then(sentinel_core::chrono_to_proto_ts),
                certificates: vec![],
            }),
            mitre_techniques: vec![],
            tree_depth: 0,
            sha256: String::new(),
            parent: None,
        }),
        payload: Some(sentinel_events::event::Payload::ProcessEvent(ProcessEvent {
            action: match action {
                ProcessEventAction::Create => sentinel_events::process_event::Action::Create as i32,
                ProcessEventAction::Terminate => sentinel_events::process_event::Action::Terminate as i32,
                ProcessEventAction::Open => sentinel_events::process_event::Action::Open as i32,
                ProcessEventAction::Access => sentinel_events::process_event::Action::Access as i32,
                ProcessEventAction::Inject => sentinel_events::process_event::Action::Inject as i32,
                ProcessEventAction::Hollow => sentinel_events::process_event::Action::Hollow as i32,
                ProcessEventAction::Dump => sentinel_events::process_event::Action::Dump as i32,
            },
            target: None,
            desired_access: 0,
        })),
        tags: vec![],
        metadata: Default::default(),
        risk_score: 0,
        correlation: Default::default(),
        host_id: String::new(),
        schema_version: 1,
    };
    
    // Add MITRE tags based on action
    match action {
        ProcessEventAction::Create => event.tags.push("mitre:T1059".to_string()),
        ProcessEventAction::Inject => event.tags.push("mitre:T1055".to_string()),
        ProcessEventAction::Hollow => event.tags.push("mitre:T1055.012".to_string()),
        ProcessEventAction::Dump => event.tags.push("mitre:T1003".to_string()),
        _ => {}
    }
    
    event
}

#[derive(Debug, Clone, Copy)]
pub enum ProcessEventAction {
    Create,
    Terminate,
    Open,
    Access,
    Inject,
    Hollow,
    Dump,
}

/// Platform module
pub mod platform {
    use super::*;
    use async_trait::async_trait;
    
    #[async_trait]
    pub trait OsProcessCollector: Send + Sync {
        async fn start(&mut self) -> Result<(), CollectorError>;
        async fn stop(&mut self) -> Result<(), CollectorError>;
        async fn poll(&mut self) -> Result<Vec<Arc<Event>>, CollectorError>;
    }
    
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
        pub signing: Option<SigningInfo>,
        pub tree_depth: u32,
        pub sha256: Option<String>,
    }
    
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct UserInfo {
        pub sid: String,
        pub username: String,
        pub domain: String,
        pub is_elevated: bool,
        pub is_system: bool,
    }
    
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct SigningInfo {
        pub is_signed: bool,
        pub is_trusted: bool,
        pub publisher: Option<String>,
        pub issuer: Option<String>,
        pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
        pub certificates: Vec<String>,
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    
    pub struct WindowsProcessCollector {
        config: ProcessCollectorConfig,
        // ETW session handle, etc.
    }
    
    impl WindowsProcessCollector {
        pub async fn new(config: &ProcessCollectorConfig) -> Result<Self, CollectorError> {
            // Initialize ETW, WMI, etc.
            Ok(Self { config: config.clone() })
        }
    }
    
    #[async_trait]
    impl OsProcessCollector for WindowsProcessCollector {
        async fn start(&mut self) -> Result<(), CollectorError> {
            // Start ETW session for process events
            Ok(())
        }
        
        async fn stop(&mut self) -> Result<(), CollectorError> {
            Ok(())
        }
        
        async fn poll(&mut self) -> Result<Vec<Arc<Event>>, CollectorError> {
            // Poll ETW events
            Ok(vec![])
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::HashSet;
    use sysinfo::{Pid, RefreshKind, System};

    pub struct LinuxProcessCollector {
        config: ProcessCollectorConfig,
        system: System,
        known_pids: HashSet<Pid>,
    }

    impl LinuxProcessCollector {
        pub async fn new(config: &ProcessCollectorConfig) -> Result<Self, CollectorError> {
            let mut system = System::new_with_specifics(RefreshKind::new());
            system.refresh_all();
            let known_pids: HashSet<Pid> = system.processes().keys().copied().collect();
            Ok(Self {
                config: config.clone(),
                system,
                known_pids,
            })
        }
    }

    #[async_trait]
    impl OsProcessCollector for LinuxProcessCollector {
        async fn start(&mut self) -> Result<(), CollectorError> {
            Ok(())
        }

        async fn stop(&mut self) -> Result<(), CollectorError> {
            Ok(())
        }

        async fn poll(&mut self) -> Result<Vec<Arc<Event>>, CollectorError> {
            let mut events = Vec::new();

            self.system.refresh_all();
            let current_pids: HashSet<Pid> = self.system.processes().keys().copied().collect();

            // Detect new processes (created)
            for pid in current_pids.difference(&self.known_pids) {
                if let Some(proc) = self.system.process(*pid) {
                    if let Some(event) = build_process_event(
                        proc,
                        "sentinel.process.create",
                        2,
                    ) {
                        events.push(Arc::new(event));
                    }
                }
            }

            // Detect terminated processes
            for _pid in self.known_pids.difference(&current_pids) {
                events.push(Arc::new(Event {
                    id: sentinel_core::Ulid::new().to_string(),
                    r#type: "sentinel.process.terminate".into(),
                    source: "process".into(),
                    severity: 2,
                    risk_score: 5,
                    host_id: String::new(),
                    schema_version: 1,
                    process: Some(ProcessContext {
                        pid: _pid.as_u32(),
                        name: "(terminated)".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }));
            }

            self.known_pids = current_pids;

            Ok(events)
        }
    }

    fn build_process_event(
        proc: &sysinfo::Process,
        event_type: &str,
        severity: i32,
    ) -> Option<Event> {
        let uid = proc
            .user_id()
            .map(|u| u.to_string())
            .unwrap_or_default();

        Some(Event {
            id: sentinel_core::Ulid::new().to_string(),
            r#type: event_type.into(),
            source: "process".into(),
            severity,
            risk_score: if event_type.contains("create") { 10 } else { 5 },
            host_id: String::new(),
            schema_version: 1,
            process: Some(ProcessContext {
                pid: proc.pid().as_u32(),
                ppid: proc.parent().map(|p| p.as_u32()).unwrap_or(0),
                name: proc.name().to_string_lossy().into_owned(),
                path: proc
                    .exe()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                command_line: proc
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" "),
                cwd: String::new(),
                user: Some(UserContext {
                    sid: uid.clone(),
                    username: uid,
                    domain: String::new(),
                    is_elevated: proc
                        .user_id()
                        .is_some_and(|u| u.to_string() == "0"),
                    is_system: false,
                }),
                ..Default::default()
            }),
            ..Default::default()
        })
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    
    pub struct MacosProcessCollector {
        config: ProcessCollectorConfig,
    }
    
    impl MacosProcessCollector {
        pub async fn new(config: &ProcessCollectorConfig) -> Result<Self, CollectorError> {
            Ok(Self { config: config.clone() })
        }
    }
    
    #[async_trait]
    impl OsProcessCollector for MacosProcessCollector {
        async fn start(&mut self) -> Result<(), CollectorError> {
            // Start Endpoint Security
            Ok(())
        }
        
        async fn stop(&mut self) -> Result<(), CollectorError> {
            Ok(())
        }
        
        async fn poll(&mut self) -> Result<Vec<Arc<Event>>, CollectorError> {
            Ok(vec![])
        }
    }
}
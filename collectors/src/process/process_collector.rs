//! Process Collector Implementation
//!
//! Monitors process creation, termination, exec, and suspicious
//! behaviour via the Linux Netlink Connector (CN_PROC) interface.
//!
//! Architecture:
//! ```
//! Kernel CN_PROC socket ──► NetlinkMonitor (async fd loop)
//!                                 │
//!                    mpsc::UnboundedSender<ProcNetlinkEvent>
//!                                 │
//!                                 ▼
//!                      event_converter task:
//!                        enrich with /proc/<pid>/*
//!                        ──► ProcessContext + Event
//!                                 │
//!                                 ▼
//!                      event_tx ──► EventBus
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::framework::*;
use sentinel_config::ProcessCollectorConfig;
use sentinel_core::traits::{Collector, CollectorContext, ConfigSchema};
use sentinel_core::{CollectorError, CollectorHealth, CollectorMetrics, CollectorState};
use sentinel_events::{
    Event, ProcessContext, ProcessEvent, Severity, UserContext,
};

use super::netlink_monitor::{NetlinkMonitor, ProcNetlinkEvent};
use super::proc_reader;

/// Process collector implementation
#[allow(dead_code)]
pub struct ProcessCollector {
    id: String,
    name: String,
    description: String,
    state: parking_lot::RwLock<CollectorState>,
    health: parking_lot::RwLock<CollectorHealth>,
    config: ProcessCollectorConfig,
    event_tx: Option<mpsc::Sender<Arc<Event>>>,
    backpressure_rx: Option<tokio::sync::watch::Receiver<sentinel_core::BackpressureSignal>>,
    metrics: CollectorMetrics,
    cancel_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl ProcessCollector {
    pub async fn new(config: ProcessCollectorConfig) -> Result<Self, CollectorError> {
        Ok(Self {
            id: "process".to_string(),
            name: "Process Monitor".to_string(),
            description: "Monitors process creation, termination, and suspicious behaviour"
                .to_string(),
            state: parking_lot::RwLock::new(CollectorState::Stopped),
            health: parking_lot::RwLock::new(CollectorHealth::default()),
            config,
            event_tx: None,
            backpressure_rx: None,
            metrics: CollectorMetrics::default(),
            cancel_tx: None,
        })
    }

    async fn do_start_inner(&mut self) -> Result<(), CollectorError> {
        info!("Starting process collector (netlink CN_PROC)");

        let event_tx = self
            .event_tx
            .as_ref()
            .ok_or_else(|| CollectorError::StartFailed("event_tx not set".into()))?
            .clone();
        let backpressure_rx = self.backpressure_rx.clone();
        let config = self.config.clone();
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
        self.cancel_tx = Some(cancel_tx);

        // ── Channel: netlink events → conversion task ─────────────
        let (netlink_tx, mut netlink_rx) = mpsc::unbounded_channel::<ProcNetlinkEvent>();

        // Spawn the netlink monitor in a background thread (it uses
        // blocking libc::read under AsyncFd which is scheduler-safe).
        let (monitor_started_tx, monitor_started_rx) = tokio::sync::oneshot::channel();
        let event_tx_clone = event_tx.clone();
        tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async move {
                let mut monitor = NetlinkMonitor::new();
                if let Err(e) = monitor.connect() {
                    error!("Netlink monitor connect failed: {e}");
                    warning_fallback_mode(&event_tx_clone).await;
                    let _ = monitor_started_tx.send(false);
                    return;
                }
                let _ = monitor_started_tx.send(true);

                // Run the monitor — it blocks here reading from the
                // netlink socket and pushing events to netlink_tx.
                monitor.run(netlink_tx).await;
                info!("Netlink monitor loop exited");
            });
        });

        // ── Conversion task: netlink events → Sentinel Events ─────
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => {
                        debug!("Process collector conversion task cancelled");
                        break;
                    }
                    maybe_event = netlink_rx.recv() => {
                        match maybe_event {
                            Some(nl_event) => {
                                // Backpressure check
                                if let Some(ref bp) = backpressure_rx {
                                    if matches!(
                                        *bp.borrow(),
                                        sentinel_core::BackpressureSignal::Critical
                                            | sentinel_core::BackpressureSignal::Overflow
                                    ) {
                                        tokio::time::sleep(
                                            tokio::time::Duration::from_millis(500),
                                        )
                                        .await;
                                        continue;
                                    }
                                }

                                if let Some(sentinel_event) =
                                    netlink_to_sentinel_event_inner(&nl_event, &config)
                                {
                                    if event_tx.send(Arc::new(sentinel_event)).await.is_err() {
                                        debug!("Event bus closed, stopping converter");
                                        break;
                                    }
                                }
                            }
                            None => {
                                debug!("Netlink channel closed");
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Wait briefly for monitor to report ready
        let started = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            monitor_started_rx,
        )
        .await
        .map(|r| r.unwrap_or(false))
        .unwrap_or(false);

        if started {
            info!("Process collector running (CN_PROC netlink)");
        }
        Ok(())
    }

    async fn do_stop_inner(&mut self, graceful: bool) -> Result<(), CollectorError> {
        info!(
            "Stopping process collector (graceful={})",
            graceful
        );
        if let Some(cancel) = self.cancel_tx.take() {
            let _ = cancel.send(());
        }
        Ok(())
    }

    async fn do_reconfigure_inner(
        &mut self,
        config: serde_json::Value,
    ) -> Result<(), CollectorError> {
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

// ── Netlink → Sentinel event conversion ───────────────────────────

pub fn netlink_to_sentinel_event_inner(
    nl: &ProcNetlinkEvent,
    config: &ProcessCollectorConfig,
) -> Option<Event> {
    match nl {
        ProcNetlinkEvent::Fork { child_pid, child_tgid, parent_pid, parent_tgid, timestamp_ns } => {
            let pid = *child_tgid as u32;
            let info = proc_reader::gather_pid_info(pid);
            Some(build_event(
                pid,
                info,
                &format!("{}/{}", parent_tgid, parent_pid),
                ProcessEventAction::Create,
                config,
            ))
        }
        ProcNetlinkEvent::Exec { process_tgid, .. } => {
            let pid = *process_tgid as u32;
            let info = proc_reader::gather_pid_info(pid);
            Some(build_event(
                pid,
                info,
                "",
                ProcessEventAction::Create,
                config,
            ))
        }
        ProcNetlinkEvent::Exit { process_tgid, exit_code, exit_signal, .. } => {
            let pid = *process_tgid as u32;
            let info = proc_reader::gather_pid_info(pid);
            let mut ev = build_event(pid, info, "", ProcessEventAction::Terminate, config);
            if let Some(payload) = &mut ev.payload {
                if let sentinel_events::event::Payload::ProcessEvent(ref mut pe) = payload {
                    pe.desired_access = *exit_code;
                }
            }
            ev.tags.push(format!("exit_signal:{}", exit_signal));
            Some(ev)
        }
        ProcNetlinkEvent::Comm { process_tgid, comm, .. } => {
            let pid = *process_tgid as u32;
            let comm_name = String::from_utf8_lossy(&comm_slice(comm)).trim_end_matches('\0').to_string();
            let mut info = proc_reader::gather_pid_info(pid);
            if !comm_name.is_empty() {
                info.name = comm_name;
            }
            Some(build_event(pid, info, "", ProcessEventAction::Create, config))
        }
        ProcNetlinkEvent::Ptrace { process_tgid, tracer_pid, tracer_tgid, .. } => {
            let target_pid = *process_tgid as u32;
            let tracer_info = proc_reader::gather_pid_info(*tracer_tgid as u32);
            let target_info = proc_reader::gather_pid_info(target_pid);

            let mut ev = build_event(
                *tracer_tgid as u32,
                tracer_info,
                "",
                ProcessEventAction::Inject,
                config,
            );
            if let Some(payload) = &mut ev.payload {
                if let sentinel_events::event::Payload::ProcessEvent(ref mut pe) = payload {
                    pe.target = Some(ProcessContext {
                        pid: target_pid,
                        ppid: *process_tgid as u32,
                        name: target_info.name,
                        path: target_info.exe_path,
                        ..Default::default()
                    });
                }
            }
            ev.tags.push(format!("tracer_pid:{}", tracer_pid));
            Some(ev)
        }
        ProcNetlinkEvent::Coredump { process_tgid, parent_tgid, .. } => {
            let pid = *process_tgid as u32;
            let info = proc_reader::gather_pid_info(pid);
            Some(build_event(pid, info, &parent_tgid.to_string(), ProcessEventAction::Dump, config))
        }
        // Ignore UID/GID changes for now (low signal)
        _ => None,
    }
}

fn comm_slice(comm: &[u8; 16]) -> &[u8] {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(16);
    &comm[..end]
}

fn build_event(
    pid: u32,
    info: proc_reader::ProcPidInfo,
    _parent_label: &str,
    action: ProcessEventAction,
    config: &ProcessCollectorConfig,
) -> Event {
    let ppid = info.ppid;
    let parent_context = if ppid > 0 {
        let parent_info = proc_reader::gather_pid_info(ppid);
        if !parent_info.exe_path.is_empty() {
            Some(ProcessContext {
                pid: ppid,
                name: parent_info.name,
                path: parent_info.exe_path,
                command_line: parent_info.cmdline,
                sha256: parent_info.sha256,
                ..Default::default()
            })
        } else {
            None
        }
    } else {
        None
    };

    let mut tags = Vec::new();
    match action {
        ProcessEventAction::Create => tags.push("mitre:T1059".to_string()),
        ProcessEventAction::Inject => {
            tags.push("mitre:T1055".to_string());
            tags.push("ptrace".to_string());
        }
        ProcessEventAction::Dump => {
            tags.push("mitre:T1003".to_string());
            tags.push("coredump".to_string());
        }
        _ => {}
    }

    let command_line = if config.include_command_line {
        info.cmdline.clone()
    } else {
        String::new()
    };

    Event {
        id: sentinel_core::Ulid::new().to_string(),
        r#type: format!("sentinel.process.{:?}", action).to_lowercase(),
        source: "process".to_string(),
        timestamp: sentinel_core::now_proto_ts(),
        ingest_timestamp: sentinel_core::now_proto_ts(),
        severity: Severity::Info as i32,
        process: Some(ProcessContext {
            pid,
            ppid,
            name: info.name.clone(),
            path: info.exe_path.clone(),
            command_line,
            cwd: info.cwd.clone(),
            user: Some(UserContext {
                sid: info.username.clone(),
                username: info.username.clone(),
                domain: String::new(),
                is_elevated: info.uid == 0,
                is_system: info.uid == 0,
            }),
            integrity_level: String::new(),
            signing: None,
            mitre_techniques: vec![],
            tree_depth: 0,
            sha256: info.sha256.clone(),
            parent: parent_context.map(Box::new),
        }),
        payload: Some(sentinel_events::event::Payload::ProcessEvent(ProcessEvent {
            action: action_code(action),
            target: None,
            desired_access: 0,
        })),
        tags,
        metadata: Default::default(),
        risk_score: match action {
            ProcessEventAction::Inject => 40,
            ProcessEventAction::Dump => 50,
            _ => 10,
        },
        correlation: Default::default(),
        host_id: String::new(),
        schema_version: 1,
    }
}

fn action_code(action: ProcessEventAction) -> i32 {
    match action {
        ProcessEventAction::Create => sentinel_events::process_event::Action::Create as i32,
        ProcessEventAction::Terminate => sentinel_events::process_event::Action::Terminate as i32,
        ProcessEventAction::Open => sentinel_events::process_event::Action::Open as i32,
        ProcessEventAction::Access => sentinel_events::process_event::Action::Access as i32,
        ProcessEventAction::Inject => sentinel_events::process_event::Action::Inject as i32,
        ProcessEventAction::Hollow => sentinel_events::process_event::Action::Hollow as i32,
        ProcessEventAction::Dump => sentinel_events::process_event::Action::Dump as i32,
    }
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

// ── Fallback: when netlink is unavailable ─────────────────────────

async fn warning_fallback_mode(event_tx: &mpsc::Sender<Arc<Event>>) {
    warn!("Netlink CN_PROC unavailable — falling back to /proc polling (5s)");
    let tx = event_tx.clone();
    tokio::spawn(async move {
        use std::collections::HashSet;
        let mut known: HashSet<u32> = HashSet::new();
        let mut tick = tokio::time::interval(tokio::time::Duration::from_secs(5));
        tick.tick().await; // skip first immediate tick

        loop {
            tick.tick().await;
            let entries = match std::fs::read_dir("/proc") {
                Ok(d) => d,
                Err(_) => continue,
            };

            let mut current = HashSet::new();
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name();
                if let Some(pid_str) = name.to_str() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        current.insert(pid);
                        if !known.contains(&pid) {
                            let info = proc_reader::gather_pid_info(pid);
                            if info.ppid > 0 {
                                // skip kernel threads
                                let ev = Arc::new(Event {
                                    id: sentinel_core::Ulid::new().to_string(),
                                    r#type: "sentinel.process.create".into(),
                                    source: "process".into(),
                                    timestamp: sentinel_core::now_proto_ts(),
                                    ingest_timestamp: sentinel_core::now_proto_ts(),
                                    severity: Severity::Info as i32,
                                    process: Some(ProcessContext {
                                        pid,
                                        ppid: info.ppid,
                                        name: info.name,
                                        path: info.exe_path,
                                        command_line: info.cmdline,
                                        sha256: info.sha256,
                                        user: Some(UserContext {
                                            sid: info.username.clone(),
                                            username: info.username,
                                            domain: String::new(),
                                            is_elevated: info.uid == 0,
                                            is_system: info.uid == 0,
                                        }),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                });
                                let _ = tx.send(ev).await;
                            }
                        }
                    }
                }
            }
            known = current;
        }
    });
}

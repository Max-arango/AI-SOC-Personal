use std::path::PathBuf;
use std::sync::Arc;
use tauri::AppHandle;

use sentinel_core::traits::{AlertState, EventQuery};
use sentinel_storage::migrations;
use sentinel_storage::sqlite::{SqliteConfig, SqliteStorage};

use crate::commands::{
    AlertQuery, AlertsResponse, ChatResponse, ConfigResponse, EventQuery as CmdEventQuery,
    EventsResponse, ExplanationResponse, HealthResponse, MitreHeatmapResponse,
    NetworkGraphResponse, NetworkQuery, NetworkResponse, ProcessQuery,
    ProcessesResponse, ProcessTreeResponse, RiskTimelineResponse, StatusResponse,
};

pub struct AppState {
    #[allow(dead_code)]
    app_handle: AppHandle,
    storage: Arc<SqliteStorage>,
    start_time: chrono::DateTime<chrono::Utc>,
}

impl AppState {
    pub async fn new(app_handle: AppHandle) -> Arc<Self> {
        let db_path = default_db_path();

        let storage = SqliteStorage::new(&SqliteConfig {
            path: db_path.clone(),
            wal_mode: true,
            busy_timeout_ms: 5000,
            max_connections: 5,
        })
        .await
        .map_err(|e| {
            tracing::error!("Failed to init SQLite: {}", e);
        })
        .expect("SQLite storage initialization failed");

        if let Err(e) = migrations::run_all(storage.pool()).await {
            tracing::error!("Failed to run migrations: {}", e);
        } else {
            tracing::info!("SQLite migrations applied");
        }

        tracing::info!("AppState initialized with storage at {}", db_path);

        Arc::new(Self {
            app_handle,
            storage: Arc::new(storage),
            start_time: chrono::Utc::now(),
        })
    }

    pub async fn health_check(&self) -> Result<HealthResponse, String> {
        let storage_healthy = self.storage.health().await.is_ok();

        Ok(HealthResponse {
            status: if storage_healthy {
                "healthy"
            } else {
                "degraded"
            }
            .to_string(),
            components: serde_json::json!({
                "core": "healthy",
                "storage": if storage_healthy { "healthy" } else { "unhealthy" },
                "event_bus": "healthy",
                "rule_engine": "healthy",
                "collectors": "healthy",
                "config": "healthy",
                "ai_engine": "healthy",
            }),
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    pub async fn get_status(&self) -> Result<StatusResponse, String> {
        let uptime = chrono::Utc::now() - self.start_time;
        let hours = uptime.num_hours();
        let mins = uptime.num_minutes() % 60;

        Ok(StatusResponse {
            state: "running".to_string(),
            uptime: format!("{}h {}m", hours, mins),
            resources: serde_json::json!({
                "cpu_percent": 0.0,
                "memory_bytes": 0,
                "event_queue_depth": 0,
            }),
        })
    }

    pub async fn query_events(&self, q: CmdEventQuery) -> Result<EventsResponse, String> {
        let repo = self.storage.events().await;

        let event_query = EventQuery {
            start_time: q.start_time.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            }),
            end_time: q.end_time.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            }),
            event_types: q.event_types.unwrap_or_default(),
            sources: q.sources.unwrap_or_default(),
            severities: vec![],
            process_names: vec![],
            pids: vec![],
            correlation_id: None,
            flow_id: None,
            min_risk_score: q.min_risk_score,
            tags: vec![],
            free_text: None,
            limit: q.limit.unwrap_or(100),
            offset: q.offset.unwrap_or(0),
            sort_by: Some("timestamp".to_string()),
            sort_desc: true,
        };

        let mut cursor = repo
            .query(event_query)
            .await
            .map_err(|e| format!("Query failed: {}", e))?;

        let total_count = cursor.total_count();

        let inner = Arc::get_mut(&mut cursor).ok_or("cursor in use".to_string())?;
        let events: Vec<serde_json::Value> = inner
            .collect(1000)
            .await
            .map_err(|e| format!("Fetch failed: {}", e))?
            .into_iter()
            .map(|e| event_to_json(&e))
            .collect();

        Ok(EventsResponse {
            events,
            total_count,
            has_more: total_count
                > q.limit.unwrap_or(100) as u64 + q.offset.unwrap_or(0) as u64,
        })
    }

    pub async fn get_alerts(&self, q: AlertQuery) -> Result<AlertsResponse, String> {
        let repo = self.storage.alerts().await;

        let alert_state = q.state.and_then(|s| match s.as_str() {
            "new" => Some(AlertState::New),
            "acknowledged" => Some(AlertState::Acknowledged),
            "investigating" => Some(AlertState::Investigating),
            "resolved_true_positive" => Some(AlertState::ResolvedTruePositive),
            "resolved_false_positive" => Some(AlertState::ResolvedFalsePositive),
            "suppressed" => Some(AlertState::Suppressed),
            _ => None,
        });

        let alert_query = sentinel_core::traits::AlertQuery {
            state: alert_state,
            min_severity: q.min_severity.and_then(|s| match s.as_str() {
                "emergency" => Some(sentinel_core::Severity::Emergency),
                "critical" => Some(sentinel_core::Severity::Critical),
                "error" => Some(sentinel_core::Severity::Error),
                "warning" => Some(sentinel_core::Severity::Warning),
                _ => None,
            }),
            start_time: None,
            end_time: None,
            limit: q.limit.unwrap_or(100),
            offset: 0,
        };

        let alerts = repo
            .query(alert_query)
            .await
            .map_err(|e| format!("Alert query failed: {}", e))?;

        let alerts_json: Vec<serde_json::Value> = alerts
            .into_iter()
            .map(|a| serde_json::json!(a))
            .collect();

        Ok(AlertsResponse {
            alerts: alerts_json.clone(),
            total_count: alerts_json.len() as u64,
        })
    }

    pub async fn get_processes(&self, _q: ProcessQuery) -> Result<ProcessesResponse, String> {
        let mut sys = sysinfo::System::new();
        sys.refresh_all();

        let processes: Vec<serde_json::Value> = sys
            .processes()
            .iter()
            .take(200)
            .map(|(pid, proc)| {
                serde_json::json!({
                    "pid": pid.as_u32(),
                    "ppid": proc.parent().map(|p| p.as_u32()),
                    "name": proc.name().to_string_lossy(),
                    "exe": proc.exe().map(|p| p.to_string_lossy().into_owned()),
                    "cmd": proc.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" "),
                    "cpu_usage": proc.cpu_usage(),
                    "memory_bytes": proc.memory(),
                    "user_id": proc.user_id().map(|u| u.to_string()),
                    "start_time": proc.start_time(),
                })
            })
            .collect();

        Ok(ProcessesResponse { processes })
    }

    pub async fn get_network_connections(
        &self,
        _q: NetworkQuery,
    ) -> Result<NetworkResponse, String> {
        Ok(NetworkResponse {
            connections: vec![],
        })
    }

    pub async fn explain_alert(&self, alert_id: String) -> Result<ExplanationResponse, String> {
        let repo = self.storage.alerts().await;
        let id = sentinel_core::Ulid::from_string(&alert_id)
            .map_err(|e| format!("Invalid alert ID: {}", e))?;

        let alert = repo
            .get(&id)
            .await
            .map_err(|e| format!("Alert fetch failed: {}", e))?;

        match alert {
            Some(a) => Ok(ExplanationResponse {
                explanation: format!(
                    "Alert '{}' (rule: {}) has risk score {} and severity {:?}.",
                    alert_id, a.rule_id, a.risk_score, a.severity
                ),
                risk_level: match a.severity {
                    sentinel_core::Severity::Emergency
                    | sentinel_core::Severity::Critical => "Critical".into(),
                    sentinel_core::Severity::Error => "High".into(),
                    sentinel_core::Severity::Warning => "Medium".into(),
                    _ => "Low".into(),
                },
                immediate_actions: vec![
                    "Investigate the alert context".into(),
                    "Review related events".into(),
                ],
                investigation_steps: vec![
                    "Check parent process chain".into(),
                    "Review network connections".into(),
                ],
                prevention_recommendations: vec!["Enable additional monitoring".into()],
            }),
            None => Ok(ExplanationResponse {
                explanation: format!("Alert {} not found in storage", alert_id),
                risk_level: "Unknown".into(),
                immediate_actions: vec![],
                investigation_steps: vec![],
                prevention_recommendations: vec![],
            }),
        }
    }

    pub async fn chat_ai(
        &self,
        message: String,
        cid: Option<String>,
    ) -> Result<ChatResponse, String> {
        Ok(ChatResponse {
            response: format!(
                "Sentinel AI is running locally. Your question was: \"{}\". AI integration coming soon.",
                message
            ),
            conversation_id: cid.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        })
    }

    pub async fn get_config(&self) -> Result<ConfigResponse, String> {
        Ok(ConfigResponse {
            config_toml: "# Sentinel AI Configuration\n# Edit at ~/.config/sentinel/config.toml\n".into(),
            version: 1,
        })
    }

    pub async fn update_config(&self, _cfg: serde_json::Value) -> Result<ConfigResponse, String> {
        Ok(ConfigResponse {
            config_toml: "# Config update coming soon\n".into(),
            version: 2,
        })
    }
}

fn event_to_json(event: &sentinel_events::Event) -> serde_json::Value {
    let ts = event.timestamp.as_ref().map(|t| t.seconds);
    let ingest_ts = event.ingest_timestamp.as_ref().map(|t| t.seconds);
    let process = event.process.as_ref().map(|p| {
        serde_json::json!({
            "pid": p.pid,
            "ppid": p.ppid,
            "name": p.name,
            "path": p.path,
            "command_line": p.command_line,
            "tree_depth": p.tree_depth,
        })
    });
    let correlation = event.correlation.as_ref().map(|c| {
        serde_json::json!({
            "session_id": c.session_id,
            "correlation_id": c.correlation_id,
            "flow_id": c.flow_id,
            "root_event_id": c.root_event_id,
            "cause_event_id": c.cause_event_id,
            "sequence": c.sequence,
        })
    });

    serde_json::json!({
        "id": event.id,
        "type": event.r#type,
        "source": event.source,
        "severity": event.severity,
        "risk_score": event.risk_score,
        "host_id": event.host_id,
        "schema_version": event.schema_version,
        "tags": event.tags,
        "timestamp": ts,
        "ingest_timestamp": ingest_ts,
        "process": process,
        "correlation": correlation,
    })
    pub async fn get_process_tree(&self) -> Result<ProcessTreeResponse, String> {
        let mut sys = sysinfo::System::new();
        sys.refresh_all();

        let mut nodes: Vec<serde_json::Value> = sys
            .processes()
            .iter()
            .take(200)
            .map(|(pid, proc)| {
                serde_json::json!({
                    "id": pid.as_u32(),
                    "pid": pid.as_u32(),
                    "ppid": proc.parent().map(|p| p.as_u32()).unwrap_or(0),
                    "name": proc.name().to_string_lossy(),
                    "cpu": proc.cpu_usage(),
                    "memory_mb": proc.memory() as f64 / 1_048_576.0,
                    "risk": 0,
                    "exe": proc.exe().map(|p| p.to_string_lossy().into_owned()),
                    "cmd": proc.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" "),
                })
            })
            .collect();

        Ok(ProcessTreeResponse {
            tree: serde_json::json!({ "nodes": nodes }),
        })
    }

    pub async fn get_risk_timeline(
        &self,
        hours: Option<u32>,
    ) -> Result<RiskTimelineResponse, String> {
        let repo = self.storage.events().await;
        let now = chrono::Utc::now();
        let h = hours.unwrap_or(24) as i64;

        let query = EventQuery {
            start_time: Some(now - chrono::Duration::hours(h)),
            end_time: Some(now),
            limit: 1440,
            offset: 0,
            sort_by: Some("timestamp".into()),
            sort_desc: false,
            ..Default::default()
        };

        let mut cursor = repo.query(query).await.map_err(|e| format!("{e}"))?;
        let total = cursor.total_count();

        let events = if let Some(c) = Arc::get_mut(&mut cursor) {
            c.collect(1440).await.map_err(|e| format!("{e}"))?
        } else {
            vec![]
        };

        let mut points = Vec::new();
        for e in &events {
            if let Some(ref ts) = e.timestamp {
                points.push(serde_json::json!({
                    "timestamp": ts.seconds,
                    "risk_score": e.risk_score,
                    "event_type": e.r#type,
                }));
            }
        }

        Ok(RiskTimelineResponse { points })
    }

    pub async fn get_mitre_heatmap(&self) -> Result<MitreHeatmapResponse, String> {
        use std::collections::HashMap;

        let tactics = [
            ("Initial Access", "TA0001"),
            ("Execution", "TA0002"),
            ("Persistence", "TA0003"),
            ("Privilege Escalation", "TA0004"),
            ("Defense Evasion", "TA0005"),
            ("Credential Access", "TA0006"),
            ("Discovery", "TA0007"),
            ("Lateral Movement", "TA0008"),
            ("Collection", "TA0009"),
            ("Command and Control", "TA0011"),
            ("Exfiltration", "TA0010"),
            ("Impact", "TA0040"),
        ];

        let repo = self.storage.events().await;
        let query = EventQuery {
            limit: 5000,
            ..Default::default()
        };

        let mut cursor = repo.query(query).await.map_err(|e| format!("{e}"))?;
        let events = if let Some(c) = Arc::get_mut(&mut cursor) {
            c.collect(5000).await.map_err(|e| format!("{e}"))?
        } else {
            vec![]
        };

        let mut counts: HashMap<&str, (u32, u32)> = HashMap::new();
        for t in &tactics {
            counts.insert(t.0, (0, 0));
        }

        for e in &events {
            for tag in &e.tags {
                if tag.starts_with("mitre:") {
                    let technique = tag.strip_prefix("mitre:").unwrap_or("");
                    for (tactic_name, _tactic_id) in &tactics {
                        if let Some((count, max_risk)) = counts.get_mut(tactic_name) {
                            *count += 1;
                            *max_risk = (*max_risk).max(e.risk_score);
                        }
                    }
                }
            }
        }

        let tactics_json: Vec<serde_json::Value> = tactics
            .iter()
            .map(|(name, id)| {
                let (count, max_risk) = counts.get(name).copied().unwrap_or((0, 0));
                serde_json::json!({
                    "tactic": name,
                    "id": id,
                    "techniques_count": count,
                    "max_risk": max_risk,
                })
            })
            .collect();

        Ok(MitreHeatmapResponse {
            tactics: tactics_json,
        })
    }

    pub async fn get_network_graph(&self) -> Result<NetworkGraphResponse, String> {
        let repo = self.storage.events().await;
        let query = EventQuery {
            event_types: vec!["sentinel.network.connect".into()],
            limit: 500,
            ..Default::default()
        };

        let mut cursor = repo.query(query).await.map_err(|e| format!("{e}"))?;
        let events = if let Some(c) = Arc::get_mut(&mut cursor) {
            c.collect(500).await.map_err(|e| format!("{e}"))?
        } else {
            vec![]
        };

        let mut nodes = std::collections::HashMap::new();
        let mut edges = Vec::new();
        let mut node_id = 0u32;

        for e in &events {
            if let Some(ref payload) = e.payload {
                if let sentinel_events::event::Payload::NetworkEvent(ref ne) = payload {
                    if !ne.remote_addr.is_empty() && !ne.local_addr.is_empty() {
                        let local_key = format!("local:{}", ne.local_addr);
                        let remote_key = format!("remote:{}", ne.remote_addr);

                        let lid = *nodes.entry(local_key.clone()).or_insert_with(|| {
                            let id = node_id;
                            node_id += 1;
                            id
                        });
                        let rid = *nodes.entry(remote_key.clone()).or_insert_with(|| {
                            let id = node_id;
                            node_id += 1;
                            id
                        });

                        edges.push(serde_json::json!({
                            "from": lid,
                            "to": rid,
                            "protocol": if ne.protocol == 1 { "tcp" } else { "udp" },
                            "local_port": ne.local_port,
                            "remote_port": ne.remote_port,
                        }));
                    }
                }
            }
        }

        let nodes_json: Vec<serde_json::Value> = nodes
            .iter()
            .map(|(key, id)| {
                let (label, risk) = if key.starts_with("local:") {
                    (key.strip_prefix("local:").unwrap_or("?"), 0u32)
                } else {
                    (key.strip_prefix("remote:").unwrap_or("?"), 10u32)
                };
                serde_json::json!({
                    "id": id,
                    "label": label,
                    "risk": risk,
                })
            })
            .collect();

        Ok(NetworkGraphResponse {
            nodes: nodes_json,
            edges,
        })
    }
}

fn default_db_path() -> String {
    let path = dirs::data_local_dir()
        .map(|mut p| {
            p.push("sentinel");
            p.push("sentinel.db");
            p
        })
        .unwrap_or_else(|| PathBuf::from("sentinel.db"));

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    path.to_string_lossy().to_string()
}

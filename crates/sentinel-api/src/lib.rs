use std::pin::Pin;
use std::sync::Arc;

use sentinel_core::traits::{AlertState as CoreAlertState, EventQuery};
use sentinel_core::{Severity, Ulid};
use sentinel_storage::sqlite::SqliteStorage;
use tokio::sync::broadcast;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use api::sentinel_server::{Sentinel, SentinelServer};
use sentinel_events::sentinel::api::v1 as api;
use sentinel_events::Event;

pub struct SentinelService {
    storage: Arc<SqliteStorage>,
    alert_broadcast: broadcast::Sender<api::AlertStreamEvent>,
    collector_registry: Arc<sentinel_core::CollectorRegistry>,
    rule_engine: Arc<sentinel_rule_engine::RuleEngine>,
    ai_engine: Arc<sentinel_ai::AiEngine>,
    started_at: std::time::Instant,
}

impl SentinelService {
    pub fn new(
        storage: Arc<SqliteStorage>,
        alert_broadcast: broadcast::Sender<api::AlertStreamEvent>,
        collector_registry: Arc<sentinel_core::CollectorRegistry>,
        rule_engine: Arc<sentinel_rule_engine::RuleEngine>,
        ai_engine: Arc<sentinel_ai::AiEngine>,
    ) -> Self {
        Self {
            storage,
            alert_broadcast,
            collector_registry,
            rule_engine,
            ai_engine,
            started_at: std::time::Instant::now(),
        }
    }
}

fn map_err(e: impl std::fmt::Display) -> Status {
    Status::internal(format!("{e}"))
}

fn plugin_info(id: &str, name: &str, desc: &str, _needs_key: bool) -> api::PluginInfo {
    api::PluginInfo {
        id: id.to_string(),
        name: name.to_string(),
        description: desc.to_string(),
        version: "0.1.0".to_string(),
        state: api::PluginState::PluginRunning as i32,
        ..Default::default()
    }
}

#[tonic::async_trait]
impl Sentinel for SentinelService {
    async fn health(
        &self,
        _: Request<api::HealthRequest>,
    ) -> Result<Response<api::HealthResponse>, Status> {
        let ok = self.storage.health().await.is_ok();
        Ok(Response::new(api::HealthResponse {
            status: if ok {
                tonic_health::ServingStatus::Serving as i32
            } else {
                tonic_health::ServingStatus::NotServing as i32
            },
            ..Default::default()
        }))
    }

    async fn version(
        &self,
        _: Request<api::VersionRequest>,
    ) -> Result<Response<api::VersionResponse>, Status> {
        Ok(Response::new(api::VersionResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_commit: option_env!("GIT_HASH").unwrap_or("dev").to_string(),
            build_date: option_env!("BUILD_DATE").unwrap_or("unknown").to_string(),
            rust_version: option_env!("RUSTC_VERSION").unwrap_or("stable").to_string(),
            ..Default::default()
        }))
    }

    async fn status(
        &self,
        _: Request<api::StatusRequest>,
    ) -> Result<Response<api::StatusResponse>, Status> {
        let metrics = self.rule_engine.metrics();
        let uptime_secs = self.started_at.elapsed().as_secs() as i64;

        let collectors: std::collections::HashMap<String, api::CollectorStatus> = self
            .collector_registry
            .list()
            .into_iter()
            .map(|s| {
                (
                    s.id.clone(),
                    api::CollectorStatus {
                        id: s.id.clone(),
                        name: s.name.clone(),
                        state: match s.state.as_str() {
                            "running" => api::collector_status::State::CsRunning as i32,
                            "stopped" => api::collector_status::State::CsStopped as i32,
                            "starting" => api::collector_status::State::CsStarting as i32,
                            "degraded" => api::collector_status::State::CsDegraded as i32,
                            "error" => api::collector_status::State::CsError as i32,
                            _ => api::collector_status::State::CsUnknown as i32,
                        },
                        stats: Some(api::CollectorStats {
                            events_produced: s.events_produced,
                            errors: s.errors,
                            ..Default::default()
                        }),
                        last_event: s.last_event_at.map(|t| prost_types::Timestamp {
                            seconds: t.timestamp(),
                            nanos: t.timestamp_subsec_nanos() as i32,
                        }),
                    },
                )
            })
            .collect();

        let cpu_pct = cpu_percent();
        let mem_bytes = memory_bytes();

        Ok(Response::new(api::StatusResponse {
            state: api::SystemState::SysRunning as i32,
            uptime: Some(prost_types::Timestamp { seconds: uptime_secs, nanos: 0 }),
            resources: Some(api::ResourceUsage {
                cpu_percent: cpu_pct,
                memory_bytes: mem_bytes,
                event_queue_depth: 0,
            }),
            collectors,
            rules: Some(api::RuleEngineStatus {
                loaded_rules: metrics.rules_loaded as u32,
                enabled_rules: metrics.rules_enabled as u32,
                evaluations_total: metrics.evaluations_total,
                matches_total: metrics.matches_total,
                avg_eval_time_ms: metrics.avg_eval_time_ms as f64,
            }),
            ai: Some(api::AiEngineStatus {
                enabled: self.ai_engine.config().enabled,
                model: self.ai_engine.config().model.clone(),
                provider: self.ai_engine.config().provider.clone(),
                requests_total: self.ai_engine.requests_total(),
                avg_latency_ms: self.ai_engine.avg_latency_ms(),
            }),
        }))
    }

    async fn query_events(
        &self,
        req: Request<api::QueryEventsRequest>,
    ) -> Result<Response<api::QueryEventsResponse>, Status> {
        let q = req.into_inner();
        let repo = self.storage.events().await;
        let filter = q.query.unwrap_or_default();

        let limit = if q.limit > 0 { q.limit as usize } else { 100 };
        let offset = if q.offset > 0 { q.offset as usize } else { 0 };

        let event_query = EventQuery {
            event_types: filter.event_types,
            sources: filter.sources,
            min_risk_score: if filter.min_risk_score > 0 {
                Some(filter.min_risk_score)
            } else {
                None
            },
            limit,
            offset,
            sort_by: Some("timestamp".into()),
            sort_desc: true,
            ..Default::default()
        };

        let mut cursor = repo.query(event_query).await.map_err(map_err)?;
        let total = cursor.total_count();
        let events: Vec<Event> = match Arc::get_mut(&mut cursor) {
            Some(c) => c
                .collect(1000)
                .await
                .map_err(map_err)?
                .into_iter()
                .map(|e| (*e).clone())
                .collect(),
            None => {
                tracing::warn!("EventCursor has multiple references — returning empty");
                vec![]
            }
        };

        Ok(Response::new(api::QueryEventsResponse {
            events,
            total_count: total as i64,
            ..Default::default()
        }))
    }

    async fn get_event(
        &self,
        req: Request<api::GetEventRequest>,
    ) -> Result<Response<Event>, Status> {
        let repo = self.storage.events().await;
        let id = Ulid::from_string(&req.into_inner().event_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let evt = repo
            .get(&id)
            .await
            .map_err(map_err)?
            .map(|e| (*e).clone())
            .ok_or_else(|| Status::not_found("event not found"))?;
        Ok(Response::new(evt))
    }

    async fn event_stats(
        &self,
        _: Request<api::EventStatsRequest>,
    ) -> Result<Response<api::EventStatsResponse>, Status> {
        Ok(Response::new(api::EventStatsResponse::default()))
    }

    async fn list_processes(
        &self,
        req: Request<api::ListProcessesRequest>,
    ) -> Result<Response<api::ListProcessesResponse>, Status> {
        let limit = req.into_inner().limit.max(1).min(1000) as usize;
        let mut sys = sysinfo::System::new();
        sys.refresh_all();
        let processes: Vec<api::ProcessSummary> = sys
            .processes()
            .iter()
            .take(limit)
            .map(|(pid, proc)| api::ProcessSummary {
                pid: pid.as_u32(),
                ppid: proc.parent().map(|p| p.as_u32()).unwrap_or(0),
                name: proc.name().to_string_lossy().into_owned(),
                ..Default::default()
            })
            .collect();
        Ok(Response::new(api::ListProcessesResponse { processes }))
    }

    async fn get_process(
        &self,
        req: Request<api::GetProcessRequest>,
    ) -> Result<Response<api::ProcessDetail>, Status> {
        let pid = req.into_inner().pid;
        let mut sys = sysinfo::System::new();
        sys.refresh_all();

        let summary = sys
            .processes()
            .iter()
            .find(|(p, _)| p.as_u32() == pid)
            .map(|(p, proc)| api::ProcessSummary {
                pid: p.as_u32(),
                ppid: proc.parent().map(|pp| pp.as_u32()).unwrap_or(0),
                name: proc.name().to_string_lossy().into_owned(),
                path: proc
                    .exe()
                    .map(|e| e.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                command_line: proc
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" "),
                ..Default::default()
            })
            .ok_or_else(|| Status::not_found(format!("PID {} not found", pid)))?;

        Ok(Response::new(api::ProcessDetail {
            summary: Some(summary),
            ..Default::default()
        }))
    }

    async fn get_process_tree(
        &self,
        _: Request<api::GetProcessTreeRequest>,
    ) -> Result<Response<api::ProcessTree>, Status> {
        let mut sys = sysinfo::System::new();
        sys.refresh_all();

        let first = sys.processes().iter().next().map(|(pid, proc)| {
            let summary = api::ProcessSummary {
                pid: pid.as_u32(),
                ppid: proc.parent().map(|pp| pp.as_u32()).unwrap_or(0),
                name: proc.name().to_string_lossy().into_owned(),
                ..Default::default()
            };
            api::ProcessTreeNode {
                process: Some(summary),
                children: vec![],
            }
        });

        Ok(Response::new(api::ProcessTree { root: first }))
    }

    async fn list_connections(
        &self,
        _: Request<api::ListConnectionsRequest>,
    ) -> Result<Response<api::ListConnectionsResponse>, Status> {
        Ok(Response::new(api::ListConnectionsResponse::default()))
    }

    async fn connection_stats(
        &self,
        _: Request<api::ConnectionStatsRequest>,
    ) -> Result<Response<api::ConnectionStatsResponse>, Status> {
        Ok(Response::new(api::ConnectionStatsResponse::default()))
    }

    async fn list_alerts(
        &self,
        req: Request<api::ListAlertsRequest>,
    ) -> Result<Response<api::ListAlertsResponse>, Status> {
        let q = req.into_inner();
        let repo = self.storage.alerts().await;
        let limit = if q.limit > 0 { q.limit as usize } else { 100 };
        let offset = q.offset.max(0) as usize;

        let alert_query = sentinel_core::traits::AlertQuery {
            state: if q.state != 0 {
                Some(proto_alert_state_to_core(q.state).map_err(|_| {
                    Status::invalid_argument(format!("invalid alert state: {}", q.state))
                })?)
            } else {
                None
            },
            min_severity: if q.min_severity != 0 {
                Some(proto_severity_to_core(q.min_severity))
            } else {
                None
            },
            start_time: q.start_time.and_then(|ts| {
                chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
            }),
            end_time: q.end_time.and_then(|ts| {
                chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
            }),
            limit,
            offset,
        };
        let alerts = repo.query(alert_query).await.map_err(map_err)?;
        let api_alerts: Vec<api::Alert> = alerts
            .into_iter()
            .map(|a| api::Alert {
                id: a.id.to_string(),
                rule_id: a.rule_id,
                risk_score: a.risk_score,
                severity: a.severity as i32,
                ..Default::default()
            })
            .collect();
        Ok(Response::new(api::ListAlertsResponse {
            alerts: api_alerts,
            ..Default::default()
        }))
    }

    async fn get_alert(
        &self,
        req: Request<api::GetAlertRequest>,
    ) -> Result<Response<api::Alert>, Status> {
        let repo = self.storage.alerts().await;
        let id = Ulid::from_string(&req.into_inner().alert_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let alert = repo
            .get(&id)
            .await
            .map_err(map_err)?
            .ok_or_else(|| Status::not_found("alert not found"))?;

        Ok(Response::new(api::Alert {
            id: alert.id.to_string(),
            rule_id: alert.rule_id,
            risk_score: alert.risk_score,
            severity: alert.severity as i32,
            ..Default::default()
        }))
    }

    async fn update_alert_state(
        &self,
        req: Request<api::UpdateAlertStateRequest>,
    ) -> Result<Response<api::UpdateAlertStateResponse>, Status> {
        let q = req.into_inner();
        let repo = self.storage.alerts().await;
        let id = Ulid::from_string(&q.alert_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let state = proto_alert_state_to_core(q.new_state).map_err(|e| e)?;

        repo.update_state(&id, state, Some(q.comment))
            .await
            .map_err(map_err)?;

        let alert = repo
            .get(&id)
            .await
            .map_err(map_err)?
            .ok_or_else(|| Status::not_found("alert not found"))?;

        let _ = self.alert_broadcast.send(api::AlertStreamEvent {
            alert: Some(api::Alert {
                id: alert.id.to_string(),
                rule_id: alert.rule_id.clone(),
                risk_score: alert.risk_score,
                severity: alert.severity as i32,
                state: core_alert_state_to_proto(alert.state),
                ..Default::default()
            }),
            event_type: api::alert_stream_event::EventType::Updated as i32,
        });

        Ok(Response::new(api::UpdateAlertStateResponse {
            alert: Some(api::Alert {
                id: alert.id.to_string(),
                rule_id: alert.rule_id,
                correlation_id: alert.correlation_id.to_string(),
                risk_score: alert.risk_score,
                severity: alert.severity as i32,
                state: core_alert_state_to_proto(alert.state),
                created_at: sentinel_core::chrono_to_proto_ts(alert.created_at),
                updated_at: sentinel_core::chrono_to_proto_ts(alert.updated_at),
                acknowledged_by: alert.acknowledged_by.unwrap_or_default(),
                acknowledged_at: alert
                    .acknowledged_at
                    .and_then(sentinel_core::chrono_to_proto_ts),
                events: alert.events.iter().map(|e| e.to_string()).collect(),
                ..Default::default()
            }),
        }))
    }

    type StreamAlertsStream =
        Pin<Box<dyn Stream<Item = Result<api::AlertStreamEvent, Status>> + Send>>;

    async fn stream_alerts(
        &self,
        _: Request<api::StreamAlertsRequest>,
    ) -> Result<Response<Self::StreamAlertsStream>, Status> {
        let mut rx = self.alert_broadcast.subscribe();

        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(event) => yield Ok(event),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("StreamAlerts lagged by {} messages", n);
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        };

        Ok(Response::new(Box::pin(stream) as Self::StreamAlertsStream))
    }

    async fn list_rules(
        &self,
        _: Request<api::ListRulesRequest>,
    ) -> Result<Response<api::ListRulesResponse>, Status> {
        let repo = self.storage.rules().await;
        let rules = repo.load_all(false).await.map_err(map_err)?;
        let api_rules: Vec<api::Rule> = rules.into_iter().map(|r| core_rule_to_proto(&r)).collect();
        Ok(Response::new(api::ListRulesResponse { rules: api_rules }))
    }

    async fn create_rule(
        &self,
        req: Request<api::CreateRuleRequest>,
    ) -> Result<Response<api::Rule>, Status> {
        let proto_rule = req
            .into_inner()
            .rule
            .ok_or_else(|| Status::invalid_argument("rule is required"))?;
        let core_rule = proto_to_core_rule(&proto_rule)?;
        let repo = self.storage.rules().await;
        repo.upsert(&core_rule).await.map_err(map_err)?;
        Ok(Response::new(core_rule_to_proto(&core_rule)))
    }

    async fn get_rule(
        &self,
        req: Request<api::GetRuleRequest>,
    ) -> Result<Response<api::Rule>, Status> {
        let id = req.into_inner().id;
        let repo = self.storage.rules().await;
        let rule = repo
            .get(&id)
            .await
            .map_err(map_err)?
            .ok_or_else(|| Status::not_found(format!("rule not found: {id}")))?;
        Ok(Response::new(core_rule_to_proto(&rule)))
    }

    async fn update_rule(
        &self,
        req: Request<api::UpdateRuleRequest>,
    ) -> Result<Response<api::Rule>, Status> {
        let q = req.into_inner();
        let proto_rule = q
            .rule
            .ok_or_else(|| Status::invalid_argument("rule is required"))?;
        let mut core_rule = proto_to_core_rule(&proto_rule)?;
        core_rule.id = q.id;

        let repo = self.storage.rules().await;
        repo.upsert(&core_rule).await.map_err(map_err)?;
        Ok(Response::new(core_rule_to_proto(&core_rule)))
    }

    async fn delete_rule(
        &self,
        req: Request<api::DeleteRuleRequest>,
    ) -> Result<Response<()>, Status> {
        let id = req.into_inner().id;
        let repo = self.storage.rules().await;
        repo.delete(&id).await.map_err(map_err)?;
        Ok(Response::new(()))
    }

    async fn test_rule(
        &self,
        req: Request<api::TestRuleRequest>,
    ) -> Result<Response<api::TestRuleResponse>, Status> {
        let q = req.into_inner();
        let proto_rule = q
            .rule
            .ok_or_else(|| Status::invalid_argument("rule is required"))?;
        let core_rule = proto_to_core_rule(&proto_rule)?;

        let mut results = Vec::new();

        for test_event in &q.test_events {
            let matched = sentinel_rule_engine::evaluate_rule_condition(&core_rule, test_event)
                .unwrap_or(false);
            results.push(api::TestResult {
                event_id: test_event.id.clone(),
                matched,
                // expected_match = matched until rule YAML supports test.expectation field
                expected_match: matched,
                ..Default::default()
            });
        }

        let all_passed = !results.is_empty() && results.iter().all(|r| r.matched);
        Ok(Response::new(api::TestRuleResponse {
            results,
            all_passed,
        }))
    }

    async fn risk_summary(
        &self,
        _: Request<api::RiskSummaryRequest>,
    ) -> Result<Response<api::RiskSummaryResponse>, Status> {
        Ok(Response::new(api::RiskSummaryResponse::default()))
    }

    async fn risk_timeline(
        &self,
        _: Request<api::RiskTimelineRequest>,
    ) -> Result<Response<api::RiskTimelineResponse>, Status> {
        Ok(Response::new(api::RiskTimelineResponse::default()))
    }

    async fn top_risks(
        &self,
        _: Request<api::TopRisksRequest>,
    ) -> Result<Response<api::TopRisksResponse>, Status> {
        Ok(Response::new(api::TopRisksResponse::default()))
    }

    async fn attack_chains(
        &self,
        req: Request<api::AttackChainsRequest>,
    ) -> Result<Response<api::AttackChainsResponse>, Status> {
        let q = req.into_inner();
        let repo = self.storage.chains().await;

        let query = sentinel_core::traits::ChainQuery {
            start_time: q.start_time.and_then(|ts| {
                std::time::SystemTime::try_from(ts).ok().map(chrono::DateTime::from)
            }),
            end_time: q.end_time.and_then(|ts| {
                std::time::SystemTime::try_from(ts).ok().map(chrono::DateTime::from)
            }),
            status: match q.status {
                1 => Some(sentinel_core::traits::ChainStatus::ActiveAttack),
                2 => Some(sentinel_core::traits::ChainStatus::SuspiciousChain),
                3 => Some(sentinel_core::traits::ChainStatus::Resolved),
                _ => None,
            },
            min_risk: if q.min_risk > 0 { Some(q.min_risk as u32) } else { None },
            limit: if q.limit > 0 { q.limit as usize } else { 100 },
        };

        let chains = repo.query_chains(query).await.map_err(map_err)?;
        let summaries: Vec<api::AttackChainSummary> =
            chains.into_iter().map(|c| api::AttackChainSummary {
                id: c.id,
                start_time: sentinel_core::chrono_to_proto_ts(c.start_time),
                end_time: sentinel_core::chrono_to_proto_ts(c.end_time),
                risk_score: c.risk_score,
                tactics: c.tactics,
                techniques: c.techniques,
                event_count: c.event_count as i32,
                status: chain_status_to_proto(c.status),
                kill_chain_coverage: c.kill_chain_coverage,
            }).collect();

        Ok(Response::new(api::AttackChainsResponse { chains: summaries }))
    }

    async fn chain_detail(
        &self,
        req: Request<api::ChainDetailRequest>,
    ) -> Result<Response<api::AttackChainDetail>, Status> {
        let chain_id = req.into_inner().chain_id;
        let repo = self.storage.chains().await;

        let chain = repo
            .get_chain(&chain_id)
            .await
            .map_err(map_err)?
            .ok_or_else(|| Status::not_found(format!("chain not found: {chain_id}")))?;

        let summary = api::AttackChainSummary {
            id: chain.id.clone(),
            start_time: sentinel_core::chrono_to_proto_ts(chain.start_time),
            end_time: sentinel_core::chrono_to_proto_ts(chain.end_time),
            risk_score: chain.risk_score,
            tactics: chain.tactics.clone(),
            techniques: chain.techniques.clone(),
            event_count: chain.event_count as i32,
            status: chain_status_to_proto(chain.status),
            kill_chain_coverage: chain.kill_chain_coverage,
        };

        Ok(Response::new(api::AttackChainDetail {
            summary: Some(summary),
            ..Default::default()
        }))
    }

    async fn explain_alert(
        &self,
        _: Request<api::ExplainAlertRequest>,
    ) -> Result<Response<api::ExplainAlertResponse>, Status> {
        Ok(Response::new(api::ExplainAlertResponse::default()))
    }

    async fn chat(
        &self,
        _: Request<api::ChatRequest>,
    ) -> Result<Response<api::ChatResponse>, Status> {
        Ok(Response::new(api::ChatResponse::default()))
    }

    async fn get_config(
        &self,
        _: Request<api::GetConfigRequest>,
    ) -> Result<Response<api::ConfigResponse>, Status> {
        Ok(Response::new(api::ConfigResponse::default()))
    }

    async fn update_config(
        &self,
        req: Request<api::UpdateConfigRequest>,
    ) -> Result<Response<api::ConfigResponse>, Status> {
        let q = req.into_inner();
        Ok(Response::new(api::ConfigResponse {
            config_toml: q.config_toml,
            version: 1,
        }))
    }

    async fn list_plugins(
        &self,
        _: Request<api::ListPluginsRequest>,
    ) -> Result<Response<api::ListPluginsResponse>, Status> {
        let plugins = vec![
            plugin_info("abuseipdb", "AbuseIPDB", "IP reputation lookup", true),
            plugin_info("virustotal", "VirusTotal", "File hash and URL analysis", true),
            plugin_info("shodan", "Shodan", "Host and service fingerprinting", true),
            plugin_info("otx", "AlienVault OTX", "Threat intelligence pulses", true),
            plugin_info("greynoise", "GreyNoise", "Benign scanner detection", true),
            plugin_info("urlhaus", "URLhaus", "Malware URL lookup", false),
            plugin_info("geoip", "GeoIP", "IP geolocation via MaxMind", false),
            plugin_info("ioc", "IOC Scanner", "Local threat intel database", false),
            plugin_info("discord", "Discord", "Alert notifications", true),
            plugin_info("telegram", "Telegram", "Alert notifications", true),
            plugin_info("slack", "Slack", "Alert notifications", true),
            plugin_info("email", "Email", "Alert notifications via SMTP", true),
            plugin_info("home-assistant", "Home Assistant", "Automation notifications", true),
        ];
        Ok(Response::new(api::ListPluginsResponse { plugins }))
    }

    async fn get_plugin(
        &self,
        req: Request<api::GetPluginRequest>,
    ) -> Result<Response<api::PluginInfo>, Status> {
        let id = req.into_inner().plugin_id;
        let plugins = [
            ("abuseipdb", "AbuseIPDB", "IP reputation lookup via AbuseIPDB API v2"),
            ("virustotal", "VirusTotal", "File hash and URL analysis via VirusTotal API v3"),
            ("shodan", "Shodan", "Host and service fingerprinting"),
            ("otx", "AlienVault OTX", "Threat intelligence pulses"),
            ("greynoise", "GreyNoise", "Benign scanner identification"),
            ("urlhaus", "URLhaus", "Malware URL database lookup"),
            ("geoip", "GeoIP", "IP geolocation with MaxMind GeoLite2"),
            ("ioc", "IOC Scanner", "Local threat intelligence from CSV/STIX"),
            ("discord", "Discord", "Alert notifications via webhook"),
            ("telegram", "Telegram", "Alert notifications via bot"),
            ("slack", "Slack", "Alert notifications via webhook"),
            ("email", "Email", "Alert notifications via SMTP"),
            ("home-assistant", "Home Assistant", "Automation notifications"),
        ];

        let plugin = plugins
            .iter()
            .find(|(pid, _, _)| *pid == id)
            .map(|(pid, name, desc)| api::PluginInfo {
                id: pid.to_string(),
                name: name.to_string(),
                description: desc.to_string(),
                version: "0.1.0".to_string(),
                state: api::PluginState::PluginRunning as i32,
                ..Default::default()
            })
            .ok_or_else(|| Status::not_found(format!("plugin not found: {id}")))?;

        Ok(Response::new(plugin))
    }

    async fn configure_plugin(
        &self,
        req: Request<api::ConfigurePluginRequest>,
    ) -> Result<Response<api::PluginConfig>, Status> {
        let q = req.into_inner();
        Ok(Response::new(api::PluginConfig {
            config: q.config,
        }))
    }

    async fn list_collectors(
        &self,
        _: Request<api::ListCollectorsRequest>,
    ) -> Result<Response<api::ListCollectorsResponse>, Status> {
        let collectors: Vec<api::CollectorInfo> = self
            .collector_registry
            .list()
            .into_iter()
            .map(|s| {
                let state = match s.state.as_str() {
                    "running" => api::CollectorState::CollectorRunning as i32,
                    "stopped" => api::CollectorState::CollectorStopped as i32,
                    "starting" => api::CollectorState::CollectorStarting as i32,
                    "degraded" => api::CollectorState::CollectorDegraded as i32,
                    "error" => api::CollectorState::CollectorError as i32,
                    _ => api::CollectorState::Unspecified as i32,
                };
                api::CollectorInfo {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    description: s.description.clone(),
                    enabled: s.state != "stopped",
                    state,
                    stats: Some(api::CollectorStats {
                        events_produced: s.events_produced,
                        errors: s.errors,
                        ..Default::default()
                    }),
                    last_event: s.last_event_at.map(|t| {
                        prost_types::Timestamp {
                            seconds: t.timestamp(),
                            nanos: t.timestamp_subsec_nanos() as i32,
                        }
                    }),
                }
            })
            .collect();

        Ok(Response::new(api::ListCollectorsResponse { collectors }))
    }

    async fn collector_status(
        &self,
        req: Request<api::CollectorStatusRequest>,
    ) -> Result<Response<api::CollectorStatusResponse>, Status> {
        let id = req.into_inner().collector_id;
        let s = self
            .collector_registry
            .get(&id)
            .ok_or_else(|| Status::not_found(format!("collector not found: {}", id)))?;

        let info = Some(api::CollectorInfo {
            id: s.id.clone(),
            name: s.name.clone(),
            description: s.description.clone(),
            enabled: s.state != "stopped",
            state: match s.state.as_str() {
                "running" => api::CollectorState::CollectorRunning as i32,
                "stopped" => api::CollectorState::CollectorStopped as i32,
                "starting" => api::CollectorState::CollectorStarting as i32,
                "degraded" => api::CollectorState::CollectorDegraded as i32,
                "error" => api::CollectorState::CollectorError as i32,
                _ => api::CollectorState::Unspecified as i32,
            },
            stats: Some(api::CollectorStats {
                events_produced: s.events_produced,
                errors: s.errors,
                ..Default::default()
            }),
            last_event: s.last_event_at.map(|t| {
                prost_types::Timestamp {
                    seconds: t.timestamp(),
                    nanos: t.timestamp_subsec_nanos() as i32,
                }
            }),
        });

        Ok(Response::new(api::CollectorStatusResponse {
            info,
            ..Default::default()
        }))
    }

    async fn restart_collector(
        &self,
        req: Request<api::RestartCollectorRequest>,
    ) -> Result<Response<()>, Status> {
        let id = req.into_inner().collector_id;
        let _ = self
            .collector_registry
            .get(&id)
            .ok_or_else(|| Status::not_found(format!("collector not found: {}", id)))?;

        self.collector_registry.update_state(&id, "restarting");
        tracing::warn!(
            "Collector restart requested for '{}' (full restart requires service-level lifecycle management)",
            id
        );
        Ok(Response::new(()))
    }
}

fn core_alert_state_to_proto(state: CoreAlertState) -> i32 {
    match state {
        CoreAlertState::New => 1,
        CoreAlertState::Acknowledged => 2,
        CoreAlertState::Investigating => 3,
        CoreAlertState::ResolvedTruePositive => 4,
        CoreAlertState::ResolvedFalsePositive => 5,
        CoreAlertState::Suppressed => 6,
    }
}

fn proto_severity_to_core(s: i32) -> Severity {
    match s {
        1 => Severity::Debug,
        2 => Severity::Info,
        3 => Severity::Notice,
        4 => Severity::Warning,
        5 => Severity::Error,
        6 => Severity::Critical,
        7 => Severity::Alert,
        8 => Severity::Emergency,
        _ => Severity::default(),
    }
}

fn proto_alert_state_to_core(state: i32) -> Result<CoreAlertState, Status> {
    match state {
        1 => Ok(CoreAlertState::New),
        2 => Ok(CoreAlertState::Acknowledged),
        3 => Ok(CoreAlertState::Investigating),
        4 => Ok(CoreAlertState::ResolvedTruePositive),
        5 => Ok(CoreAlertState::ResolvedFalsePositive),
        6 => Ok(CoreAlertState::Suppressed),
        _ => Err(Status::invalid_argument(format!(
            "invalid alert state: {}. Valid: 1-6",
            state
        ))),
    }
}

fn chain_status_to_proto(status: sentinel_core::traits::ChainStatus) -> i32 {
    match status {
        sentinel_core::traits::ChainStatus::ActiveAttack => 1,
        sentinel_core::traits::ChainStatus::SuspiciousChain => 2,
        sentinel_core::traits::ChainStatus::Resolved => 3,
        sentinel_core::traits::ChainStatus::Unspecified => 0,
    }
}

fn core_rule_to_proto(rule: &sentinel_core::traits::Rule) -> api::Rule {
    api::Rule {
        id: rule.id.clone(),
        version: rule.version,
        name: rule.name.clone(),
        description: rule.description.clone(),
        author: rule.author.clone(),
        created: sentinel_core::chrono_to_proto_ts(rule.created),
        modified: sentinel_core::chrono_to_proto_ts(rule.modified),
        enabled: rule.enabled,
        category: rule.category.clone(),
        subcategory: rule.subcategory.clone().unwrap_or_default(),
        mitre: rule
            .mitre
            .iter()
            .map(|m| api::MitreMapping {
                technique: m.technique.clone(),
                name: m.name.clone(),
                tactic: m.tactic.clone(),
            })
            .collect(),
        severity: rule.severity as i32,
        risk: Some(api::RiskConfig {
            base_score: rule.risk.base_score,
            confidence: rule.risk.confidence,
            multipliers: rule
                .risk
                .multipliers
                .iter()
                .map(|m| api::RiskMultiplier {
                    condition: m.condition.clone(),
                    factor: m.factor,
                })
                .collect(),
        }),
        condition: rule.condition.clone(),
        and_conditions: rule.and_conditions.clone(),
        or_conditions: rule.or_conditions.clone(),
        not_conditions: rule.not_conditions.clone(),
        actions: rule
            .actions
            .iter()
            .map(|a| api::RuleAction {
                r#type: match a.action_type {
                    sentinel_core::RuleActionType::Alert => 1,
                    sentinel_core::RuleActionType::Enrich => 2,
                    sentinel_core::RuleActionType::Correlate => 3,
                    sentinel_core::RuleActionType::Snapshot => 4,
                },
                config: Some(prost_types::Struct {
                    fields: a
                        .config
                        .as_object()
                        .map(|o| {
                            o.iter()
                                .map(|(k, v)| {
                                    (k.clone(), serde_json_to_proto_value(v))
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                }),
            })
            .collect(),
        suppressions: rule
            .suppressions
            .iter()
            .map(|s| api::SuppressionRule {
                id: s.id.clone(),
                condition: s.condition.clone(),
                reason: s.reason.clone(),
            })
            .collect(),
    }
}

fn proto_to_core_rule(proto: &api::Rule) -> Result<sentinel_core::traits::Rule, Status> {
    let now = chrono::Utc::now();
    Ok(sentinel_core::traits::Rule {
        id: if proto.id.is_empty() {
            Ulid::new().to_string()
        } else {
            proto.id.clone()
        },
        version: proto.version,
        name: proto.name.clone(),
        description: proto.description.clone(),
        author: proto.author.clone(),
        created: if let Some(ref ts) = proto.created {
            chrono::DateTime::from(std::time::SystemTime::try_from(ts.clone()).map_err(|e| {
                Status::invalid_argument(format!("invalid timestamp: {e}"))
            })?)
        } else {
            now
        },
        modified: now,
        enabled: proto.enabled,
        category: proto.category.clone(),
        subcategory: if proto.subcategory.is_empty() {
            None
        } else {
            Some(proto.subcategory.clone())
        },
        mitre: proto
            .mitre
            .iter()
            .map(|m| sentinel_core::traits::MitreMapping {
                technique: m.technique.clone(),
                name: m.name.clone(),
                tactic: m.tactic.clone(),
            })
            .collect(),
        severity: proto_severity_to_core(proto.severity),
        risk: proto
            .risk
            .as_ref()
            .map(|r| sentinel_core::traits::RiskConfig {
                base_score: r.base_score,
                confidence: r.confidence,
                multipliers: r
                    .multipliers
                    .iter()
                    .map(|m| sentinel_core::traits::RiskMultiplier {
                        condition: m.condition.clone(),
                        factor: m.factor,
                    })
                    .collect(),
            })
            .unwrap_or_default(),
        condition: proto.condition.clone(),
        and_conditions: proto.and_conditions.clone(),
        or_conditions: proto.or_conditions.clone(),
        not_conditions: proto.not_conditions.clone(),
        actions: proto
            .actions
            .iter()
            .map(|a| sentinel_core::traits::RuleAction {
                action_type: match a.r#type {
                    1 => sentinel_core::RuleActionType::Alert,
                    2 => sentinel_core::RuleActionType::Enrich,
                    3 => sentinel_core::RuleActionType::Correlate,
                    4 => sentinel_core::RuleActionType::Snapshot,
                    _ => sentinel_core::RuleActionType::Alert,
                },
                config: a
                    .config
                    .as_ref()
                    .map(|s| {
                        let mut map = serde_json::Map::new();
                        for (k, v) in &s.fields {
                            map.insert(k.clone(), prost_value_to_serde_json(v));
                        }
                        serde_json::Value::Object(map)
                    })
                    .unwrap_or(serde_json::Value::Null),
            })
            .collect(),
        suppressions: proto
            .suppressions
            .iter()
            .map(|s| sentinel_core::traits::SuppressionRule {
                id: s.id.clone(),
                condition: s.condition.clone(),
                reason: s.reason.clone(),
            })
            .collect(),
        tests: vec![],
    })
}

fn serde_json_to_proto_value(v: &serde_json::Value) -> prost_types::Value {
    match v {
        serde_json::Value::Null => prost_types::Value {
            kind: Some(prost_types::value::Kind::NullValue(0)),
        },
        serde_json::Value::Bool(b) => prost_types::Value {
            kind: Some(prost_types::value::Kind::BoolValue(*b)),
        },
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::NumberValue(i as f64)),
                }
            } else {
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::NumberValue(n.as_f64().unwrap_or(0.0))),
                }
            }
        }
        serde_json::Value::String(s) => prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(s.clone())),
        },
        serde_json::Value::Array(arr) => {
            let values = arr.iter().map(serde_json_to_proto_value).collect();
            prost_types::Value {
                kind: Some(prost_types::value::Kind::ListValue(prost_types::ListValue {
                    values,
                })),
            }
        }
        serde_json::Value::Object(obj) => {
            let fields = obj
                .iter()
                .map(|(k, v)| (k.clone(), serde_json_to_proto_value(v)))
                .collect();
            prost_types::Value {
                kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                    fields,
                })),
            }
        }
    }
}

fn prost_value_to_serde_json(v: &prost_types::Value) -> serde_json::Value {
    match &v.kind {
        Some(prost_types::value::Kind::NullValue(_)) => serde_json::Value::Null,
        Some(prost_types::value::Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(prost_types::value::Kind::NumberValue(n)) => {
            serde_json::Value::Number(serde_json::Number::from_f64(*n).unwrap_or_else(|| {
                serde_json::Number::from(*n as i64)
            }))
        }
        Some(prost_types::value::Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(prost_types::value::Kind::ListValue(arr)) => {
            serde_json::Value::Array(arr.values.iter().map(prost_value_to_serde_json).collect())
        }
        Some(prost_types::value::Kind::StructValue(s)) => {
            let mut map = serde_json::Map::new();
            for (k, v) in &s.fields {
                map.insert(k.clone(), prost_value_to_serde_json(v));
            }
            serde_json::Value::Object(map)
        }
        None => serde_json::Value::Null,
    }
}

fn cpu_percent() -> f64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        sysinfo::ProcessRefreshKind::new(),
    );
    let pid = sysinfo::Pid::from_u32(std::process::id());
    sys.process(pid).map(|p| p.cpu_usage() as f64).unwrap_or(0.0)
}

fn memory_bytes() -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        sysinfo::ProcessRefreshKind::new(),
    );
    let pid = sysinfo::Pid::from_u32(std::process::id());
    sys.process(pid).map(|p| p.memory()).unwrap_or(0)
}

pub async fn serve(
    addr: &str,
    storage: Arc<SqliteStorage>,
    alert_broadcast: broadcast::Sender<api::AlertStreamEvent>,
    collector_registry: Arc<sentinel_core::CollectorRegistry>,
    rule_engine: Arc<sentinel_rule_engine::RuleEngine>,
    ai_engine: Arc<sentinel_ai::AiEngine>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use tonic::transport::Server;
    tracing::info!("gRPC server starting on {addr}");

    let svc = SentinelService::new(
        storage,
        alert_broadcast,
        collector_registry,
        rule_engine,
        ai_engine,
    );

    let (mut reporter, health_svc) = tonic_health::server::health_reporter();
    reporter
        .set_serving::<SentinelServer<SentinelService>>()
        .await;

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
        .build()
        .map_err(|e| anyhow::anyhow!("reflection error: {e}"))?;

    Server::builder()
        .add_service(health_svc)
        .add_service(reflection)
        .add_service(SentinelServer::new(svc))
        .serve_with_shutdown(addr.parse()?, async move {
            let _ = shutdown.changed().await;
        })
        .await?;

    Ok(())
}

use std::sync::Arc;

use sentinel_core::traits::{EventQuery, EventRepository};
use sentinel_storage::sqlite::SqliteStorage;
use tonic::{Request, Response, Status};

use api::sentinel_server::{Sentinel, SentinelServer};
use sentinel_events::sentinel::api::v1 as api;

pub struct SentinelService {
    storage: Arc<SqliteStorage>,
}

impl SentinelService {
    pub fn new(storage: Arc<SqliteStorage>) -> Self {
        Self { storage }
    }
}

fn map_err(e: impl std::fmt::Display) -> Status {
    Status::internal(format!("{e}"))
}

#[tonic::async_trait]
impl Sentinel for SentinelService {
    async fn health(
        &self,
        _: Request<api::HealthRequest>,
    ) -> Result<Response<api::HealthResponse>, Status> {
        let ok = self.storage.health().await.is_ok();
        Ok(Response::new(api::HealthResponse {
            status: if ok { 1 } else { 3 },
            ..Default::default()
        }))
    }

    async fn version(
        &self,
        _: Request<api::VersionRequest>,
    ) -> Result<Response<api::VersionResponse>, Status> {
        Ok(Response::new(api::VersionResponse::default()))
    }

    async fn status(
        &self,
        _: Request<api::StatusRequest>,
    ) -> Result<Response<api::StatusResponse>, Status> {
        Ok(Response::new(api::StatusResponse {
            state: api::SystemState::SysRunning as i32,
            ..Default::default()
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
        let events: Vec<sentinel_events::Event> = if let Some(c) = Arc::get_mut(&mut cursor) {
            c.collect(1000)
                .await
                .map_err(map_err)?
                .into_iter()
                .map(|e| (*e).clone())
                .collect()
        } else {
            vec![]
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
    ) -> Result<Response<sentinel_events::Event>, Status> {
        let repo = self.storage.events().await;
        let id = sentinel_core::Ulid::from_string(&req.into_inner().event_id)
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
        _: Request<api::ListProcessesRequest>,
    ) -> Result<Response<api::ListProcessesResponse>, Status> {
        let mut sys = sysinfo::System::new();
        sys.refresh_all();
        let processes: Vec<api::ProcessSummary> = sys
            .processes()
            .iter()
            .take(200)
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
                path: proc.exe().map(|e| e.to_string_lossy().into_owned()).unwrap_or_default(),
                command_line: proc.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" "),
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
        let offset = 0usize;
        let alert_query = sentinel_core::traits::AlertQuery { limit, offset, ..Default::default() };
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
        Ok(Response::new(api::ListAlertsResponse { alerts: api_alerts, ..Default::default() }))
    }

    async fn get_alert(
        &self,
        req: Request<api::GetAlertRequest>,
    ) -> Result<Response<api::Alert>, Status> {
        let repo = self.storage.alerts().await;
        let id = sentinel_core::Ulid::from_string(&req.into_inner().alert_id)
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

    async fn list_rules(
        &self,
        _: Request<api::ListRulesRequest>,
    ) -> Result<Response<api::ListRulesResponse>, Status> {
        Ok(Response::new(api::ListRulesResponse::default()))
    }

    async fn create_rule(
        &self,
        _: Request<api::CreateRuleRequest>,
    ) -> Result<Response<api::Rule>, Status> {
        Err(Status::unimplemented("not yet"))
    }

    async fn get_rule(
        &self,
        _: Request<api::GetRuleRequest>,
    ) -> Result<Response<api::Rule>, Status> {
        Err(Status::unimplemented("not yet"))
    }

    async fn update_rule(
        &self,
        _: Request<api::UpdateRuleRequest>,
    ) -> Result<Response<api::Rule>, Status> {
        Err(Status::unimplemented("not yet"))
    }

    async fn delete_rule(
        &self,
        _: Request<api::DeleteRuleRequest>,
    ) -> Result<Response<()>, Status> {
        Err(Status::unimplemented("not yet"))
    }

    async fn test_rule(
        &self,
        _: Request<api::TestRuleRequest>,
    ) -> Result<Response<api::TestRuleResponse>, Status> {
        Err(Status::unimplemented("not yet"))
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
        _: Request<api::AttackChainsRequest>,
    ) -> Result<Response<api::AttackChainsResponse>, Status> {
        Err(Status::unimplemented("not yet"))
    }

    async fn chain_detail(
        &self,
        _: Request<api::ChainDetailRequest>,
    ) -> Result<Response<api::AttackChainDetail>, Status> {
        Err(Status::unimplemented("not yet"))
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
        _: Request<api::UpdateConfigRequest>,
    ) -> Result<Response<api::ConfigResponse>, Status> {
        Err(Status::unimplemented("not yet"))
    }

    async fn list_plugins(
        &self,
        _: Request<api::ListPluginsRequest>,
    ) -> Result<Response<api::ListPluginsResponse>, Status> {
        Ok(Response::new(api::ListPluginsResponse::default()))
    }

    async fn get_plugin(
        &self,
        _: Request<api::GetPluginRequest>,
    ) -> Result<Response<api::PluginInfo>, Status> {
        Err(Status::unimplemented("not yet"))
    }

    async fn configure_plugin(
        &self,
        _: Request<api::ConfigurePluginRequest>,
    ) -> Result<Response<api::PluginConfig>, Status> {
        Err(Status::unimplemented("not yet"))
    }

    async fn list_collectors(
        &self,
        _: Request<api::ListCollectorsRequest>,
    ) -> Result<Response<api::ListCollectorsResponse>, Status> {
        Ok(Response::new(api::ListCollectorsResponse::default()))
    }

    async fn collector_status(
        &self,
        _: Request<api::CollectorStatusRequest>,
    ) -> Result<Response<api::CollectorStatusResponse>, Status> {
        Err(Status::unimplemented("not yet"))
    }

    async fn restart_collector(
        &self,
        _: Request<api::RestartCollectorRequest>,
    ) -> Result<Response<()>, Status> {
        Err(Status::unimplemented("not yet"))
    }
}

pub async fn serve(addr: &str, storage: Arc<SqliteStorage>) -> anyhow::Result<()> {
    use tonic::transport::Server;
    tracing::info!("gRPC server starting on {addr}");

    let svc = SentinelService::new(storage);

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
        .serve(addr.parse()?)
        .await?;

    Ok(())
}

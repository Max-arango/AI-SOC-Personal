use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status, Streaming};
use tracing::info;

use sentinel_events::sentinel::mgmt::v1::agent_service_server::{AgentService, AgentServiceServer};
use sentinel_events::sentinel::mgmt::v1::{
    AgentEvent, CommandRequest, CommandResponse, HeartbeatRequest,
    HeartbeatResponse, RegisterRequest, RegisterResponse,
};

use crate::fleet::FleetManager;

pub struct MgmtService {
    fleet: Arc<FleetManager>,
}

impl MgmtService {
    pub fn new(fleet: Arc<FleetManager>) -> Self {
        Self { fleet }
    }
}

#[tonic::async_trait]
impl AgentService for MgmtService {
    async fn register(
        &self,
        req: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let r = req.into_inner();
        info!(
            "Agent registering: host_id={}, hostname={}, os={}",
            r.host_id, r.hostname, r.os
        );

        self.fleet.register(crate::fleet::RegisteredAgent {
            host_id: r.host_id.clone(),
            hostname: r.hostname,
            os: r.os,
            version: r.version,
            last_heartbeat: chrono::Utc::now(),
            status: crate::fleet::AgentStatus::Online,
            tags: r.tags,
        });

        Ok(Response::new(RegisterResponse {
            agent_id: r.host_id,
            server_version: env!("CARGO_PKG_VERSION").into(),
            heartbeat_interval_secs: 30,
        }))
    }

    async fn heartbeat(
        &self,
        req: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let r = req.into_inner();
        let found = self.fleet.heartbeat(&r.agent_id);
        Ok(Response::new(HeartbeatResponse {
            acknowledged: found,
            server_time_unix: chrono::Utc::now().timestamp(),
        }))
    }

    type StreamStream = tokio_stream::wrappers::ReceiverStream<
        Result<CommandRequest, Status>,
    >;

    async fn stream(
        &self,
        req: Request<Streaming<AgentEvent>>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        let mut inbound = req.into_inner();
        let fleet = self.fleet.clone();

        let (_tx, rx) = mpsc::channel(100);

        tokio::spawn(async move {
            while let Ok(Some(event)) = inbound.message().await {
                let agent_id = event.agent_id.clone();
                fleet.heartbeat(&agent_id);

                if event.event.is_some() {
                    info!(
                        "Received event from agent {}: type={:?}",
                        agent_id,
                        event.event.as_ref().map(|e| &e.r#type)
                    );
                }
            }
            info!("Agent stream ended");
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn send_command(
        &self,
        req: Request<CommandRequest>,
    ) -> Result<Response<CommandResponse>, Status> {
        let cmd = req.into_inner();
        info!(
            "Command received: id={}, agent={}",
            cmd.command_id, cmd.agent_id
        );

        Ok(Response::new(CommandResponse {
            command_id: cmd.command_id,
            success: false,
            message: "command routing not yet implemented".into(),
        }))
    }
}

pub async fn serve(addr: &str, fleet: Arc<FleetManager>) -> anyhow::Result<()> {
    use tonic::transport::Server;

    let svc = MgmtService::new(fleet);

    info!("Management gRPC server starting on {}", addr);

    Server::builder()
        .add_service(AgentServiceServer::new(svc))
        .serve(addr.parse()?)
        .await?;

    Ok(())
}

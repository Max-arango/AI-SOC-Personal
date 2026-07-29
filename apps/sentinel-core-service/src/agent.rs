use std::sync::Arc;
use sentinel_core::traits::EventBus;
use sentinel_events::sentinel::mgmt::v1::agent_service_client::AgentServiceClient;
use sentinel_events::sentinel::mgmt::v1::{
    AgentEvent, AgentStats, CommandRequest, HeartbeatRequest, RegisterRequest,
};
use tonic::transport::Channel;
use tracing::{info, warn};

pub struct AgentClient {
    server_addr: String,
    host_id: String,
    hostname: String,
    os: String,
    version: String,
    tags: Vec<String>,
    connected: tokio::sync::RwLock<bool>,
    events_processed: std::sync::atomic::AtomicU64,
    alerts_generated: std::sync::atomic::AtomicU64,
}

impl AgentClient {
    pub fn new(
        server_addr: String,
        host_id: String,
        hostname: String,
    ) -> Self {
        Self {
            server_addr,
            host_id,
            hostname,
            os: std::env::consts::OS.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            tags: vec![],
            connected: tokio::sync::RwLock::new(false),
            events_processed: std::sync::atomic::AtomicU64::new(0),
            alerts_generated: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    pub fn inc_events(&self, n: u64) {
        self.events_processed.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn inc_alerts(&self, n: u64) {
        self.alerts_generated.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }

    pub async fn connect_and_stream(
        &self,
        bus: Arc<dyn EventBus>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let addr = self.server_addr.clone();
        let host_id = self.host_id.clone();
        let hostname = self.hostname.clone();
        let os = self.os.clone();
        let version = self.version.clone();
        let tags = self.tags.clone();
        let events_count = &self.events_processed;
        let alerts_count = &self.alerts_generated;

        tokio::spawn(async move {
            loop {
                if *shutdown_rx.borrow() {
                    info!("Agent shutting down");
                    break;
                }

                info!("Agent connecting to management server at {}", addr);

                let mut client = match AgentServiceClient::connect(format!("http://{}", addr)).await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Failed to connect: {e}. Retrying in 10s...");
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        continue;
                    }
                };

                let register_req = tonic::Request::new(RegisterRequest {
                    host_id: host_id.clone(),
                    hostname: hostname.clone(),
                    os: os.clone(),
                    version: version.clone(),
                    tags: tags.clone(),
                });

                match client.register(register_req).await {
                    Ok(resp) => {
                        info!("Agent registered: agent_id={}, heartbeat_interval={}s",
                            resp.into_inner().agent_id,
                            resp.into_inner().heartbeat_interval_secs);
                    }
                    Err(e) => {
                        warn!("Registration failed: {e}. Retrying...");
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        continue;
                    }
                }

                let mut stream = match client.stream(tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new({
                    let (tx, rx) = tokio::sync::mpsc::channel(100);
                    let bus_clone = bus.clone();
                    let host_id_clone = host_id.clone();
                    tokio::spawn(async move {
                        let mut event_sub = match bus_clone.subscribe_type("*").await {
                            Ok(s) => s,
                            Err(_) => return,
                        };
                        while let Some(event) = event_sub.receiver.recv().await {
                            let _ = tx.send(AgentEvent {
                                agent_id: host_id_clone.clone(),
                                event: Some((*event).clone()),
                            }).await;
                        }
                    });
                    rx
                }))).await
                {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Stream failed: {e}. Reconnecting...");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }
                };

                let mut stream_inner = stream.into_inner();

                let mut heartbeat_interval = tokio::time::interval(std::time::Duration::from_secs(30));

                loop {
                    tokio::select! {
                        _ = heartbeat_interval.tick() => {
                            let stats = AgentStats {
                                events_processed: events_count.load(std::sync::atomic::Ordering::Relaxed),
                                alerts_generated: alerts_count.load(std::sync::atomic::Ordering::Relaxed),
                                rules_evaluated: 0,
                                cpu_percent: 0.0,
                                memory_bytes: 0,
                                event_queue_depth: 0,
                            };

                            let hb_req = tonic::Request::new(HeartbeatRequest {
                                agent_id: host_id.clone(),
                                stats: Some(stats),
                            });

                            match client.heartbeat(hb_req).await {
                                Ok(_) => {
                                    debug!("Heartbeat sent");
                                }
                                Err(e) => {
                                    warn!("Heartbeat failed: {e}");
                                    break;
                                }
                            }
                        }

                        cmd = stream_inner.message() => {
                            match cmd {
                                Ok(Some(command)) => {
                                    info!("Received command: id={}", command.command_id);
                                }
                                Ok(None) => {
                                    info!("Server closed stream");
                                    break;
                                }
                                Err(e) => {
                                    warn!("Stream error: {e}");
                                    break;
                                }
                            }
                        }

                        Ok(()) = shutdown_rx.changed() => {
                            info!("Agent shutdown signal received");
                            break;
                        }
                    }
                }

                warn!("Agent disconnected. Reconnecting in 10s...");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });

        Ok(())
    }

    pub fn server_addr(&self) -> &str {
        &self.server_addr
    }

    pub fn host_id(&self) -> &str {
        &self.host_id
    }
}

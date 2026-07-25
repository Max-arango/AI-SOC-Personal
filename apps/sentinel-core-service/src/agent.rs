use std::sync::Arc;
use sentinel_core::traits::EventBus;
use sentinel_events::sentinel::mgmt::v1::agent_service_client::AgentServiceClient;
use sentinel_events::sentinel::mgmt::v1::AgentEvent;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub struct AgentClient {
    server_addr: String,
    host_id: String,
    hostname: String,
    os: String,
    version: String,
    tags: Vec<String>,
    connected: tokio::sync::RwLock<bool>,
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
        }
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    pub async fn connect_and_stream(
        &self,
        bus: Arc<dyn EventBus>,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let addr = self.server_addr.clone();
        let host_id = self.host_id.clone();
        let hostname = self.hostname.clone();
        let os = self.os.clone();
        let version = self.version.clone();
        let tags = self.tags.clone();

        tokio::spawn(async move {
            loop {
                info!("Agent connecting to management server at {}", addr);

                let client = match AgentServiceClient::connect(format!("http://{}", addr)).await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Failed to connect to mgmt server: {e}. Retrying in 10s...");
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        continue;
                    }
                };

                info!("Agent connected to management server");

                // TODO: full bidirectional streaming + heartbeat loop
                // For now, register and keep connection alive

                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
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

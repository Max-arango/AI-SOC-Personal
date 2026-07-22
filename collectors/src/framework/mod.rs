//! Sentinel AI Collector Framework
//!
//! Base traits and infrastructure for event collectors.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::sync::{mpsc, watch};
use tracing::info;

use sentinel_core::{
    traits::{Collector, CollectorContext, CollectorHealth, CollectorMetrics, CollectorState, EventBus, OsAbstraction},
    BackpressureSignal, ConfigProvider as ConfigProviderTrait, Result as CoreResult, SentinelError,
};
use sentinel_events::Event;

/// Collector manager for lifecycle management
#[allow(dead_code)]
pub struct CollectorManager {
    collectors: RwLock<HashMap<String, Box<dyn Collector>>>,
    contexts: RwLock<HashMap<String, CollectorContext>>,
    #[allow(dead_code)]
    event_bus: Arc<dyn EventBus>,
    config: Arc<dyn ConfigProviderTrait>,
    os: Arc<dyn OsAbstraction>,
    metrics: Arc<CollectorMetricsRegistry>,
    backpressure_rx: watch::Receiver<BackpressureSignal>,
}

#[allow(clippy::await_holding_lock)]
impl CollectorManager {
    /// Create new collector manager
    pub fn new(
        event_bus: Arc<dyn EventBus>,
        config: Arc<dyn ConfigProviderTrait>,
        os: Arc<dyn OsAbstraction>,
        metrics: Arc<CollectorMetricsRegistry>,
        backpressure_rx: watch::Receiver<BackpressureSignal>,
    ) -> Self {
        Self {
            collectors: RwLock::new(HashMap::new()),
            contexts: RwLock::new(HashMap::new()),
            event_bus,
            config,
            os,
            metrics,
            backpressure_rx,
        }
    }
    
    /// Register a collector
    pub async fn register(&self, mut collector: Box<dyn Collector>) -> Result<()> {
        let id = collector.id().to_string();
        
        // Create context with a forwarding task that bridges the collector
        // output channel into the shared event bus.
        let (event_tx, mut event_rx) = mpsc::channel(1000);
        {
            let bus = self.event_bus.clone();
            tokio::spawn(async move {
                while let Some(event) = event_rx.recv().await {
                    let _ = bus.publish(event).await;
                }
            });
        }
        let context = CollectorContext {
            event_tx,
            backpressure_rx: self.backpressure_rx.clone(),
            config: self.config.clone(),
            os: self.os.clone(),
            metrics: self.metrics.for_collector(&id),
        };
        
        // Initialize collector
        collector.start(context.clone()).await
            .map_err(|e| anyhow::anyhow!("Failed to start collector {}: {}", id, e))?;
        
        self.collectors.write().insert(id.clone(), collector);
        self.contexts.write().insert(id.clone(), context);
        
        info!("Registered collector: {}", id);
        Ok(())
    }
    
    /// Unregister a collector
    pub async fn unregister(&self, id: &str) -> Result<()> {
        if let Some(mut collector) = self.collectors.write().remove(id) {
            collector.stop(true).await?;
            self.contexts.write().remove(id);
            info!("Unregistered collector: {}", id);
        }
        Ok(())
    }
    
    /// Restart a collector
    pub async fn restart(&self, id: &str) -> Result<()> {
        let mut collectors = self.collectors.write();
        if let Some(mut collector) = collectors.remove(id) {
            collector.stop(true).await?;
            
            let (event_tx, mut event_rx) = mpsc::channel(1000);
            {
                let bus = self.event_bus.clone();
                tokio::spawn(async move {
                    while let Some(event) = event_rx.recv().await {
                        let _ = bus.publish(event).await;
                    }
                });
            }
            let context = CollectorContext {
                event_tx,
                backpressure_rx: self.backpressure_rx.clone(),
                config: self.config.clone(),
                os: self.os.clone(),
                metrics: self.metrics.for_collector(id),
            };
            
            collector.start(context.clone()).await
                .map_err(|e| anyhow::anyhow!("Failed to restart collector {}: {}", id, e))?;
            
            collectors.insert(id.to_string(), collector);
            self.contexts.write().insert(id.to_string(), context);
            info!("Restarted collector: {}", id);
        }
        Ok(())
    }
    
    /// Get collector health
    pub async fn health(&self, id: &str) -> Option<CollectorHealth> {
        match self.collectors.read().get(id) {
            Some(c) => Some(c.health().await),
            None => None,
        }
    }
    
    /// Get all collector health
    pub async fn all_health(&self) -> HashMap<String, CollectorHealth> {
        let mut health = HashMap::new();
        for (id, c) in self.collectors.read().iter() {
            health.insert(id.clone(), c.health().await);
        }
        health
    }
    
    /// Reconfigure a collector
    pub async fn reconfigure(&self, id: &str, config: serde_json::Value) -> Result<()> {
        if let Some(collector) = self.collectors.write().get_mut(id) {
            collector.reconfigure(config).await.map_err(|e| anyhow::anyhow!(e.to_string()))
        } else {
            Err(anyhow::anyhow!("Collector not found: {}", id))
        }
    }
    
    /// Get collector list
    pub fn list(&self) -> Vec<String> {
        self.collectors.read().keys().cloned().collect()
    }
}

/// Metrics registry for collectors
pub struct CollectorMetricsRegistry {
    metrics: RwLock<HashMap<String, CollectorMetrics>>,
}

impl CollectorMetricsRegistry {
    pub fn new() -> Self {
        Self { metrics: RwLock::new(HashMap::new()) }
    }
    
    pub fn for_collector(&self, id: &str) -> CollectorMetrics {
        self.metrics.read().get(id).cloned().unwrap_or_default()
    }
    
    pub fn register(&self, id: String, metrics: CollectorMetrics) {
        self.metrics.write().insert(id, metrics);
    }
}

impl Default for CollectorMetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Base collector implementation
pub struct BaseCollector {
    id: String,
    name: String,
    description: String,
    event_types: Vec<String>,
    required_capabilities: Vec<String>,
    config_schema: sentinel_core::traits::ConfigSchema,
    state: RwLock<CollectorState>,
    health: RwLock<CollectorHealth>,
    metrics: RwLock<CollectorMetrics>,
    event_tx: Option<mpsc::Sender<Arc<Event>>>,
    backpressure_rx: Option<watch::Receiver<BackpressureSignal>>,
}

impl BaseCollector {
    pub fn new(
        id: String,
        name: String,
        description: String,
        event_types: Vec<String>,
        required_capabilities: Vec<String>,
        config_schema: sentinel_core::traits::ConfigSchema,
    ) -> Self {
        Self {
            id,
            name,
            description,
            event_types,
            required_capabilities,
            config_schema,
            state: RwLock::new(CollectorState::Stopped),
            health: RwLock::new(CollectorHealth {
                state: CollectorState::Stopped,
                message: None,
                last_event: None,
                events_per_sec: 0.0,
                error_rate: 0.0,
            }),
            metrics: RwLock::new(CollectorMetrics::default()),
            event_tx: None,
            backpressure_rx: None,
        }
    }
    
    /// Publish an event
    pub async fn publish(&self, event: Arc<Event>) -> CoreResult<()> {
        if let Some(tx) = &self.event_tx {
            tx.send(event).await
                .map_err(|_| SentinelError::EventBus(sentinel_core::EventBusError::ChannelFull("Channel closed".to_string())))?;
            self.metrics.write().events_produced += 1;
        }
        Ok(())
    }
    
    /// Check backpressure and adjust rate
    pub fn check_backpressure(&self) -> BackpressureSignal {
        self.backpressure_rx.as_ref()
            .map(|rx| *rx.borrow())
            .unwrap_or(BackpressureSignal::Normal)
    }
    
    /// Update health status
    pub fn update_health(&self, state: CollectorState, message: Option<String>) {
        let metrics = self.metrics.read();
        *self.health.write() = CollectorHealth {
            state,
            message,
            last_event: Some(chrono::Utc::now()),
            events_per_sec: metrics.events_produced as f64,
            error_rate: if metrics.events_produced > 0 {
                metrics.errors as f64 / metrics.events_produced as f64
            } else {
                0.0
            },
        };
    }
}

#[async_trait]
impl Collector for BaseCollector {
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
        self.event_types.iter().map(|s| s.as_str()).collect()
    }
    
    fn required_capabilities(&self) -> Vec<String> {
        self.required_capabilities.clone()
    }
    
    fn config_schema(&self) -> sentinel_core::traits::ConfigSchema {
        self.config_schema.clone()
    }
    
    async fn start(&mut self, ctx: CollectorContext) -> CoreResult<()> {
        self.event_tx = Some(ctx.event_tx);
        self.backpressure_rx = Some(ctx.backpressure_rx);
        *self.state.write() = CollectorState::Starting;
        self.update_health(CollectorState::Starting, None);

        // Start collection logic
        self.do_start().await?;

        *self.state.write() = CollectorState::Running;
        self.update_health(CollectorState::Running, Some("Started successfully".into()));
        Ok(())
    }

    async fn stop(&mut self, graceful: bool) -> CoreResult<()> {
        *self.state.write() = CollectorState::Stopped;
        self.update_health(CollectorState::Stopped, Some("Stopped".into()));
        self.do_stop(graceful).await
    }
    
    async fn health(&self) -> CollectorHealth {
        self.health.read().clone()
    }
    
    async fn reconfigure(&mut self, config: serde_json::Value) -> CoreResult<()> {
        self.do_reconfigure(config).await
    }
}

#[async_trait]
impl CollectorImpl for BaseCollector {
    async fn do_start(&mut self) -> CoreResult<()> {
        Ok(())
    }

    async fn do_stop(&mut self, _graceful: bool) -> CoreResult<()> {
        Ok(())
    }

    async fn do_reconfigure(&mut self, _config: serde_json::Value) -> CoreResult<()> {
        Ok(())
    }
}

/// Extension trait for collector-specific logic
#[async_trait]
pub trait CollectorImpl: Send + Sync {
    async fn do_start(&mut self) -> CoreResult<()>;
    async fn do_stop(&mut self, graceful: bool) -> CoreResult<()>;
    async fn do_reconfigure(&mut self, config: serde_json::Value) -> CoreResult<()>;
}
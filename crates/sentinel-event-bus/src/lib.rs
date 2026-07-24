//! In-memory event bus implementation for Sentinel AI.
//!
//! This module provides a high-performance, thread-safe event bus that routes
//! events to subscribers based on configurable filters. It supports backpressure
//! signaling and runtime statistics.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::sync::{mpsc, watch};
use tokio::time::interval;
use tracing::{error, info};

use sentinel_core::{
    BackpressureConfig, BackpressureSignal, ChannelConfig, EventBus, EventBusStats, EventFilter,
    EventSubscription, Result as CoreResult, SentinelError,
};
use sentinel_events::Event;

/// Default backpressure configuration used by the monitor when none is supplied.
fn default_backpressure() -> BackpressureConfig {
    BackpressureConfig { elevated: 50, high: 75, critical: 90 }
}

/// Internal statistics backed by atomics for lock-free updates.
#[derive(Default)]
struct BusStats {
    events_published: AtomicU64,
    events_dropped: AtomicU64,
    ingest_queue_depth: AtomicUsize,
    active_subscriptions: AtomicUsize,
}

/// A subscribed receiver together with the filter it subscribed with.
#[derive(Clone)]
struct Subscriber {
    filter: EventFilter,
    sender: mpsc::Sender<Arc<Event>>,
}

/// Routes events to the set of subscribers whose filter matches.
struct TopicRouter {
    subscribers: RwLock<HashMap<String, Vec<Subscriber>>>,
    wildcard_subscribers: RwLock<Vec<Subscriber>>,
    stats: Arc<BusStats>,
}

impl TopicRouter {
    fn new(stats: Arc<BusStats>) -> Self {
        Self {
            subscribers: RwLock::new(HashMap::new()),
            wildcard_subscribers: RwLock::new(Vec::new()),
            stats,
        }
    }

    async fn route(&self, event: Arc<Event>) -> Result<()> {
        let event_type = &event.r#type;
        let exact = {
            let subs = self.subscribers.read();
            subs.get(event_type).cloned().unwrap_or_default()
        };
        let wildcard = self.wildcard_subscribers.read().clone();
        let targets: Vec<Subscriber> = exact
            .into_iter()
            .chain(wildcard)
            .filter(|s| Self::matches_filter(&s.filter, &event))
            .collect();

        for sub in targets {
            if sub.sender.send(event.clone()).await.is_err() {
                self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn matches_filter(filter: &EventFilter, event: &Event) -> bool {
        if let Some(types) = &filter.event_types {
            if !types.iter().any(|t| t == &event.r#type || t == "*") {
                return false;
            }
        }
        if let Some(sources) = &filter.sources {
            if !sources.iter().any(|s| s == &event.source || s == "*") {
                return false;
            }
        }
        if let Some(min_sev) = filter.min_severity {
            if (event.severity as u8) < (min_sev as u8) {
                return false;
            }
        }
        if let Some(process_names) = &filter.process_names {
            match &event.process {
                Some(proc) if process_names.iter().any(|n| n == &proc.name || n == "*") => {},
                _ => return false,
            }
        }
        if let Some(cid) = &filter.correlation_id {
            match &event.correlation {
                Some(c) if &c.correlation_id == cid => {},
                _ => return false,
            }
        }
        if let Some(fid) = &filter.flow_id {
            match &event.correlation {
                Some(c) if &c.flow_id == fid => {},
                _ => return false,
            }
        }
        if let Some(min_risk) = filter.min_risk_score {
            if event.risk_score < min_risk {
                return false;
            }
        }
        true
    }

    async fn subscribe(
        &self,
        filter: &EventFilter,
        sender: mpsc::Sender<Arc<Event>>,
    ) -> Result<()> {
        let subscriber = Subscriber { filter: filter.clone(), sender };
        match &filter.event_types {
            Some(event_types) => {
                for et in event_types {
                    if et == "*" || et.ends_with('*') {
                        self.wildcard_subscribers.write().push(subscriber.clone());
                    } else {
                        self.subscribers
                            .write()
                            .entry(et.clone())
                            .or_default()
                            .push(subscriber.clone());
                    }
                }
            },
            None => {
                self.wildcard_subscribers.write().push(subscriber);
            },
        }
        self.stats
            .active_subscriptions
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// The event bus implementation.
pub struct EventBusImpl {
    config: ChannelConfig,
    ingest_tx: mpsc::Sender<Arc<Event>>,
    ingest_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Arc<Event>>>>,
    router: Arc<TopicRouter>,
    backpressure_tx: watch::Sender<BackpressureSignal>,
    _backpressure_rx: watch::Receiver<BackpressureSignal>,
    stats: Arc<BusStats>,
    shutdown_tx: watch::Sender<()>,
    shutdown_rx: watch::Receiver<()>,
    ingest_depth: Arc<AtomicUsize>,
}

impl EventBusImpl {
    /// Create a new event bus with the given channel configuration.
    pub fn new(config: ChannelConfig) -> Self {
        let (ingest_tx, ingest_rx) = mpsc::channel(config.ingest.max(1));
        let (backpressure_tx, backpressure_rx) = watch::channel(BackpressureSignal::Normal);
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let stats = Arc::new(BusStats::default());
        let router = Arc::new(TopicRouter::new(stats.clone()));
        let ingest_depth = Arc::new(AtomicUsize::new(0));
        Self {
            config,
            ingest_tx,
            ingest_rx: Arc::new(tokio::sync::Mutex::new(ingest_rx)),
            router,
            backpressure_tx,
            _backpressure_rx: backpressure_rx,
            stats,
            shutdown_tx,
            shutdown_rx,
            ingest_depth,
        }
    }

    /// Get a sender for publishing events to the ingest channel.
    pub fn ingest_sender(&self) -> mpsc::Sender<Arc<Event>> {
        self.ingest_tx.clone()
    }

    /// Get a receiver for backpressure signals.
    pub fn backpressure_receiver(&self) -> watch::Receiver<BackpressureSignal> {
        self._backpressure_rx.clone()
    }

    /// Run the event bus processing loop until shutdown.
    ///
    /// This borrows `&self` (not `self`) so the same bus instance can be shared
    /// via `Arc` and keep accepting `publish`/`subscribe` calls while the
    /// routing loop runs in a spawned task.
    pub async fn run(&self) -> Result<()> {
        info!("Starting event bus");
        let backpressure_monitor = self.start_backpressure_monitor();
        let mut shutdown_rx = self.shutdown_rx.clone();
        let process_loop = self.process_events();

        tokio::select! {
            _ = backpressure_monitor => info!("Backpressure monitor stopped"),
            _ = process_loop => info!("Event processing loop stopped"),
            _ = shutdown_rx.changed() => info!("Shutdown signal received"),
        }

        Ok(())
    }

    async fn process_events(&self) {
        let mut ingest_rx = self.ingest_rx.lock().await;
        while let Some(event) = ingest_rx.recv().await {
            self.stats.events_published.fetch_add(1, Ordering::Relaxed);
            self.ingest_depth.fetch_sub(1, Ordering::Relaxed);
            if let Err(e) = self.router.route(event).await {
                error!("Failed to route event: {}", e);
                self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        info!("Ingest channel closed, event bus stopping");
    }

    fn start_backpressure_monitor(&self) -> tokio::task::JoinHandle<()> {
        let ingest_tx = self.ingest_tx.clone();
        let backpressure_tx = self.backpressure_tx.clone();
        let bp = default_backpressure();
        let capacity = self.config.ingest.max(1);
        let stats = self.stats.clone();
        let depth = self.ingest_depth.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(100));
            loop {
                ticker.tick().await;
                let d = depth.load(Ordering::Relaxed);
                stats.ingest_queue_depth.store(d, Ordering::Relaxed);
                let usage =
                    if capacity > 0 { ((d as u64 * 100) / capacity as u64) as u8 } else { 0 };
                let signal = if usage >= bp.critical {
                    BackpressureSignal::Critical
                } else if usage >= bp.high {
                    BackpressureSignal::High
                } else if usage >= bp.elevated {
                    BackpressureSignal::Elevated
                } else {
                    BackpressureSignal::Normal
                };
                let _ = backpressure_tx.send(signal);
                let _ = ingest_tx; // keep the sender alive for the task lifetime
            }
        })
    }

    /// Signal the event bus to shut down.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

#[async_trait]
impl EventBus for EventBusImpl {
    async fn publish(&self, event: Arc<Event>) -> CoreResult<()> {
        self.ingest_depth.fetch_add(1, Ordering::Relaxed);
        self.ingest_tx.send(event).await.map_err(|_| {
            SentinelError::EventBus(sentinel_core::EventBusError::ChannelFull(
                "ingest closed".into(),
            ))
        })?;
        Ok(())
    }

    async fn subscribe(&self, filter: EventFilter) -> CoreResult<EventSubscription> {
        let (tx, rx) = mpsc::channel(1000);
        self.router.subscribe(&filter, tx).await.map_err(|e| {
            SentinelError::EventBus(sentinel_core::EventBusError::Subscription(e.to_string()))
        })?;
        Ok(EventSubscription { receiver: rx, filter })
    }

    async fn subscribe_type(&self, event_type: &str) -> CoreResult<EventSubscription> {
        let filter =
            EventFilter { event_types: Some(vec![event_type.to_string()]), ..Default::default() };
        self.subscribe(filter).await
    }

    fn backpressure(&self) -> BackpressureSignal {
        *self.backpressure_tx.subscribe().borrow()
    }

    fn stats(&self) -> EventBusStats {
        EventBusStats {
            ingest_queue_depth: self.stats.ingest_queue_depth.load(Ordering::Relaxed),
            broadcast_queue_depths: vec![],
            storage_queue_depth: 0,
            plugin_queue_depth: 0,
            ipc_queue_depth: 0,
            events_published: self.stats.events_published.load(Ordering::Relaxed),
            events_dropped: self.stats.events_dropped.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_type: &str, severity: sentinel_core::Severity) -> Arc<Event> {
        Arc::new(Event {
            id: "test-id".to_string(),
            r#type: event_type.to_string(),
            source: "test".to_string(),
            timestamp: None,
            ingest_timestamp: None,
            severity: severity as i32,
            process: None,
            payload: None,
            tags: vec![],
            metadata: None,
            risk_score: 0,
            correlation: None,
            host_id: "host-1".to_string(),
            schema_version: 1,
        })
    }

    /// Spawn the routing loop of a shared bus and return the handle plus a
    /// shutdown guard that stops the loop when dropped.
    fn spawn_bus() -> (Arc<EventBusImpl>, tokio::task::JoinHandle<()>) {
        let bus = Arc::new(EventBusImpl::new(ChannelConfig::default()));
        let runner = bus.clone();
        let handle = tokio::spawn(async move {
            let _ = runner.run().await;
        });
        (bus, handle)
    }

    #[tokio::test]
    async fn test_publish_subscribe() {
        let (bus, handle) = spawn_bus();
        let mut sub = bus.subscribe_type("*").await.unwrap();

        let event = make_event("process.create", sentinel_core::Severity::Info);
        bus.publish(event.clone()).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), sub.receiver.recv())
            .await
            .expect("timed out waiting for routed event")
            .unwrap();
        assert_eq!(received.r#type, "process.create");

        bus.shutdown();
        handle.abort();
    }

    #[tokio::test]
    async fn test_event_filter() {
        let (bus, handle) = spawn_bus();
        let mut filter = EventFilter::default();
        filter.event_types = Some(vec!["process.create".to_string()]);
        let mut sub = bus.subscribe(filter).await.unwrap();

        let matching = make_event("process.create", sentinel_core::Severity::Warning);
        let non_matching = make_event("file.write", sentinel_core::Severity::Warning);

        bus.publish(non_matching).await.unwrap();
        bus.publish(matching).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), sub.receiver.recv())
            .await
            .expect("timed out waiting for routed event")
            .unwrap();
        assert_eq!(received.r#type, "process.create");

        bus.shutdown();
        handle.abort();
    }
}

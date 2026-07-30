//! Metrics infrastructure for Sentinel AI

use parking_lot::RwLock;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge, histogram::Histogram};
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::sync::Arc;

/// Global metrics registry
pub struct MetricsRegistry {
    registry: Arc<RwLock<Registry>>,
    collectors: RwLock<HashMap<String, Box<dyn Collector>>>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            registry: Arc::new(RwLock::new(Registry::default())),
            collectors: RwLock::new(HashMap::new()),
        }
    }

    pub fn registry(&self) -> Arc<RwLock<Registry>> {
        self.registry.clone()
    }

    pub fn register_collector(&self, name: String, collector: Box<dyn Collector>) {
        self.collectors.write().insert(name, collector);
    }

    pub fn unregister_collector(&self, name: &str) {
        self.collectors.write().remove(name);
    }

    pub fn gather(&self) -> String {
        let mut buffer = String::new();
        encode(&mut buffer, &self.registry.read()).expect("Prometheus encode failed");
        buffer
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for custom metric collectors
pub trait Collector: Send + Sync {
    fn collect(&self, registry: &mut Registry);
}

/// Counter metric builder
pub struct CounterBuilder {
    name: String,
    help: String,
    labels: Vec<(String, String)>,
}

impl CounterBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), help: String::new(), labels: vec![] }
    }

    pub fn help(mut self, help: impl Into<String>) -> Self {
        self.help = help.into();
        self
    }

    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push((key.into(), value.into()));
        self
    }

    pub fn build(self, registry: &MetricsRegistry) -> Counter {
        let counter = Counter::default();
        let mut reg = registry.registry.write();
        reg.register(self.name.clone(), self.help.clone(), counter.clone());
        counter
    }
}

/// Gauge metric builder
pub struct GaugeBuilder {
    name: String,
    help: String,
    labels: Vec<(String, String)>,
}

impl GaugeBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), help: String::new(), labels: vec![] }
    }

    pub fn help(mut self, help: impl Into<String>) -> Self {
        self.help = help.into();
        self
    }

    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push((key.into(), value.into()));
        self
    }

    pub fn build(self, registry: &MetricsRegistry) -> Gauge {
        let gauge = Gauge::default();
        let mut reg = registry.registry.write();
        reg.register(self.name.clone(), self.help.clone(), gauge.clone());
        gauge
    }
}

/// Histogram metric builder
pub struct HistogramBuilder {
    name: String,
    help: String,
    buckets: Vec<f64>,
    labels: Vec<(String, String)>,
}

impl HistogramBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: String::new(),
            buckets: vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            labels: vec![],
        }
    }

    pub fn help(mut self, help: impl Into<String>) -> Self {
        self.help = help.into();
        self
    }

    pub fn buckets(mut self, buckets: Vec<f64>) -> Self {
        self.buckets = buckets;
        self
    }

    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push((key.into(), value.into()));
        self
    }

    pub fn build(self, registry: &MetricsRegistry) -> Histogram {
        let histogram = Histogram::new(self.buckets.into_iter());
        let mut reg = registry.registry.write();
        reg.register(self.name.clone(), self.help.clone(), histogram.clone());
        histogram
    }
}

/// Common metrics for all modules
pub struct ModuleMetrics {
    pub events_processed: Counter,
    pub events_dropped: Counter,
    pub errors: Counter,
    pub processing_time: Histogram,
    pub queue_depth: Gauge,
    pub memory_usage: Gauge,
    pub cpu_usage: Gauge,
}

impl ModuleMetrics {
    pub fn new(registry: &MetricsRegistry, module_name: &str) -> Self {
        let prefix = format!("sentinel_{}", module_name.replace('-', "_"));

        Self {
            events_processed: CounterBuilder::new(format!("{}_events_processed_total", prefix))
                .help("Total number of events processed")
                .build(registry),
            events_dropped: CounterBuilder::new(format!("{}_events_dropped_total", prefix))
                .help("Total number of events dropped due to backpressure")
                .build(registry),
            errors: CounterBuilder::new(format!("{}_errors_total", prefix))
                .help("Total number of errors")
                .build(registry),
            processing_time: HistogramBuilder::new(format!("{}_processing_time_seconds", prefix))
                .help("Event processing time in seconds")
                .build(registry),
            queue_depth: GaugeBuilder::new(format!("{}_queue_depth", prefix))
                .help("Current event queue depth")
                .build(registry),
            memory_usage: GaugeBuilder::new(format!("{}_memory_bytes", prefix))
                .help("Memory usage in bytes")
                .build(registry),
            cpu_usage: GaugeBuilder::new(format!("{}_cpu_percent", prefix))
                .help("CPU usage percentage")
                .build(registry),
        }
    }
}

/// Collector-specific metrics
pub struct CollectorMetrics {
    pub events_produced: Counter,
    pub events_dropped: Counter,
    pub errors: Counter,
    pub avg_latency_ms: Gauge,
    pub cpu_percent: Gauge,
    pub memory_bytes: Gauge,
}

impl CollectorMetrics {
    pub fn new(registry: &MetricsRegistry, collector_id: &str) -> Self {
        let prefix = format!("sentinel_collector_{}", collector_id.replace('-', "_"));

        Self {
            events_produced: CounterBuilder::new(format!("{}_events_produced_total", prefix))
                .help("Total events produced by this collector")
                .build(registry),
            events_dropped: CounterBuilder::new(format!("{}_events_dropped_total", prefix))
                .help("Total events dropped by this collector")
                .build(registry),
            errors: CounterBuilder::new(format!("{}_errors_total", prefix))
                .help("Total errors in this collector")
                .build(registry),
            avg_latency_ms: GaugeBuilder::new(format!("{}_avg_latency_ms", prefix))
                .help("Average event processing latency in milliseconds")
                .build(registry),
            cpu_percent: GaugeBuilder::new(format!("{}_cpu_percent", prefix))
                .help("CPU usage percentage")
                .build(registry),
            memory_bytes: GaugeBuilder::new(format!("{}_memory_bytes", prefix))
                .help("Memory usage in bytes")
                .build(registry),
        }
    }
}

/// Rule engine metrics
pub struct RuleEngineMetrics {
    pub rules_loaded: Gauge,
    pub rules_enabled: Gauge,
    pub evaluations_total: Counter,
    pub matches_total: Counter,
    pub evaluation_time: Histogram,
}

impl RuleEngineMetrics {
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            rules_loaded: GaugeBuilder::new("sentinel_rule_engine_rules_loaded")
                .help("Number of loaded rules")
                .build(registry),
            rules_enabled: GaugeBuilder::new("sentinel_rule_engine_rules_enabled")
                .help("Number of enabled rules")
                .build(registry),
            evaluations_total: CounterBuilder::new("sentinel_rule_engine_evaluations_total")
                .help("Total rule evaluations")
                .build(registry),
            matches_total: CounterBuilder::new("sentinel_rule_engine_matches_total")
                .help("Total rule matches")
                .build(registry),
            evaluation_time: HistogramBuilder::new("sentinel_rule_engine_evaluation_seconds")
                .help("Rule evaluation time in seconds")
                .build(registry),
        }
    }
}

/// Correlation engine metrics
pub struct CorrelationMetrics {
    pub active_chains: Gauge,
    pub events_correlated: Counter,
    pub chains_detected: Counter,
    pub chain_length: Histogram,
}

impl CorrelationMetrics {
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            active_chains: GaugeBuilder::new("sentinel_correlation_active_chains")
                .help("Number of active correlation chains")
                .build(registry),
            events_correlated: CounterBuilder::new("sentinel_correlation_events_correlated_total")
                .help("Total events correlated")
                .build(registry),
            chains_detected: CounterBuilder::new("sentinel_correlation_chains_detected_total")
                .help("Total attack chains detected")
                .build(registry),
            chain_length: HistogramBuilder::new("sentinel_correlation_chain_length")
                .help("Length of detected chains")
                .build(registry),
        }
    }
}

/// Risk engine metrics
pub struct RiskMetrics {
    pub current_risk: Gauge,
    pub peak_risk_24h: Gauge,
    pub alerts_generated: Counter,
    pub alerts_escalated: Counter,
    pub alerts_suppressed: Counter,
}

impl RiskMetrics {
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            current_risk: GaugeBuilder::new("sentinel_risk_current_score")
                .help("Current aggregate risk score")
                .build(registry),
            peak_risk_24h: GaugeBuilder::new("sentinel_risk_peak_24h")
                .help("Peak risk score in last 24 hours")
                .build(registry),
            alerts_generated: CounterBuilder::new("sentinel_risk_alerts_generated_total")
                .help("Total alerts generated")
                .build(registry),
            alerts_escalated: CounterBuilder::new("sentinel_risk_alerts_escalated_total")
                .help("Total alerts escalated")
                .build(registry),
            alerts_suppressed: CounterBuilder::new("sentinel_risk_alerts_suppressed_total")
                .help("Total alerts suppressed (flapping)")
                .build(registry),
        }
    }
}

/// AI engine metrics
pub struct AiMetrics {
    pub requests_total: Counter,
    pub request_latency: Histogram,
    pub tokens_used: Counter,
    pub errors: Counter,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
}

impl AiMetrics {
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            requests_total: CounterBuilder::new("sentinel_ai_requests_total")
                .help("Total AI requests")
                .build(registry),
            request_latency: HistogramBuilder::new("sentinel_ai_request_latency_seconds")
                .help("AI request latency in seconds")
                .build(registry),
            tokens_used: CounterBuilder::new("sentinel_ai_tokens_used_total")
                .help("Total tokens used")
                .build(registry),
            errors: CounterBuilder::new("sentinel_ai_errors_total")
                .help("Total AI errors")
                .build(registry),
            cache_hits: CounterBuilder::new("sentinel_ai_cache_hits_total")
                .help("Total cache hits")
                .build(registry),
            cache_misses: CounterBuilder::new("sentinel_ai_cache_misses_total")
                .help("Total cache misses")
                .build(registry),
        }
    }
}

/// Plugin metrics
pub struct PluginMetrics {
    pub plugins_loaded: Gauge,
    pub plugins_running: Gauge,
    pub plugin_errors: Counter,
    pub action_calls: Counter,
    pub action_latency: Histogram,
}

impl PluginMetrics {
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            plugins_loaded: GaugeBuilder::new("sentinel_plugins_loaded")
                .help("Number of loaded plugins")
                .build(registry),
            plugins_running: GaugeBuilder::new("sentinel_plugins_running")
                .help("Number of running plugins")
                .build(registry),
            plugin_errors: CounterBuilder::new("sentinel_plugin_errors_total")
                .help("Total plugin errors")
                .build(registry),
            action_calls: CounterBuilder::new("sentinel_plugin_action_calls_total")
                .help("Total plugin action calls")
                .build(registry),
            action_latency: HistogramBuilder::new("sentinel_plugin_action_latency_seconds")
                .help("Plugin action latency in seconds")
                .build(registry),
        }
    }
}

/// Snapshot of metrics for health checks
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub modules: HashMap<String, ModuleMetricsSnapshot>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ModuleMetricsSnapshot {
    pub events_processed: u64,
    pub events_dropped: u64,
    pub errors: u64,
    pub avg_processing_time_ms: f64,
    pub queue_depth: i64,
    pub memory_bytes: u64,
    pub cpu_percent: f64,
}

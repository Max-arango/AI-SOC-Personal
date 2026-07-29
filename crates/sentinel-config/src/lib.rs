//! Sentinel AI Configuration Management
//!
//! Handles loading, validation, hot-reload, and secrets management for TOML configuration.

pub mod migration;
pub mod schema;
pub mod secrets;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwap;
use config::{Config, Environment, File, FileFormat};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tracing::{error, info};
use validator::Validate;

use async_trait::async_trait;
use sentinel_core::{
    BackpressureConfig, ConfigError as CoreConfigError, ConfigProvider, ConfigSchema, ConfigValue,
    ConfigWatcher, Result as CoreResult, RetentionPolicy, SentinelError,
};

/// Main configuration manager
pub struct ConfigManager {
    config: Arc<ArcSwap<AppConfig>>,
    #[allow(dead_code)]
    watcher: Option<RecommendedWatcher>,
    #[allow(dead_code)]
    watch_tx: watch::Sender<()>,
    #[allow(dead_code)]
    schema_registry: SchemaRegistry,
    secrets_manager: secrets::SecretsManager,
    config_paths: Vec<PathBuf>,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub async fn new(config_paths: Vec<PathBuf>) -> Result<Self> {
        let (watch_tx, _watch_rx) = watch::channel(());

        let mut manager = Self {
            config: Arc::new(ArcSwap::new(Arc::new(AppConfig::default()))),
            watcher: None,
            watch_tx,
            schema_registry: SchemaRegistry::new(),
            secrets_manager: secrets::SecretsManager::new(),
            config_paths,
        };

        // Load initial configuration
        manager.load().await?;

        // Start file watcher for hot-reload
        manager.start_watcher().await?;

        Ok(manager)
    }

    /// Load configuration from all sources
    pub async fn load(&mut self) -> Result<()> {
        let mut builder = Config::builder();

        // Add configuration files in priority order (last wins)
        for path in &self.config_paths {
            if path.exists() {
                builder = builder.add_source(File::from(path.clone()).format(FileFormat::Toml));
                info!("Loading config from: {}", path.display());
            }
        }

        // Add environment variables with SENTINEL_ prefix
        builder = builder.add_source(
            Environment::with_prefix("SENTINEL")
                .separator("__")
                .try_parsing(true),
        );

        let raw_config = builder
            .build()
            .map_err(|e| SentinelError::Config(CoreConfigError::Parse(e.to_string())))?;

        // Deserialize and validate
        let mut app_config: AppConfig = raw_config
            .try_deserialize()
            .map_err(|e| SentinelError::Config(CoreConfigError::Parse(e.to_string())))?;

        // Decrypt secrets
        self.secrets_manager.decrypt_config(&mut app_config).await?;

        // Validate
        app_config
            .validate()
            .map_err(|e| anyhow::anyhow!("Configuration validation failed: {}", e))?;

        // Run migrations if needed
        migration::migrate(&mut app_config)?;

        // Store
        self.config.store(Arc::new(app_config));

        info!("Configuration loaded successfully");
        Ok(())
    }

    /// Start file watcher for hot-reload
    async fn start_watcher(&mut self) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        let config_paths = self.config_paths.clone();
        let config_swap = Arc::clone(&self.config);
        let schema_registry = self.schema_registry.clone();
        let secrets_manager = self.secrets_manager.clone();

        let mut watcher: RecommendedWatcher = Watcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        let _ = tx.try_send(());
                    }
                }
            },
            notify::Config::default(),
        )?;

        for path in &config_paths {
            if let Some(parent) = path.parent() {
                watcher.watch(parent, RecursiveMode::NonRecursive)?;
            }
        }

        self.watcher = Some(watcher);

        // Spawn reload task
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                // Debounce
                tokio::time::sleep(Duration::from_millis(500)).await;

                // Drain any additional events
                while rx.try_recv().is_ok() {}

                info!("Configuration file changed, reloading...");

                if let Err(e) = Self::reload_static(
                    &config_swap,
                    &config_paths,
                    &schema_registry,
                    &secrets_manager,
                )
                .await
                {
                    error!("Failed to reload configuration: {}", e);
                } else {
                    info!("Configuration reloaded successfully");
                }
            }
        });

        Ok(())
    }

    /// Static reload function for the watcher task
    async fn reload_static(
        config_swap: &Arc<ArcSwap<AppConfig>>,
        config_paths: &[PathBuf],
        _schema_registry: &SchemaRegistry,
        secrets_manager: &secrets::SecretsManager,
    ) -> Result<()> {
        let mut builder = Config::builder();

        for path in config_paths {
            if path.exists() {
                builder = builder.add_source(File::from(path.clone()).format(FileFormat::Toml));
            }
        }

        builder = builder.add_source(
            Environment::with_prefix("SENTINEL")
                .separator("__")
                .try_parsing(true),
        );

        let raw_config = builder
            .build()
            .map_err(|e| SentinelError::Config(CoreConfigError::Parse(e.to_string())))?;
        let mut app_config: AppConfig = raw_config
            .try_deserialize()
            .map_err(|e| SentinelError::Config(CoreConfigError::Parse(e.to_string())))?;

        secrets_manager.decrypt_config(&mut app_config).await?;
        app_config
            .validate()
            .map_err(|e| anyhow::anyhow!("Configuration validation failed: {}", e))?;

        migration::migrate(&mut app_config)?;

        config_swap.store(Arc::new(app_config));
        Ok(())
    }

    /// Get current configuration
    pub fn get(&self) -> Arc<AppConfig> {
        self.config.load_full()
    }

    /// Get a typed configuration section
    pub fn get_typed<T: for<'de> Deserialize<'de>>(&self, path: &str) -> CoreResult<Option<T>> {
        let config = self.get();
        config.get_section(path)
    }

    /// Watch for configuration changes on a specific path.
    ///
    /// Returns a channel that will be notified when the specified config
    /// section changes. The hot-reload watcher must be active for updates
    /// to be delivered.
    pub fn watch(&self, path: &str) -> CoreResult<ConfigWatcher> {
        let (tx, rx) = watch::channel(self.get_section_value(path)?);

        let path = path.to_string();
        tokio::spawn({
            let config = self.config.clone();
            let mut reload_rx = self.watch_tx.subscribe();
            async move {
                while reload_rx.changed().await.is_ok() {
                    let new_config = config.load_full();
                    if let Ok(new_value) = new_config.get_section_value(&path) {
                        let _ = tx.send(new_value);
                    }
                }
            }
        });

        Ok(ConfigWatcher { receiver: rx })
    }

    /// Get a specific section value
    fn get_section_value(&self, path: &str) -> CoreResult<ConfigValue> {
        let config = self.get();
        config.get_section_value(path)
    }

    /// Validate configuration without applying
    pub fn validate(&self, config_toml: &str) -> CoreResult<ValidateConfigResponse> {
        let mut builder = Config::builder();
        builder = builder.add_source(config::File::from_str(config_toml, FileFormat::Toml));
        builder = builder.add_source(
            Environment::with_prefix("SENTINEL")
                .separator("__")
                .try_parsing(true),
        );

        let raw_config = builder
            .build()
            .map_err(|e| SentinelError::Config(CoreConfigError::Parse(e.to_string())))?;
        let mut app_config: AppConfig = raw_config
            .try_deserialize()
            .map_err(|e| SentinelError::Config(CoreConfigError::Parse(e.to_string())))?;

        // Try to decrypt secrets (will fail if keys not available)
        let _ = futures::executor::block_on(self.secrets_manager.decrypt_config(&mut app_config));

        match app_config.validate() {
            Ok(_) => Ok(ValidateConfigResponse { valid: true, errors: vec![], warnings: vec![] }),
            Err(e) => Ok(ValidateConfigResponse {
                valid: false,
                errors: vec![ConfigError { path: "".to_string(), message: e.to_string() }],
                warnings: vec![],
            }),
        }
    }

    /// Update configuration (partial or full)
    pub async fn update(
        &self,
        config_toml: &str,
        validate_only: bool,
    ) -> CoreResult<ValidateConfigResponse> {
        let validation = self.validate(config_toml)?;

        if !validation.valid || validate_only {
            return Ok(validation);
        }

        // Write to the primary config file
        if let Some(primary) = self.config_paths.first() {
            tokio::fs::write(primary, config_toml)
                .await
                .map_err(|e| SentinelError::Config(CoreConfigError::Parse(e.to_string())))?;
        }

        // Trigger reload (will happen via watcher)
        Ok(ValidateConfigResponse {
            valid: true,
            errors: vec![],
            warnings: vec![ConfigWarning {
                path: ".".to_string(),
                message: "Configuration updated, reload triggered".to_string(),
            }],
        })
    }

    /// Get schema for a module
    pub fn schema(&self, module: &str) -> Option<ConfigSchema> {
        self.schema_registry.get(module)
    }

    /// Get all registered schemas
    pub fn all_schemas(&self) -> Vec<ConfigSchema> {
        self.schema_registry.all()
    }
}

/// Complete application configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
#[derive(Default)]
pub struct AppConfig {
    pub core: CoreConfig,
    pub grpc: GrpcConfig,
    pub rest_gateway: RestGatewayConfig,
    pub storage: StorageConfig,
    pub event_bus: EventBusConfig,
    pub rule_engine: RuleEngineConfig,
    pub risk_engine: RiskEngineConfig,
    pub correlation_engine: CorrelationConfig,
    pub ai_engine: AiEngineConfig,
    pub plugin_manager: PluginManagerConfig,
    pub collectors: CollectorsConfig,
    pub threat_intel: ThreatIntelConfig,
    pub privacy: PrivacyConfig,
    pub logging: LoggingConfig,
}

impl AppConfig {
    /// Get a configuration section by path
    pub fn get_section<T: for<'de> Deserialize<'de>>(&self, path: &str) -> CoreResult<Option<T>> {
        let value = self.get_section_value(path)?;
        if value.is_null() {
            return Ok(None);
        }
        serde_json::from_value(value.0)
            .map(Some)
            .map_err(|e| SentinelError::Config(CoreConfigError::Parse(e.to_string())))
    }

    /// Get a section as ConfigValue
    pub fn get_section_value(&self, path: &str) -> CoreResult<ConfigValue> {
        let json = serde_json::to_value(self)
            .map_err(|e| SentinelError::Config(CoreConfigError::Parse(e.to_string())))?;

        let value = json.get(path).cloned().unwrap_or(serde_json::Value::Null);

        Ok(ConfigValue::from(value))
    }
}

/// Core service configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct CoreConfig {
    #[validate(length(min = 1))]
    pub host_id: String,

    pub instance_name: String,

    #[validate(
        range(
            min = 1,
            max = 300
        )
    )]
    pub graceful_shutdown_timeout: u32,

    #[validate(
        range(
            min = 1,
            max = 60
        )
    )]
    pub health_check_interval: u32,

    pub metrics_enabled: bool,

    #[validate(
        range(
            min = 1024,
            max = 65535
        )
    )]
    pub metrics_port: u16,

    #[validate(
        range(
            min = 64,
            max = 8192
        )
    )]
    pub max_memory_mb: u32,

    #[validate(
        range(
            min = 1,
            max = 100
        )
    )]
    pub max_cpu_percent: u8,

    #[validate(
        range(
            min = 100,
            max = 100000
        )
    )]
    pub event_buffer_size: usize,

    pub features: Vec<String>,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            host_id: String::new(),
            instance_name: "Sentinel AI".to_string(),
            graceful_shutdown_timeout: 30,
            health_check_interval: 10,
            metrics_enabled: true,
            metrics_port: 9090,
            max_memory_mb: 512,
            max_cpu_percent: 25,
            event_buffer_size: 10000,
            features: vec![
                "ai_engine".to_string(),
                "correlation_engine".to_string(),
                "plugin_system".to_string(),
                "grpc_api".to_string(),
                "rest_gateway".to_string(),
            ],
        }
    }
}

/// gRPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct GrpcConfig {
    pub enabled: bool,

    #[validate(length(min = 1))]
    pub address: String,

    pub tls_enabled: bool,

    #[validate(
        range(
            min = 1,
            max = 100
        )
    )]
    pub max_message_size_mb: u32,

    #[validate(
        range(
            min = 1,
            max = 1000
        )
    )]
    pub max_concurrent_streams: u32,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            address: "127.0.0.1:7777".to_string(),
            tls_enabled: false,
            max_message_size_mb: 16,
            max_concurrent_streams: 100,
        }
    }
}

/// REST gateway configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct RestGatewayConfig {
    pub enabled: bool,

    #[validate(length(min = 1))]
    pub address: String,

    pub cors_origins: Vec<String>,
}

impl Default for RestGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            address: "127.0.0.1:7778".to_string(),
            cors_origins: vec![
                "http://localhost:3000".to_string(),
                "tauri://localhost".to_string(),
            ],
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct StorageConfig {
    #[validate(length(min = 1))]
    pub sqlite_path: String,

    pub sqlite_wal_mode: bool,

    #[validate(
        range(
            min = 1000,
            max = 60000
        )
    )]
    pub sqlite_busy_timeout_ms: u32,

    #[validate(length(min = 1))]
    pub duckdb_path: String,

    #[validate(
        range(
            min = 64,
            max = 2048
        )
    )]
    pub duckdb_memory_limit_mb: u32,

    #[validate(
        range(
            min = 1,
            max = 16
        )
    )]
    pub duckdb_threads: u32,

    pub retention: Vec<RetentionPolicy>,

    pub aggregations: Vec<AggregationConfig>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            sqlite_path: "data/sentinel.db".to_string(),
            sqlite_wal_mode: true,
            sqlite_busy_timeout_ms: 5000,
            duckdb_path: "data/events.duckdb".to_string(),
            duckdb_memory_limit_mb: 256,
            duckdb_threads: 2,
            retention: vec![
                RetentionPolicy {
                    event_type_pattern: "sentinel.process.*".to_string(),
                    max_age_days: 30,
                    max_count: 1_000_000,
                },
                RetentionPolicy {
                    event_type_pattern: "sentinel.network.*".to_string(),
                    max_age_days: 14,
                    max_count: 500_000,
                },
                RetentionPolicy {
                    event_type_pattern: "sentinel.file.*".to_string(),
                    max_age_days: 30,
                    max_count: 200_000,
                },
                RetentionPolicy {
                    event_type_pattern: "sentinel.registry.*".to_string(),
                    max_age_days: 90,
                    max_count: 100_000,
                },
                RetentionPolicy {
                    event_type_pattern: "sentinel.usb.*".to_string(),
                    max_age_days: 90,
                    max_count: 10_000,
                },
                RetentionPolicy {
                    event_type_pattern: "sentinel.browser.*".to_string(),
                    max_age_days: 7,
                    max_count: 50_000,
                },
                RetentionPolicy {
                    event_type_pattern: "sentinel.startup.*".to_string(),
                    max_age_days: 180,
                    max_count: 5_000,
                },
                RetentionPolicy {
                    event_type_pattern: "*".to_string(),
                    max_age_days: 7,
                    max_count: 100_000,
                },
            ],
            aggregations: vec![
                AggregationConfig {
                    name: "hourly_risk".to_string(),
                    interval: "1h".to_string(),
                    retention_days: 90,
                },
                AggregationConfig {
                    name: "daily_mitre".to_string(),
                    interval: "1d".to_string(),
                    retention_days: 365,
                },
                AggregationConfig {
                    name: "process_behavior".to_string(),
                    interval: "1h".to_string(),
                    retention_days: 30,
                },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AggregationConfig {
    pub name: String,
    pub interval: String,
    #[validate(
        range(
            min = 1,
            max = 3650
        )
    )]
    pub retention_days: u32,
}

/// Event bus configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct EventBusConfig {
    #[validate(
        range(
            min = 100,
            max = 100000
        )
    )]
    pub ingest_channel_size: usize,

    #[validate(
        range(
            min = 100,
            max = 10000
        )
    )]
    pub broadcast_channel_size: usize,

    #[validate(
        range(
            min = 100,
            max = 50000
        )
    )]
    pub storage_channel_size: usize,

    #[validate(
        range(
            min = 100,
            max = 20000
        )
    )]
    pub plugin_channel_size: usize,

    #[validate(
        range(
            min = 100,
            max = 5000
        )
    )]
    pub ipc_channel_size: usize,

    pub backpressure: BackpressureConfig,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            ingest_channel_size: 10_000,
            broadcast_channel_size: 1_000,
            storage_channel_size: 5_000,
            plugin_channel_size: 2_000,
            ipc_channel_size: 500,
            backpressure: BackpressureConfig::default(),
        }
    }
}

/// Rule engine configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct RuleEngineConfig {
    pub rules_directories: Vec<String>,

    pub hot_reload: bool,

    pub validation_on_load: bool,

    #[validate(
        range(
            min = 1,
            max = 100000
        )
    )]
    pub max_rules: usize,

    #[validate(
        range(
            min = 1,
            max = 1000
        )
    )]
    pub evaluation_timeout_ms: u32,

    #[validate(
        range(
            min = 1,
            max = 32
        )
    )]
    pub worker_threads: usize,

    pub default_multipliers: Vec<RiskMultiplierConfig>,
}

impl Default for RuleEngineConfig {
    fn default() -> Self {
        Self {
            rules_directories: vec![
                "/etc/sentinel/rules/builtin".to_string(),
                "/etc/sentinel/rules/custom".to_string(),
                "~/.config/sentinel/rules/custom".to_string(),
            ],
            hot_reload: true,
            validation_on_load: true,
            max_rules: 10_000,
            evaluation_timeout_ms: 50,
            worker_threads: 4,
            default_multipliers: vec![
                RiskMultiplierConfig {
                    condition: "event.process.user.is_elevated".to_string(),
                    factor: 1.5,
                },
                RiskMultiplierConfig {
                    condition: "event.process.signing.is_trusted == false".to_string(),
                    factor: 1.3,
                },
                RiskMultiplierConfig {
                    condition: "event.network.geoip.country in ['CN', 'RU', 'KP', 'IR']"
                        .to_string(),
                    factor: 1.2,
                },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RiskMultiplierConfig {
    pub condition: String,
    #[validate(
        range(
            min = 0.1,
            max = 10.0
        )
    )]
    pub factor: f64,
}

/// Risk engine configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate, Default)]
pub struct RiskEngineConfig {
    pub decay_half_life: DecayHalfLifeConfig,

    pub alert_thresholds: AlertThresholdsConfig,

    pub escalation: EscalationConfig,

    pub asset_criticality: AssetCriticalityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct DecayHalfLifeConfig {
    #[validate(
        range(
            min = 1,
            max = 168
        )
    )]
    pub critical: u32,
    #[validate(
        range(
            min = 1,
            max = 168
        )
    )]
    pub high: u32,
    #[validate(
        range(
            min = 1,
            max = 168
        )
    )]
    pub medium: u32,
    #[validate(
        range(
            min = 1,
            max = 168
        )
    )]
    pub low: u32,
}

impl Default for DecayHalfLifeConfig {
    fn default() -> Self {
        Self { critical: 72, high: 48, medium: 24, low: 12 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AlertThresholdsConfig {
    #[validate(
        range(
            min = 0,
            max = 1000
        )
    )]
    pub low: u32,
    #[validate(
        range(
            min = 0,
            max = 1000
        )
    )]
    pub medium: u32,
    #[validate(
        range(
            min = 0,
            max = 1000
        )
    )]
    pub high: u32,
    #[validate(
        range(
            min = 0,
            max = 1000
        )
    )]
    pub critical: u32,
}

impl Default for AlertThresholdsConfig {
    fn default() -> Self {
        Self { low: 100, medium: 300, high: 600, critical: 900 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct EscalationConfig {
    #[validate(
        range(
            min = 1,
            max = 168
        )
    )]
    pub sustained_high_hours: u32,

    #[validate(
        range(
            min = 1,
            max = 100
        )
    )]
    pub flapping_max_alerts_per_hour: u32,

    #[validate(
        range(
            min = 1,
            max = 168
        )
    )]
    pub auto_acknowledge_low_after_hours: u32,
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            sustained_high_hours: 2,
            flapping_max_alerts_per_hour: 10,
            auto_acknowledge_low_after_hours: 24,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AssetCriticalityConfig {
    #[validate(
        range(
            min = 0.1,
            max = 10.0
        )
    )]
    pub system_process: f64,
    #[validate(
        range(
            min = 0.1,
            max = 10.0
        )
    )]
    pub domain_admin: f64,
    #[validate(
        range(
            min = 0.1,
            max = 10.0
        )
    )]
    pub critical_service: f64,
    #[validate(
        range(
            min = 0.1,
            max = 10.0
        )
    )]
    pub standard_user: f64,
}

impl Default for AssetCriticalityConfig {
    fn default() -> Self {
        Self { system_process: 1.5, domain_admin: 2.0, critical_service: 1.3, standard_user: 1.0 }
    }
}

/// Correlation engine configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CorrelationConfig {
    pub enabled: bool,

    #[validate(
        range(
            min = 100,
            max = 100000
        )
    )]
    pub max_chains: usize,

    #[validate(
        range(
            min = 1,
            max = 168
        )
    )]
    pub chain_timeout_hours: u32,

    #[validate(
        range(
            min = 2,
            max = 20
        )
    )]
    pub min_chain_length: usize,

    #[validate(
        range(
            min = 0,
            max = 1000
        )
    )]
    pub min_chain_risk: u32,

    pub flow_tracking: FlowTrackingConfig,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_chains: 10_000,
            chain_timeout_hours: 24,
            min_chain_length: 3,
            min_chain_risk: 400,
            flow_tracking: FlowTrackingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct FlowTrackingConfig {
    pub enabled: bool,
    #[validate(
        range(
            min = 1000,
            max = 1_000_000
        )
    )]
    pub max_objects: usize,
    #[validate(
        range(
            min = 1,
            max = 168
        )
    )]
    pub ttl_hours: u32,
}

impl Default for FlowTrackingConfig {
    fn default() -> Self {
        Self { enabled: true, max_objects: 50_000, ttl_hours: 48 }
    }
}

/// AI engine configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct AiEngineConfig {
    pub enabled: bool,

    pub provider: AiProvider,

    pub model: String,

    pub fallback_models: Vec<String>,

    pub ollama: OllamaConfig,

    pub llama_cpp: LlamaCppConfig,

    pub generation: GenerationConfig,

    pub context: ContextConfig,
}

impl Default for AiEngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: AiProvider::Ollama,
            model: "llama-3.2-3b-instruct".to_string(),
            fallback_models: vec![
                "llama-3.1-8b-instruct".to_string(),
                "qwen2.5-7b-instruct".to_string(),
            ],
            ollama: OllamaConfig::default(),
            llama_cpp: LlamaCppConfig::default(),
            generation: GenerationConfig::default(),
            context: ContextConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiProvider {
    Ollama,
    LlamaCpp,
    OpenAI,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct OllamaConfig {
    pub base_url: String,
    #[validate(
        range(
            min = 1,
            max = 300
        )
    )]
    pub timeout_seconds: u32,
    pub keep_alive: String,
    #[validate(
        range(
            min = 512,
            max = 32768
        )
    )]
    pub num_ctx: u32,
    pub num_gpu: i32,
    #[validate(
        range(
            min = 1,
            max = 64
        )
    )]
    pub num_thread: u32,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:11434".to_string(),
            timeout_seconds: 60,
            keep_alive: "5m".to_string(),
            num_ctx: 8192,
            num_gpu: -1,
            num_thread: 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct LlamaCppConfig {
    pub model_path: String,
    pub n_gpu_layers: i32,
    #[validate(
        range(
            min = 1,
            max = 64
        )
    )]
    pub n_threads: u32,
    #[validate(
        range(
            min = 512,
            max = 32768
        )
    )]
    pub n_ctx: u32,
    #[validate(
        range(
            min = 1,
            max = 2048
        )
    )]
    pub n_batch: u32,
}

impl Default for LlamaCppConfig {
    fn default() -> Self {
        Self {
            model_path: "models/llama-3.2-3b-instruct-Q4_K_M.gguf".to_string(),
            n_gpu_layers: -1,
            n_threads: 4,
            n_ctx: 8192,
            n_batch: 512,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct GenerationConfig {
    #[validate(
        range(
            min = 0.0,
            max = 2.0
        )
    )]
    pub temperature: f32,
    #[validate(
        range(
            min = 0.0,
            max = 1.0
        )
    )]
    pub top_p: f32,
    #[validate(
        range(
            min = 1,
            max = 100
        )
    )]
    pub top_k: u32,
    #[validate(
        range(
            min = 0.0,
            max = 2.0
        )
    )]
    pub repeat_penalty: f32,
    #[validate(
        range(
            min = 1,
            max = 8192
        )
    )]
    pub max_tokens: u32,
    pub stop_sequences: Vec<String>,
}

impl Default for GenerationConfig {
    fn default() -> Self {
        Self {
            temperature: 0.0,
            top_p: 0.9,
            top_k: 40,
            repeat_penalty: 1.1,
            max_tokens: 2048,
            stop_sequences: vec!["###".to_string(), "User:".to_string(), "Assistant:".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ContextConfig {
    #[validate(
        range(
            min = 10,
            max = 1000
        )
    )]
    pub max_events: usize,
    #[validate(
        range(
            min = 10,
            max = 500
        )
    )]
    pub max_chain_events: usize,
    pub anonymize: bool,
    pub include_process_tree: bool,
    pub include_network_summary: bool,
    pub include_file_summary: bool,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            max_events: 100,
            max_chain_events: 50,
            anonymize: true,
            include_process_tree: true,
            include_network_summary: true,
            include_file_summary: true,
        }
    }
}

/// Plugin manager configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PluginManagerConfig {
    pub enabled: bool,

    pub plugin_directories: Vec<String>,

    #[validate(
        range(
            min = 1,
            max = 100
        )
    )]
    pub max_plugins: usize,

    pub default_sandbox: SandboxProfile,

    pub allowed_capabilities: Vec<String>,
}

impl Default for PluginManagerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            plugin_directories: vec![
                "/etc/sentinel/plugins".to_string(),
                "~/.config/sentinel/plugins".to_string(),
                "./plugins".to_string(),
            ],
            max_plugins: 50,
            default_sandbox: SandboxProfile::Basic,
            allowed_capabilities: vec![
                "event:read".to_string(),
                "event:write".to_string(),
                "config:read".to_string(),
                "config:write".to_string(),
                "network:http".to_string(),
                "secret:read".to_string(),
                "ai:query".to_string(),
                "storage:read".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxProfile {
    None,
    Basic,
    Strict,
}

/// Collectors global configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct CollectorsConfig {
    #[validate(
        range(
            min = 0.0,
            max = 1.0
        )
    )]
    pub sample_rate: f64,

    pub backpressure_response: BackpressureResponse,

    pub process: ProcessCollectorConfig,
    pub network: NetworkCollectorConfig,
    pub file: FileCollectorConfig,
    pub registry: RegistryCollectorConfig,
    pub usb: UsbCollectorConfig,
    pub browser: BrowserCollectorConfig,
    pub startup: StartupCollectorConfig,
}

impl Default for CollectorsConfig {
    fn default() -> Self {
        Self {
            sample_rate: 1.0,
            backpressure_response: BackpressureResponse::Throttle,
            process: ProcessCollectorConfig::default(),
            network: NetworkCollectorConfig::default(),
            file: FileCollectorConfig::default(),
            registry: RegistryCollectorConfig::default(),
            usb: UsbCollectorConfig::default(),
            browser: BrowserCollectorConfig::default(),
            startup: StartupCollectorConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackpressureResponse {
    Throttle,
    Drop,
    Pause,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct ProcessCollectorConfig {
    pub enabled: bool,
    #[validate(
        range(
            min = 0.0,
            max = 1.0
        )
    )]
    pub sample_rate: f64,
    pub include_command_line: bool,
    pub include_environment: bool,
    pub resolve_signatures: bool,
    #[validate(
        range(
            min = 1,
            max = 50
        )
    )]
    pub track_ancestry_depth: u32,
    pub monitor_injection: bool,
    pub monitor_hollowing: bool,
    pub monitor_dumps: bool,
    pub exclude_paths: Vec<String>,
}

impl Default for ProcessCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_rate: 1.0,
            include_command_line: true,
            include_environment: false,
            resolve_signatures: true,
            track_ancestry_depth: 10,
            monitor_injection: true,
            monitor_hollowing: true,
            monitor_dumps: true,
            exclude_paths: vec![
                "C:\\Windows\\System32\\*".to_string(),
                "C:\\Program Files\\*".to_string(),
                "/usr/bin/*".to_string(),
                "/bin/*".to_string(),
                "/sbin/*".to_string(),
                "/lib*".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct NetworkCollectorConfig {
    pub enabled: bool,
    #[validate(
        range(
            min = 0.0,
            max = 1.0
        )
    )]
    pub sample_rate: f64,
    pub capture_dns: bool,
    pub capture_http: bool,
    pub capture_tls_fingerprints: bool,
    pub capture_payloads: bool,
    #[validate(
        range(
            min = 0,
            max = 10_000_000
        )
    )]
    pub max_payload_bytes: u32,
    pub resolve_hostnames: bool,
    pub geoip_enabled: bool,
    pub geoip_db_path: String,
    pub exclude_ports: Vec<u16>,
    pub exclude_local: bool,
    pub tls_sni_extraction: bool,
    pub http_host_extraction: bool,
}

impl Default for NetworkCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_rate: 1.0,
            capture_dns: true,
            capture_http: true,
            capture_tls_fingerprints: true,
            capture_payloads: false,
            max_payload_bytes: 0,
            resolve_hostnames: true,
            geoip_enabled: true,
            geoip_db_path: "data/GeoLite2-Country.mmdb".to_string(),
            exclude_ports: vec![53, 67, 68, 123, 1900, 5353, 5355],
            exclude_local: true,
            tls_sni_extraction: true,
            http_host_extraction: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct FileCollectorConfig {
    pub enabled: bool,
    #[validate(
        range(
            min = 0.0,
            max = 1.0
        )
    )]
    pub sample_rate: f64,
    pub monitor_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub calculate_hashes: bool,
    pub calculate_entropy: bool,
    #[validate(
        range(
            min = 1,
            max = 1_000_000_000
        )
    )]
    pub max_file_size_hash: u64,
    pub monitor_executable_only: bool,
    pub monitor_sensitive_paths: bool,
}

impl Default for FileCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_rate: 1.0,
            monitor_paths: vec![
                "C:\\Users\\*\\AppData\\*".to_string(),
                "C:\\ProgramData\\*".to_string(),
                "C:\\Temp\\*".to_string(),
                "/home/*/.config/*".to_string(),
                "/home/*/.local/*".to_string(),
                "/tmp/*".to_string(),
                "/var/tmp/*".to_string(),
                "/Library/LaunchAgents/*".to_string(),
                "/Library/LaunchDaemons/*".to_string(),
            ],
            exclude_paths: vec![
                "C:\\Windows\\*".to_string(),
                "C:\\Program Files\\*".to_string(),
                "/usr/*".to_string(),
                "/bin/*".to_string(),
                "/sbin/*".to_string(),
                "/lib*".to_string(),
                "/var/log/*".to_string(),
                "*/node_modules/*".to_string(),
                "*/.git/*".to_string(),
                "*/target/*".to_string(),
            ],
            calculate_hashes: true,
            calculate_entropy: true,
            max_file_size_hash: 104_857_600,
            monitor_executable_only: false,
            monitor_sensitive_paths: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct RegistryCollectorConfig {
    pub enabled: bool,
    #[validate(
        range(
            min = 0.0,
            max = 1.0
        )
    )]
    pub sample_rate: f64,
    pub monitor_hives: Vec<String>,
    pub monitor_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub capture_value_data: bool,
    #[validate(
        range(
            min = 1,
            max = 1_000_000
        )
    )]
    pub max_value_size: u32,
}

impl Default for RegistryCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_rate: 1.0,
            monitor_hives: vec!["HKLM".to_string(), "HKCU".to_string()],
            monitor_paths: vec![
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*".to_string(),
                "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*".to_string(),
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*".to_string(),
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\*".to_string(),
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon*".to_string(),
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects*".to_string(),
            ],
            exclude_paths: vec![
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\*".to_string(),
            ],
            capture_value_data: true,
            max_value_size: 8192,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct UsbCollectorConfig {
    pub enabled: bool,
    #[validate(
        range(
            min = 0.0,
            max = 1.0
        )
    )]
    pub sample_rate: f64,
    pub monitor_hid: bool,
    pub monitor_mass_storage: bool,
    pub scan_on_mount: bool,
    #[validate(
        range(
            min = 1,
            max = 1000
        )
    )]
    pub scan_max_files: u32,
    #[validate(
        range(
            min = 1,
            max = 100_000_000
        )
    )]
    pub scan_max_file_size: u64,
    pub scan_extensions: Vec<String>,
    pub notify_on_new_device: bool,
}

impl Default for UsbCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_rate: 1.0,
            monitor_hid: true,
            monitor_mass_storage: true,
            scan_on_mount: true,
            scan_max_files: 100,
            scan_max_file_size: 10_485_760,
            scan_extensions: vec![
                ".exe".to_string(),
                ".dll".to_string(),
                ".ps1".to_string(),
                ".bat".to_string(),
                ".cmd".to_string(),
                ".vbs".to_string(),
                ".js".to_string(),
                ".jar".to_string(),
                ".scr".to_string(),
                ".lnk".to_string(),
            ],
            notify_on_new_device: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct BrowserCollectorConfig {
    pub enabled: bool,
    #[validate(
        range(
            min = 0.0,
            max = 1.0
        )
    )]
    pub sample_rate: f64,
    pub browsers: Vec<String>,
    pub monitor_history: bool,
    pub monitor_downloads: bool,
    pub monitor_extensions: bool,
    pub monitor_cookies: bool,
    pub monitor_localstorage: bool,
    pub download_hash_calculation: bool,
    pub incognito_mode: IncognitoMode,
    pub extension_allowlist: Vec<String>,
    pub native_messaging_enabled: bool,
    #[validate(
        range(
            min = 1,
            max = 3600
        )
    )]
    pub poll_interval_seconds: u32,
}

impl Default for BrowserCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_rate: 1.0,
            browsers: vec![
                "chrome".to_string(),
                "edge".to_string(),
                "firefox".to_string(),
                "brave".to_string(),
            ],
            monitor_history: true,
            monitor_downloads: true,
            monitor_extensions: true,
            monitor_cookies: false,
            monitor_localstorage: false,
            download_hash_calculation: true,
            incognito_mode: IncognitoMode::Ignore,
            extension_allowlist: vec![],
            native_messaging_enabled: true,
            poll_interval_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncognitoMode {
    Ignore,
    MetadataOnly,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct StartupCollectorConfig {
    pub enabled: bool,
    #[validate(
        range(
            min = 1,
            max = 168
        )
    )]
    pub scan_interval_hours: u32,
    pub monitor_registry_run_keys: bool,
    pub monitor_scheduled_tasks: bool,
    pub monitor_services: bool,
    pub monitor_startup_folder: bool,
    pub monitor_winlogon: bool,
    pub monitor_systemd: bool,
    pub monitor_cron: bool,
    pub monitor_launchd: bool,
    pub monitor_shell_profiles: bool,
    pub monitor_browser_extensions: bool,
    pub verify_signatures: bool,
    pub alert_on_unsigned: bool,
}

impl Default for StartupCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_hours: 4,
            monitor_registry_run_keys: true,
            monitor_scheduled_tasks: true,
            monitor_services: true,
            monitor_startup_folder: true,
            monitor_winlogon: true,
            monitor_systemd: true,
            monitor_cron: true,
            monitor_launchd: true,
            monitor_shell_profiles: true,
            monitor_browser_extensions: true,
            verify_signatures: true,
            alert_on_unsigned: true,
        }
    }
}

/// Threat intelligence configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ThreatIntelConfig {
    pub enabled: bool,
    pub providers: Vec<ThreatIntelProviderConfig>,
    #[validate(
        range(
            min = 1,
            max = 168
        )
    )]
    pub update_interval_hours: u32,
    #[validate(
        range(
            min = 1000,
            max = 10_000_000
        )
    )]
    pub max_iocs: usize,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            providers: vec![ThreatIntelProviderConfig {
                name: "local".to_string(),
                provider_type: "file".to_string(),
                path: Some("data/threat_intel/".to_string()),
                api_key_secret: None,
            }],
            update_interval_hours: 6,
            max_iocs: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ThreatIntelProviderConfig {
    pub name: String,
    pub provider_type: String,
    pub path: Option<String>,
    pub api_key_secret: Option<String>,
}

/// Privacy configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(default)]
pub struct PrivacyConfig {
    pub telemetry_enabled: bool,
    pub crash_reporting: bool,
    pub ai_local_only: bool,
    pub data_sharing: bool,
    pub anonymize_host_id: bool,
    pub strip_command_line_secrets: bool,
    pub strip_environment_secrets: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            telemetry_enabled: false,
            crash_reporting: false,
            ai_local_only: true,
            data_sharing: false,
            anonymize_host_id: true,
            strip_command_line_secrets: true,
            strip_environment_secrets: true,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct LoggingConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    pub output: LogOutput,
    pub file_path: String,
    #[validate(
        range(
            min = 1,
            max = 1000
        )
    )]
    pub max_file_size_mb: u32,
    #[validate(
        range(
            min = 1,
            max = 100
        )
    )]
    pub max_files: u32,
    pub include_timestamp: bool,
    pub include_thread: bool,
    pub include_location: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Json,
            output: LogOutput::File,
            file_path: "logs/sentinel.log".to_string(),
            max_file_size_mb: 100,
            max_files: 10,
            include_timestamp: true,
            include_thread: true,
            include_location: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
    Pretty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    Stdout,
    File,
    Both,
}

/// Configuration validation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateConfigResponse {
    pub valid: bool,
    pub errors: Vec<ConfigError>,
    pub warnings: Vec<ConfigWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigError {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigWarning {
    pub path: String,
    pub message: String,
}

/// Schema registry for configuration validation
#[derive(Debug, Clone)]
pub struct SchemaRegistry {
    schemas: HashMap<String, ConfigSchema>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self { schemas: HashMap::new() }
    }

    pub fn register(&mut self, schema: ConfigSchema) {
        self.schemas.insert(schema.module.clone(), schema);
    }

    pub fn get(&self, module: &str) -> Option<ConfigSchema> {
        self.schemas.get(module).cloned()
    }

    pub fn all(&self) -> Vec<ConfigSchema> {
        self.schemas.values().cloned().collect()
    }
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ConfigProvider for ConfigManager {
    async fn get(&self, path: &str) -> CoreResult<Option<ConfigValue>> {
        Ok(self.get().get_section_value(path).ok())
    }

    async fn watch(&self, path: &str) -> CoreResult<ConfigWatcher> {
        ConfigManager::watch(self, path)
    }

    fn schema(&self) -> &ConfigSchema {
        static EMPTY: std::sync::OnceLock<ConfigSchema> = std::sync::OnceLock::new();
        EMPTY.get_or_init(|| ConfigSchema {
            module: "root".to_string(),
            version: 1,
            schema: serde_json::json!({}),
        })
    }
}

//! Sentinel AI Core Service
//!
//! Main daemon process that coordinates all components.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sentinel_core::{ModuleContext, ShutdownSignal};
use sentinel_config::ConfigManager;
use sentinel_storage::StorageManager;
use sentinel_event_bus::EventBusImpl;
use sentinel_rule_engine::RuleEngine;

#[derive(Parser, Debug)]
#[command(name = "sentinel-core-service")]
#[command(about = "Sentinel AI Core Service", long_about = None)]
struct Args {
    /// Configuration file paths
    #[arg(short, long, value_delimiter = ',')]
    config: Vec<PathBuf>,
    
    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,
    
    /// Validate configuration and exit
    #[arg(long)]
    validate_config: bool,
    
    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Initialize logging
    init_logging(&args.log_level)?;
    
    info!("Starting Sentinel AI Core Service");
    
    // Load configuration
    let config_paths = if args.config.is_empty() {
        default_config_paths()
    } else {
        args.config
    };
    
    let config_manager = ConfigManager::new(config_paths.clone()).await
        .context("Failed to load configuration")?;
    
    if args.validate_config {
        info!("Configuration validation requested");
        let config = config_manager.get();
        println!("Configuration valid: {}", config.core.instance_name);
        return Ok(());
    }
    
    // Create shutdown signal
    let (shutdown, shutdown_tx) = ShutdownSignal::new();
    let shutdown_wait = shutdown.clone();
    
    // Handle shutdown signals
    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("Received Ctrl+C, initiating shutdown");
                let _ = shutdown_tx.send(true);
            }
            Err(e) => {
                error!("Failed to listen for Ctrl+C: {}", e);
            }
        }
        
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).unwrap();
            sigterm.recv().await;
            info!("Received SIGTERM, initiating shutdown");
            let _ = shutdown_tx.send(true);
        }
    });
    
    // Initialize components
    let storage_cfg = config_manager.get().storage.clone();
    let sqlite_cfg = sentinel_storage::sqlite::SqliteConfig {
        path: storage_cfg.sqlite_path.clone(),
        wal_mode: storage_cfg.sqlite_wal_mode,
        busy_timeout_ms: storage_cfg.sqlite_busy_timeout_ms,
        max_connections: 5,
    };
    let duckdb_cfg = sentinel_storage::duckdb::DuckDbConfig {
        path: storage_cfg.duckdb_path.clone(),
        memory_limit_mb: storage_cfg.duckdb_memory_limit_mb,
        threads: storage_cfg.duckdb_threads,
        read_only: false,
    };
    let storage = StorageManager::new(&sqlite_cfg, &duckdb_cfg)
        .await
        .context("Failed to initialize storage")?;
    
    let bus_cfg = config_manager.get().event_bus.clone();
    let channel_cfg = sentinel_core::ChannelConfig {
        ingest: bus_cfg.ingest_channel_size,
        broadcast: bus_cfg.broadcast_channel_size,
        storage: bus_cfg.storage_channel_size,
        plugin: bus_cfg.plugin_channel_size,
        ipc: bus_cfg.ipc_channel_size,
    };
    let event_bus = EventBusImpl::new(channel_cfg);
    let _rule_engine = RuleEngine::new(&config_manager.get().rule_engine).await
        .context("Failed to initialize rule engine")?;
    
    // Create module context
    let _module_ctx = ModuleContext::new(
        Arc::new(event_bus),
        Arc::new(storage),
        Arc::new(config_manager),
        Arc::new(sentinel_core::metrics::MetricsRegistry::new()),
        Arc::new(sentinel_plugins::PluginManager::new()),
        shutdown,
    );
    
    // Start components
    info!("Starting core components");
    
    // TODO: Start collectors, correlation engine, risk engine, AI engine, plugin manager
    
    // Wait for shutdown
    shutdown_wait.wait().await;
    
    info!("Shutting down gracefully");
    
    // TODO: Stop all components
    
    info!("Sentinel AI Core Service stopped");
    Ok(())
}

fn init_logging(log_level: &str) -> Result<()> {
    let level: tracing::Level = log_level.parse()?;
    
    let file_appender = tracing_appender::rolling::daily("logs", "sentinel.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(level.to_string()))
        .with(tracing_subscriber::fmt::layer()
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .with_writer(non_blocking))
        .with(tracing_subscriber::fmt::layer()
            .with_writer(std::io::stdout)
            .with_ansi(true))
        .init();
    
    Ok(())
}

fn default_config_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/sentinel/config.toml"),
        PathBuf::from("~/.config/sentinel/config.toml"),
        PathBuf::from("sentinel-local/config.toml"),
    ]
}
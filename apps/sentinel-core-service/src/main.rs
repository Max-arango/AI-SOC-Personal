//! Sentinel AI Core Service
//!
//! Main daemon process that coordinates all components.
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal;
use tokio::sync::{broadcast, watch};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sentinel_ai::{AiConfig, AiEngine};
use sentinel_config::ConfigManager;
use sentinel_core::{ChannelConfig, EventBus};
use sentinel_correlation::{CorrelationConfig, CorrelationEngine};
use sentinel_event_bus::EventBusImpl;
use sentinel_events::Event;
use sentinel_privacy::PrivacyEngine;
use sentinel_privacy::config::PrivacyConfig;
use sentinel_risk::{RiskConfig, RiskEngine};
use sentinel_rule_engine::RuleEngine;
use sentinel_storage::sqlite::SqliteStorage;

mod alert_manager;
mod enrichment;
mod notifier;
use alert_manager::AlertManager;

#[derive(Parser, Debug)]
#[command(name = "sentinel-core-service")]
#[command(about = "Sentinel AI Core Service", long_about = None)]
struct Args {
    #[arg(
        short,
        long,
        value_delimiter = ','
    )]
    config: Vec<PathBuf>,

    #[arg(
        short, long
    )]
    foreground: bool,

    #[arg(long)]
    validate_config: bool,

    #[arg(
        short,
        long,
        default_value = "info"
    )]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log_level)?;
    info!("Starting Sentinel AI Core Service");
    let config_paths = if args.config.is_empty() { default_config_paths() } else { args.config };

    let config_manager = ConfigManager::new(config_paths.clone())
        .await
        .context("Failed to load configuration")?;

    if args.validate_config {
        let cfg = config_manager.get();
        println!("Configuration valid: {}", cfg.core.instance_name);
        return Ok(());
    }
    // ── Shutdown signal ─────────────────────────────────────────
    let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let shutdown_tx2 = _shutdown_tx.clone();
    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("Received Ctrl+C, initiating shutdown");
                let _ = shutdown_tx2.send(true);
            },
            Err(e) => {
                error!("Failed to listen for Ctrl+C: {}", e);
            },
        }

        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
                sigterm.recv().await;
                info!("Received SIGTERM, initiating shutdown");
                let _ = shutdown_tx2.send(true);
            }
        }
    });

    // ── Storage (SQLite only for MVP) ─────────────────────────
    let storage_cfg = config_manager.get().storage.clone();
    let sqlite_cfg = sentinel_storage::sqlite::SqliteConfig {
        path: storage_cfg.sqlite_path.clone(),
        wal_mode: storage_cfg.sqlite_wal_mode,
        busy_timeout_ms: storage_cfg.sqlite_busy_timeout_ms,
        max_connections: 5,
    };
    let sqlite = Arc::new(
        sentinel_storage::sqlite::SqliteStorage::new(&sqlite_cfg)
            .await
            .context("Failed to initialize SQLite")?,
    );
    sentinel_storage::migrations::run_all(sqlite.pool())
        .await
        .context("Failed to run SQLite migrations")?;

    // ── Event Bus ───────────────────────────────────────────────
    let bus_cfg = config_manager.get().event_bus.clone();
    let channel_cfg = ChannelConfig {
        ingest: bus_cfg.ingest_channel_size,
        broadcast: bus_cfg.broadcast_channel_size,
        storage: bus_cfg.storage_channel_size,
        plugin: bus_cfg.plugin_channel_size,
        ipc: bus_cfg.ipc_channel_size,
    };
    let bus_impl = Arc::new(EventBusImpl::new(channel_cfg));
    let bus: Arc<dyn EventBus> = bus_impl.clone();

    // Spawn the event-bus routing loop (requires the concrete type)
    let bus_runner = bus_impl.clone();
    let bus_handle = tokio::spawn(async move {
        let _ = bus_runner.run().await;
    });

    // ── Rule Engine ─────────────────────────────────────────────
    let rule_engine = Arc::new(
        RuleEngine::new(&config_manager.get().rule_engine)
            .await
            .context("Failed to initialize rule engine")?,
    );

    // ── M2: Correlation + Risk + Alerts ─────────────────────────
    let correlation = Arc::new(CorrelationEngine::new(CorrelationConfig::default()));
    let risk = Arc::new(RiskEngine::new(RiskConfig::default()));
    let (alert_broadcast_tx, _alert_broadcast_rx) = broadcast::channel::<sentinel_events::sentinel::api::v1::AlertStreamEvent>(256);
    let alert_mgr = Arc::new(AlertManager::new(sqlite.alerts().await, alert_broadcast_tx.clone()));

    // ── M3: AI Engine ──────────────────────────────────────────
    let ai_config = AiConfig::default();
    let ai = Arc::new(AiEngine::new(ai_config.clone(), ai_config.create_provider()));
    info!("AI engine initialised (model: {}, enabled: {})", ai_config.model, ai_config.enabled);

    let privacy = Arc::new(PrivacyEngine::new(PrivacyConfig::default()));
    info!(
        "Privacy engine initialised (mode: {}, command_lines: {:?})",
        privacy.config().mode, privacy.config().sharing.command_lines
    );

    // Subscribe rule engine to ALL events ("*")
    let mut rule_sub = bus
        .subscribe_type("*")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to subscribe: {e}"))?;

    // ── Linux process collector (CN_PROC netlink) ───────────
    sentinel_collectors::process::start_process_monitor(bus.clone()).await;
    info!("Process collector started (netlink CN_PROC)");
    sentinel_collectors::network::start_network_monitor(bus.clone()).await;
    info!("Network collector started");
    sentinel_collectors::file::start_file_monitor(bus.clone()).await;
    info!("File collector started");
    sentinel_collectors::startup::start_startup_monitor(bus.clone()).await;
    info!("Startup collector started");
    sentinel_collectors::browser::start_browser_monitor(bus.clone()).await;
    info!("Browser collector started");
    sentinel_collectors::usb::start_usb_monitor(bus.clone()).await;
    info!("USB collector started");
    sentinel_collectors::registry::start_registry_monitor(bus.clone()).await;
    info!("Registry collector started");
    info!("All core components started");

    // ── Main event loop: route events + wait for shutdown ─────────
    loop {
        tokio::select! {
            Some(event) = rule_sub.receiver.recv() => {
                let mut enriched_event = (*event).clone();

                enrichment::enrich(&mut enriched_event).await;

                let sanitized_event = Arc::new(privacy.sanitize_event(&enriched_event.clone().into()));
                let enriched_arc = Arc::new(enriched_event);

                let chain = correlation.ingest(&enriched_arc);

                let result = rule_engine.evaluate(&enriched_arc).await;
                if !result.matches.is_empty() {
                    info!(
                        "Rule engine: {} matches for event {} (type={}, {} rules in {:?})",
                        result.matches.len(), enriched_arc.id, enriched_arc.r#type,
                        result.rules_evaluated, result.evaluation_time,
                    );
                    for m in &result.matches {
                        let score = risk.calculate(
                            m.risk_score,
                            "Warning",
                            1.0,
                            Some(&chain.id),
                        );

                        if let Some(alert) = risk.should_alert(
                            &m.rule_id,
                            &m.rule_name,
                            score,
                            &enriched_arc.source,
                            vec![enriched_arc.id.clone()],
                            Some(chain.id.clone()),
                        ) {
                            info!("  → ALERT [{}] {} (risk={})", alert.severity as i32, alert.rule_name, alert.risk_score);

                            // Persist alert
                            if let Err(e) = alert_mgr.create(
                                &alert.rule_id,
                                alert.risk_score,
                                m.severity,
                                alert.event_ids.clone(),
                                serde_json::json!({"chain_id": chain.id, "source": enriched_arc.source}),
                            ).await {
                                error!("Failed to persist alert: {e}");
                            }

                            // AI explanation (async, non-blocking)
                            let ai_clone = ai.clone();
                            let alert_clone = alert.clone();
                            let event_clone = sanitized_event.clone();
                            tokio::spawn(async move {
                                let explanation = ai_clone.explain_alert(
                                    &sentinel_core::traits::Alert {
                                        id: sentinel_core::Ulid::new(),
                                        rule_id: alert_clone.rule_id.clone(),
                                        correlation_id: sentinel_core::Ulid::new(),
                                        risk_score: alert_clone.risk_score,
                                        severity: sentinel_core::Severity::Info,
                                        state: sentinel_core::traits::AlertState::New,
                                        created_at: chrono::Utc::now(),
                                        updated_at: chrono::Utc::now(),
                                        acknowledged_by: None,
                                        acknowledged_at: None,
                                        events: vec![],
                                        context: serde_json::Value::Null,
                                        ai_summary: None,
                                    },
                                    &[event_clone],
                                ).await;
                                info!("AI explanation: {}", explanation);
                            });

                            let severity_name = format!("{:?}", alert.severity);
                            let alert_name = alert.rule_name.clone();
                            let alert_risk = alert.risk_score;
                            let alert_eid = alert.rule_id.clone();
                            let event_source = enriched_arc.source.clone();
                            let event_count = alert.event_ids.len();

                            notifier::notify_alerts(
                                &alert_eid,
                                &alert_name,
                                alert_risk,
                                &severity_name,
                                &event_source,
                                event_count,
                            ).await;
                        } else {
                            info!("  → MATCH {} [risk={} below alert threshold]", m.rule_name, m.risk_score);
                        }
                    }
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
            Ok(()) = shutdown_rx.changed() => {
                info!("Shutting down");
                break;
            }
        }
    }

    bus_impl.shutdown();

    info!("Sentinel AI Core Service stopped");
    Ok(())
}

fn init_logging(log_level: &str) -> Result<()> {
    let level: tracing::Level = log_level.parse()?;

    let file_appender = tracing_appender::rolling::daily("logs", "sentinel.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(level.to_string()))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_writer(non_blocking),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout)
                .with_ansi(true),
        )
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

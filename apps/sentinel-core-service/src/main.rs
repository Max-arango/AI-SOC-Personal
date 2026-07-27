//! Sentinel AI Core Service
//!
//! Main daemon process that coordinates all components.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sentinel_ai::{AiConfig, AiEngine};
use sentinel_config::ConfigManager;
use sentinel_core::{ChannelConfig, EventBus};
use sentinel_correlation::{CorrelationConfig, CorrelationEngine};
use sentinel_event_bus::EventBusImpl;
use sentinel_events::{Event, ProcessContext, UserContext};
use sentinel_privacy::PrivacyEngine;
use sentinel_privacy::config::PrivacyConfig;
use sentinel_risk::{RiskConfig, RiskEngine};
use sentinel_rule_engine::RuleEngine;
use sentinel_storage::sqlite::SqliteStorage;

mod alert_manager;
use alert_manager::AlertManager;
use tokio::sync::mpsc;

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
    let alert_mgr = Arc::new(AlertManager::new(sqlite.alerts().await));

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

    // Synthetic test event (verification)
    {
        let test_bus = bus.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let test_event = Arc::new(Event {
                id: "test-startup".into(),
                r#type: "test.event".into(),
                source: "core-service".into(),
                severity: 1,
                risk_score: 0,
                host_id: "local".into(),
                schema_version: 1,
                ..Default::default()
            });
            if let Err(e) = test_bus.publish(test_event).await {
                warn!("Failed to publish test event: {e}");
            } else {
                info!("Published start-up test event");
            }
        });
    }

    // ── Linux process watcher (M1 — real process events) ───────
    #[cfg(target_os = "linux")]
    {
        let watcher_bus = bus.clone();
        tokio::spawn(async move {
            use std::collections::HashSet;
            let mut sys = sysinfo::System::new();
            sys.refresh_all();
            let mut known: HashSet<sysinfo::Pid> = sys.processes().keys().copied().collect();
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tick.tick().await; // skip first immediate tick
            loop {
                tick.tick().await;
                sys.refresh_all();
                let current: HashSet<sysinfo::Pid> = sys.processes().keys().copied().collect();

                for pid in current.difference(&known) {
                    if let Some(proc) = sys.process(*pid) {
                        let event = Arc::new(Event {
                            id: sentinel_core::Ulid::new().to_string(),
                            r#type: "sentinel.process.create".into(),
                            source: "process".into(),
                            severity: 2,
                            risk_score: 10,
                            host_id: String::new(),
                            schema_version: 1,
                            process: Some(ProcessContext {
                                pid: pid.as_u32(),
                                ppid: proc.parent().map(|p| p.as_u32()).unwrap_or(0),
                                name: proc.name().to_string_lossy().into_owned(),
                                path: proc
                                    .exe()
                                    .map(|p| p.to_string_lossy().into_owned())
                                    .unwrap_or_default(),
                                command_line: proc
                                    .cmd()
                                    .iter()
                                    .map(|s| s.to_string_lossy())
                                    .collect::<Vec<_>>()
                                    .join(" "),
                                user: Some(UserContext {
                                    sid: proc.user_id().map(|u| u.to_string()).unwrap_or_default(),
                                    username: proc
                                        .user_id()
                                        .map(|u| u.to_string())
                                        .unwrap_or_default(),
                                    domain: String::new(),
                                    is_elevated: false,
                                    is_system: false,
                                }),
                                ..Default::default()
                            }),
                            ..Default::default()
                        });
                        if let Err(e) = watcher_bus.publish(event).await {
                            warn!("Process collector publish failed: {e}");
                        }
                    }
                }
                known = current;
            }
        });
        info!("Linux process watcher started (5s interval)");
    }

    #[cfg(not(target_os = "linux"))]
    {
        let bus_clone = bus.clone();
        tokio::spawn(async move {
            use std::collections::HashSet;
            let mut sys = sysinfo::System::new();
            sys.refresh_all();
            let mut known: HashSet<sysinfo::Pid> = sys.processes().keys().copied().collect();
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tick.tick().await;
            loop {
                tick.tick().await;
                sys.refresh_all();
                let current: HashSet<sysinfo::Pid> = sys.processes().keys().copied().collect();
                for pid in current.difference(&known) {
                    if let Some(proc) = sys.process(*pid) {
                        let event = Arc::new(Event {
                            id: sentinel_core::Ulid::new().to_string(),
                            r#type: "sentinel.process.create".into(),
                            source: "process".into(),
                            severity: 2,
                            risk_score: 10,
                            host_id: String::new(),
                            schema_version: 1,
                            process: Some(ProcessContext {
                                pid: pid.as_u32(),
                                ppid: proc.parent().map(|p| p.as_u32()).unwrap_or(0),
                                name: proc.name().to_string_lossy().into_owned(),
                                path: proc
                                    .exe()
                                    .map(|p| p.to_string_lossy().into_owned())
                                    .unwrap_or_default(),
                                command_line: proc
                                    .cmd()
                                    .iter()
                                    .map(|s| s.to_string_lossy())
                                    .collect::<Vec<_>>()
                                    .join(" "),
                                ..Default::default()
                            }),
                            ..Default::default()
                        });
                        let _ = bus_clone.publish(event).await;
                    }
                }
                known = current;
            }
        });
        info!("Process watcher started (5s interval, sysinfo)");
    }

    sentinel_collectors::network::start_network_monitor(bus.clone()).await;
    info!("Network collector started");

    sentinel_collectors::file::start_file_monitor(bus.clone()).await;
    info!("File collector started");

    sentinel_collectors::startup::start_startup_monitor(bus.clone()).await;
    info!("Startup collector started");

    info!("All core components started");

    // ── Main event loop: route events + wait for shutdown ─────────
    loop {
        tokio::select! {
            Some(event) = rule_sub.receiver.recv() => {
                if sentinel_plugin_abuseipdb::enabled() {
                    if event.source == "network" {
                        if let Some(ref payload) = event.payload {
                            if let sentinel_events::event::Payload::NetworkEvent(ref ne) = payload {
                                if !ne.remote_addr.is_empty() {
                                    let ip = ne.remote_addr.clone();
                                    tokio::spawn(async move {
                                        sentinel_plugin_abuseipdb::check_ip(&ip).await;
                                    });
                                }
                            }
                        }
                    }
                }

                if sentinel_plugin_shodan::enabled() {
                    if event.source == "network" {
                        if let Some(ref payload) = event.payload {
                            if let sentinel_events::event::Payload::NetworkEvent(ref ne) = payload {
                                if !ne.remote_addr.is_empty() {
                                    let ip = ne.remote_addr.clone();
                                    tokio::spawn(async move {
                                        sentinel_plugin_shodan::lookup_host(&ip).await;
                                    });
                                }
                            }
                        }
                    }
                }

                let sanitized_event = Arc::new(privacy.sanitize_event(&event));

                let chain = correlation.ingest(&sanitized_event);

                let result = rule_engine.evaluate(&sanitized_event).await;
                if !result.matches.is_empty() {
                    info!(
                        "Rule engine: {} matches for event {} (type={}, {} rules in {:?})",
                        result.matches.len(), sanitized_event.id, sanitized_event.r#type,
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
                            &sanitized_event.source,
                            vec![sanitized_event.id.clone()],
                            Some(chain.id.clone()),
                        ) {
                            info!("  → ALERT [{}] {} (risk={})", alert.severity as i32, alert.rule_name, alert.risk_score);

                            // Persist alert
                            if let Err(e) = alert_mgr.create(
                                &alert.rule_id,
                                alert.risk_score,
                                m.severity,
                                alert.event_ids.clone(),
                                serde_json::json!({"chain_id": chain.id, "source": sanitized_event.source}),
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
                            let event_source = sanitized_event.source.clone();
                            let event_count = alert.event_ids.len();

                            if sentinel_plugin_discord::enabled() {
                                if let Some(url) = sentinel_plugin_discord::webhook_url() {
                                    let eid = alert_eid.clone();
                                    let name = alert_name.clone();
                                    let src = event_source.clone();
                                    let sev = severity_name.clone();
                                    tokio::spawn(async move {
                                        sentinel_plugin_discord::send_alert(
                                            &url,
                                            &eid,
                                            &name,
                                            alert_risk,
                                            &sev,
                                            &src,
                                            Some(&format!("{} events in chain", event_count)),
                                        ).await;
                                    });
                                }
                            }

                            if sentinel_plugin_telegram::enabled() {
                                if let (Some(token), Some(chat_id)) = (
                                    sentinel_plugin_telegram::bot_token(),
                                    sentinel_plugin_telegram::chat_id(),
                                ) {
                                    let eid = alert_eid.clone();
                                    let name = alert_name.clone();
                                    let src = event_source.clone();
                                    let sev = severity_name.clone();
                                    tokio::spawn(async move {
                                        sentinel_plugin_telegram::send_alert(
                                            &token,
                                            &chat_id,
                                            &eid,
                                            &name,
                                            alert_risk,
                                            &sev,
                                            &src,
                                            Some(&format!("{} events in chain", event_count)),
                                        ).await;
                                    });
                                }
                            }

                            if sentinel_plugin_home_assistant::enabled() {
                                let eid = alert_eid.clone();
                                let name = alert_name.clone();
                                let src = event_source.clone();
                                let sev = severity_name.clone();
                                tokio::spawn(async move {
                                    sentinel_plugin_home_assistant::send_alert(
                                        &eid, &name, alert_risk, &sev, &src,
                                        Some(&format!("{} events in chain", event_count)),
                                    ).await;
                                });
                            }

                            if sentinel_plugin_slack::enabled() {
                                let eid = alert_eid.clone();
                                let name = alert_name.clone();
                                let src = event_source.clone();
                                let sev = severity_name.clone();
                                tokio::spawn(async move {
                                    sentinel_plugin_slack::send_alert(
                                        &eid, &name, alert_risk, &sev, &src,
                                        Some(&format!("{} events in chain", event_count)),
                                    ).await;
                                });
                            }

                            if sentinel_plugin_email::enabled() {
                                let eid = alert_eid.clone();
                                let name = alert_name.clone();
                                let src = event_source.clone();
                                let sev = severity_name.clone();
                                tokio::spawn(async move {
                                    sentinel_plugin_email::send_alert(
                                        &eid, &name, alert_risk, &sev, &src,
                                        Some(&format!("{} events in chain", event_count)),
                                    ).await;
                                });
                            }
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

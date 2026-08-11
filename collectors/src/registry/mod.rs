//! Registry Collector — Monitors persistence mechanisms.
//!
//! Linux: scans systemd user services for new persistence entries.
//! Windows: monitors registry Run/RunOnce keys.

use std::collections::HashSet;
use std::sync::Arc;

use sentinel_core::traits::EventBus;
use sentinel_events::registry_event::{Action, Hive};
use sentinel_events::RegistryEvent;
use tracing::info;

#[cfg(target_os = "linux")]
pub async fn start_registry_monitor(
    bus: Arc<dyn EventBus>,
    registry: Arc<sentinel_core::CollectorRegistry>,
) {
    tokio::spawn(async move {
        registry.register(sentinel_core::CollectorStatus::new(
            "registry",
            "Registry Monitor",
            "Systemd user service persistence",
        ));
        let reg = registry.clone();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        tick.tick().await;
        let mut reported: HashSet<String> = HashSet::new();

        info!("Registry collector started (Linux persistence monitor, 1h interval)");

        loop {
            tick.tick().await;

            let user_services = dirs::home_dir()
                .map(|h| h.join(".config/systemd/user"))
                .filter(|p| p.exists());

            if let Some(dir) = user_services {
                if let Ok(rd) = std::fs::read_dir(&dir) {
                    for entry in rd.flatten() {
                        let path = entry.path();
                        let file_name = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();

                        if path.extension().map(|e| e == "service").unwrap_or(false)
                            && reported.insert(file_name.clone())
                        {
                            let event = sentinel_events::Event {
                                id: sentinel_core::Ulid::new().to_string(),
                                r#type: "sentinel.registry.persistence".into(),
                                source: "registry".into(),
                                timestamp: sentinel_core::now_proto_ts(),
                                ingest_timestamp: sentinel_core::now_proto_ts(),
                                severity: sentinel_events::Severity::Notice as i32,
                                risk_score: 15u32,
                                host_id: String::new(),
                                schema_version: 1,
                                payload: Some(sentinel_events::event::Payload::RegistryEvent(
                                    RegistryEvent {
                                        action: Action::SetValue as i32,
                                        hive: Hive::Hkcu as i32,
                                        key_path: format!("systemd/user/{}", file_name),
                                        value_name: String::new(),
                                        value_data: Some(
                                            sentinel_events::RegistryValueData::default(),
                                        ),
                                        old_value: String::new(),
                                    },
                                )),
                                tags: vec!["persistence".into(), "mitre:T1543".into()],
                                ..Default::default()
                            };
                            let _ = bus.publish(Arc::new(event)).await;
                            reg.increment_events("registry", 1);
                        }
                    }
                }
            }
        }
    });
}

#[cfg(not(target_os = "linux"))]
pub async fn start_registry_monitor(
    _bus: Arc<dyn EventBus>,
    _registry: Arc<sentinel_core::CollectorRegistry>,
) {
    tracing::info!("Registry collector: not supported on this platform");
}

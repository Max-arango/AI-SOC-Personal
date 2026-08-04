//! Process collector — netlink-based Linux implementation.

pub mod process_collector;
pub mod netlink_bindings;
pub mod netlink_monitor;
pub mod proc_reader;

use std::sync::Arc;

use sentinel_config::ProcessCollectorConfig;
use sentinel_core::traits::EventBus;
use sentinel_events::{Event, ProcessContext, UserContext};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use netlink_monitor::NetlinkMonitor;

/// Start the process monitor using CN_PROC netlink events.
///
/// If netlink is unavailable (permissions, kernel config), falls back
/// to `/proc` polling every 5 seconds.
pub async fn start_process_monitor(bus: Arc<dyn EventBus>) {
    let (netlink_tx, mut netlink_rx) = mpsc::unbounded_channel();
    let config = ProcessCollectorConfig::default();

    // ── Netlink monitor (spawned in blocking thread) ──────────────
    let started = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async move {
            let mut monitor = NetlinkMonitor::new();
            match monitor.connect() {
                Ok(()) => {
                    info!("CN_PROC netlink monitor connected");
                    monitor.run(netlink_tx).await;
                    true
                }
                Err(e) => {
                    warn!("Netlink CN_PROC unavailable: {e} — falling back to /proc polling");
                    false
                }
            }
        })
    });

    // ── Event converter: netlink → Sentinel Events → bus ─────────
    tokio::spawn(async move {
        let started = started.await.unwrap_or(false);

        if started {
            // Netlink mode: convert real-time events
            while let Some(nl_event) = netlink_rx.recv().await {
                if let Some(event) = process_collector::netlink_to_sentinel_event_inner(
                    &nl_event,
                    &config,
                ) {
                    if bus.publish(Arc::new(event)).await.is_err() {
                        break;
                    }
                }
            }
        } else {
            // Fallback mode: /proc polling
            info!("Process monitor running in fallback mode (/proc poll, 5s)");
            let mut known: std::collections::HashSet<u32> = std::collections::HashSet::new();
            let mut tick = tokio::time::interval(tokio::time::Duration::from_secs(5));
            tick.tick().await;

            loop {
                tick.tick().await;
                let entries = match std::fs::read_dir("/proc") {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                let mut current = std::collections::HashSet::new();
                for entry in entries.filter_map(|e| e.ok()) {
                    if let Some(pid_str) = entry.file_name().to_str() {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            current.insert(pid);
                            if !known.contains(&pid) {
                                let info = proc_reader::gather_pid_info(pid);
                                if info.ppid > 0 {
                                    let ev = Arc::new(Event {
                                        id: sentinel_core::Ulid::new().to_string(),
                                        r#type: "sentinel.process.create".into(),
                                        source: "process".into(),
                                        timestamp: sentinel_core::now_proto_ts(),
                                        ingest_timestamp: sentinel_core::now_proto_ts(),
                                        severity: sentinel_events::Severity::Info as i32,
                                        process: Some(ProcessContext {
                                            pid,
                                            ppid: info.ppid,
                                            name: info.name,
                                            path: info.exe_path,
                                            command_line: info.cmdline,
                                            sha256: info.sha256,
                                            user: Some(UserContext {
                                                sid: info.username.clone(),
                                                username: info.username,
                                                domain: String::new(),
                                                is_elevated: info.uid == 0,
                                                is_system: info.uid == 0,
                                            }),
                                            ..Default::default()
                                        }),
                                        ..Default::default()
                                    });
                                    let _ = bus.publish(ev).await;
                                }
                            }
                        }
                    }
                }
                known = current;
            }
        }
    });

    info!("Process collector started");
}

#![allow(dead_code)]

use std::fs;
use std::path::Path;
use std::sync::Arc;

use sentinel_core::traits::EventBus;
use sentinel_events::startup_event::{Action, Location};
use sentinel_events::{Event, StartupEvent};
use tracing::{debug, info};

fn scan_entries(location: Location, entries: Vec<(String, String)>) -> Vec<Event> {
    entries
        .into_iter()
        .map(|(name, command)| Event {
            id: sentinel_core::Ulid::new().to_string(),
            r#type: "sentinel.startup.add".into(),
            source: "startup".into(),
            severity: 3,
            risk_score: 15,
            host_id: String::new(),
            schema_version: 1,
            payload: Some(sentinel_events::event::Payload::StartupEvent(StartupEvent {
                action: Action::Add as i32,
                location: location as i32,
                name: name.clone(),
                command: command.clone(),
                arguments: String::new(),
                user: String::new(),
                is_signed: false,
                publisher: String::new(),
            })),
            tags: vec!["persistence".into(), format!("startup:{:?}", location)],
            ..Default::default()
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn scan_cron_jobs() -> Vec<(String, String)> {
    let mut entries = Vec::new();

    let cron_dirs = [
        "/etc/crontab",
        "/var/spool/cron",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ];

    for dir in &cron_dirs {
        let path = Path::new(dir);
        if !path.exists() {
            continue;
        }

        if path.is_file() {
            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    entries.push((
                        format!("cron:{}", path.file_name().unwrap_or_default().to_string_lossy()),
                        line.to_string(),
                    ));
                }
            }
        } else if path.is_dir() {
            if let Ok(rd) = fs::read_dir(path) {
                for entry in rd.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        entries.push((format!("cron:{}", name), content));
                    }
                }
            }
        }
    }

    entries
}

#[cfg(target_os = "linux")]
fn scan_systemd_services() -> Vec<(String, String)> {
    let mut entries = Vec::new();

    let systemd_dirs = ["/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"];

    let user_dir = dirs::config_dir().map(|mut p| {
        p.push("systemd");
        p.push("user");
        p
    });

    let dirs_to_scan: Vec<_> = systemd_dirs
        .iter()
        .map(Path::new)
        .chain(user_dir.as_deref())
        .collect();

    for dir in &dirs_to_scan {
        if !dir.exists() {
            continue;
        }
        if let Ok(rd) = fs::read_dir(dir) {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "service").unwrap_or(false) {
                    let name = path
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if let Ok(content) = fs::read_to_string(&path) {
                        entries.push((format!("systemd:{}", name), content));
                    }
                }
            }
        }
    }

    entries
}

fn scan_shell_profiles() -> Vec<(String, String)> {
    let mut entries = Vec::new();

    let home = dirs::home_dir();
    if let Some(ref home) = home {
        let profiles = [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".zprofile",
            ".config/fish/config.fish",
        ];

        for profile in &profiles {
            let path = home.join(profile);
            if path.exists() {
                if let Ok(content) = fs::read_to_string(&path) {
                    entries.push((format!("profile:{}", profile), content));
                }
            }
        }
    }

    entries
}

fn scan_xdg_autostart() -> Vec<(String, String)> {
    let mut entries = Vec::new();

    let autostart_dirs: Vec<_> = dirs::config_dir()
        .map(|mut p| {
            p.push("autostart");
            p
        })
        .into_iter()
        .chain(
            std::path::PathBuf::from("/etc/xdg/autostart")
                .exists()
                .then(|| std::path::PathBuf::from("/etc/xdg/autostart")),
        )
        .collect();

    for dir in &autostart_dirs {
        if !dir.exists() {
            continue;
        }
        if let Ok(rd) = fs::read_dir(dir) {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "desktop").unwrap_or(false) {
                    let name = path
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    if let Ok(content) = fs::read_to_string(&path) {
                        entries.push((format!("autostart:{}", name), content));
                    }
                }
            }
        }
    }

    entries
}

#[cfg(not(target_os = "linux"))]
fn scan_cron_jobs() -> Vec<(String, String)> {
    vec![]
}

#[cfg(not(target_os = "linux"))]
fn scan_systemd_services() -> Vec<(String, String)> {
    vec![]
}

pub async fn start_startup_monitor(bus: Arc<dyn EventBus>, registry: Arc<sentinel_core::CollectorRegistry>) {
    tokio::spawn(async move {
        registry.register(sentinel_core::CollectorStatus::new("startup", "Startup Monitor", "Startup collector"));
        let reg = registry.clone();
        info!("Startup collector started");

        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));

        let scan_fn = move || {
            let mut events = Vec::new();

            events.extend(scan_entries(Location::Cron, scan_cron_jobs()));
            events.extend(scan_entries(Location::Systemd, scan_systemd_services()));
            events.extend(scan_entries(Location::ProfileScript, scan_shell_profiles()));
            events.extend(scan_entries(Location::BrowserExtension, scan_xdg_autostart()));

            events
        };

        let events = scan_fn();
        let total = events.len();
        for event in events {
            let _ = bus.publish(Arc::new(event)).await;
                reg.increment_events("startup", 1);
            reg.increment_events("startup", 1);
        }
        info!("Startup collector: initial scan found {total} entries");

        loop {
            tick.tick().await;

            let events = scan_fn();
            let new_count = events.len();
            for event in events {
                let _ = bus.publish(Arc::new(event)).await;
                reg.increment_events("startup", 1);
            reg.increment_events("startup", 1);
            }
            debug!("Startup collector rescanned: {new_count} entries");
        }
    });
}

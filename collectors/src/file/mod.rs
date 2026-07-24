#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use sentinel_core::traits::EventBus;
use sentinel_events::file_event::Action;
use sentinel_events::{Event, FileAttributes, FileEvent};
use tracing::{debug, info};

const SENSITIVE_DIRS: &[&str] = &["/etc", "/tmp", "/var/log"];

fn scan_dir(dir: &Path, known: &mut HashMap<String, u64>) -> Vec<Event> {
    let mut events = Vec::new();
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return events,
    };

    for entry in rd.flatten() {
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();

        let metadata = match path.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if !metadata.is_file() {
            continue;
        }

        let mtime = metadata
            .modified()
            .map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            })
            .unwrap_or(0);

        let previous = known.insert(path_str.clone(), mtime);

        if previous.is_none() {
            events.push(file_create_event(&path_str, metadata.len()));
        } else if previous != Some(mtime) {
            events.push(file_modify_event(&path_str, metadata.len()));
        }
    }

    events
}

fn file_create_event(path: &str, size: u64) -> Event {
    Event {
        id: sentinel_core::Ulid::new().to_string(),
        r#type: "sentinel.file.create".into(),
        source: "file".into(),
        severity: 3,
        risk_score: 10,
        host_id: String::new(),
        schema_version: 1,
        payload: Some(sentinel_events::event::Payload::FileEvent(FileEvent {
            action: Action::Create as i32,
            path: path.into(),
            destination: String::new(),
            size,
            sha256: String::new(),
            entropy: String::new(),
            attributes: Some(FileAttributes::default()),
            is_executable: false,
            mime_type: String::new(),
            is_sensitive_path: true,
        })),
        tags: vec!["sensitive_path".into()],
        ..Default::default()
    }
}

fn file_modify_event(path: &str, size: u64) -> Event {
    Event {
        id: sentinel_core::Ulid::new().to_string(),
        r#type: "sentinel.file.modify".into(),
        source: "file".into(),
        severity: 3,
        risk_score: 15,
        host_id: String::new(),
        schema_version: 1,
        payload: Some(sentinel_events::event::Payload::FileEvent(FileEvent {
            action: Action::Modify as i32,
            path: path.into(),
            destination: String::new(),
            size,
            sha256: String::new(),
            entropy: String::new(),
            attributes: Some(FileAttributes::default()),
            is_executable: false,
            mime_type: String::new(),
            is_sensitive_path: true,
        })),
        tags: vec!["sensitive_path".into()],
        ..Default::default()
    }
}

pub async fn start_file_monitor(bus: Arc<dyn EventBus>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.tick().await;

        let mut known: HashMap<String, u64> = HashMap::new();

        info!("File collector started (60s poll interval)");

        loop {
            tick.tick().await;

            let mut total = 0u64;
            for dir in SENSITIVE_DIRS {
                let path = Path::new(dir);
                if !path.exists() {
                    continue;
                }
                let events = scan_dir(path, &mut known);
                total += events.len() as u64;
                for event in events {
                    let _ = bus.publish(Arc::new(event)).await;
                }
            }

            if total > 0 {
                debug!("File collector: {} new events", total);
            }
        }
    });
}

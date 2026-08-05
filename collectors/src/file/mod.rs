//! File Collector — Real-time file event monitoring.
//!
//! Uses Linux `fanotify` for kernel-level file event notifications
//! (create, modify, delete, execute) with automatic fallback to
//! directory polling when fanotify is unavailable.
//!
//! Ransomware detection: multiple `CLOSE_WRITE` events with high
//! entropy (>7.5) within a short window indicate possible encryption.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sentinel_core::traits::EventBus;
use sentinel_events::file_event::Action;
use sentinel_events::{Event, FileAttributes, FileEvent};
use tracing::{debug, info, warn};

mod fanotify_watcher;
mod file_hasher;

use fanotify_watcher::{FanotifyWatcher, FileAction, FileEvent as RawFileEvent};
use file_hasher::hash_file;

const DEFAULT_WATCH_PATHS: &[&str] = &[
    "/etc",
    "/tmp",
    "/var/log",
    "/var/spool/cron",
];

const MAX_HASH_BYTES: u64 = 10 * 1024 * 1024; // 10 MB
const RANSOMWARE_WINDOW: Duration = Duration::from_secs(10);
const RANSOMWARE_ENTROPY_THRESHOLD: f64 = 7.5;
const RANSOMWARE_MIN_FILES: usize = 3;

struct EntropyRecord {
    path: String,
    entropy: f64,
    timestamp: Instant,
}

pub async fn start_file_monitor(bus: Arc<dyn EventBus>) {
    tokio::spawn(async move {
        let watch_paths: Vec<PathBuf> = DEFAULT_WATCH_PATHS
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect();

        // Try fanotify first
        let mut watcher = FanotifyWatcher::new();
        if watcher.init(&watch_paths).is_ok() {
            info!(
                "File collector started (fanotify, {} paths)",
                watch_paths.len()
            );

            let (tx, rx) = std::sync::mpsc::channel::<RawFileEvent>();

            let watcher_handle = watcher;
            tokio::task::spawn_blocking(move || {
                watcher_handle.run_blocking(tx);
            });

            // Convert sync mpsc → async stream
            let (async_tx, mut async_rx) = tokio::sync::mpsc::unbounded_channel();
            tokio::spawn(async move {
                while let Ok(event) = rx.recv() {
                    if async_tx.send(event).is_err() {
                        break;
                    }
                }
            });

            run_event_loop(&bus, &mut async_rx, true).await;
        } else {
            warn!("Fanotify unavailable — falling back to directory polling (30s)");
            run_polling_loop(&bus, &watch_paths).await;
        }
    });
}

// ── Fanotify event loop ───────────────────────────────────────────

async fn run_event_loop(
    bus: &Arc<dyn EventBus>,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<RawFileEvent>,
    _fanotify_mode: bool,
) {
    let mut entropy_window: VecDeque<EntropyRecord> = VecDeque::new();

    while let Some(raw) = rx.recv().await {
        // Skip noisy dir-only events
        if raw.path.is_empty() || raw.path.ends_with('/') {
            continue;
        }

        // Hash suspicious files (executables, scripts, modified configs)
        let needs_hash = is_sensitive_path(&raw.path);
        let hash_result = if needs_hash {
            hash_file(&raw.path, MAX_HASH_BYTES).await
        } else {
            file_hasher::FileHashResult::empty()
        };

        if needs_hash && !hash_result.sha256.is_empty() {
            debug!(
                "Hashed {}: sha256={} entropy={} mime={}",
                raw.path,
                &hash_result.sha256[..16.min(hash_result.sha256.len())],
                hash_result.entropy,
                hash_result.mime_type,
            );
        }

        // Ransomware detection: track high-entropy CloseWrite events
        if raw.action == FileAction::CloseWrite && hash_result.entropy > RANSOMWARE_ENTROPY_THRESHOLD
        {
            entropy_window.push_back(EntropyRecord {
                path: raw.path.clone(),
                entropy: hash_result.entropy,
                timestamp: Instant::now(),
            });

            // Prune old records
            while entropy_window
                .front()
                .map(|r| r.timestamp.elapsed() > RANSOMWARE_WINDOW)
                .unwrap_or(false)
            {
                entropy_window.pop_front();
            }

            if entropy_window.len() >= RANSOMWARE_MIN_FILES {
                warn!(
                    "RANSOMWARE DETECTED: {} high-entropy file writes in {}s",
                    entropy_window.len(),
                    RANSOMWARE_WINDOW.as_secs(),
                );
                let paths: Vec<String> =
                    entropy_window.iter().map(|r| r.path.clone()).collect();
                let alert = build_ransomware_alert(&paths, entropy_window.len());
                let _ = bus.publish(Arc::new(alert)).await;
                entropy_window.clear();
            }
        }

        let severity = match raw.action {
            FileAction::Exec => sentinel_events::Severity::Notice as i32,
            FileAction::Delete => sentinel_events::Severity::Warning as i32,
            FileAction::CloseWrite if hash_result.entropy > 6.0 => {
                sentinel_events::Severity::Notice as i32
            }
            _ => sentinel_events::Severity::Info as i32,
        };

        let risk = match raw.action {
            FileAction::Exec if is_sensitive_path(&raw.path) => 35u32,
            FileAction::Delete if is_sensitive_path(&raw.path) => 50u32,
            FileAction::CloseWrite if hash_result.entropy > 7.0 => 40u32,
            FileAction::CloseWrite => 10u32,
            FileAction::Modify if is_sensitive_path(&raw.path) => 20u32,
            _ => 5u32,
        };

        let action = match raw.action {
            FileAction::Open => Action::Read,
            FileAction::Modify => Action::Modify,
            FileAction::CloseWrite => Action::Write,
            FileAction::Delete => Action::Delete,
            FileAction::Exec => Action::Execute,
        };

        let mut tags = Vec::new();

        if is_sensitive_path(&raw.path) {
            tags.push("sensitive_path".into());
        }
        if hash_result.entropy > RANSOMWARE_ENTROPY_THRESHOLD {
            tags.push(format!("high_entropy:{:.1}", hash_result.entropy));
        }
        if raw.action == FileAction::Exec {
            tags.push("executable".into());
        }
        if !hash_result.mime_type.is_empty() {
            tags.push(format!("mime:{}", hash_result.mime_type));
        }

        let file_event = FileEvent {
            action: action as i32,
            path: raw.path.clone(),
            destination: String::new(),
            size: hash_result.size,
            sha256: hash_result.sha256,
            entropy: if hash_result.entropy > 0.0 {
                format!("{:.2}", hash_result.entropy)
            } else {
                String::new()
            },
            attributes: Some(FileAttributes {
                readonly: false,
                hidden: false,
                system: false,
                archive: false,
                compressed: false,
                encrypted: hash_result.entropy > 7.0,
                ..Default::default()
            }),
            is_executable: raw.action == FileAction::Exec
                || hash_result.mime_type.contains("x-elf")
                || hash_result.mime_type.contains("x-mach-o")
                || hash_result.mime_type.contains("dosexec")
                || hash_result.mime_type.contains("shellscript"),
            mime_type: hash_result.mime_type,
            is_sensitive_path: is_sensitive_path(&raw.path),
        };

        let event = Arc::new(Event {
            id: sentinel_core::Ulid::new().to_string(),
            r#type: format!("sentinel.file.{:?}", raw.action).to_lowercase(),
            source: "file".into(),
            timestamp: sentinel_core::now_proto_ts(),
            ingest_timestamp: sentinel_core::now_proto_ts(),
            severity,
            risk_score: risk,
            host_id: String::new(),
            schema_version: 1,
            process: if raw.pid > 0 {
                Some(sentinel_events::ProcessContext {
                    pid: raw.pid as u32,
                    name: String::new(),
                    ..Default::default()
                })
            } else {
                None
            },
            payload: Some(sentinel_events::event::Payload::FileEvent(file_event)),
            tags,
            ..Default::default()
        });

        if bus.publish(event).await.is_err() {
            break;
        }
    }
}

// ── Polling fallback ──────────────────────────────────────────────

async fn run_polling_loop(bus: &Arc<dyn EventBus>, watch_paths: &[PathBuf]) {
    let mut known: HashMap<String, (u64, u64)> = HashMap::new(); // path → (mtime, size)
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.tick().await;

    info!(
        "File collector running in polling mode ({} paths)",
        watch_paths.len()
    );

    loop {
        tick.tick().await;
        let mut total = 0u64;

        for dir in watch_paths {
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
            debug!("File poll: {} events", total);
        }
    }
}

fn scan_dir(dir: &Path, known: &mut HashMap<String, (u64, u64)>) -> Vec<Event> {
    let mut events = Vec::new();
    let rd = match std::fs::read_dir(dir) {
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
            .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
            .unwrap_or(0);

        let size = metadata.len();

        if let Some(&(prev_mtime, prev_size)) = known.get(&path_str) {
            if prev_mtime != mtime || prev_size != size {
                events.push(build_poll_event(
                    &path_str,
                    size,
                    sentinel_events::file_event::Action::Modify,
                ));
                known.insert(path_str, (mtime, size));
            }
        } else {
            events.push(build_poll_event(
                &path_str,
                size,
                sentinel_events::file_event::Action::Create,
            ));
            known.insert(path_str, (mtime, size));
        }
    }

    // Detect deleted files (in known but not on disk)
    let current_paths: std::collections::HashSet<String> = events
        .iter()
        .filter_map(|e| {
            if let Some(sentinel_events::event::Payload::FileEvent(ref fe)) = e.payload {
                Some(fe.path.clone())
            } else {
                None
            }
        })
        .collect();

    let deleted: Vec<String> = known
        .keys()
        .filter(|k| !current_paths.contains(*k))
        .cloned()
        .collect();

    for path in &deleted {
        events.push(build_poll_event(
            path,
            0,
            sentinel_events::file_event::Action::Delete,
        ));
        known.remove(path);
    }

    events
}

fn build_poll_event(path: &str, size: u64, action: sentinel_events::file_event::Action) -> Event {
    Event {
        id: sentinel_core::Ulid::new().to_string(),
        r#type: match action {
            sentinel_events::file_event::Action::Create => "sentinel.file.create",
            sentinel_events::file_event::Action::Modify => "sentinel.file.modify",
            sentinel_events::file_event::Action::Delete => "sentinel.file.delete",
            _ => "sentinel.file.modify",
        }
        .into(),
        source: "file".into(),
        severity: sentinel_events::Severity::Info as i32,
        risk_score: 10,
        host_id: String::new(),
        schema_version: 1,
        payload: Some(sentinel_events::event::Payload::FileEvent(FileEvent {
            action: action as i32,
            path: path.into(),
            size,
            is_sensitive_path: is_sensitive_path(path),
            ..Default::default()
        })),
        tags: vec!["polling_mode".into()],
        ..Default::default()
    }
}

// ── Ransomware alert ──────────────────────────────────────────────

fn build_ransomware_alert(paths: &[String], count: usize) -> Event {
    Event {
        id: sentinel_core::Ulid::new().to_string(),
        r#type: "sentinel.file.ransomware".into(),
        source: "file".into(),
        timestamp: sentinel_core::now_proto_ts(),
        ingest_timestamp: sentinel_core::now_proto_ts(),
        severity: sentinel_events::Severity::Critical as i32,
        risk_score: 95u32,
        host_id: String::new(),
        schema_version: 1,
        payload: Some(sentinel_events::event::Payload::FileEvent(FileEvent {
            action: Action::Write as i32,
            path: paths.first().cloned().unwrap_or_default(),
            entropy: format!("{}_files", count),
            is_sensitive_path: true,
            attributes: Some(FileAttributes {
                encrypted: true,
                ..Default::default()
            }),
            ..Default::default()
        })),
        tags: vec![
            "ransomware".into(),
            "mitre:T1486".into(),
            format!("files_encrypted:{}", count),
        ],
        ..Default::default()
    }
}

// ── Helpers ───────────────────────────────────────────────────────

fn is_sensitive_path(path: &str) -> bool {
    path.starts_with("/etc/")
        || path.starts_with("/tmp/")
        || path.starts_with("/var/log/")
        || path.starts_with("/var/spool/cron/")
        || path.contains("/.ssh/")
        || path.contains("/.bash")
        || path.contains("/.zsh")
        || path.contains("/.profile")
        || path.ends_with(".sh")
        || path.ends_with(".py")
        || path.ends_with(".rb")
        || path.ends_with(".pl")
        || path.ends_with(".php")
        || path.ends_with(".so")
        || path.ends_with(".service")
        || path.ends_with(".timer")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sensitive_paths() {
        assert!(is_sensitive_path("/etc/passwd"));
        assert!(is_sensitive_path("/tmp/malware.sh"));
        assert!(is_sensitive_path("/home/user/.ssh/authorized_keys"));
        assert!(is_sensitive_path("/root/.bashrc"));
    }

    #[test]
    fn ignores_normal_paths() {
        assert!(!is_sensitive_path("/home/user/Documents/report.txt"));
        assert!(!is_sensitive_path("/usr/share/icons/icon.png"));
        assert!(!is_sensitive_path("/opt/app/config.toml"));
    }

    #[test]
    fn script_extensions_are_sensitive() {
        assert!(is_sensitive_path("/tmp/script.sh"));
        assert!(is_sensitive_path("/var/tmp/exploit.py"));
        assert!(is_sensitive_path("/dev/shm/backdoor.pl"));
    }

    #[test]
    fn service_files_are_sensitive() {
        assert!(is_sensitive_path("/etc/systemd/system/evil.service"));
        assert!(is_sensitive_path("/tmp/persistence.timer"));
    }
}

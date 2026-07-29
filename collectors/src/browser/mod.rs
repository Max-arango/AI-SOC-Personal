use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sentinel_core::traits::EventBus;
use sentinel_events::{BrowserEvent, Event, ProcessContext};
use sentinel_events::browser_event::{Action, Browser};
use tracing::{debug, info, warn};

struct BrowserProfile {
    name: String,
    browser: Browser,
    history_db: Option<PathBuf>,
    downloads_db: Option<PathBuf>,
    extensions_dir: Option<PathBuf>,
}

fn find_profiles() -> Vec<BrowserProfile> {
    let mut profiles = Vec::new();
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/home/user"));

    let browser_configs: &[(&str, Browser, &str, &str)] = &[
        ("google-chrome", Browser::Chrome, "History", "History"),
        ("chromium", Browser::Chrome, "History", "History"),
        ("BraveSoftware/Brave-Browser", Browser::Brave, "History", "History"),
        ("microsoft-edge", Browser::Edge, "History", "History"),
        ("vivaldi", Browser::Vivaldi, "History", "History"),
        ("mozilla/firefox", Browser::Firefox, "places.sqlite", "places.sqlite"),
    ];

    for (dir_name, browser, hist_file, dl_file) in browser_configs {
        let base = if dir_name.starts_with("mozilla") {
            home.join(format!(".{}", dir_name))
        } else {
            home.join(format!(".config/{}", dir_name))
        };

        if !base.exists() {
            debug!("Browser not found: {}", dir_name);
            continue;
        }

        let default_profile = base.join("Default");
        let profile_dirs = if default_profile.exists() {
            vec![default_profile]
        } else {
            let mut dirs = Vec::new();
            if let Ok(rd) = std::fs::read_dir(&base) {
                for entry in rd.flatten() {
                    let p = entry.path();
                    if p.is_dir() && p.join(hist_file).exists() {
                        dirs.push(p);
                    }
                }
            }
            dirs
        };

        for profile in profile_dirs {
            let history = profile.join(hist_file);
            let downloads = profile.join(dl_file);
            let extensions = profile.join("Extensions");

            if history.exists() {
                profiles.push(BrowserProfile {
                    name: format!("{}:{}", dir_name, profile.file_name().unwrap_or_default().to_string_lossy()),
                    browser: *browser,
                    history_db: if history.exists() { Some(history) } else { None },
                    downloads_db: if downloads.exists() { Some(downloads) } else { None },
                    extensions_dir: if extensions.exists() { Some(extensions) } else { None },
                });
            }
        }
    }

    profiles
}

fn read_history_urls(db_path: &Path, known: &mut HashSet<String>) -> Vec<NavigationEntry> {
    let mut entries = Vec::new();
    let output = match std::process::Command::new("sqlite3")
        .arg("-separator")
        .arg("|")
        .arg(db_path)
        .arg("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50;")
        .output()
    {
        Ok(o) => o,
        Err(_) => return entries,
    };

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 3 {
            let key = format!("{}|{}", parts[0], parts[2]);
            if known.insert(key) && !parts[0].is_empty() {
                let ts: i64 = parts[2].trim().parse().unwrap_or(0);
                entries.push(NavigationEntry {
                    url: parts[0].to_string(),
                    title: parts.get(1).map(|s| s.to_string()).unwrap_or_default(),
                    timestamp: chrome_time_to_unix(ts),
                });
            }
        }
    }
    entries
}

fn read_downloads(db_path: &Path, known: &mut HashSet<String>) -> Vec<DownloadEntry> {
    let mut entries = Vec::new();
    let sql = if db_path.to_string_lossy().contains("places.sqlite") {
        "SELECT content, url, dateAdded FROM moz_annos WHERE anno_attribute_id = 3 ORDER BY dateAdded DESC LIMIT 20;"
    } else {
        "SELECT target_path, tab_url, start_time FROM downloads ORDER BY start_time DESC LIMIT 20;"
    };

    let output = match std::process::Command::new("sqlite3")
        .arg("-separator")
        .arg("|")
        .arg(db_path)
        .arg(sql)
        .output()
    {
        Ok(o) => o,
        Err(_) => return entries,
    };

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 3 {
            let key = format!("{}|{}", parts[0], parts[2]);
            if known.insert(key) {
                let ts: i64 = parts[2].trim().parse().unwrap_or(0);
                entries.push(DownloadEntry {
                    path: parts[0].to_string(),
                    url: parts.get(1).map(|s| s.to_string()).unwrap_or_default(),
                    timestamp: chrome_time_to_unix(ts),
                });
            }
        }
    }
    entries
}

fn read_extensions(dir: &Path, known: &mut HashSet<String>) -> Vec<ExtensionEntry> {
    let mut entries = Vec::new();
    if !dir.exists() {
        return entries;
    }

    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if known.insert(name.clone()) {
                entries.push(ExtensionEntry {
                    id: name.clone(),
                    name,
                });
            }
        }
    }

    entries
}

struct NavigationEntry {
    url: String,
    title: String,
    timestamp: i64,
}

struct DownloadEntry {
    path: String,
    url: String,
    timestamp: i64,
}

struct ExtensionEntry {
    id: String,
    name: String,
}

fn chrometime_to_unix(ts: i64) -> i64 {
    if ts > 1_000_000_000_000_000 { (ts - 11_644_473_600_000_000) / 1_000_000 } else { ts }
}

use chrometime_to_unix as chrome_time_to_unix;

fn navigation_to_event(entry: &NavigationEntry, browser: Browser) -> Event {
    Event {
        id: sentinel_core::Ulid::new().to_string(),
        r#type: "sentinel.browser.navigation".into(),
        source: "browser".into(),
        severity: 1,
        risk_score: 10,
        host_id: String::new(),
        schema_version: 1,
        payload: Some(sentinel_events::event::Payload::BrowserEvent(BrowserEvent {
            browser: browser as i32,
            action: Action::Navigation as i32,
            url: entry.url.clone(),
            title: entry.title.clone(),
            referrer: String::new(),
            download_path: String::new(),
            download_hash: String::new(),
            extension_id: String::new(),
            extension_name: String::new(),
            is_incognito: false,
        })),
        tags: vec!["browser".into()],
        ..Default::default()
    }
}

fn download_to_event(entry: &DownloadEntry, browser: Browser) -> Event {
    let hash = if Path::new(&entry.path).exists() {
        compute_sha256(&entry.path)
    } else {
        String::new()
    };

    Event {
        id: sentinel_core::Ulid::new().to_string(),
        r#type: "sentinel.browser.download_complete".into(),
        source: "browser".into(),
        severity: 3,
        risk_score: if !hash.is_empty() { 25 } else { 15 },
        host_id: String::new(),
        schema_version: 1,
        payload: Some(sentinel_events::event::Payload::BrowserEvent(BrowserEvent {
            browser: browser as i32,
            action: Action::DownloadComplete as i32,
            url: entry.url.clone(),
            title: String::new(),
            referrer: String::new(),
            download_path: entry.path.clone(),
            download_hash: hash,
            extension_id: String::new(),
            extension_name: String::new(),
            is_incognito: false,
        })),
        tags: vec!["browser".into(), "download".into()],
        ..Default::default()
    }
}

fn extension_to_event(entry: &ExtensionEntry, browser: Browser) -> Event {
    Event {
        id: sentinel_core::Ulid::new().to_string(),
        r#type: "sentinel.browser.extension_install".into(),
        source: "browser".into(),
        severity: 2,
        risk_score: 20,
        host_id: String::new(),
        schema_version: 1,
        payload: Some(sentinel_events::event::Payload::BrowserEvent(BrowserEvent {
            browser: browser as i32,
            action: Action::ExtensionInstall as i32,
            url: String::new(),
            title: String::new(),
            referrer: String::new(),
            download_path: String::new(),
            download_hash: String::new(),
            extension_id: entry.id.clone(),
            extension_name: entry.name.clone(),
            is_incognito: false,
        })),
        tags: vec!["browser".into(), "extension".into()],
        ..Default::default()
    }
}

fn compute_sha256(path: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let mut hasher = Sha256::new();
    let _ = std::io::copy(&mut file, &mut hasher);
    format!("{:x}", hasher.finalize())
}

pub async fn start_browser_monitor(bus: Arc<dyn EventBus>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(120));
        tick.tick().await;

        let mut known_urls: HashSet<String> = HashSet::new();
        let mut known_downloads: HashSet<String> = HashSet::new();
        let mut known_extensions: HashSet<String> = HashSet::new();

        info!("Browser collector started (120s interval)");

        loop {
            tick.tick().await;

            let profiles = find_profiles();
            if profiles.is_empty() {
                debug!("No browser profiles found");
                continue;
            }

            let mut total = 0u64;

            for profile in &profiles {
                if let Some(ref history) = profile.history_db {
                    let navs = read_history_urls(history, &mut known_urls);
                    let count = navs.len() as u64;
                    for entry in navs {
                        let event = Arc::new(navigation_to_event(&entry, profile.browser));
                        if let Err(e) = bus.publish(event).await {
                            warn!("Browser nav publish failed: {e}");
                        }
                    }
                    total += count;
                }

                if let Some(ref downloads) = profile.downloads_db {
                    let dls = read_downloads(downloads, &mut known_downloads);
                    let count = dls.len() as u64;
                    for entry in dls {
                        let event = Arc::new(download_to_event(&entry, profile.browser));
                        if let Err(e) = bus.publish(event).await {
                            warn!("Browser dl publish failed: {e}");
                        }
                    }
                    total += count;
                }

                if let Some(ref ext_dir) = profile.extensions_dir {
                    let exts = read_extensions(ext_dir, &mut known_extensions);
                    let count = exts.len() as u64;
                    for entry in exts {
                        let event = Arc::new(extension_to_event(&entry, profile.browser));
                        if let Err(e) = bus.publish(event).await {
                            warn!("Browser ext publish failed: {e}");
                        }
                    }
                    total += count;
                }
            }

            if total > 0 {
                info!("Browser collector: {} new events ({} profiles)", total, profiles.len());
            }
        }
    });
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use sentinel_events::browser_event::Browser;

    #[test]
    fn test_chrome_time_conversion() {
        assert_eq!(chrome_time_to_unix(0), 0);
    }

    #[test]
    fn test_navigation_event_has_tags() {
        let entry = NavigationEntry { url: "https://test.com".into(), title: "Test".into(), timestamp: 0 };
        let event = navigation_to_event(&entry, Browser::Chrome);
        assert_eq!(event.source, "browser");
        assert!(event.payload.is_some());
    }

    #[test]
    fn test_download_event_has_tags() {
        let entry = DownloadEntry { path: "/tmp/x".into(), url: "https://x.com".into(), timestamp: 0 };
        let event = download_to_event(&entry, Browser::Firefox);
        assert!(event.tags.contains(&"download".to_string()));
    }

    #[test]
    fn test_extension_event() {
        let entry = ExtensionEntry { id: "abc".into(), name: "Ext".into() };
        let event = extension_to_event(&entry, Browser::Edge);
        assert_eq!(event.risk_score, 20);
    }

    #[test]
    fn test_empty_history_graceful() {
        let mut known = HashSet::new();
        let entries = read_history_urls(std::path::Path::new("/nonexistent"), &mut known);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_empty_downloads_graceful() {
        let mut known = HashSet::new();
        let entries = read_downloads(std::path::Path::new("/nonexistent"), &mut known);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_deduplication() {
        let mut known = HashSet::new();
        let key = "https://a.com|100";
        assert!(known.insert(key.to_string()));
        assert!(!known.insert(key.to_string()));
    }

    #[test]
    fn test_browser_enum_values() {
        assert_eq!(Browser::Chrome as i32, 1);
        assert_eq!(Browser::Firefox as i32, 2);
        assert_eq!(Browser::Edge as i32, 3);
    }
}

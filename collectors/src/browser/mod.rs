//! Browser Collector — Monitors browser history, downloads, and
//! extensions across Chrome, Firefox, Edge, Brave, Opera, Vivaldi.
//!
//! Features:
//! - Incremental scanning via `last_max_timestamp` per profile
//! - DB lock handling: copies SQLite to temp dir before reading
//! - Extension risk: checks against known malicious extension IDs
//! - Suspicious download detection: multiple risky files in window
//! - IP-based URL detection (phishing/exploit kit indicator)
//! - Snap + Flatpak browser support

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sentinel_core::traits::EventBus;
use sentinel_events::browser_event::{Action, Browser};
use sentinel_events::{BrowserEvent, Event};
use tracing::{debug, info, warn};

const POLL_INTERVAL: Duration = Duration::from_secs(120);
const SUSPICIOUS_DL_WINDOW: Duration = Duration::from_secs(300); // 5 min
const SUSPICIOUS_DL_THRESHOLD: usize = 3;
const MAX_DB_COPY_BYTES: u64 = 100 * 1024 * 1024; // 100 MB limit

// ── Malicious extension IDs (known info-stealers, adware) ─────────

const MALICIOUS_EXTENSIONS: &[&str] = &[
    "kfclfkdkobhcchbhmfdboddphkfoakdg", // Fake adblock
    "lkdpbfpmehkdggjmhlncopmbkgbmjgej", // Search hijacker
    "lfcgiflbpkgedpohgffeeamcegfkined", // Clipboard stealer
    "cmfefdghcnmejmhoeknhkpodpfjflkod", // Session hijacker
    "jlgmijgohgphlgmpppeighedppkgpifh", // Credential stealer
    "hnmpcagpplbolnmiinmjdfbcepgkcoph", // Browser hijacker
    "pglamkbkmhmjjnakjclciigehbmbninj", // Form grabber
];

const SUSPICIOUS_TLDS: &[&str] = &[
    ".tk", ".ml", ".ga", ".cf", ".gq",  // Freenom (abused)
    ".xyz", ".top", ".club", ".work", ".click",
    ".download", ".review", ".country", ".stream",
];

const DANGEROUS_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".msi", ".scr", ".ps1",
    ".bat", ".cmd", ".vbs", ".js", ".hta",
    ".sh", ".shs", ".app", ".dmg", ".pkg",
    ".deb", ".rpm", ".apk", ".jar",
];

struct BrowserProfile {
    name: String,
    browser: Browser,
    history_db: Option<PathBuf>,
    downloads_db: Option<PathBuf>,
    extensions_dir: Option<PathBuf>,
    last_history_ts: i64,
    last_downloads_ts: i64,
}

impl BrowserProfile {
    fn profile_dir_name(&self) -> String {
        self.name.clone()
    }
}

// ── Profile discovery ─────────────────────────────────────────────

fn find_profiles() -> Vec<BrowserProfile> {
    let mut profiles = Vec::new();
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/home/user"));

    let browser_configs: &[(&str, Browser, &str, &str, &str)] = &[
        // (relative_path, browser, history_file, downloads_file, profile_subdir)
        ("google-chrome",            Browser::Chrome,  "History",       "History", ".config"),
        ("chromium",                 Browser::Chrome,  "History",       "History", ".config"),
        ("BraveSoftware/Brave-Browser", Browser::Brave, "History",    "History", ".config"),
        ("microsoft-edge",           Browser::Edge,    "History",       "History", ".config"),
        ("vivaldi",                  Browser::Vivaldi, "History",       "History", ".config"),
        ("opera",                    Browser::Opera,   "History",       "History", ".config"),
        ("mozilla/firefox",          Browser::Firefox, "places.sqlite", "places.sqlite", "."),
        // Snap packages
        ("snap/chromium/common/chromium", Browser::Chrome, "Default/History", "Default/History", "snap"),
        ("snap/firefox/common/.mozilla/firefox", Browser::Firefox, "places.sqlite", "places.sqlite", "snap"),
        ("snap/opera/common/opera",  Browser::Opera,   "History",       "History", "snap"),
        ("snap/brave/common/brave",  Browser::Brave,   "History",       "History", "snap"),
        // Flatpak
        ("var/app/com.google.Chrome/config/google-chrome", Browser::Chrome, "Default/History", "Default/History", ".local/share/flatpak/exports/share"),
        ("var/app/org.mozilla.firefox/.mozilla/firefox",   Browser::Firefox, "places.sqlite",   "places.sqlite", ".local/share/flatpak/exports/share"),
    ];

    for (dir_name, browser, hist_file, dl_file, prefix) in browser_configs {
        let base = resolve_browser_base(&home, dir_name, prefix);
        if !base.exists() {
            continue;
        }

        for profile in discover_profiles(&base, hist_file) {
            let history = profile.join(hist_file);
            if history.exists() {
                let downloads = profile.join(dl_file);
                profiles.push(BrowserProfile {
                    name: format!(
                        "{}:{}",
                        dir_name,
                        profile.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    browser: *browser,
                    history_db: Some(history),
                    downloads_db: if downloads.exists() { Some(downloads) } else { None },
                    extensions_dir: Some(profile.join("Extensions")),
                    last_history_ts: 0,
                    last_downloads_ts: 0,
                });
            }
        }
    }

    info!("Found {} browser profiles", profiles.len());
    profiles
}

fn resolve_browser_base(home: &Path, dir_name: &str, prefix: &str) -> PathBuf {
    match prefix {
        ".config" => home.join(".config").join(dir_name),
        "." => home.join(format!(".{}", dir_name)),
        "snap" => home.join(dir_name),
        ".local/share/flatpak/exports/share" => {
            let flatpak_base = PathBuf::from("/var/lib/flatpak/exports/share");
            if flatpak_base.join(dir_name).exists() {
                flatpak_base.join(dir_name)
            } else {
                home.join(".local/share/flatpak/exports/share").join(dir_name)
            }
        }
        _ => home.join(dir_name),
    }
}

fn discover_profiles(base: &Path, hist_file: &str) -> Vec<PathBuf> {
    let default = base.join("Default");
    if default.join(hist_file).exists() {
        return vec![default];
    }

    // Firefox: find profiles.ini subdirectories
    let profiles_ini = base.join("profiles.ini");
    if profiles_ini.exists() {
        if let Ok(content) = std::fs::read_to_string(&profiles_ini) {
            let mut dirs = Vec::new();
            for line in content.lines() {
                if line.starts_with("Path=") {
                    let rel = &line[5..];
                    let abs = base.join(rel);
                    if abs.join(hist_file).exists() {
                        dirs.push(abs);
                    }
                }
            }
            if !dirs.is_empty() {
                return dirs;
            }
        }
    }

    // Generic: any subdirectory with the history file
    let mut dirs = Vec::new();
    if let Ok(rd) = std::fs::read_dir(base) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() && p.join(hist_file).exists() {
                dirs.push(p);
            }
        }
    }
    dirs
}

// ── DB reading with lock protection ───────────────────────────────

fn safe_read_db<T>(
    db_path: &Path,
    known: &mut HashSet<String>,
    last_ts: &mut i64,
    query_fn: &dyn Fn(&Path, &mut HashSet<String>, &mut i64) -> Vec<T>,
) -> Vec<T> {
    // Try direct read first
    let result = query_fn(db_path, known, last_ts);
    if !result.is_empty() || !db_path.exists() {
        return result;
    }

    // DB might be locked — copy to temp
    let tmp = std::env::temp_dir().join(format!(
        "sentinel_browser_{}_{}",
        db_path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));

    if let Ok(meta) = std::fs::metadata(db_path) {
        if meta.len() > MAX_DB_COPY_BYTES {
            debug!("Skipping large DB: {} ({})", db_path.display(), meta.len());
            return vec![];
        }
    }

    match std::fs::copy(db_path, &tmp) {
        Ok(_) => {
            let result = query_fn(&tmp, known, last_ts);
            let _ = std::fs::remove_file(&tmp);
            result
        }
        Err(e) => {
            debug!("Failed to copy browser DB {}: {e}", db_path.display());
            vec![]
        }
    }
}

// ── History reader (incremental) ──────────────────────────────────

#[derive(Clone)]
struct NavigationEntry {
    url: String,
    title: String,
    timestamp: i64,
}

fn read_history_incremental(
    db_path: &Path,
    known: &mut HashSet<String>,
    last_ts: &mut i64,
) -> Vec<NavigationEntry> {
    let mut entries = Vec::new();
    let check_ts = *last_ts;
    let sql = format!(
        "SELECT url, title, last_visit_time FROM urls WHERE last_visit_time > {} ORDER BY last_visit_time DESC LIMIT 100;",
        check_ts
    );

    let output = match std::process::Command::new("sqlite3")
        .args(["-readonly", "-separator", "|", "-cmd", ".timeout 5000"])
        .arg(db_path)
        .arg(&sql)
        .output()
    {
        Ok(o) => o,
        Err(_) => return entries,
    };

    let mut max_ts = *last_ts;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 3 && !parts[0].is_empty() {
            let key = format!("{}|{}", parts[0], parts[2]);
            if known.insert(key) {
                let ts: i64 = parts[2].trim().parse().unwrap_or(0);
                let unix = chrome_time_to_unix(ts);
                entries.push(NavigationEntry {
                    url: parts[0].to_string(),
                    title: parts.get(1).map(|s| s.to_string()).unwrap_or_default(),
                    timestamp: unix,
                });
                if ts > max_ts {
                    max_ts = ts;
                }
            }
        }
    }

    *last_ts = max_ts;
    entries
}

// ── Downloads reader (incremental) ────────────────────────────────

#[derive(Clone)]
struct DownloadEntry {
    path: String,
    url: String,
    timestamp: i64,
}

fn read_downloads_incremental(
    db_path: &Path,
    known: &mut HashSet<String>,
    last_ts: &mut i64,
) -> Vec<DownloadEntry> {
    let mut entries = Vec::new();
    let check_ts = *last_ts;

    let sql = if db_path.to_string_lossy().contains("places.sqlite") {
        format!(
            "SELECT content, url, dateAdded FROM moz_annos WHERE anno_attribute_id = 3 AND dateAdded > {} ORDER BY dateAdded DESC LIMIT 50;",
            check_ts
        )
    } else {
        format!(
            "SELECT target_path, tab_url, start_time FROM downloads WHERE start_time > {} ORDER BY start_time DESC LIMIT 50;",
            check_ts
        )
    };

    let output = match std::process::Command::new("sqlite3")
        .args(["-readonly", "-separator", "|", "-cmd", ".timeout 5000"])
        .arg(db_path)
        .arg(&sql)
        .output()
    {
        Ok(o) => o,
        Err(_) => return entries,
    };

    let mut max_ts = *last_ts;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 3 {
            let key = format!("{}|{}", parts[0], parts[2]);
            if known.insert(key) {
                let ts: i64 = parts[2].trim().parse().unwrap_or(0);
                let unix = chrome_time_to_unix(ts);
                entries.push(DownloadEntry {
                    path: parts[0].to_string(),
                    url: parts.get(1).map(|s| s.to_string()).unwrap_or_default(),
                    timestamp: unix,
                });
                if ts > max_ts {
                    max_ts = ts;
                }
            }
        }
    }

    *last_ts = max_ts;
    entries
}

// ── Extensions reader ─────────────────────────────────────────────

#[derive(Clone)]
struct ExtensionEntry {
    id: String,
    name: String,
}

fn read_extensions(dir: &Path, known: &mut HashSet<String>) -> Vec<ExtensionEntry> {
    if !dir.exists() {
        return vec![];
    }

    let mut entries = Vec::new();
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

// ── Detection helpers ─────────────────────────────────────────────

fn is_malicious_extension(ext_id: &str) -> bool {
    MALICIOUS_EXTENSIONS.contains(&ext_id)
}

fn url_has_ip_address(url: &str) -> bool {
    // Check if URL host portion is an IP address
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("");

    host.parse::<std::net::IpAddr>().is_ok()
}

fn url_has_suspicious_tld(url: &str) -> bool {
    let lower = url.to_lowercase();
    let domain = lower
        .split("://")
        .nth(1)
        .unwrap_or(&lower)
        .split('/')
        .next()
        .unwrap_or("");

    SUSPICIOUS_TLDS.iter().any(|tld| domain.ends_with(tld))
}

fn is_dangerous_download(path: &str) -> bool {
    let lower = path.to_lowercase();
    DANGEROUS_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

fn chrome_time_to_unix(ts: i64) -> i64 {
    if ts > 1_000_000_000_000_000 {
        (ts - 11_644_473_600_000_000) / 1_000_000
    } else {
        ts
    }
}

// ── Event builders ────────────────────────────────────────────────

fn navigation_to_event(entry: &NavigationEntry, browser: Browser) -> Event {
    let mut risk = 5u32;
    let mut tags = vec!["browser".to_string()];

    if url_has_ip_address(&entry.url) {
        risk += 15;
        tags.push("ip_url".into());
    }

    if url_has_suspicious_tld(&entry.url) {
        risk += 10;
        tags.push("suspicious_tld".into());
    }

    Event {
        id: sentinel_core::Ulid::new().to_string(),
        r#type: "sentinel.browser.navigation".into(),
        source: "browser".into(),
        severity: if risk > 10 { sentinel_events::Severity::Notice as i32 } else { sentinel_events::Severity::Debug as i32 },
        risk_score: risk,
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
        tags,
        ..Default::default()
    }
}

fn download_to_event(entry: &DownloadEntry, browser: Browser) -> Event {
    let is_dangerous = is_dangerous_download(&entry.path);
    let hash = if Path::new(&entry.path).exists() {
        compute_sha256(&entry.path)
    } else {
        String::new()
    };

    let mut risk: u32 = if is_dangerous { 30 } else { 10 };
    let mut tags = vec!["browser".to_string(), "download".to_string()];

    if is_dangerous {
        risk += 15;
        tags.push("dangerous_ext".into());
    }
    if !hash.is_empty() {
        risk += 10;
        tags.push("hashed".into());
    }
    if url_has_ip_address(&entry.url) {
        risk += 5;
        tags.push("ip_url".into());
    }

    Event {
        id: sentinel_core::Ulid::new().to_string(),
        r#type: "sentinel.browser.download_complete".into(),
        source: "browser".into(),
        severity: if risk > 30 { sentinel_events::Severity::Warning as i32 } else { sentinel_events::Severity::Notice as i32 },
        risk_score: risk,
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
        tags,
        ..Default::default()
    }
}

fn extension_to_event(entry: &ExtensionEntry, browser: Browser) -> Event {
    let malicious = is_malicious_extension(&entry.id);
    let risk: u32 = if malicious { 80 } else { 20 };

    let mut tags = vec!["browser".to_string(), "extension".to_string()];
    if malicious {
        tags.push("malicious_extension".into());
    }

    Event {
        id: sentinel_core::Ulid::new().to_string(),
        r#type: "sentinel.browser.extension_install".into(),
        source: "browser".into(),
        severity: if malicious { sentinel_events::Severity::Warning as i32 } else { sentinel_events::Severity::Notice as i32 },
        risk_score: risk,
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
        tags,
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

// ── Suspicious download detector ──────────────────────────────────

struct SuspiciousDownloadTracker {
    records: Vec<(String, i64)>, // (path, unix_timestamp)
}

impl SuspiciousDownloadTracker {
    fn new() -> Self {
        Self { records: Vec::new() }
    }

    fn record(&mut self, path: &str, ts: i64) -> Option<usize> {
        if !is_dangerous_download(path) {
            return None;
        }

        // Prune old records
        self.records.retain(|(_, t)| ts - t < SUSPICIOUS_DL_WINDOW.as_secs() as i64);
        self.records.push((path.to_string(), ts));

        if self.records.len() >= SUSPICIOUS_DL_THRESHOLD {
            Some(self.records.len())
        } else {
            None
        }
    }
}

// ── Main monitor loop ─────────────────────────────────────────────

pub async fn start_browser_monitor(bus: Arc<dyn EventBus>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        tick.tick().await;

        let mut known_urls: HashSet<String> = HashSet::new();
        let mut known_downloads: HashSet<String> = HashSet::new();
        let mut known_extensions: HashSet<String> = HashSet::new();
        let mut profile_ts: HashMap<String, (i64, i64)> = HashMap::new();
        let mut dl_tracker = SuspiciousDownloadTracker::new();

        info!("Browser collector started ({}s incremental)", POLL_INTERVAL.as_secs());

        loop {
            tick.tick().await;
            let profiles = find_profiles();

            if profiles.is_empty() {
                debug!("No browser profiles found");
                continue;
            }

            let mut total = 0u64;
            let profile_count = profiles.len();

            for mut profile in profiles {
                let key = profile.profile_dir_name();
                let (mut hist_ts, mut dl_ts) =
                    profile_ts.get(&key).copied().unwrap_or((0, 0));

                profile.last_history_ts = hist_ts;
                profile.last_downloads_ts = dl_ts;

                if let Some(ref history) = profile.history_db {
                    let navs = safe_read_db(
                        history,
                        &mut known_urls,
                        &mut profile.last_history_ts,
                        &|db, known, ts| read_history_incremental(db, known, ts),
                    );

                    let count = navs.len() as u64;
                    for entry in navs {
                        let event = Arc::new(navigation_to_event(&entry, profile.browser));
                        if let Err(e) = bus.publish(event).await {
                            warn!("Browser nav publish failed: {e}");
                        }
                    }
                    total += count;
                    hist_ts = profile.last_history_ts;
                }

                if let Some(ref downloads) = profile.downloads_db {
                    let dls = safe_read_db(
                        downloads,
                        &mut known_downloads,
                        &mut profile.last_downloads_ts,
                        &|db, known, ts| read_downloads_incremental(db, known, ts),
                    );

                    let count = dls.len() as u64;
                    for entry in &dls {
                        let mut event = download_to_event(entry, profile.browser);

                        if let Some(suspicious_count) =
                            dl_tracker.record(&entry.path, entry.timestamp)
                        {
                            event.severity = sentinel_events::Severity::Warning as i32;
                            event.risk_score = 60;
                            event.tags.push(format!(
                                "suspicious_downloads:{}",
                                suspicious_count
                            ));
                        }

                        let _ = bus.publish(Arc::new(event)).await;
                    }
                    total += count;
                    dl_ts = profile.last_downloads_ts;
                }

                if let Some(ref ext_dir) = profile.extensions_dir {
                    let exts = read_extensions(ext_dir, &mut known_extensions);
                    let count = exts.len() as u64;
                    for entry in exts {
                        let event = Arc::new(extension_to_event(&entry, profile.browser));
                        let _ = bus.publish(event).await;
                    }
                    total += count;
                }

                profile_ts.insert(key, (hist_ts, dl_ts));
            }

            if total > 0 {
                info!(
                    "Browser collector: {} new events ({} profiles)",
                    total, profile_count
                );
            }
        }
    });
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_events::browser_event::Browser;

    #[test]
    fn test_chrome_time_conversion() {
        assert_eq!(chrome_time_to_unix(0), 0);
        let chrome_ts = 13300000000000000i64;
        let unix = chrome_time_to_unix(chrome_ts);
        assert!(unix > 1_600_000_000, "Expected future timestamp");
    }

    #[test]
    fn test_ip_url_detection() {
        assert!(url_has_ip_address("http://192.168.1.1/admin"));
        assert!(url_has_ip_address("https://10.0.0.1/phish"));
        assert!(!url_has_ip_address("https://google.com"));
    }

    #[test]
    fn test_suspicious_tld() {
        assert!(url_has_suspicious_tld("http://evil.xyz/payload"));
        assert!(url_has_suspicious_tld("https://free.tk/login"));
        assert!(!url_has_suspicious_tld("https://github.com"));
    }

    #[test]
    fn test_dangerous_extension() {
        assert!(is_dangerous_download("/tmp/payload.exe"));
        assert!(is_dangerous_download("/home/user/script.sh"));
        assert!(!is_dangerous_download("/home/user/report.pdf"));
        assert!(!is_dangerous_download("/tmp/image.png"));
    }

    #[test]
    fn test_malicious_extension() {
        assert!(is_malicious_extension("kfclfkdkobhcchbhmfdboddphkfoakdg"));
        assert!(!is_malicious_extension("google-translate-extension-id"));
    }

    #[test]
    fn test_navigation_event_has_tags() {
        let entry = NavigationEntry {
            url: "https://test.com".into(),
            title: "Test".into(),
            timestamp: 0,
        };
        let event = navigation_to_event(&entry, Browser::Chrome);
        assert_eq!(event.source, "browser");
        assert!(event.payload.is_some());
    }

    #[test]
    fn test_download_event_has_tags() {
        let entry = DownloadEntry {
            path: "/tmp/x".into(),
            url: "https://x.com".into(),
            timestamp: 0,
        };
        let event = download_to_event(&entry, Browser::Firefox);
        assert!(event.tags.contains(&"download".to_string()));
    }

    #[test]
    fn test_dangerous_download_flagged() {
        let entry = DownloadEntry {
            path: "/tmp/evil.exe".into(),
            url: "https://malware.com/payload".into(),
            timestamp: 0,
        };
        let event = download_to_event(&entry, Browser::Chrome);
        assert!(event.tags.contains(&"dangerous_ext".to_string()));
        assert!(event.risk_score >= 30);
    }

    #[test]
    fn test_ip_navigation_flagged() {
        let entry = NavigationEntry {
            url: "http://45.33.32.156/login".into(),
            title: "".into(),
            timestamp: 0,
        };
        let event = navigation_to_event(&entry, Browser::Chrome);
        assert!(event.tags.contains(&"ip_url".to_string()));
        assert!(event.risk_score > 5);
    }

    #[test]
    fn test_extension_event() {
        let entry = ExtensionEntry {
            id: "abc".into(),
            name: "Ext".into(),
        };
        let event = extension_to_event(&entry, Browser::Edge);
        assert_eq!(event.risk_score, 20);
    }

    #[test]
    fn test_malicious_extension_flagged() {
        let entry = ExtensionEntry {
            id: "kfclfkdkobhcchbhmfdboddphkfoakdg".into(),
            name: "Fake AdBlock".into(),
        };
        let event = extension_to_event(&entry, Browser::Chrome);
        assert!(event.tags.contains(&"malicious_extension".to_string()));
        assert_eq!(event.risk_score, 80);
    }

    #[test]
    fn test_empty_history_graceful() {
        let mut known = HashSet::new();
        let mut ts = 0i64;
        let entries = read_history_incremental(
            std::path::Path::new("/nonexistent"),
            &mut known,
            &mut ts,
        );
        assert!(entries.is_empty());
    }

    #[test]
    fn test_empty_downloads_graceful() {
        let mut known = HashSet::new();
        let mut ts = 0i64;
        let entries = read_downloads_incremental(
            std::path::Path::new("/nonexistent"),
            &mut known,
            &mut ts,
        );
        assert!(entries.is_empty());
    }

    #[test]
    fn test_deduplication() {
        let mut known = HashSet::new();
        let key = "https://a.com|100".to_string();
        assert!(known.insert(key.clone()));
        assert!(!known.insert(key.clone()));
    }

    #[test]
    fn test_browser_enum_values() {
        assert_eq!(Browser::Chrome as i32, 1);
        assert_eq!(Browser::Firefox as i32, 2);
        assert_eq!(Browser::Edge as i32, 3);
    }

    #[test]
    fn test_suspicious_download_burst() {
        let mut tracker = SuspiciousDownloadTracker::new();
        let base_ts = 1_700_000_000i64;

        assert!(tracker.record("/tmp/a.exe", base_ts).is_none());
        assert!(tracker.record("/tmp/b.exe", base_ts + 1).is_none());
        let result = tracker.record("/tmp/c.exe", base_ts + 2);
        assert_eq!(result, Some(3));
    }

    #[test]
    fn test_suspicious_download_window_expires() {
        let mut tracker = SuspiciousDownloadTracker::new();
        let base_ts = 1_700_000_000i64;

        tracker.record("/tmp/a.exe", base_ts);
        tracker.record("/tmp/b.exe", base_ts + 1);
        // After window expires, count resets
        let result = tracker.record(
            "/tmp/c.exe",
            base_ts + SUSPICIOUS_DL_WINDOW.as_secs() as i64 + 10,
        );
        assert!(result.is_none());
    }
}

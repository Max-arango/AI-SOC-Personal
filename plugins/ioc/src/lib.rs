use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct IocEntry {
    pub indicator: String,
    pub ioc_type: IocType,
    pub risk_score: u32,
    pub description: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IocType {
    Ip,
    Domain,
    Hash,
}

#[derive(Debug, Default)]
struct IocDatabase {
    ips: HashMap<String, Vec<IocEntry>>,
    domains: HashMap<String, Vec<IocEntry>>,
    hashes: HashMap<String, Vec<IocEntry>>,
    count: usize,
}

pub struct IocEngine {
    db: RwLock<IocDatabase>,
    paths: Vec<PathBuf>,
}

impl IocEngine {
    pub fn new() -> Self {
        Self { db: RwLock::new(IocDatabase::default()), paths: default_ioc_paths() }
    }

    pub fn load(&self) {
        let mut db = IocDatabase::default();

        for dir in &self.paths {
            if !dir.exists() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    match path.extension().and_then(|e| e.to_str()) {
                        Some("csv") => {
                            if let Err(e) = Self::load_csv(&path, &mut db) {
                                warn!("Failed to load IOC CSV {}: {e}", path.display());
                            }
                        },
                        Some("json") => {
                            if let Err(e) = Self::load_stix(&path, &mut db) {
                                warn!("Failed to load IOC STIX {}: {e}", path.display());
                            }
                        },
                        _ => {},
                    }
                }
            }
        }

        db.count = db.ips.len() + db.domains.len() + db.hashes.len();

        let mut current = self.db.write().expect("IOC lock poisoned");
        *current = db;

        info!(
            "IOC database loaded: {} entries ({} IPs, {} domains, {} hashes)",
            current.count,
            current.ips.len(),
            current.domains.len(),
            current.hashes.len(),
        );
    }

    fn load_csv(path: &Path, db: &mut IocDatabase) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(content.as_bytes());

        for result in reader.records() {
            let record = result?;
            if record.len() < 3 {
                continue;
            }

            let ioc_type = record[0].trim().to_lowercase();
            let indicator = record[1].trim().to_string();
            let risk_score: u32 = record[2].trim().parse().unwrap_or(50);
            let description = record
                .get(3)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let source = format!("ioc:{}", path.file_stem().unwrap_or_default().to_string_lossy());

            let entry = IocEntry {
                indicator: indicator.clone(),
                ioc_type: match ioc_type.as_str() {
                    "ip" | "ipv4" | "ipv6" => IocType::Ip,
                    "domain" | "hostname" => IocType::Domain,
                    "hash" | "sha256" | "md5" | "sha1" => IocType::Hash,
                    _ => continue,
                },
                risk_score,
                description,
                source,
            };

            match entry.ioc_type {
                IocType::Ip => db.ips.entry(indicator).or_default().push(entry),
                IocType::Domain => db.domains.entry(indicator).or_default().push(entry),
                IocType::Hash => db.hashes.entry(indicator).or_default().push(entry),
            }
        }

        Ok(())
    }

    fn load_stix(path: &Path, db: &mut IocDatabase) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let bundle: serde_json::Value = serde_json::from_str(&content)?;

        let objects = bundle
            .get("objects")
            .and_then(|o| o.as_array())
            .cloned()
            .unwrap_or_default();

        for obj in objects {
            let obj_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if obj_type != "indicator" {
                continue;
            }

            let pattern = obj.get("pattern").and_then(|p| p.as_str()).unwrap_or("");

            let name = obj.get("name").and_then(|n| n.as_str()).unwrap_or("");

            let (ioc_type, indicator) =
                if pattern.contains("ipv4-addr:value") || pattern.contains("ipv6-addr:value") {
                    let val = extract_stix_value(pattern);
                    (IocType::Ip, val)
                } else if pattern.contains("domain-name:value") {
                    let val = extract_stix_value(pattern);
                    (IocType::Domain, val)
                } else if pattern.contains("file:hashes.'SHA-256'")
                    || pattern.contains("file:hashes.MD5")
                {
                    let val = extract_stix_value(pattern);
                    (IocType::Hash, val)
                } else {
                    continue;
                };

            if indicator.is_empty() {
                continue;
            }

            let risk_score = if name.to_lowercase().contains("critical") {
                90
            } else if name.to_lowercase().contains("high") {
                70
            } else {
                50
            };

            let source = format!("stix:{}", path.file_stem().unwrap_or_default().to_string_lossy());

            let entry = IocEntry {
                indicator: indicator.clone(),
                ioc_type,
                risk_score,
                description: name.to_string(),
                source,
            };

            match entry.ioc_type {
                IocType::Ip => db.ips.entry(indicator).or_default().push(entry),
                IocType::Domain => db.domains.entry(indicator).or_default().push(entry),
                IocType::Hash => db.hashes.entry(indicator).or_default().push(entry),
            }
        }

        Ok(())
    }

    pub fn lookup_ip(&self, ip: &str) -> Option<u32> {
        let db = self.db.read().expect("IOC lock poisoned");
        db.ips
            .get(ip)
            .map(|entries| entries.iter().map(|e| e.risk_score).max().unwrap_or(0))
    }

    pub fn lookup_domain(&self, domain: &str) -> Option<u32> {
        let db = self.db.read().expect("IOC lock poisoned");
        db.domains
            .get(domain)
            .map(|entries| entries.iter().map(|e| e.risk_score).max().unwrap_or(0))
    }

    pub fn lookup_hash(&self, hash: &str) -> Option<u32> {
        let db = self.db.read().expect("IOC lock poisoned");
        db.hashes
            .get(hash)
            .map(|entries| entries.iter().map(|e| e.risk_score).max().unwrap_or(0))
    }

    pub fn is_loaded(&self) -> bool {
        self.db.read().expect("IOC lock poisoned").count > 0
    }
}

fn extract_stix_value(pattern: &str) -> String {
    let start = pattern.find('\'');
    let end = pattern.rfind('\'');

    match (start, end) {
        (Some(s), Some(e)) if e > s => pattern[s + 1..e].to_string(),
        _ => String::new(),
    }
}

fn default_ioc_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("iocs")];

    if let Some(config) = dirs::config_dir() {
        let mut p = config;
        p.push("sentinel");
        p.push("iocs");
        paths.push(p);
    }

    paths.push(PathBuf::from("/etc/sentinel/iocs"));
    paths
}

static ENGINE: std::sync::OnceLock<IocEngine> = std::sync::OnceLock::new();

pub fn engine() -> &'static IocEngine {
    ENGINE.get_or_init(|| {
        let engine = IocEngine::new();
        engine.load();
        engine
    })
}

pub fn enabled() -> bool {
    engine().is_loaded()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_entry_fields() {
        let entry = IocEntry {
            indicator: "192.168.1.1".into(),
            ioc_type: IocType::Ip,
            risk_score: 75,
            description: "C2 server".into(),
            source: "test".into(),
        };
        assert_eq!(entry.indicator, "192.168.1.1");
        assert_eq!(entry.risk_score, 75);
    }

    #[test]
    fn ioc_type_equality() {
        assert_eq!(IocType::Ip, IocType::Ip);
        assert_ne!(IocType::Ip, IocType::Domain);
    }

    #[test]
    fn engine_new_has_paths() {
        let engine = IocEngine::new();
        assert!(!engine.paths.is_empty());
    }

    #[test]
    fn engine_not_loaded_initially() {
        let engine = IocEngine::new();
        assert!(!engine.is_loaded());
    }

    #[test]
    fn enabled_without_db_returns_false() {
        std::env::remove_var("SENTINEL_IOC_DIR");
        let engine = IocEngine::new();
        assert!(!engine.is_loaded());
    }
}

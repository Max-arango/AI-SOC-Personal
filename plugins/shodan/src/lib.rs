use serde::Deserialize;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct ShodanHost {
    ip_str: Option<String>,
    org: Option<String>,
    isp: Option<String>,
    os: Option<String>,
    country_name: Option<String>,
    city: Option<String>,
    ports: Option<Vec<u16>>,
    hostnames: Option<Vec<String>>,
    domains: Option<Vec<String>>,
    vulns: Option<Vec<String>>,
    tags: Option<Vec<String>>,
    #[serde(rename = "last_update")]
    last_update: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShodanError {
    error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HostReport {
    pub ip: String,
    pub organization: String,
    pub isp: String,
    pub os: String,
    pub country: String,
    pub city: String,
    pub open_ports: Vec<u16>,
    pub hostnames: Vec<String>,
    pub domains: Vec<String>,
    pub vulnerabilities: Vec<String>,
    pub tags: Vec<String>,
    pub last_update: String,
    pub risk_score: u32,
}

fn calculate_risk(host: &ShodanHost) -> u32 {
    let mut score = 0u32;
    let ports = host.ports.as_deref().unwrap_or(&[]);
    let vulns = host.vulns.as_deref().unwrap_or(&[]);

    score += (vulns.len() as u32).min(50);

    let risky_ports: &[u16] =
        &[22, 23, 21, 3389, 5900, 445, 135, 139, 1433, 3306, 5432, 27017, 6379, 11211];
    for p in ports {
        if risky_ports.contains(p) {
            score += 10;
        }
    }

    if ports.len() > 10 {
        score += 15;
    }

    score.min(100)
}

fn base_url() -> String {
    std::env::var("SENTINEL_SHODAN_TEST_URL")
        .unwrap_or_else(|_| "https://api.shodan.io".to_string())
}

pub fn enabled() -> bool {
    std::env::var("SENTINEL_SHODAN_API_KEY").is_ok()
}

pub async fn lookup_host(ip: &str) -> Option<HostReport> {
    let api_key = match std::env::var("SENTINEL_SHODAN_API_KEY") {
        Ok(k) => k,
        Err(_) => {
            warn!("Shodan API key not set");
            return None;
        },
    };

    let url = format!("{}/shodan/host/{}?key={}", base_url(), ip, api_key);

    let client = reqwest::Client::new();
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!("Shodan request failed: {e}");
            return None;
        },
    };

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        info!("Shodan: {} has no record (first-time scan)", ip);
        return None;
    }

    if !resp.status().is_success() {
        let err = resp.json::<ShodanError>().await.ok();
        warn!("Shodan error for {}: {:?}", ip, err.and_then(|e| e.error));
        return None;
    }

    let host: ShodanHost = match resp.json().await {
        Ok(h) => h,
        Err(e) => {
            warn!("Shodan parse error: {e}");
            return None;
        },
    };

    let risk = calculate_risk(&host);
    let vulns = host.vulns.unwrap_or_default();
    let ports = host.ports.unwrap_or_default();

    let report = HostReport {
        ip: host.ip_str.unwrap_or_else(|| ip.into()),
        organization: host.org.unwrap_or_default(),
        isp: host.isp.unwrap_or_default(),
        os: host.os.unwrap_or_default(),
        country: host.country_name.unwrap_or_else(|| "??".into()),
        city: host.city.unwrap_or_default(),
        hostnames: host.hostnames.unwrap_or_default(),
        domains: host.domains.unwrap_or_default(),
        open_ports: ports.clone(),
        vulnerabilities: vulns.clone(),
        tags: host.tags.unwrap_or_default(),
        last_update: host.last_update.unwrap_or_default(),
        risk_score: risk,
    };

    info!(
        "Shodan: {} — {} ports open, {} vulns, org={}, country={}, risk={}/100",
        report.ip,
        ports.len(),
        vulns.len(),
        report.organization,
        report.country,
        risk,
    );

    Some(report)
}

pub async fn search(query: &str) -> Option<Vec<String>> {
    let api_key = match std::env::var("SENTINEL_SHODAN_API_KEY") {
        Ok(k) => k,
        Err(_) => return None,
    };

    let url = format!(
        "{}/shodan/host/search?key={}&query={}&minify=true",
        base_url(),
        api_key,
        urlencoding(query),
    );

    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await.ok()?;

    #[derive(Debug, Deserialize)]
    struct SearchResult {
        matches: Option<Vec<Match>>,
    }

    #[derive(Debug, Deserialize)]
    struct Match {
        ip_str: Option<String>,
    }

    let results: SearchResult = resp.json().await.ok()?;
    Some(
        results
            .matches
            .unwrap_or_default()
            .into_iter()
            .filter_map(|m| m.ip_str)
            .collect(),
    )
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ' ' => "%20".into(),
            c if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' => {
                c.to_string()
            },
            c => format!("%{:02X}", c as u8),
        })
        .collect::<String>()
}

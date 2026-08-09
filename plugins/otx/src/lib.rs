use serde::Deserialize;
use tracing::info;

#[derive(Debug, Deserialize)]
struct OtxResponse {
    reputation: Option<i32>,
    pulse_info: Option<PulseInfo>,
    validation: Option<Vec<Validation>>,
}

#[derive(Debug, Deserialize)]
struct PulseInfo {
    count: Option<u32>,
    pulses: Option<Vec<Pulse>>,
}

#[derive(Debug, Deserialize)]
struct Pulse {
    name: Option<String>,
    description: Option<String>,
    tags: Option<Vec<String>>,
    adversary: Option<String>,
    targeted_countries: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct Validation {
    source: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OtxReport {
    pub indicator: String,
    pub indicator_type: String,
    pub reputation: i32,
    pub pulse_count: u32,
    pub top_tags: Vec<String>,
    pub adversary: String,
    pub malware_families: Vec<String>,
    pub risk_score: u32,
}

fn base_url() -> String {
    std::env::var("SENTINEL_OTX_TEST_URL")
        .unwrap_or_else(|_| "https://otx.alienvault.com".to_string())
}

pub fn enabled() -> bool {
    std::env::var("SENTINEL_OTX_API_KEY").is_ok()
}

fn api_key() -> Option<String> {
    std::env::var("SENTINEL_OTX_API_KEY").ok()
}

async fn query_otx(indicator: &str, indicator_type: &str) -> Option<OtxReport> {
    let key = api_key()?;
    let url = format!(
        "{}/api/v1/indicators/{}/{}/general",
        base_url(), indicator_type, indicator
    );

    let resp = reqwest::Client::new()
        .get(&url)
        .header("X-OTX-API-KEY", &key)
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        if resp.status().as_u16() == 404 {
            info!("OTX: {} not found in database", indicator);
        }
        return None;
    }

    let data: OtxResponse = resp.json().await.ok()?;

    let pulse_count = data.pulse_info.as_ref().and_then(|p| p.count).unwrap_or(0);
    let reputation = data.reputation.unwrap_or(0);
    let pulses = data.pulse_info.and_then(|p| p.pulses).unwrap_or_default();

    let mut all_tags: Vec<String> = Vec::new();
    let mut adversary = String::new();
    for p in &pulses {
        if let Some(ref tags) = p.tags {
            all_tags.extend(tags.iter().cloned());
        }
        if adversary.is_empty() {
            if let Some(ref adv) = p.adversary {
                adversary = adv.clone();
            }
        }
    }

    let malware: Vec<String> = data
        .validation
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.name)
        .collect();

    all_tags.sort();
    all_tags.dedup();
    let top_tags: Vec<String> = all_tags.into_iter().take(10).collect();

    let risk = calculate_risk(pulse_count, reputation, &top_tags, &malware);

    let report = OtxReport {
        indicator: indicator.into(),
        indicator_type: indicator_type.into(),
        reputation,
        pulse_count,
        top_tags: top_tags.clone(),
        adversary,
        malware_families: malware.clone(),
        risk_score: risk,
    };

    if pulse_count > 0 {
        info!(
            "OTX: {} — {} pulses, rep={}, risk={}/100, malware={:?}",
            indicator, pulse_count, reputation, risk, malware
        );
    }

    Some(report)
}

fn calculate_risk(
    pulse_count: u32,
    reputation: i32,
    tags: &[String],
    malware: &[String],
) -> u32 {
    let mut score = 0u32;

    if pulse_count > 50 {
        score += 30;
    } else if pulse_count > 10 {
        score += 20;
    } else if pulse_count > 0 {
        score += 10;
    }

    if reputation < -2 {
        score += 30;
    } else if reputation < 0 {
        score += 15;
    }

    let malicious_tags = [
        "malware", "ransomware", "c2", "botnet", "phishing", "exploit",
        "trojan", "apt", "backdoor", "rat", "stealer", "spyware",
    ];

    let tag_hits = tags
        .iter()
        .filter(|t| malicious_tags.iter().any(|mt| t.to_lowercase().contains(mt)))
        .count() as u32;

    score += tag_hits * 5;

    if !malware.is_empty() {
        score += (malware.len() as u32).min(5) * 10;
    }

    score.min(100)
}

pub async fn check_ip(ip: &str) -> Option<OtxReport> {
    query_otx(ip, "IPv4").await
}

pub async fn check_domain(domain: &str) -> Option<OtxReport> {
    query_otx(domain, "domain").await
}

pub async fn check_hash(hash: &str) -> Option<OtxReport> {
    query_otx(hash, "file").await
}

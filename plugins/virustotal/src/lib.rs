use serde::Deserialize;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct VtResponse {
    data: Option<VtData>,
    error: Option<VtError>,
}

#[derive(Debug, Deserialize)]
struct VtData {
    id: String,
    attributes: Option<VtAttributes>,
}

#[derive(Debug, Deserialize, Default)]
struct VtAttributes {
    #[serde(rename = "last_analysis_stats")]
    last_analysis_stats: Option<AnalysisStats>,
    #[serde(rename = "meaningful_name")]
    meaningful_name: Option<String>,
    size: Option<u64>,
    #[serde(rename = "type_description")]
    type_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnalysisStats {
    malicious: Option<u32>,
    suspicious: Option<u32>,
    undetected: Option<u32>,
    harmless: Option<u32>,
    timeout: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct VtError {
    message: String,
}

#[derive(Debug, Clone)]
pub struct FileReport {
    pub sha256: String,
    pub name: String,
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub total: u32,
    pub threat_ratio: f64,
    pub type_desc: String,
}

fn base_url() -> String {
    std::env::var("SENTINEL_VIRUSTOTAL_TEST_URL")
        .unwrap_or_else(|_| "https://www.virustotal.com".to_string())
}

pub fn enabled() -> bool {
    std::env::var("SENTINEL_VIRUSTOTAL_API_KEY").is_ok()
}

pub async fn lookup_hash(sha256: &str) -> Option<FileReport> {
    let api_key = match std::env::var("SENTINEL_VIRUSTOTAL_API_KEY") {
        Ok(k) => k,
        Err(_) => {
            warn!("VirusTotal API key not set");
            return None;
        },
    };

    let url = format!("{}/api/v3/files/{}", base_url(), sha256);

    let client = reqwest::Client::new();
    let resp = match client
        .get(&url)
        .header("x-apikey", &api_key)
        .header("accept", "application/json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("VirusTotal request failed: {e}");
            return None;
        },
    };

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        info!("VirusTotal: file {} not found in database", sha256);
        return None;
    }

    let body: VtResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            warn!("VirusTotal response parse failed: {e}");
            return None;
        },
    };

    if let Some(err) = body.error {
        warn!("VirusTotal API error: {}", err.message);
        return None;
    }

    let data = body.data?;
    let attrs = data.attributes.unwrap_or_default();
    let stats = attrs.last_analysis_stats.unwrap_or(AnalysisStats {
        malicious: None,
        suspicious: None,
        undetected: None,
        harmless: None,
        timeout: None,
    });

    let malicious = stats.malicious.unwrap_or(0);
    let suspicious = stats.suspicious.unwrap_or(0);
    let harmless = stats.harmless.unwrap_or(0);
    let undetected = stats.undetected.unwrap_or(0);
    let total = malicious + suspicious + harmless + undetected;
    let threat_ratio = if total > 0 { (malicious + suspicious) as f64 / total as f64 } else { 0.0 };

    let report = FileReport {
        sha256: sha256.into(),
        name: attrs.meaningful_name.unwrap_or_else(|| "unknown".into()),
        malicious,
        suspicious,
        harmless,
        undetected,
        total,
        threat_ratio,
        type_desc: attrs.type_description.unwrap_or_default(),
    };

    info!(
        "VirusTotal: {} ({}) — {}/{} detections ({:.0}%)",
        report.name,
        sha256,
        malicious + suspicious,
        total,
        threat_ratio * 100.0,
    );

    Some(report)
}

pub async fn lookup_url(url: &str) -> Option<String> {
    let api_key = match std::env::var("SENTINEL_VIRUSTOTAL_API_KEY") {
        Ok(k) => k,
        Err(_) => return None,
    };

    let encoded = url::encoding(url, url::ENCODING).unwrap_or_default();
    let vt_url = format!("{}/api/v3/urls/{}", base_url(), base64_url_safe(&encoded));

    let client = reqwest::Client::new();
    let resp = match client
        .get(&vt_url)
        .header("x-apikey", &api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("VirusTotal URL lookup failed: {e}");
            return None;
        },
    };

    if resp.status().is_success() {
        let body: VtResponse = resp.json().await.ok()?;
        let data = body.data?;
        let attrs = data.attributes.unwrap_or_default();
        let stats = attrs.last_analysis_stats.unwrap_or(AnalysisStats {
            malicious: None,
            suspicious: None,
            undetected: None,
            harmless: None,
            timeout: None,
        });
        Some(format!(
            "URL: {}/{} detections (malicious: {}, suspicious: {})",
            stats.malicious.unwrap_or(0) + stats.suspicious.unwrap_or(0),
            stats.malicious.unwrap_or(0)
                + stats.suspicious.unwrap_or(0)
                + stats.harmless.unwrap_or(0)
                + stats.undetected.unwrap_or(0),
            stats.malicious.unwrap_or(0),
            stats.suspicious.unwrap_or(0),
        ))
    } else {
        None
    }
}

fn base64_url_safe(input: &str) -> String {
    let mut out = String::new();
    for &b in input.as_bytes() {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

mod url {
    pub const ENCODING: &str = "utf-8";

    pub fn encoding(s: &str, _enc: &str) -> Option<String> {
        Some(s.to_string())
    }
}

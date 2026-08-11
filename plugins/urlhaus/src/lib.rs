use serde::Deserialize;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct UrlhausResponse {
    query_status: Option<String>,
    url_status: Option<String>,
    threat: Option<String>,
    tags: Option<Vec<String>>,
    urlhaus_reference: Option<String>,
    blacklists: Option<Blacklists>,
}

#[derive(Debug, Deserialize)]
struct Blacklists {
    spamhaus_dbl: Option<String>,
    surbl: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UrlReport {
    pub url: String,
    pub status: String,
    pub threat: String,
    pub tags: Vec<String>,
    pub reference: String,
    pub is_malicious: bool,
    pub risk_score: u32,
}

fn base_url() -> String {
    std::env::var("SENTINEL_URLHAUS_TEST_URL")
        .unwrap_or_else(|_| "https://urlhaus-api.abuse.ch".to_string())
}

pub fn enabled() -> bool {
    true
}

pub async fn check_url(url: &str) -> Option<UrlReport> {
    let api_url = format!("{}/v1/url/", base_url());

    let client = reqwest::Client::new();
    let resp = match client
        .post(api_url)
        .form(&[("url", url)])
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("URLhaus request failed: {e}");
            return None;
        },
    };

    if !resp.status().is_success() {
        warn!("URLhaus HTTP {}", resp.status());
        return None;
    }

    let data: UrlhausResponse = match resp.json().await {
        Ok(d) => d,
        Err(e) => {
            warn!("URLhaus parse error: {e}");
            return None;
        },
    };

    if data.query_status.as_deref() == Some("no_results") {
        return None;
    }

    let is_malicious = data.url_status.as_deref() == Some("online") && data.threat.is_some();

    let tags = data.tags.unwrap_or_default();
    let threat = data.threat.unwrap_or_else(|| "unknown".into());

    let risk_score = if is_malicious {
        let base = 50u32;
        let tag_bonus = if tags
            .iter()
            .any(|t| t.contains("exe") || t.contains("ransomware"))
        {
            30
        } else {
            10
        };
        (base + tag_bonus).min(100)
    } else {
        0
    };

    let report = UrlReport {
        url: url.into(),
        status: data.url_status.unwrap_or_else(|| "unknown".into()),
        threat: threat.clone(),
        tags: tags.clone(),
        reference: data.urlhaus_reference.unwrap_or_default(),
        is_malicious,
        risk_score,
    };

    if is_malicious {
        info!("URLhaus: {} → {} (tags: {:?})", report.url, report.threat, report.tags,);
    }

    Some(report)
}

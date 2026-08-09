use serde::Deserialize;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct ApiResponse {
    data: Option<IpData>,
    errors: Option<Vec<ApiError>>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    detail: String,
}

#[derive(Debug, Deserialize, Default)]
struct IpData {
    #[serde(rename = "ipAddress")]
    ip_address: String,
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: u32,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    #[serde(rename = "countryName")]
    country_name: Option<String>,
    #[serde(rename = "isp")]
    isp: Option<String>,
    #[serde(rename = "domain")]
    domain: Option<String>,
    #[serde(rename = "totalReports")]
    total_reports: Option<u64>,
    #[serde(rename = "lastReportedAt")]
    last_reported_at: Option<String>,
    #[serde(rename = "usageType")]
    usage_type: Option<String>,
    #[serde(rename = "isPublic")]
    is_public: Option<bool>,
    #[serde(rename = "isWhitelisted")]
    is_whitelisted: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct IpReport {
    pub ip: String,
    pub abuse_score: u32,
    pub total_reports: u64,
    pub country: String,
    pub isp: String,
    pub domain: String,
    pub usage_type: String,
    pub last_reported: String,
    pub is_public: bool,
    pub is_whitelisted: bool,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: u32) -> Self {
        match score {
            0 => RiskLevel::Safe,
            1..=25 => RiskLevel::Low,
            26..=50 => RiskLevel::Medium,
            51..=75 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            RiskLevel::Safe => "Safe",
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Critical => "Critical",
        }
    }
}

fn base_url() -> String {
    std::env::var("SENTINEL_ABUSEIPDB_TEST_URL")
        .unwrap_or_else(|_| "https://api.abuseipdb.com".to_string())
}

pub fn enabled() -> bool {
    std::env::var("SENTINEL_ABUSEIPDB_API_KEY").is_ok()
}

pub async fn check_ip(ip: &str) -> Option<IpReport> {
    let api_key = match std::env::var("SENTINEL_ABUSEIPDB_API_KEY") {
        Ok(k) => k,
        Err(_) => {
            warn!("AbuseIPDB API key not set");
            return None;
        },
    };

    let max_age = std::env::var("SENTINEL_ABUSEIPDB_MAX_AGE")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(90);

    let url =
        format!("{}/api/v2/check?ipAddress={}&maxAgeInDays={}", base_url(), ip, max_age);

    let client = reqwest::Client::new();
    let resp = match client
        .get(&url)
        .header("Key", &api_key)
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("AbuseIPDB request failed: {e}");
            return None;
        },
    };

    let body: ApiResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            warn!("AbuseIPDB parse error: {e}");
            return None;
        },
    };

    if let Some(errors) = body.errors {
        for e in errors {
            warn!("AbuseIPDB API error: {}", e.detail);
        }
        return None;
    }

    let data = body.data?;
    let score = data.abuse_confidence_score;
    let risk = RiskLevel::from_score(score);

    let report = IpReport {
        ip: data.ip_address,
        abuse_score: score,
        total_reports: data.total_reports.unwrap_or(0),
        country: data.country_code.unwrap_or_else(|| "??".into()),
        isp: data.isp.unwrap_or_default(),
        domain: data.domain.unwrap_or_default(),
        usage_type: data.usage_type.unwrap_or_default(),
        last_reported: data.last_reported_at.unwrap_or_default(),
        is_public: data.is_public.unwrap_or(false),
        is_whitelisted: data.is_whitelisted.unwrap_or(false),
        risk_level: risk,
    };

    if score > 0 {
        info!(
            "AbuseIPDB: {} — score={}/100 ({}), {} reports, ISP={}, country={}",
            report.ip,
            report.abuse_score,
            report.risk_level.as_str(),
            report.total_reports,
            report.isp,
            report.country,
        );
    }

    Some(report)
}

pub async fn check_bulk(ips: &[String]) -> Vec<IpReport> {
    let mut results = Vec::new();
    for ip in ips {
        if let Some(r) = check_ip(ip).await {
            results.push(r);
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    results
}

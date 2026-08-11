use serde::Deserialize;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct GnResponse {
    ip: Option<String>,
    noise: Option<bool>,
    riot: Option<bool>,
    classification: Option<String>,
    name: Option<String>,
    last_seen: Option<String>,
    link: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GreyNoiseReport {
    pub ip: String,
    pub classification: String,
    pub name: String,
    pub is_noise: bool,
    pub is_riot: bool,
    pub risk_modifier: i32,
}

pub fn enabled() -> bool {
    std::env::var("SENTINEL_GREYNOISE_API_KEY").is_ok()
}

fn api_key() -> Option<String> {
    std::env::var("SENTINEL_GREYNOISE_API_KEY").ok()
}

pub async fn check_ip(ip: &str) -> Option<GreyNoiseReport> {
    let key = api_key()?;
    let url = format!("https://api.greynoise.io/v3/community/{}", ip);

    let resp = match reqwest::Client::new()
        .get(&url)
        .header("key", &key)
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("GreyNoise request failed: {e}");
            return None;
        },
    };

    if resp.status().as_u16() == 404 {
        return None;
    }

    if !resp.status().is_success() {
        warn!("GreyNoise HTTP {}", resp.status());
        return None;
    }

    let data: GnResponse = match resp.json().await {
        Ok(d) => d,
        Err(e) => {
            warn!("GreyNoise parse error: {e}");
            return None;
        },
    };

    if data.message.is_some() {
        return None;
    }

    let classification = data.classification.unwrap_or_else(|| "unknown".into());
    let name = data.name.unwrap_or_default();
    let is_noise = data.noise.unwrap_or(false);
    let is_riot = data.riot.unwrap_or(false);

    let risk_modifier = match classification.as_str() {
        "malicious" => 25,
        "benign" => -20,
        _ => 0,
    };

    let report = GreyNoiseReport {
        ip: data.ip.unwrap_or_else(|| ip.into()),
        classification: classification.clone(),
        name: name.clone(),
        is_noise,
        is_riot,
        risk_modifier,
    };

    if risk_modifier != 0 {
        info!("GreyNoise: {} → {} ({}) modifier={}", ip, classification, name, risk_modifier);
    }

    Some(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enabled_without_key() {
        std::env::remove_var("SENTINEL_GREYNOISE_API_KEY");
        assert!(!enabled());
    }

    #[test]
    fn test_enabled_with_key() {
        std::env::set_var("SENTINEL_GREYNOISE_API_KEY", "test-key-123");
        assert!(enabled());
    }

    #[test]
    fn test_risk_modifier_malicious() {
        let report = GreyNoiseReport {
            ip: "10.0.0.1".into(),
            classification: "malicious".into(),
            name: "Mirai".into(),
            is_noise: true,
            is_riot: false,
            risk_modifier: 25,
        };
        assert_eq!(report.risk_modifier, 25);
        assert_eq!(report.classification, "malicious");
        assert!(!report.name.is_empty());
    }

    #[test]
    fn test_risk_modifier_benign() {
        let report = GreyNoiseReport {
            ip: "1.2.3.4".into(),
            classification: "benign".into(),
            name: "Shodan".into(),
            is_noise: true,
            is_riot: false,
            risk_modifier: -20,
        };
        assert_eq!(report.risk_modifier, -20);
        assert!(report.is_noise);
    }

    #[test]
    fn test_risk_modifier_unknown() {
        let report = GreyNoiseReport {
            ip: "8.8.8.8".into(),
            classification: "unknown".into(),
            name: String::new(),
            is_noise: false,
            is_riot: false,
            risk_modifier: 0,
        };
        assert_eq!(report.risk_modifier, 0);
    }

    #[test]
    fn test_check_ip_no_key() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        std::env::remove_var("SENTINEL_GREYNOISE_API_KEY");
        let result = rt.block_on(check_ip("8.8.8.8"));
        assert!(result.is_none());
    }
}

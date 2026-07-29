use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Serialize)]
struct HaNotification {
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notification_id: Option<String>,
}

#[derive(Serialize)]
struct HaSensorUpdate {
    state: serde_json::Value,
    attributes: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct HaApiError {
    message: Option<String>,
}

fn api_url() -> Option<String> {
    let base = std::env::var("SENTINEL_HA_URL").ok()?;
    Some(base.trim_end_matches('/').to_string())
}

fn api_token() -> Option<String> {
    std::env::var("SENTINEL_HA_TOKEN").ok()
}

fn auth_headers(token: &str) -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token))
            .unwrap_or_else(|_| HeaderValue::from_static("Bearer invalid")),
    );
    headers
}

pub fn enabled() -> bool {
    api_url().is_some() && api_token().is_some()
}

pub async fn send_notification(message: &str, title: Option<&str>) {
    let (base, token) = match (api_url(), api_token()) {
        (Some(b), Some(t)) => (b, t),
        _ => {
            warn!("Home Assistant not configured");
            return;
        },
    };

    let payload = HaNotification {
        message: message.into(),
        title: title.map(|t| t.into()),
        notification_id: Some(format!("sentinel_{}", chrono_now())),
    };

    let url = format!("{}/api/services/persistent_notification/create", base);

    match reqwest::Client::new()
        .post(&url)
        .headers(auth_headers(&token))
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!("HA notification sent: {}", message);
        },
        Ok(resp) => {
            warn!("HA notification failed: HTTP {}", resp.status());
        },
        Err(e) => {
            warn!("HA request error: {e}",);
        },
    }
}

pub async fn update_sensor(
    entity_id: &str,
    state: serde_json::Value,
    attributes: Option<serde_json::Value>,
) {
    let (base, token) = match (api_url(), api_token()) {
        (Some(b), Some(t)) => (b, t),
        _ => return,
    };

    let payload = HaSensorUpdate {
        state,
        attributes: attributes.unwrap_or(serde_json::json!({
            "source": "Sentinel AI",
            "friendly_name": entity_id.replace("sensor.", "").replace('_', " "),
        })),
    };

    let url = format!("{}/api/states/{}", base, entity_id);

    match reqwest::Client::new()
        .post(&url)
        .headers(auth_headers(&token))
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 201 => {
            info!("HA sensor {} updated", entity_id);
        },
        Ok(resp) => {
            warn!("HA sensor update failed: HTTP {}", resp.status());
        },
        Err(e) => {
            warn!("HA sensor error: {e}");
        },
    }
}

pub async fn send_alert(
    alert_id: &str,
    rule_name: &str,
    risk_score: u32,
    severity: &str,
    source: &str,
    details: Option<&str>,
) {
    let message = format!(
        "{} Alert: {} (risk: {}, source: {}) [{}]",
        severity, rule_name, risk_score, source, alert_id,
    );

    send_notification(&message, Some(&format!("Sentinel AI — {} Alert", severity))).await;

    let sensor_id = std::env::var("SENTINEL_HA_SENSOR_ID")
        .unwrap_or_else(|_| "sensor.sentinel_last_alert".into());

    update_sensor(
        &sensor_id,
        serde_json::json!(risk_score),
        Some(serde_json::json!({
            "source": "Sentinel AI",
            "alert_id": alert_id,
            "rule": rule_name,
            "severity": severity,
            "source_entity": source,
            "details": details.unwrap_or(""),
        })),
    )
    .await;
}

fn chrono_now() -> String {
    chrono::Utc::now().timestamp().to_string()
}

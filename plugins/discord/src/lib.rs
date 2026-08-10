use serde::Serialize;
use tracing::{info, warn};

#[derive(Serialize)]
struct DiscordWebhook {
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    embeds: Vec<DiscordEmbed>,
}

#[derive(Serialize)]
struct DiscordEmbed {
    title: String,
    description: String,
    color: u32,
    fields: Vec<DiscordField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    footer: Option<DiscordFooter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
}

#[derive(Serialize)]
struct DiscordField {
    name: String,
    value: String,
    inline: bool,
}

#[derive(Serialize)]
struct DiscordFooter {
    text: String,
}

fn severity_color(severity: &str) -> u32 {
    match severity {
        "Emergency" | "Critical" => 0xFF0000,
        "Error" => 0xFF4444,
        "Warning" => 0xFFA500,
        "Notice" => 0x3498DB,
        _ => 0x808080,
    }
}

fn severity_emoji(severity: &str) -> &str {
    match severity {
        "Emergency" => "🔴",
        "Critical" => "🔴",
        "Error" => "🟠",
        "Warning" => "🟡",
        "Notice" => "🔵",
        _ => "⚪",
    }
}

pub async fn send_alert(
    webhook_url: &str,
    alert_id: &str,
    rule_name: &str,
    risk_score: u32,
    severity: &str,
    source: &str,
    details: Option<&str>,
) {
    let color = severity_color(severity);
    let emoji = severity_emoji(severity);

    let mut fields = vec![
        DiscordField { name: "Alert ID".into(), value: format!("`{}`", alert_id), inline: true },
        DiscordField {
            name: "Risk Score".into(),
            value: format!("**{}**", risk_score),
            inline: true,
        },
        DiscordField { name: "Source".into(), value: source.into(), inline: true },
    ];

    if let Some(d) = details {
        fields.push(DiscordField { name: "Details".into(), value: d.into(), inline: false });
    }

    let embed = DiscordEmbed {
        title: format!("{} {} Alert: {}", emoji, severity, rule_name),
        description: format!(
            "Sentinel AI detected a **{}** severity security alert.",
            severity.to_lowercase()
        ),
        color,
        fields,
        footer: Some(DiscordFooter { text: "Sentinel AI — Local Security Assistant".into() }),
        timestamp: Some(chrono_now()),
    };

    let payload =
        DiscordWebhook { content: None, username: Some("Sentinel AI".into()), embeds: vec![embed] };

    match reqwest::Client::new()
        .post(webhook_url)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                info!("Discord alert sent: {}", alert_id);
            } else {
                warn!("Discord webhook failed: HTTP {}", resp.status());
            }
        },
        Err(e) => {
            warn!("Discord webhook error: {e}");
        },
    }
}

pub fn enabled() -> bool {
    std::env::var("SENTINEL_DISCORD_WEBHOOK").is_ok()
}

pub fn webhook_url() -> Option<String> {
    std::env::var("SENTINEL_DISCORD_WEBHOOK").ok()
}

fn chrono_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_without_webhook_url() {
        std::env::remove_var("SENTINEL_DISCORD_WEBHOOK_URL");
        assert!(!enabled());
    }
}

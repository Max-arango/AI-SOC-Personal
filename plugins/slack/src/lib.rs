use serde::Serialize;
use tracing::{info, warn};

#[derive(Serialize)]
struct SlackMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    blocks: Vec<SlackBlock>,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum SlackBlock {
    #[serde(rename = "header")]
    Header {
        text: SlackText,
    },
    #[serde(rename = "section")]
    Section {
        text: SlackText,
        #[serde(skip_serializing_if = "Option::is_none")]
        fields: Option<Vec<SlackText>>,
    },
    #[serde(rename = "divider")]
    Divider,
    #[serde(rename = "context")]
    Context {
        elements: Vec<SlackText>,
    },
}

#[derive(Serialize)]
struct SlackText {
    #[serde(rename = "type")]
    text_type: String,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    emoji: Option<bool>,
}

impl SlackText {
    fn plain(t: &str) -> Self {
        Self { text_type: "plain_text".into(), text: t.into(), emoji: Some(true) }
    }
    fn markdown(t: &str) -> Self {
        Self { text_type: "mrkdwn".into(), text: t.into(), emoji: None }
    }
}

fn severity_emoji(severity: &str) -> &str {
    match severity.to_lowercase().as_str() {
        "emergency" | "critical" => ":red_circle:",
        "error" => ":large_orange_diamond:",
        "warning" => ":warning:",
        _ => ":information_source:",
    }
}

pub fn enabled() -> bool {
    std::env::var("SENTINEL_SLACK_WEBHOOK").is_ok()
}

pub async fn send_alert(
    alert_id: &str,
    rule_name: &str,
    risk_score: u32,
    severity: &str,
    source: &str,
    details: Option<&str>,
) {
    let webhook_url = match std::env::var("SENTINEL_SLACK_WEBHOOK") {
        Ok(u) => u,
        Err(_) => {
            warn!("Slack webhook URL not set");
            return;
        },
    };

    let emoji = severity_emoji(severity);
    let fields = vec![
        SlackText::markdown(&format!("*Alert ID*\n`{}`", alert_id)),
        SlackText::markdown(&format!("*Risk Score*\n{}", risk_score)),
        SlackText::markdown(&format!("*Source*\n{}", source)),
    ];

    let blocks = vec![
        SlackBlock::Header { text: SlackText::plain(&format!("{} Sentinel AI Alert", emoji)) },
        SlackBlock::Section {
            text: SlackText::markdown(&format!(
                "*{}* — {} severity\n{}",
                rule_name,
                severity,
                details.unwrap_or("Security alert detected by Sentinel AI.")
            )),
            fields: Some(fields),
        },
        SlackBlock::Divider,
        SlackBlock::Context {
            elements: vec![SlackText::markdown(
                ":shield: *Sentinel AI* — Local Security Assistant",
            )],
        },
    ];

    let payload = SlackMessage { text: None, blocks };

    match reqwest::Client::new()
        .post(&webhook_url)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!("Slack alert sent: {}", alert_id);
        },
        Ok(resp) => {
            warn!("Slack webhook failed: HTTP {}", resp.status());
        },
        Err(e) => {
            warn!("Slack webhook error: {e}");
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_without_webhook_url() {
        std::env::remove_var("SENTINEL_SLACK_WEBHOOK_URL");
        assert!(!enabled());
    }
}

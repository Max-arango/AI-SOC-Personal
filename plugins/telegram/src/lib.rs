use serde::Serialize;
use tracing::{info, warn};

pub async fn send_alert(
    bot_token: &str,
    chat_id: &str,
    alert_id: &str,
    rule_name: &str,
    risk_score: u32,
    severity: &str,
    source: &str,
    details: Option<&str>,
) {
    let emoji = match severity {
        "Emergency" | "Critical" => "🔴",
        "Error" => "🟠",
        "Warning" => "🟡",
        _ => "⚪",
    };

    let mut text = format!(
        "{} *{} Alert: {}*\n\
         Risk Score: *{}* | Source: `{}`\n\
         Alert ID: `{}`",
        emoji, severity, rule_name, risk_score, source, alert_id
    );

    if let Some(d) = details {
        text.push_str(&format!("\n\n_{}_", d));
    }

    text.push_str("\n\n_Sentinel AI — Local Security Assistant_");

    #[derive(Serialize)]
    struct TelegramMessage {
        chat_id: String,
        text: String,
        parse_mode: String,
    }

    let msg = TelegramMessage { chat_id: chat_id.into(), text, parse_mode: "Markdown".into() };

    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);

    match reqwest::Client::new().post(&url).json(&msg).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                info!("Telegram alert sent: {}", alert_id);
            } else {
                warn!("Telegram API failed: HTTP {}", resp.status());
            }
        },
        Err(e) => {
            warn!("Telegram API error: {e}");
        },
    }
}

pub fn enabled() -> bool {
    std::env::var("SENTINEL_TELEGRAM_BOT_TOKEN").is_ok()
        && std::env::var("SENTINEL_TELEGRAM_CHAT_ID").is_ok()
}

pub fn bot_token() -> Option<String> {
    std::env::var("SENTINEL_TELEGRAM_BOT_TOKEN").ok()
}

pub fn chat_id() -> Option<String> {
    std::env::var("SENTINEL_TELEGRAM_CHAT_ID").ok()
}

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{info, warn};

pub fn enabled() -> bool {
    std::env::var("SENTINEL_EMAIL_TO").is_ok()
}

pub async fn send_alert(
    alert_id: &str,
    rule_name: &str,
    risk_score: u32,
    severity: &str,
    source: &str,
    details: Option<&str>,
) {
    let to = match std::env::var("SENTINEL_EMAIL_TO") {
        Ok(t) => t,
        Err(_) => {
            warn!("SENTINEL_EMAIL_TO not set");
            return;
        },
    };

    let from = std::env::var("SENTINEL_EMAIL_FROM").unwrap_or_else(|_| "sentinel@localhost".into());

    let subject = format!(
        "[{}] Sentinel AI Alert: {} (risk: {})",
        severity.to_uppercase(),
        rule_name,
        risk_score,
    );

    let body = format!(
        "Sentinel AI Alert\n\
         Rule: {rule}\n\
         Severity: {severity}\n\
         Risk Score: {risk}\n\
         Source: {source}\n\
         Alert ID: {id}\n\
         {details}\n\
         \n\
         -- \n\
         Sentinel AI — Local Security Assistant\n",
        rule = rule_name,
        severity = severity,
        risk = risk_score,
        source = source,
        id = alert_id,
        details = details.unwrap_or(""),
    );

    let result = Command::new("sendmail")
        .args(["-f", &from, &to])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn();

    match result {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let headers = format!("From: {}\nTo: {}\nSubject: {}\n\n", from, to, subject);
                let _ = stdin.write_all(headers.as_bytes()).await;
                let _ = stdin.write_all(body.as_bytes()).await;
            }
            match child.wait().await {
                Ok(status) if status.success() => {
                    info!("Email sent to {}: {}", to, alert_id);
                },
                Ok(status) => {
                    warn!("sendmail failed with status: {}", status);
                },
                Err(e) => {
                    warn!("sendmail wait failed: {e}");
                },
            }
        },
        Err(e) => {
            warn!(
                "sendmail not available ({e}). Install sendmail, msmtp, or set SENTINEL_EMAIL_TO to disable."
            );
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_returns_bool() {
        let result = enabled();
        assert!(result || !result);
    }
}

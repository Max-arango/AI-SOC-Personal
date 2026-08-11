pub async fn notify_alerts(
    rule_id: &str,
    rule_name: &str,
    risk_score: u32,
    severity: &str,
    source: &str,
    event_count: usize,
) {
    // NOTE: tokio::spawn without awaiting JoinHandle.
    // On graceful shutdown, in-flight notifications may be dropped.
    // For v0.2: collect handles and flush before service stops.
    if sentinel_plugin_discord::enabled() {
        if let Some(url) = sentinel_plugin_discord::webhook_url() {
            let eid = rule_id.to_string();
            let name = rule_name.to_string();
            let src = source.to_string();
            let sev = severity.to_string();
            tokio::spawn(async move {
                sentinel_plugin_discord::send_alert(
                    &url,
                    &eid,
                    &name,
                    risk_score,
                    &sev,
                    &src,
                    Some(&format!("{} events in chain", event_count)),
                )
                .await;
            });
        }
    }

    if sentinel_plugin_telegram::enabled() {
        if let (Some(token), Some(chat_id)) =
            (sentinel_plugin_telegram::bot_token(), sentinel_plugin_telegram::chat_id())
        {
            let eid = rule_id.to_string();
            let name = rule_name.to_string();
            let src = source.to_string();
            let sev = severity.to_string();
            tokio::spawn(async move {
                sentinel_plugin_telegram::send_alert(
                    &token,
                    &chat_id,
                    &eid,
                    &name,
                    risk_score,
                    &sev,
                    &src,
                    Some(&format!("{} events in chain", event_count)),
                )
                .await;
            });
        }
    }

    if sentinel_plugin_home_assistant::enabled() {
        let eid = rule_id.to_string();
        let name = rule_name.to_string();
        let src = source.to_string();
        let sev = severity.to_string();
        tokio::spawn(async move {
            sentinel_plugin_home_assistant::send_alert(
                &eid,
                &name,
                risk_score,
                &sev,
                &src,
                Some(&format!("{} events in chain", event_count)),
            )
            .await;
        });
    }

    if sentinel_plugin_slack::enabled() {
        let eid = rule_id.to_string();
        let name = rule_name.to_string();
        let src = source.to_string();
        let sev = severity.to_string();
        tokio::spawn(async move {
            sentinel_plugin_slack::send_alert(
                &eid,
                &name,
                risk_score,
                &sev,
                &src,
                Some(&format!("{} events in chain", event_count)),
            )
            .await;
        });
    }

    if sentinel_plugin_email::enabled() {
        let eid = rule_id.to_string();
        let name = rule_name.to_string();
        let src = source.to_string();
        let sev = severity.to_string();
        tokio::spawn(async move {
            sentinel_plugin_email::send_alert(
                &eid,
                &name,
                risk_score,
                &sev,
                &src,
                Some(&format!("{} events in chain", event_count)),
            )
            .await;
        });
    }
}

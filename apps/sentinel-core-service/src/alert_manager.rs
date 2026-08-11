//! Alert Manager
//!
//! Wraps the AlertRepository with business logic: persists alerts,
//! manages state transitions, and exposes query operations.

use chrono::Utc;
use sentinel_core::traits::{Alert, AlertQuery, AlertRepository, AlertState};
use sentinel_core::{AlertId, Result as CoreResult, Ulid};
use sentinel_events::sentinel::api::v1::{alert_stream_event::EventType, AlertStreamEvent};
use std::sync::Arc;
use tokio::sync::broadcast;

pub struct AlertManager {
    repo: Arc<dyn AlertRepository>,
    tx: broadcast::Sender<AlertStreamEvent>,
}

impl AlertManager {
    pub fn new(repo: Arc<dyn AlertRepository>, tx: broadcast::Sender<AlertStreamEvent>) -> Self {
        Self { repo, tx }
    }

    pub async fn create(
        &self,
        rule_id: &str,
        risk_score: u32,
        severity: sentinel_core::Severity,
        event_ids: Vec<String>,
        context: serde_json::Value,
    ) -> CoreResult<Alert> {
        let alert = Alert {
            id: Ulid::new(),
            rule_id: rule_id.to_string(),
            correlation_id: Ulid::new(),
            risk_score,
            severity,
            state: AlertState::New,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            acknowledged_by: None,
            acknowledged_at: None,
            events: event_ids
                .into_iter()
                .filter_map(|e| Ulid::from_string(&e).ok())
                .collect(),
            context,
            ai_summary: None,
        };
        self.repo.create(&alert).await?;

        let _ = self
            .tx
            .send(alert_to_stream_event(&alert, EventType::Created));

        Ok(alert)
    }

    pub async fn acknowledge(&self, alert_id: &AlertId, username: &str) -> CoreResult<()> {
        let comment = Some(username.to_string());
        self.repo
            .update_state(alert_id, AlertState::Acknowledged, comment)
            .await?;

        if let Ok(Some(updated)) = self.repo.get(alert_id).await {
            let _ = self
                .tx
                .send(alert_to_stream_event(&updated, EventType::Updated));
        }

        Ok(())
    }

    pub async fn resolve(&self, alert_id: &AlertId, is_true_positive: bool) -> CoreResult<()> {
        let state = if is_true_positive {
            AlertState::ResolvedTruePositive
        } else {
            AlertState::ResolvedFalsePositive
        };
        self.repo.update_state(alert_id, state, None).await?;

        if let Ok(Some(updated)) = self.repo.get(alert_id).await {
            let _ = self
                .tx
                .send(alert_to_stream_event(&updated, EventType::Updated));
        }

        Ok(())
    }

    pub async fn update_state(
        &self,
        alert_id: &AlertId,
        state: AlertState,
        username: Option<String>,
    ) -> CoreResult<()> {
        self.repo.update_state(alert_id, state, username).await?;

        if let Ok(Some(updated)) = self.repo.get(alert_id).await {
            let _ = self
                .tx
                .send(alert_to_stream_event(&updated, EventType::Updated));
        }

        Ok(())
    }

    pub async fn get(&self, id: &AlertId) -> CoreResult<Option<Alert>> {
        self.repo.get(id).await
    }

    pub async fn query(&self, state: Option<AlertState>, limit: usize) -> CoreResult<Vec<Alert>> {
        self.repo
            .query(AlertQuery {
                state,
                min_severity: None,
                start_time: None,
                end_time: None,
                limit,
                offset: 0,
            })
            .await
    }

    pub async fn count_by_state(&self, state: Option<AlertState>) -> CoreResult<u64> {
        self.repo
            .count(&AlertQuery {
                state,
                min_severity: None,
                start_time: None,
                end_time: None,
                limit: 100_000,
                offset: 0,
            })
            .await
    }
}

fn alert_to_stream_event(alert: &Alert, event_type: EventType) -> AlertStreamEvent {
    use sentinel_events::sentinel::api::v1;

    AlertStreamEvent {
        alert: Some(v1::Alert {
            id: alert.id.to_string(),
            rule_id: alert.rule_id.clone(),
            risk_score: alert.risk_score,
            severity: alert.severity as i32,
            state: core_alert_state_to_proto(alert.state),
            ..Default::default()
        }),
        event_type: event_type as i32,
    }
}

fn core_alert_state_to_proto(state: AlertState) -> i32 {
    match state {
        AlertState::New => 1,
        AlertState::Acknowledged => 2,
        AlertState::Investigating => 3,
        AlertState::ResolvedTruePositive => 4,
        AlertState::ResolvedFalsePositive => 5,
        AlertState::Suppressed => 6,
    }
}

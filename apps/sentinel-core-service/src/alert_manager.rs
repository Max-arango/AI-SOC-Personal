//! Alert Manager
//!
//! Wraps the AlertRepository with business logic: persists alerts,
//! manages state transitions, and exposes query operations.

use std::sync::Arc;
use sentinel_core::traits::{Alert, AlertRepository, AlertState, AlertQuery};
use sentinel_core::{AlertId, Result as CoreResult, Ulid};
use chrono::Utc;

pub struct AlertManager {
    repo: Arc<dyn AlertRepository>,
}

impl AlertManager {
    pub fn new(repo: Arc<dyn AlertRepository>) -> Self {
        Self { repo }
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
            events: event_ids.into_iter().filter_map(|e| Ulid::from_string(&e).ok()).collect(),
            context,
            ai_summary: None,
        };
        self.repo.create(&alert).await?;
        Ok(alert)
    }

    pub async fn acknowledge(
        &self,
        alert_id: &AlertId,
        username: &str,
    ) -> CoreResult<()> {
        let comment = Some(username.to_string());
        self.repo
            .update_state(alert_id, AlertState::Acknowledged, comment)
            .await
    }

    pub async fn resolve(
        &self,
        alert_id: &AlertId,
        is_true_positive: bool,
    ) -> CoreResult<()> {
        let state = if is_true_positive {
            AlertState::ResolvedTruePositive
        } else {
            AlertState::ResolvedFalsePositive
        };
        self.repo.update_state(alert_id, state, None).await
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

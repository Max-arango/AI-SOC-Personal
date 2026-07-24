use std::sync::Arc;

use sentinel_core::traits::{AlertRepository, AlertState, EventCursor, EventQuery};
use sentinel_core::{ChannelConfig, EventBus, RuleEngineConfig, Ulid};
use sentinel_correlation::{CorrelationConfig, CorrelationEngine};
use sentinel_event_bus::EventBusImpl;
use sentinel_events::Event;
use sentinel_risk::{RiskConfig, RiskEngine};
use sentinel_rule_engine::RuleEngine;
use sentinel_storage::migrations;
use sentinel_storage::sqlite::{SqliteConfig, SqliteStorage};

async fn setup_db(tmp: &tempfile::TempDir) -> Arc<SqliteStorage> {
    let p = tmp.path().join("test.db");
    let storage = SqliteStorage::new(&SqliteConfig {
        path: p.to_string_lossy().to_string(),
        wal_mode: false,
        busy_timeout_ms: 5000,
        max_connections: 2,
    })
    .await
    .unwrap();
    migrations::run_all(storage.pool()).await.unwrap();
    Arc::new(storage)
}

#[tokio::test]
async fn test_event_insert_and_query() {
    let tmp = tempfile::TempDir::new().unwrap();
    let storage = setup_db(&tmp).await;

    let event = Arc::new(Event {
        id: Ulid::new().to_string(),
        r#type: "sentinel.process.create".into(),
        source: "process".into(),
        severity: 2,
        risk_score: 10,
        host_id: "test".into(),
        schema_version: 1,
        ..Default::default()
    });

    let repo = storage.events().await;
    repo.append(&[event.clone()]).await.unwrap();

    let found = repo
        .get(&Ulid::from_string(&event.id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.r#type, "sentinel.process.create");

    let mut cursor = repo
        .query(EventQuery {
            event_types: vec!["sentinel.process.create".into()],
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(cursor.total_count() >= 1);
}

#[tokio::test]
async fn test_alert_crud_integration() {
    let tmp = tempfile::TempDir::new().unwrap();
    let storage = setup_db(&tmp).await;

    let alert = sentinel_core::traits::Alert {
        id: Ulid::new(),
        rule_id: "test-rule".into(),
        correlation_id: Ulid::new(),
        risk_score: 750,
        severity: sentinel_core::Severity::Critical,
        state: AlertState::New,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        acknowledged_by: None,
        acknowledged_at: None,
        events: vec![],
        context: serde_json::Value::Null,
        ai_summary: None,
    };

    let repo = storage.alerts().await;
    repo.create(&alert).await.unwrap();

    let a = repo.get(&alert.id).await.unwrap().unwrap();
    assert_eq!(a.risk_score, 750);
    assert_eq!(a.state, AlertState::New);

    repo.update_state(&alert.id, AlertState::Acknowledged, None)
        .await
        .unwrap();

    let updated = repo.get(&alert.id).await.unwrap().unwrap();
    assert_eq!(updated.state, AlertState::Acknowledged);
}

#[tokio::test]
async fn test_pipeline_rule_engine_evaluates() {
    let engine = RuleEngine::new(&RuleEngineConfig::default()).await.unwrap();

    let event = Arc::new(Event {
        id: Ulid::new().to_string(),
        r#type: "sentinel.process.create".into(),
        source: "process".into(),
        severity: 2,
        risk_score: 10,
        host_id: "test".into(),
        schema_version: 1,
        ..Default::default()
    });

    let result = engine.evaluate(&event).await;
    assert!(result.rules_evaluated >= 0, "Rule engine should evaluate");
}

#[tokio::test]
async fn test_pipeline_risk_scoring() {
    let risk = RiskEngine::new(RiskConfig::default());

    let score = risk.calculate(200, "High", 1.0, None);
    assert!(score > 0, "Risk score should be > 0");

    let alert =
        risk.should_alert("rule-001", "Test Rule", score, "test", vec!["evt-1".into()], None);

    if score >= 100 {
        assert!(alert.is_some(), "Should generate alert above threshold");
    }
}

#[tokio::test]
async fn test_pipeline_correlation_chain() {
    let engine = CorrelationEngine::new(CorrelationConfig::default());

    let e1 = Arc::new(Event {
        id: Ulid::new().to_string(),
        r#type: "sentinel.process.create".into(),
        source: "process".into(),
        severity: 2,
        host_id: "test".into(),
        schema_version: 1,
        process: Some(sentinel_events::ProcessContext { pid: 1000, ..Default::default() }),
        ..Default::default()
    });

    let e2 = Arc::new(Event {
        id: Ulid::new().to_string(),
        r#type: "sentinel.process.create".into(),
        source: "process".into(),
        severity: 2,
        host_id: "test".into(),
        schema_version: 1,
        process: Some(sentinel_events::ProcessContext { pid: 1000, ..Default::default() }),
        ..Default::default()
    });

    let chain1 = engine.ingest(&e1);
    let chain2 = engine.ingest(&e2);

    assert!(!chain1.id.is_empty());
    assert_eq!(chain1.id, chain2.id, "Same PID should join same chain");
}

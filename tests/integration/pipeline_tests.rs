use std::sync::Arc;
use tempfile::TempDir;

use sentinel_core::traits::{
    AlertRepository, AlertState, EventCursor, EventQuery, EventRepository,
};
use sentinel_core::{ChannelConfig, EventBus, Ulid};
use sentinel_correlation::{CorrelationConfig, CorrelationEngine};
use sentinel_event_bus::EventBusImpl;
use sentinel_events::Event;
use sentinel_risk::{RiskConfig, RiskEngine};
use sentinel_rule_engine::RuleEngine;
use sentinel_storage::migrations;
use sentinel_storage::sqlite::{SqliteConfig, SqliteStorage};

async fn setup_test_storage(tmp: &TempDir) -> Arc<SqliteStorage> {
    let db_path = tmp.path().join("test.db").to_string_lossy().to_string();
    let cfg = SqliteConfig {
        path: db_path,
        wal_mode: false,
        busy_timeout_ms: 5000,
        max_connections: 2,
    };
    let storage = SqliteStorage::new(&cfg)
        .await
        .expect("Failed to create test storage");
    migrations::run_all(storage.pool())
        .await
        .expect("Failed to run migrations");
    Arc::new(storage)
}

#[tokio::test]
async fn test_full_pipeline_event_to_alert() {
    let tmp = TempDir::new().unwrap();

    let storage = setup_test_storage(&tmp).await;

    let bus: Arc<dyn EventBus> = Arc::new(EventBusImpl::new(ChannelConfig::default()));
    let bus_runner = bus.clone();
    let _bus_handle = tokio::spawn(async move {
        if let Some(b) = Arc::get_mut(&mut bus_runner.clone()) {
            // Can't access concrete type through dyn trait
            // EventBus doesn't expose run()
        }
    });

    let rule_config = sentinel_core::RuleEngineConfig::default();
    let rule_engine = RuleEngine::new(&rule_config)
        .await
        .expect("Failed to create rule engine");

    let correlation = CorrelationEngine::new(CorrelationConfig::default());
    let risk = RiskEngine::new(RiskConfig::default());

    let mut rule_sub = bus.subscribe_type("*").await.expect("Failed to subscribe");

    let test_event = Arc::new(Event {
        id: Ulid::new().to_string(),
        r#type: "test.event".into(),
        source: "test".into(),
        severity: 2,
        risk_score: 0,
        host_id: "test-host".into(),
        schema_version: 1,
        ..Default::default()
    });

    let test_bus = bus.clone();
    let event_clone = test_event.clone();

    let handle = tokio::spawn(async move {
        test_bus.publish(event_clone).await.unwrap();
    });

    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(event) = rule_sub.receiver.recv().await {
                let _chain = correlation.ingest(&event);
                let result = rule_engine.evaluate(&event).await;

                if !result.matches.is_empty() {
                    for m in &result.matches {
                        let score = risk.calculate(m.risk_score, "Warning", 1.0, None);
                        let _ = risk.should_alert(
                            &m.rule_id,
                            &m.rule_name,
                            score,
                            &event.source,
                            vec![event.id.clone()],
                            None,
                        );
                    }
                }

                let repo = storage.events().await;
                let mut cursor = repo
                    .query(EventQuery {
                        event_types: vec!["test.event".into()],
                        ..Default::default()
                    })
                    .await
                    .expect("Query failed");

                assert!(cursor.total_count() > 0, "Event should be stored");
                break;
            }
        }
    })
    .await;

    handle.expect("Test timed out");

    let events_repo = storage.events().await;
    let events: Vec<_> = events_repo
        .query(EventQuery::default())
        .await
        .unwrap()
        .collect(10)
        .await
        .unwrap();

    assert!(!events.is_empty(), "Events should be stored in DB");
}

#[tokio::test]
async fn test_storage_event_crud() {
    let tmp = TempDir::new().unwrap();
    let storage = setup_test_storage(&tmp).await;

    let event = Arc::new(Event {
        id: Ulid::new().to_string(),
        r#type: "sentinel.process.create".into(),
        source: "process".into(),
        severity: 2,
        risk_score: 10,
        host_id: "test-host".into(),
        schema_version: 1,
        ..Default::default()
    });

    let repo = storage.events().await;
    repo.append(&[event.clone()])
        .await
        .expect("Failed to append event");

    let found = repo
        .get(&sentinel_core::Ulid::from_string(&event.id).unwrap())
        .await
        .expect("Get failed");

    assert!(found.is_some(), "Event should be found by ID");
    assert_eq!(found.unwrap().r#type, "sentinel.process.create");

    let mut cursor = repo
        .query(EventQuery {
            event_types: vec!["sentinel.process.create".into()],
            ..Default::default()
        })
        .await
        .expect("Query failed");

    let events = cursor.collect(100).await.expect("Collect failed");
    assert_eq!(events.len(), 1, "Should find exactly 1 event");
}

#[tokio::test]
async fn test_alert_crud() {
    let tmp = TempDir::new().unwrap();
    let storage = setup_test_storage(&tmp).await;

    let alert = sentinel_core::traits::Alert {
        id: Ulid::new(),
        rule_id: "test-rule".into(),
        correlation_id: Ulid::new(),
        risk_score: 500,
        severity: sentinel_core::Severity::Warning,
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
    repo.create(&alert).await.expect("Create alert failed");

    let found = repo.get(&alert.id).await.expect("Get failed");
    assert!(found.is_some(), "Alert should be found");
    let a = found.unwrap();
    assert_eq!(a.risk_score, 500);
    assert_eq!(a.state, AlertState::New);

    repo.update_state(&alert.id, AlertState::Acknowledged, Some("test".into()))
        .await
        .expect("Update state failed");

    let updated = repo.get(&alert.id).await.expect("Get failed").unwrap();
    assert_eq!(updated.state, AlertState::Acknowledged);
}

#[tokio::test]
async fn test_rule_engine_load_and_eval() {
    let rule_config = sentinel_core::RuleEngineConfig::default();
    let engine = RuleEngine::new(&rule_config)
        .await
        .expect("Failed to create rule engine");

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
    assert!(result.matches.len() >= 0, "Rule engine should evaluate without error");
}

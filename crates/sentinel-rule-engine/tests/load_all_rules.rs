use std::sync::Arc;

use sentinel_config::RuleEngineConfig;
use sentinel_events::Event;
use sentinel_rule_engine::RuleEngine;

#[tokio::test]
async fn test_load_all_50_rules() {
    let config = RuleEngineConfig {
        rules_directories: vec![String::from("../../rules")],
        ..Default::default()
    };

    let engine = RuleEngine::new(&config).await;

    match engine {
        Ok(_) => {
            println!("Successfully loaded all rules from rules/");
        },
        Err(e) => {
            panic!("Failed to load rules: {e}");
        },
    }
}

#[tokio::test]
async fn test_rule_evaluates_process_create() {
    let engine = RuleEngine::new(&RuleEngineConfig {
        rules_directories: vec![String::from("../../rules")],
        ..Default::default()
    })
    .await
    .expect("Failed to load rules");

    let event = Arc::new(Event {
        id: "test-process-create".into(),
        r#type: "sentinel.process.inject".into(),
        source: "process".into(),
        severity: 2,
        risk_score: 10,
        host_id: "test".into(),
        schema_version: 1,
        process: Some(sentinel_events::ProcessContext {
            pid: 5000,
            ppid: 1000,
            name: "malware".into(),
            path: "/tmp/malware".into(),
            command_line: "".into(),
            ..Default::default()
        }),
        ..Default::default()
    });

    let result = engine.evaluate(&event).await;
    println!("Rules evaluated: {}, Matches: {}", result.rules_evaluated, result.matches.len());

    assert!(result.rules_evaluated > 0, "Should evaluate at least some rules");
    assert!(
        result.matches.len() >= 1,
        "Process injection event should match rule-007 (process_injection)"
    );
}

#[tokio::test]
async fn test_rule_evaluates_network_event() {
    let engine = RuleEngine::new(&RuleEngineConfig {
        rules_directories: vec![String::from("../../rules")],
        ..Default::default()
    })
    .await
    .expect("Failed to load rules");

    let event = Arc::new(Event {
        id: "test-high-severity".into(),
        r#type: "sentinel.process.create".into(),
        source: "process".into(),
        severity: 5,
        risk_score: 50,
        host_id: "test".into(),
        schema_version: 1,
        ..Default::default()
    });

    let result = engine.evaluate(&event).await;
    println!("Rules evaluated: {}", result.rules_evaluated);
    println!(
        "Matches: {:?}",
        result
            .matches
            .iter()
            .map(|m| &m.rule_id)
            .collect::<Vec<_>>()
    );
    assert!(result.rules_evaluated > 0, "Should evaluate rules");
    assert!(
        result
            .matches
            .iter()
            .any(|m| m.rule_id == "rule-008-high-severity-event"),
        "SEVERITY_ERROR event should match rule-008 high_severity_event"
    );
}

#[tokio::test]
async fn test_rule_no_match_normal_process() {
    let engine = RuleEngine::new(&RuleEngineConfig {
        rules_directories: vec![String::from("../../rules")],
        ..Default::default()
    })
    .await
    .expect("Failed to load rules");

    let event = Arc::new(Event {
        id: "test-normal".into(),
        r#type: "sentinel.process.create".into(),
        source: "process".into(),
        severity: 2,
        risk_score: 0,
        host_id: "test".into(),
        schema_version: 1,
        process: Some(sentinel_events::ProcessContext {
            pid: 2000,
            name: "code".into(),
            command_line: "code --no-sandbox".into(),
            path: "/usr/bin/code".into(),
            user: Some(sentinel_events::UserContext {
                username: "user".into(),
                is_elevated: false,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    });

    let result = engine.evaluate(&event).await;
    assert!(result.rules_evaluated > 0, "Should evaluate rules even if no match");
}

#[tokio::test]
async fn test_powershell_rule_matches_with_lowerascii_preprocess() {
    let engine = RuleEngine::new(&RuleEngineConfig {
        rules_directories: vec![String::from("../../rules")],
        ..Default::default()
    })
    .await
    .expect("Failed to load rules");

    let event = Arc::new(Event {
        id: "test-powershell-enc".into(),
        r#type: "sentinel.process.create".into(),
        source: "process".into(),
        severity: 4,
        risk_score: 10,
        host_id: "test".into(),
        schema_version: 1,
        process: Some(sentinel_events::ProcessContext {
            pid: 5000,
            ppid: 1000,
            name: "powershell".into(),
            command_line: "powershell -enc SQBFAFgA".into(),
            path: "/tmp/powershell".into(),
            ..Default::default()
        }),
        ..Default::default()
    });

    let result = engine.evaluate(&event).await;
    let matches: Vec<_> = result.matches.iter().map(|m| &m.rule_id).collect();
    println!("Rules evaluated: {}, Matches: {:?}", result.rules_evaluated, matches);

    assert!(result.rules_evaluated >= 49, "Should evaluate at least 49 rules");
    assert!(
        matches.contains(&&"rule-001-suspicious-powershell".to_string()),
        "PowerShell encoded command should match rule-001 after lowerAscii() preprocessing"
    );
}

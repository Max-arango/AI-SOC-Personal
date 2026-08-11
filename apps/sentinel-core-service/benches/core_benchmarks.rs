use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::Arc;

use sentinel_core::{ChannelConfig, EventBus, RuleEngineConfig, Ulid};
use sentinel_event_bus::EventBusImpl;
use sentinel_events::Event;
use sentinel_rule_engine::RuleEngine;

fn bench_event_bus_publish(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let bus: Arc<dyn EventBus> = Arc::new(EventBusImpl::new(ChannelConfig::default()));
    let event = Arc::new(Event {
        id: Ulid::new().to_string(),
        r#type: "sentinel.process.create".into(),
        source: "process".into(),
        severity: 2,
        risk_score: 10,
        host_id: "bench".into(),
        schema_version: 1,
        ..Default::default()
    });

    c.bench_function("event_bus_publish", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = bus.publish(event.clone()).await;
            });
        });
    });
}

fn bench_rule_engine_evaluate(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let engine =
        rt.block_on(async { RuleEngine::new(&RuleEngineConfig::default()).await.unwrap() });

    let event = Arc::new(Event {
        id: Ulid::new().to_string(),
        r#type: "sentinel.process.create".into(),
        source: "process".into(),
        severity: 4,
        risk_score: 10,
        host_id: "bench".into(),
        schema_version: 1,
        process: Some(sentinel_events::ProcessContext {
            pid: 5000,
            ppid: 1000,
            name: "powershell".into(),
            command_line: "powershell -enc SQBFAFgA".into(),
            ..Default::default()
        }),
        ..Default::default()
    });

    c.bench_function("rule_engine_evaluate", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = engine.evaluate(&event).await;
            });
        });
    });
}

fn bench_risk_engine_calculate(c: &mut Criterion) {
    let risk = sentinel_risk::RiskEngine::new(sentinel_risk::RiskConfig::default());

    c.bench_function("risk_engine_calculate", |b| {
        b.iter(|| {
            risk.calculate(black_box(200), black_box("High"), black_box(1.0), black_box(None));
        });
    });
}

criterion_group!(
    benches,
    bench_event_bus_publish,
    bench_rule_engine_evaluate,
    bench_risk_engine_calculate,
);
criterion_main!(benches);

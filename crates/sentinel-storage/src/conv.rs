//! Localized conversions between generated proto event types and JSON used by
//! the storage layer. The generated types intentionally do not derive serde
//! (the `.proto` contract is unchanged); these helpers adapt the well-known
//! `prost_types` types and the event payloads for persistence.

use prost_types::{value::Kind, Struct, Timestamp, Value};
use sentinel_events::{CorrelationContext, Event};

/// Recursively convert a `google.protobuf.Struct` into a `serde_json::Value`.
pub fn struct_to_json(s: &Struct) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (k, v) in &s.fields {
        map.insert(k.clone(), value_to_json(v));
    }
    serde_json::Value::Object(map)
}

fn value_to_json(v: &Value) -> serde_json::Value {
    match &v.kind {
        Some(Kind::NullValue(_)) => serde_json::Value::Null,
        Some(Kind::NumberValue(n)) => serde_json::Value::from(*n),
        Some(Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(Kind::StructValue(st)) => struct_to_json(st),
        Some(Kind::ListValue(lv)) => {
            serde_json::Value::Array(lv.values.iter().map(value_to_json).collect())
        }
        None => serde_json::Value::Null,
    }
}

/// Convert an optional `google.protobuf.Timestamp` into an RFC3339 string
/// (empty when absent, since the backing columns are `NOT NULL`).
pub fn ts_to_rfc3339(ts: &Option<Timestamp>) -> String {
    match ts {
        Some(t) => chrono::DateTime::from_timestamp(t.seconds, t.nanos.max(0) as u32)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default(),
        None => String::new(),
    }
}

/// Convert a `CorrelationContext` into a JSON object.
pub fn correlation_to_json(c: &CorrelationContext) -> serde_json::Value {
    serde_json::json!({
        "session_id": c.session_id,
        "cause_event_id": c.cause_event_id,
        "root_event_id": c.root_event_id,
        "correlation_id": c.correlation_id,
        "flow_id": c.flow_id,
        "sequence": c.sequence,
    })
}

/// Serialize a complex nested payload as a debug string. The storage layer only
/// persists these for forensic retention; structured querying is done via the
/// dedicated columns above.
pub fn debug_json<T: std::fmt::Debug>(v: &T) -> String {
    format!("{:?}", v)
}

/// Build the JSON object persisted for an `Event` in the `metadata`/`payload`
/// style columns. This is intentionally minimal and localized to storage.
pub fn event_payload_json(event: &Event) -> serde_json::Value {
    serde_json::json!({
        "id": event.id,
        "type": event.r#type,
        "source": event.source,
        "severity": event.severity,
        "tags": event.tags,
        "risk_score": event.risk_score,
        "host_id": event.host_id,
        "schema_version": event.schema_version,
        "timestamp": ts_to_rfc3339(&event.timestamp),
        "ingest_timestamp": ts_to_rfc3339(&event.ingest_timestamp),
        "process": event.process.as_ref().map(debug_json),
        "payload": event.payload.as_ref().map(debug_json),
        "metadata": event.metadata.as_ref().map(struct_to_json),
        "correlation": event.correlation.as_ref().map(correlation_to_json),
    })
}

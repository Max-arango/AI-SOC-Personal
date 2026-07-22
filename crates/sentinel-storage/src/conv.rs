//! Conversions between proto event types and JSON for the storage layer.
//! The protobuf types do not derive serde, so these helpers produce proper
//! JSON (not Rust Debug format) for all nested structures.

use prost_types::{value::Kind, Struct, Timestamp, Value as PbValue};
use sentinel_events::{event, CodeSigningInfo, CorrelationContext, Event, ProcessContext, UserContext};

// ── core type converters ──────────────────────────────────────────

pub fn struct_to_json(s: &Struct) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (k, v) in &s.fields {
        map.insert(k.clone(), value_to_json(v));
    }
    serde_json::Value::Object(map)
}

fn value_to_json(v: &PbValue) -> serde_json::Value {
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

pub fn ts_to_rfc3339(ts: &Option<Timestamp>) -> String {
    match ts {
        Some(t) => chrono::DateTime::from_timestamp(t.seconds, t.nanos.max(0) as u32)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default(),
        None => String::new(),
    }
}

// ── nested proto → JSON converters ───────────────────────────────

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

pub fn process_to_json(proc: &ProcessContext) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "pid": proc.pid,
        "ppid": proc.ppid,
        "name": proc.name,
        "path": proc.path,
        "command_line": proc.command_line,
        "cwd": proc.cwd,
        "integrity_level": proc.integrity_level,
        "tree_depth": proc.tree_depth,
        "sha256": proc.sha256,
        "mitre_techniques": proc.mitre_techniques,
    });
    if let Some(ref user) = proc.user {
        obj["user"] = user_to_json(user);
    }
    if let Some(ref signing) = proc.signing {
        obj["signing"] = signing_to_json(signing);
    }
    if let Some(ref parent) = proc.parent {
        obj["parent"] = process_to_json(parent);
    }
    obj
}

pub fn user_to_json(user: &UserContext) -> serde_json::Value {
    serde_json::json!({
        "sid": user.sid,
        "username": user.username,
        "domain": user.domain,
        "is_elevated": user.is_elevated,
        "is_system": user.is_system,
    })
}

pub fn signing_to_json(signing: &CodeSigningInfo) -> serde_json::Value {
    serde_json::json!({
        "is_signed": signing.is_signed,
        "is_trusted": signing.is_trusted,
        "publisher": signing.publisher,
        "issuer": signing.issuer,
    })
}

pub fn payload_to_json(payload: &event::Payload) -> serde_json::Value {
    use event::Payload;
    match payload {
        Payload::ProcessEvent(e) => serde_json::json!({
            "kind": "ProcessEvent",
            "action": e.action,
            "desired_access": e.desired_access,
        }),
        Payload::NetworkEvent(e) => serde_json::json!({
            "kind": "NetworkEvent",
            "direction": e.direction,
            "protocol": e.protocol,
            "action": e.action,
            "local_addr": e.local_addr,
            "local_port": e.local_port,
            "remote_addr": e.remote_addr,
            "remote_port": e.remote_port,
            "hostname": e.hostname,
            "dns_query": e.dns_query,
            "ja3_fingerprint": e.ja3_fingerprint,
            "ja3s_fingerprint": e.ja3s_fingerprint,
        }),
        Payload::FileEvent(e) => serde_json::json!({
            "kind": "FileEvent",
            "action": e.action,
            "path": e.path,
            "sha256": e.sha256,
            "entropy": e.entropy,
            "is_executable": e.is_executable,
            "is_sensitive_path": e.is_sensitive_path,
        }),
        Payload::RegistryEvent(e) => serde_json::json!({
            "kind": "RegistryEvent",
            "action": e.action,
            "hive": e.hive,
            "key_path": e.key_path,
            "value_name": e.value_name,
        }),
        Payload::UsbEvent(e) => serde_json::json!({
            "kind": "UsbEvent",
            "action": e.action,
            "vendor_id": e.vendor_id,
            "product_id": e.product_id,
            "serial_number": e.serial_number,
            "manufacturer": e.manufacturer,
            "product": e.product,
            "is_encrypted": e.is_encrypted,
        }),
        Payload::BrowserEvent(e) => serde_json::json!({
            "kind": "BrowserEvent",
            "browser": e.browser,
            "action": e.action,
            "url": e.url,
            "title": e.title,
            "referrer": e.referrer,
            "download_path": e.download_path,
            "is_incognito": e.is_incognito,
        }),
        Payload::StartupEvent(e) => serde_json::json!({
            "kind": "StartupEvent",
            "action": e.action,
            "location": e.location,
            "name": e.name,
            "command": e.command,
            "arguments": e.arguments,
            "user": e.user,
            "is_signed": e.is_signed,
            "publisher": e.publisher,
        }),
        Payload::GenericEvent(e) => serde_json::json!({
            "kind": "GenericEvent",
            "custom_type": e.custom_type,
        }),
    }
}

/// Build the full JSON object persisted for an Event.
pub fn event_to_json(event: &Event) -> serde_json::Value {
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
        "process": event.process.as_ref().map(process_to_json),
        "payload": event.payload.as_ref().map(payload_to_json),
        "metadata": event.metadata.as_ref().map(struct_to_json),
        "correlation": event.correlation.as_ref().map(correlation_to_json),
    })
}

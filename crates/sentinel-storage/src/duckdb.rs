//! DuckDB storage for analytical queries

use anyhow::{Context, Result};
use chrono::Utc;
use duckdb::{params, Connection};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use sentinel_core::{
    traits::{
        AggregationBucket, AggregationQuery, AggregationResult, EventCursor, EventQuery,
        RetentionPolicy,
    },
    EventId, Result as CoreResult,
};
use sentinel_events::Event;

/// DuckDB configuration
#[derive(Debug, Clone)]
pub struct DuckDbConfig {
    pub path: String,
    pub memory_limit_mb: u32,
    pub threads: u32,
    pub read_only: bool,
}

impl Default for DuckDbConfig {
    fn default() -> Self {
        Self {
            path: "data/events.duckdb".to_string(),
            memory_limit_mb: 256,
            threads: 2,
            read_only: false,
        }
    }
}

/// DuckDB storage implementation
pub struct DuckDbStorage {
    conn: Arc<Mutex<Connection>>,
}

impl DuckDbStorage {
    /// Create new DuckDB storage
    pub async fn new(config: &DuckDbConfig) -> Result<Self> {
        if let Some(parent) = Path::new(&config.path).parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("Failed to create database directory")?;
        }

        let conn = Connection::open(&config.path).context("Failed to open DuckDB connection")?;

        // Configure
        conn.execute(&format!("PRAGMA memory_limit='{}MB'", config.memory_limit_mb), [])?;
        conn.execute(&format!("PRAGMA threads={}", config.threads), [])?;

        // Create schema
        Self::create_schema(&conn)?;

        info!("DuckDB storage initialized at {}", config.path);

        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    /// Create database schema
    fn create_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(r#"
            CREATE TABLE IF NOT EXISTS events (
                id VARCHAR PRIMARY KEY,
                type VARCHAR NOT NULL,
                source VARCHAR NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                ingest_timestamp TIMESTAMP NOT NULL,
                severity INTEGER NOT NULL,
                process_json JSON,
                payload_json JSON NOT NULL,
                tags VARCHAR[],
                metadata_json JSON,
                risk_score INTEGER DEFAULT 0,
                correlation_json JSON,
                host_id VARCHAR,
                schema_version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
            CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_events_risk_score ON events(risk_score);
            CREATE INDEX IF NOT EXISTS idx_events_host_id ON events(host_id);
            CREATE INDEX IF NOT EXISTS idx_events_process_name ON events(JSON_EXTRACT(process_json, '$.name'));
            CREATE INDEX IF NOT EXISTS idx_events_correlation_id ON events(JSON_EXTRACT(correlation_json, '$.correlation_id'));
            CREATE INDEX IF NOT EXISTS idx_events_flow_id ON events(JSON_EXTRACT(correlation_json, '$.flow_id'));
        "#)?;

        // Aggregation tables
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS hourly_risk (
                hour TIMESTAMP PRIMARY KEY,
                host_id VARCHAR,
                risk_score INTEGER,
                event_count BIGINT,
                alert_count INTEGER,
                by_category JSON,
                by_tactic JSON
            );
            
            CREATE TABLE IF NOT EXISTS daily_mitre (
                day DATE PRIMARY KEY,
                tactic VARCHAR,
                technique VARCHAR,
                count BIGINT
            );
            
            CREATE TABLE IF NOT EXISTS process_behavior (
                hour TIMESTAMP,
                process_name VARCHAR,
                pid INTEGER,
                event_count BIGINT,
                risk_score INTEGER,
                mitre_techniques VARCHAR[],
                PRIMARY KEY (hour, process_name, pid)
            );
        "#,
        )?;

        Ok(())
    }

    /// Health check
    pub async fn health(&self) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("SELECT 1", [])?;
        Ok(())
    }

    /// Append events
    pub async fn append_events(&self, events: &[Arc<Event>]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "INSERT INTO events (id, type, source, timestamp, ingest_timestamp, severity, process_json, payload_json, tags, metadata_json, risk_score, correlation_json, host_id, schema_version)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )?;

        for event in events {
            let process_json = event
                .process
                .as_ref()
                .map(crate::conv::process_to_json)
                .map(|v| v.to_string())
                .unwrap_or_default();
            let payload_json = event
                .payload
                .as_ref()
                .map(crate::conv::payload_to_json)
                .map(|v| v.to_string())
                .unwrap_or_default();
            let tags = event.tags.join(",");
            let metadata_json = event
                .metadata
                .as_ref()
                .map(|m| crate::conv::struct_to_json(m).to_string())
                .unwrap_or_default();
            let correlation_json = event
                .correlation
                .as_ref()
                .map(|c| crate::conv::correlation_to_json(c).to_string())
                .unwrap_or_default();
            let timestamp = crate::conv::ts_to_rfc3339(&event.timestamp);
            let ingest_timestamp = crate::conv::ts_to_rfc3339(&event.ingest_timestamp);

            stmt.execute(params![
                event.id,
                event.r#type,
                event.source,
                timestamp,
                ingest_timestamp,
                { event.severity },
                process_json,
                payload_json,
                tags,
                metadata_json,
                event.risk_score as i64,
                correlation_json,
                event.host_id,
                event.schema_version as i32,
            ])?;
        }

        Ok(())
    }

    /// Query events
    pub async fn query_events(&self, query: EventQuery) -> Result<DuckDbEventCursor> {
        let conn = self.conn.lock().await;

        let mut sql = String::from("SELECT * FROM events WHERE 1=1");
        let mut params: Vec<String> = Vec::new();

        // Time range
        if let Some(start) = query.start_time {
            sql.push_str(" AND timestamp >= ?");
            params.push(start.to_rfc3339());
        }
        if let Some(end) = query.end_time {
            sql.push_str(" AND timestamp <= ?");
            params.push(end.to_rfc3339());
        }

        // Event types
        if !query.event_types.is_empty() {
            let placeholders = query
                .event_types
                .iter()
                .map(|_| "?")
                .collect::<Vec<_>>()
                .join(",");
            sql.push_str(&format!(" AND type IN ({})", placeholders));
            params.extend(query.event_types);
        }

        // Sources
        if !query.sources.is_empty() {
            let placeholders = query
                .sources
                .iter()
                .map(|_| "?")
                .collect::<Vec<_>>()
                .join(",");
            sql.push_str(&format!(" AND source IN ({})", placeholders));
            params.extend(query.sources);
        }

        // Severities
        if !query.severities.is_empty() {
            let placeholders = query
                .severities
                .iter()
                .map(|_| "?")
                .collect::<Vec<_>>()
                .join(",");
            sql.push_str(&format!(" AND severity IN ({})", placeholders));
            for sev in &query.severities {
                params.push((*sev as i32).to_string());
            }
        }

        // Process names
        if !query.process_names.is_empty() {
            let placeholders = query
                .process_names
                .iter()
                .map(|_| "?")
                .collect::<Vec<_>>()
                .join(",");
            sql.push_str(&format!(
                " AND JSON_EXTRACT(process_json, '$.name') IN ({})",
                placeholders
            ));
            params.extend(query.process_names);
        }

        // PIDs
        if !query.pids.is_empty() {
            let placeholders = query.pids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            sql.push_str(&format!(
                " AND JSON_EXTRACT(process_json, '$.pid') IN ({})",
                placeholders
            ));
            for pid in &query.pids {
                params.push(pid.to_string());
            }
        }

        // Correlation ID
        if let Some(ref cid) = query.correlation_id {
            sql.push_str(" AND JSON_EXTRACT(correlation_json, '$.correlation_id') = ?");
            params.push(cid.clone());
        }

        // Flow ID
        if let Some(ref fid) = query.flow_id {
            sql.push_str(" AND JSON_EXTRACT(correlation_json, '$.flow_id') = ?");
            params.push(fid.clone());
        }

        // Min risk score
        if let Some(min_risk) = query.min_risk_score {
            sql.push_str(" AND risk_score >= ?");
            params.push(min_risk.to_string());
        }

        // Tags
        for tag in &query.tags {
            sql.push_str(" AND tags LIKE ?");
            params.push(format!("%{}%", tag));
        }

        // Free text
        if let Some(ref text) = query.free_text {
            sql.push_str(
                " AND (payload_json LIKE ? OR JSON_EXTRACT(process_json, '$.command_line') LIKE ?)",
            );
            let pattern = format!("%{}%", text);
            params.push(pattern.clone());
            params.push(pattern);
        }

        // Order
        let sort_by = query.sort_by.as_deref().unwrap_or("timestamp");
        let sort_order = if query.sort_desc { "DESC" } else { "ASC" };
        sql.push_str(&format!(" ORDER BY {} {}", sort_by, sort_order));

        // Limit/offset
        sql.push_str(" LIMIT ? OFFSET ?");
        params.push(query.limit.to_string());
        params.push(query.offset.to_string());

        // Convert params to duckdb params
        let duckdb_params: Vec<&str> = params.iter().map(|s| s.as_str()).collect();
        let dyn_params: Vec<&dyn duckdb::ToSql> = duckdb_params
            .iter()
            .map(|s| s as &dyn duckdb::ToSql)
            .collect();

        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(&dyn_params[..])?;

        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            let event = self.row_to_event(row)?;
            events.push(Arc::new(event));
        }

        Ok(DuckDbEventCursor { events, index: 0 })
    }

    /// Get single event
    pub async fn get_event(&self, _id: &EventId) -> Result<Option<Arc<Event>>> {
        // Stub: a full implementation would query by id and rebuild the event.
        Ok(None)
    }

    /// Count events
    pub async fn count_events(&self, query: &EventQuery) -> Result<u64> {
        let conn = self.conn.lock().await;

        let mut sql = String::from("SELECT COUNT(*) FROM events WHERE 1=1");
        let mut params: Vec<String> = Vec::new();

        // Apply same filters as query_events (abbreviated)
        if let Some(start) = query.start_time {
            sql.push_str(" AND timestamp >= ?");
            params.push(start.to_rfc3339());
        }
        if let Some(end) = query.end_time {
            sql.push_str(" AND timestamp <= ?");
            params.push(end.to_rfc3339());
        }

        let dyn_params: Vec<&dyn duckdb::ToSql> =
            params.iter().map(|s| s as &dyn duckdb::ToSql).collect();
        let mut stmt = conn.prepare(&sql)?;
        let count: i64 = stmt.query_row(&dyn_params[..], |row| row.get::<_, i64>(0))?;
        Ok(count as u64)
    }

    /// Aggregate events
    pub async fn aggregate_events(&self, agg: AggregationQuery) -> Result<AggregationResult> {
        let conn = self.conn.lock().await;

        let group_by = match agg.group_by.as_str() {
            "hour" => "strftime('%Y-%m-%d %H:00:00', timestamp)",
            "day" => "date(timestamp)",
            "type" => "type",
            "source" => "source",
            "severity" => "severity",
            _ => "strftime('%Y-%m-%d %H:00:00', timestamp)",
        };

        let sql = format!(
            "SELECT {} as group_key, COUNT(*) as count, AVG(risk_score) as avg_risk, MIN(risk_score) as min_risk, MAX(risk_score) as max_risk
             FROM events 
             WHERE timestamp >= ? AND timestamp <= ?
             GROUP BY {}",
            group_by, group_by
        );

        let start = agg.start_time.to_rfc3339();
        let end = agg.end_time.to_rfc3339();
        let dyn_params: Vec<&dyn duckdb::ToSql> = vec![&start, &end];
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(&dyn_params[..])?;

        let mut buckets = Vec::new();
        while let Some(row) = rows.next()? {
            buckets.push(AggregationBucket {
                key: row.get(0)?,
                count: row.get::<_, i64>(1)? as u64,
                avg_risk: row.get(2)?,
                min_risk: row.get::<_, Option<i64>>(3)?.map(|v| v as u32),
                max_risk: row.get::<_, Option<i64>>(4)?.map(|v| v as u32),
            });
        }

        Ok(AggregationResult { buckets })
    }

    /// Apply retention policy
    pub async fn apply_retention(&self, policy: RetentionPolicy) -> Result<u64> {
        let conn = self.conn.lock().await;

        let sql = "DELETE FROM events WHERE type LIKE ? AND timestamp < datetime('now', ?) AND id IN (
                SELECT id FROM events WHERE type LIKE ? AND timestamp < datetime('now', ?) ORDER BY timestamp DESC LIMIT ?
            )".to_string();

        let max_age = format!("-{} days", policy.max_age_days);

        let deleted = conn.execute(
            &sql,
            params![
                &policy.event_type_pattern,
                &max_age,
                &policy.event_type_pattern,
                &max_age,
                policy.max_count as i64,
            ],
        )?;

        Ok(deleted as u64)
    }

    /// Convert row to Event
    fn row_to_event(&self, row: &duckdb::Row) -> Result<Event> {
        row_to_event(row)
    }
}

/// Parse an RFC3339 string into a proto `Timestamp`.
fn parse_timestamp(s: &str) -> Option<prost_types::Timestamp> {
    let dt = chrono::DateTime::parse_from_rfc3339(s).ok()?;
    let dt = dt.with_timezone(&Utc);
    Some(prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    })
}

/// Convert a DuckDB row into a proto `Event`.
///
/// `process`, `payload`, `metadata` and `correlation` are stored as JSON text in
/// DuckDB but the generated proto types are not `serde`-deserializable, so they are
/// left as `None` on read. This keeps the analytics store functional while avoiding
/// coupling to generated-type serde.
fn row_to_event(row: &duckdb::Row) -> Result<Event> {
    let tags: String = row.get("tags")?;
    let tags = tags
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let timestamp: String = row.get("timestamp")?;
    let ingest_timestamp: String = row.get("ingest_timestamp")?;

    Ok(Event {
        id: row.get("id")?,
        r#type: row.get("type")?,
        source: row.get("source")?,
        timestamp: parse_timestamp(&timestamp),
        ingest_timestamp: parse_timestamp(&ingest_timestamp),
        severity: row.get::<_, i32>("severity")?,
        process: None,
        payload: None,
        tags,
        metadata: None,
        risk_score: row.get::<_, i64>("risk_score")? as u32,
        correlation: None,
        host_id: row.get("host_id")?,
        schema_version: row.get::<_, i32>("schema_version")? as u32,
    })
}

/// DuckDB event cursor
pub struct DuckDbEventCursor {
    events: Vec<Arc<Event>>,
    index: usize,
}

#[async_trait::async_trait]
impl EventCursor for DuckDbEventCursor {
    async fn next(&mut self) -> CoreResult<Option<Arc<Event>>> {
        if self.index < self.events.len() {
            let event = self.events[self.index].clone();
            self.index += 1;
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    async fn collect(&mut self, limit: usize) -> CoreResult<Vec<Arc<Event>>> {
        let mut events = Vec::new();
        for _ in 0..limit {
            if let Some(event) = self.next().await? {
                events.push(event);
            } else {
                break;
            }
        }
        Ok(events)
    }

    fn total_count(&self) -> u64 {
        self.events.len() as u64
    }
}

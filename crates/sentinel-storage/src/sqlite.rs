//! SQLite storage for metadata, config, rules, alerts

use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use sentinel_core::{
    traits::{
        AggregationBucket, AggregationQuery, AggregationResult, AlertRepository, ChainRepository,
        ConfigRepository, EventCursor, EventQuery, EventRepository, RetentionPolicy, RuleRepository,
        AttackChain, ChainQuery, ChainStatus,
    },
    AlertId, ConfigValue, EventId, Result as CoreResult, SentinelError,
};
use sentinel_events::Event;

/// SQLite configuration
#[derive(Debug, Clone)]
pub struct SqliteConfig {
    pub path: String,
    pub wal_mode: bool,
    pub busy_timeout_ms: u32,
    pub max_connections: u32,
}

impl Default for SqliteConfig {
    fn default() -> Self {
        Self {
            path: "data/sentinel.db".to_string(),
            wal_mode: true,
            busy_timeout_ms: 5000,
            max_connections: 5,
        }
    }
}

/// SQLite storage implementation
pub struct SqliteStorage {
    pool: SqlitePool,
    event_repo: Arc<RwLock<Option<Arc<SqliteEventRepository>>>>,
    rule_repo: Arc<RwLock<Option<Arc<SqliteRuleRepository>>>>,
    alert_repo: Arc<RwLock<Option<Arc<SqliteAlertRepository>>>>,
    config_repo: Arc<RwLock<Option<Arc<SqliteConfigRepository>>>>,
    chain_repo: Arc<RwLock<Option<Arc<SqliteChainRepository>>>>,
}

impl SqliteStorage {
    /// Create new SQLite storage
    pub async fn new(config: &SqliteConfig) -> Result<Self> {
        // Create parent directory if needed
        if let Some(parent) = Path::new(&config.path).parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("Failed to create database directory")?;
        }

        let pool = SqlitePoolOptions::new()
            .max_connections(config.max_connections)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&config.path)
                    .create_if_missing(true)
                    .journal_mode(if config.wal_mode {
                        sqlx::sqlite::SqliteJournalMode::Wal
                    } else {
                        sqlx::sqlite::SqliteJournalMode::Delete
                    })
                    .busy_timeout(std::time::Duration::from_millis(config.busy_timeout_ms as u64)),
            )
            .await
            .context("Failed to connect to SQLite")?;

        // Enable foreign keys
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await?;

        info!("SQLite storage initialized at {}", config.path);

        Ok(Self {
            pool,
            event_repo: Arc::new(RwLock::new(None)),
            rule_repo: Arc::new(RwLock::new(None)),
            alert_repo: Arc::new(RwLock::new(None)),
            config_repo: Arc::new(RwLock::new(None)),
            chain_repo: Arc::new(RwLock::new(None)),
        })
    }

    /// Get connection pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Health check
    pub async fn health(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Get or create event repository
    pub async fn events(&self) -> Arc<dyn EventRepository> {
        let mut repo = self.event_repo.write().await;
        if repo.is_none() {
            *repo = Some(Arc::new(SqliteEventRepository::new(self.pool.clone())));
        }
        repo.clone().expect("event repo must be initialized")
    }

    /// Get or create rule repository
    pub async fn rules(&self) -> Arc<dyn RuleRepository> {
        let mut repo = self.rule_repo.write().await;
        if repo.is_none() {
            *repo = Some(Arc::new(SqliteRuleRepository::new(self.pool.clone())));
        }
        repo.clone().expect("rule repo must be initialized")
    }

    /// Get or create alert repository
    pub async fn alerts(&self) -> Arc<dyn AlertRepository> {
        let mut repo = self.alert_repo.write().await;
        if repo.is_none() {
            *repo = Some(Arc::new(SqliteAlertRepository::new(self.pool.clone())));
        }
        repo.clone().expect("alert repo must be initialized")
    }

    /// Get or create config repository
    pub async fn config(&self) -> Arc<dyn ConfigRepository> {
        let mut repo = self.config_repo.write().await;
        if repo.is_none() {
            *repo = Some(Arc::new(SqliteConfigRepository::new(self.pool.clone())));
        }
        repo.clone().expect("config repo must be initialized")
    }

    /// Get or create chain repository
    pub async fn chains(&self) -> Arc<dyn ChainRepository> {
        let mut repo = self.chain_repo.write().await;
        if repo.is_none() {
            *repo = Some(Arc::new(SqliteChainRepository::new(self.pool.clone())));
        }
        repo.clone().expect("chain repo must be initialized")
    }
}

/// SQLite event repository
pub struct SqliteEventRepository {
    pool: SqlitePool,
}

impl SqliteEventRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl EventRepository for SqliteEventRepository {
    async fn append(&self, events: &[Arc<Event>]) -> CoreResult<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await.map_err(|e| {
            SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
        })?;

        for event in events {
            let process_json = event
                .process
                .as_ref()
                .map(crate::conv::process_to_json)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "{}".to_string());
            let payload_json = event
                .payload
                .as_ref()
                .map(crate::conv::payload_to_json)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "{}".to_string());
            let tags_json = serde_json::to_string(&event.tags)
                .map_err(|e| SentinelError::Serialization(e.into()))?;
            let metadata_json = event
                .metadata
                .as_ref()
                .map(|m| crate::conv::struct_to_json(m).to_string())
                .unwrap_or_else(|| "{}".to_string());
            let correlation_json = event
                .correlation
                .as_ref()
                .map(|c| crate::conv::correlation_to_json(c).to_string())
                .unwrap_or_else(|| "{}".to_string());
            let timestamp = crate::conv::ts_to_rfc3339(&event.timestamp);
            let ingest_timestamp = crate::conv::ts_to_rfc3339(&event.ingest_timestamp);
            let severity = event.severity;
            let risk_score = event.risk_score as i64;
            let schema_version = event.schema_version as i32;

            sqlx::query(
                r#"
                INSERT INTO events (id, type, source, timestamp, ingest_timestamp, severity, process, payload, tags, metadata, risk_score, correlation, host_id, schema_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&event.id)
            .bind(&event.r#type)
            .bind(&event.source)
            .bind(&timestamp)
            .bind(&ingest_timestamp)
            .bind(severity)
            .bind(&process_json)
            .bind(&payload_json)
            .bind(&tags_json)
            .bind(&metadata_json)
            .bind(risk_score)
            .bind(&correlation_json)
            .bind(&event.host_id)
            .bind(schema_version)
            .execute(&mut *tx)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        }

        tx.commit().await.map_err(|e| {
            SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
        })?;

        Ok(())
    }

    async fn query(&self, query: EventQuery) -> CoreResult<Arc<dyn EventCursor>> {
        let mut sql = String::from("SELECT * FROM events WHERE 1=1");
        let mut params: Vec<String> = Vec::new();
        let limit = query.limit;
        let offset = query.offset;

        if let Some(ref start) = query.start_time {
            sql.push_str(" AND timestamp >= ?");
            params.push(start.to_rfc3339());
        }
        if let Some(ref end) = query.end_time {
            sql.push_str(" AND timestamp <= ?");
            params.push(end.to_rfc3339());
        }

        if !query.event_types.is_empty() {
            let placeholders: Vec<&str> = vec!["?"; query.event_types.len()];
            sql.push_str(&format!(" AND type IN ({})", placeholders.join(",")));
            params.extend(query.event_types.iter().cloned());
        }

        if !query.sources.is_empty() {
            let placeholders: Vec<&str> = vec!["?"; query.sources.len()];
            sql.push_str(&format!(" AND source IN ({})", placeholders.join(",")));
            params.extend(query.sources.iter().cloned());
        }

        if !query.severities.is_empty() {
            let placeholders: Vec<&str> = vec!["?"; query.severities.len()];
            sql.push_str(&format!(" AND severity IN ({})", placeholders.join(",")));
            for sev in &query.severities {
                params.push(format!("{}", *sev as i32));
            }
        }

        if !query.process_names.is_empty() {
            for pn in &query.process_names {
                sql.push_str(" AND process LIKE ?");
                params.push(format!("%\"name\":\"{}\"%", pn));
            }
        }

        if !query.pids.is_empty() {
            for pid in &query.pids {
                sql.push_str(" AND process LIKE ?");
                params.push(format!("%\"pid\":{}%", pid));
            }
        }

        if let Some(ref cid) = query.correlation_id {
            sql.push_str(" AND correlation LIKE ?");
            params.push(format!("%\"correlation_id\":\"{}\"%", cid));
        }

        if let Some(ref fid) = query.flow_id {
            sql.push_str(" AND correlation LIKE ?");
            params.push(format!("%\"flow_id\":\"{}\"%", fid));
        }

        if let Some(min_risk) = query.min_risk_score {
            sql.push_str(" AND risk_score >= ?");
            params.push(format!("{}", min_risk));
        }

        if !query.tags.is_empty() {
            for tag in &query.tags {
                sql.push_str(" AND tags LIKE ?");
                params.push(format!("%{}%", tag));
            }
        }

        if let Some(ref text) = query.free_text {
            sql.push_str(" AND (payload LIKE ? OR process LIKE ?)");
            let p = format!("%{}%", text);
            params.push(p.clone());
            params.push(p);
        }

        let sort_by = query.sort_by.as_deref().unwrap_or("timestamp");
        let valid_sort = ["timestamp", "severity", "risk_score", "type", "source", "host_id"];
        let sort_col = valid_sort.iter().find(|&&c| c == sort_by).unwrap_or(&"timestamp");
        let sort_order = if query.sort_desc { "DESC" } else { "ASC" };
        sql.push_str(&format!(" ORDER BY {} {}", sort_col, sort_order));
        sql.push_str(" LIMIT ? OFFSET ?");
        params.push(format!("{}", limit));
        params.push(format!("{}", offset));

        // Build a query with dynamically-bound parameters
        let mut q = sqlx::query(&sql);
        for p in &params {
            q = q.bind(p);
        }

        let rows = q.fetch_all(&self.pool).await.map_err(|e| {
            SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
        })?;

        let total_count = rows.len() as u64;
        let events: Vec<Arc<Event>> = rows.iter().filter_map(|r| row_to_event(r).ok()).collect();

        Ok(Arc::new(SqliteEventCursor {
            events,
            position: tokio::sync::Mutex::new(0),
            total_count,
        }))
    }

    async fn get(&self, id: &EventId) -> CoreResult<Option<Arc<Event>>> {
        let id_str = id.to_string();
        let row = sqlx::query("SELECT * FROM events WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
            })?;

        row.map(|r| row_to_event(&r)).transpose()
    }

    async fn count(&self, query: &EventQuery) -> CoreResult<u64> {
        let mut sql = String::from("SELECT COUNT(*) as cnt FROM events WHERE 1=1");
        let mut params: Vec<String> = Vec::new();

        if let Some(ref start) = query.start_time {
            sql.push_str(" AND timestamp >= ?");
            params.push(start.to_rfc3339());
        }
        if let Some(ref end) = query.end_time {
            sql.push_str(" AND timestamp <= ?");
            params.push(end.to_rfc3339());
        }
        if !query.event_types.is_empty() {
            let placeholders: Vec<&str> = vec!["?"; query.event_types.len()];
            sql.push_str(&format!(" AND type IN ({})", placeholders.join(",")));
            params.extend(query.event_types.iter().cloned());
        }
        if !query.sources.is_empty() {
            let placeholders: Vec<&str> = vec!["?"; query.sources.len()];
            sql.push_str(&format!(" AND source IN ({})", placeholders.join(",")));
            params.extend(query.sources.iter().cloned());
        }
        if !query.severities.is_empty() {
            let placeholders: Vec<&str> = vec!["?"; query.severities.len()];
            sql.push_str(&format!(" AND severity IN ({})", placeholders.join(",")));
            for sev in &query.severities {
                params.push(format!("{}", *sev as i32));
            }
        }
        if let Some(min_risk) = query.min_risk_score {
            sql.push_str(" AND risk_score >= ?");
            params.push(format!("{}", min_risk));
        }
        if !query.process_names.is_empty() {
            for pn in &query.process_names {
                sql.push_str(" AND process LIKE ?");
                params.push(format!("%\"name\":\"{}\"%", pn));
            }
        }
        if !query.pids.is_empty() {
            for pid in &query.pids {
                sql.push_str(" AND process LIKE ?");
                params.push(format!("%\"pid\":{}%", pid));
            }
        }
        if let Some(ref cid) = query.correlation_id {
            sql.push_str(" AND correlation LIKE ?");
            params.push(format!("%\"correlation_id\":\"{}\"%", cid));
        }
        if let Some(ref fid) = query.flow_id {
            sql.push_str(" AND correlation LIKE ?");
            params.push(format!("%\"flow_id\":\"{}\"%", fid));
        }
        if !query.tags.is_empty() {
            for tag in &query.tags {
                sql.push_str(" AND tags LIKE ?");
                params.push(format!("%{}%", tag));
            }
        }
        if let Some(ref text) = query.free_text {
            sql.push_str(" AND (payload LIKE ? OR process LIKE ?)");
            let p = format!("%{}%", text);
            params.push(p.clone());
            params.push(p);
        }

        let mut q = sqlx::query(&sql);
        for p in &params {
            q = q.bind(p);
        }

        let row = q.fetch_one(&self.pool).await.map_err(|e| {
            SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
        })?;

        Ok(row.get::<i64, _>("cnt") as u64)
    }

    async fn aggregate(&self, agg: AggregationQuery) -> CoreResult<AggregationResult> {
        let valid_columns = ["type", "source", "severity", "host_id"];
        let column = valid_columns
            .iter()
            .find(|&&c| c == agg.group_by)
            .ok_or_else(|| {
                SentinelError::Storage(sentinel_core::StorageError::Query(format!(
                    "invalid group_by column: {}. Valid: {:?}",
                    agg.group_by, valid_columns
                )))
            })?;

        let sql = format!(
            "SELECT {} as group_key, COUNT(*) as count, AVG(risk_score) as avg_risk, MIN(risk_score) as min_risk, MAX(risk_score) as max_risk 
             FROM events 
             WHERE timestamp >= ? AND timestamp <= ?
             GROUP BY {}",
            column, column
        );

        let rows = sqlx::query(&sql)
            .bind(agg.start_time.to_rfc3339())
            .bind(agg.end_time.to_rfc3339())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
            })?;

        let buckets = rows
            .into_iter()
            .map(|r| AggregationBucket {
                key: r.get("group_key"),
                count: r.get::<i64, _>("count") as u64,
                avg_risk: r.get::<Option<f64>, _>("avg_risk"),
                min_risk: r.get::<Option<i64>, _>("min_risk").map(|v| v as u32),
                max_risk: r.get::<Option<i64>, _>("max_risk").map(|v| v as u32),
            })
            .collect();

        Ok(AggregationResult { buckets })
    }

    async fn retention(&self, policy: RetentionPolicy) -> CoreResult<u64> {
        let sql = "DELETE FROM events WHERE type LIKE ? AND timestamp < datetime('now', ?) AND id IN (
            SELECT id FROM events WHERE type LIKE ? AND timestamp < datetime('now', ?) ORDER BY timestamp DESC LIMIT ?
        )";

        let max_age = format!("-{} days", policy.max_age_days);

        let result = sqlx::query(sql)
            .bind(&policy.event_type_pattern)
            .bind(&max_age)
            .bind(&policy.event_type_pattern)
            .bind(&max_age)
            .bind(policy.max_count as i64)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
            })?;

        Ok(result.rows_affected())
    }
}

#[allow(dead_code)]
fn row_to_event(row: &sqlx::sqlite::SqliteRow) -> CoreResult<Arc<Event>> {
    let id: String = row.get("id");
    let event_type: String = row.get("type");
    let source: String = row.get("source");
    let severity: i32 = row.get("severity");
    let tags_str: String = row.get("tags");
    let tags: Vec<String> = serde_json::from_str(&tags_str).unwrap_or_default();
    let risk_score_val: i32 = row.get("risk_score");
    let host_id: String = row.get("host_id");
    let schema_version: i32 = row.get("schema_version");

    let process: Option<sentinel_events::ProcessContext> = deser_process_opt(row, "process");

    Ok(Arc::new(Event {
        id,
        r#type: event_type,
        source,
        severity,
        risk_score: risk_score_val as u32,
        host_id,
        schema_version: schema_version as u32,
        tags,
        process,
        payload: None,
        metadata: None,
        correlation: None,
        timestamp: None,
        ingest_timestamp: None,
    }))
}

fn deser_process_opt(
    row: &sqlx::sqlite::SqliteRow,
    col: &str,
) -> Option<sentinel_events::ProcessContext> {
    use sentinel_events::ProcessContext;
    let s: String = row.get(col);
    if s.is_empty() || s == "{}" {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&s).ok()?;
    let o = v.as_object()?;
    Some(ProcessContext {
        pid: o.get("pid").and_then(|j| j.as_u64()).unwrap_or(0) as u32,
        ppid: o.get("ppid").and_then(|j| j.as_u64()).unwrap_or(0) as u32,
        name: o.get("name").and_then(|j| j.as_str()).unwrap_or("").into(),
        path: o.get("path").and_then(|j| j.as_str()).unwrap_or("").into(),
        command_line: o
            .get("command_line")
            .and_then(|j| j.as_str())
            .unwrap_or("")
            .into(),
        cwd: o.get("cwd").and_then(|j| j.as_str()).unwrap_or("").into(),
        integrity_level: o
            .get("integrity_level")
            .and_then(|j| j.as_str())
            .unwrap_or("")
            .into(),
        tree_depth: o.get("tree_depth").and_then(|j| j.as_u64()).unwrap_or(0) as u32,
        sha256: o
            .get("sha256")
            .and_then(|j| j.as_str())
            .unwrap_or("")
            .into(),
        mitre_techniques: o
            .get("mitre_techniques")
            .and_then(|j| j.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        ..Default::default()
    })
}

/// SQLite event cursor
struct SqliteEventCursor {
    events: Vec<Arc<Event>>,
    position: tokio::sync::Mutex<usize>,
    total_count: u64,
}

#[async_trait::async_trait]
impl EventCursor for SqliteEventCursor {
    async fn next(&mut self) -> CoreResult<Option<Arc<Event>>> {
        let mut pos = self.position.lock().await;
        if *pos >= self.events.len() {
            return Ok(None);
        }
        let event = self.events[*pos].clone();
        *pos += 1;
        Ok(Some(event))
    }

    async fn collect(&mut self, limit: usize) -> CoreResult<Vec<Arc<Event>>> {
        let mut pos = self.position.lock().await;
        let remaining = self.events.len().saturating_sub(*pos);
        let take = (limit as usize).min(remaining);
        let batch: Vec<Arc<Event>> = self.events[*pos..*pos + take].to_vec();
        *pos += take;
        Ok(batch)
    }

    fn total_count(&self) -> u64 {
        self.total_count
    }
}

/// SQLite rule repository
pub struct SqliteRuleRepository {
    pool: SqlitePool,
}

impl SqliteRuleRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl RuleRepository for SqliteRuleRepository {
    async fn load_all(&self, enabled_only: bool) -> CoreResult<Vec<sentinel_core::traits::Rule>> {
        let query = if enabled_only {
            "SELECT * FROM rules WHERE enabled = 1"
        } else {
            "SELECT * FROM rules"
        };
        let rows = sqlx::query(query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
            })?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let rule_json: String = r.get("rule_json");
                serde_json::from_str(&rule_json).unwrap_or_default()
            })
            .collect())
    }

    async fn get(&self, id: &str) -> CoreResult<Option<sentinel_core::traits::Rule>> {
        let row = sqlx::query("SELECT * FROM rules WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
            })?;

        Ok(row.map(|r| {
            let rule_json: String = r.get("rule_json");
            serde_json::from_str(&rule_json).unwrap_or_default()
        }))
    }

    async fn upsert(&self, rule: &sentinel_core::traits::Rule) -> CoreResult<()> {
        let rule_json =
            serde_json::to_string(rule).map_err(|e| SentinelError::Serialization(e.into()))?;
        let created = rule.created.to_rfc3339();
        let modified = rule.modified.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO rules (id, rule_json, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                rule_json = excluded.rule_json,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&rule.id)
        .bind(&rule_json)
        .bind(rule.enabled)
        .bind(&created)
        .bind(&modified)
        .execute(&self.pool)
        .await
        .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;

        Ok(())
    }

    async fn delete(&self, id: &str) -> CoreResult<()> {
        sqlx::query("DELETE FROM rules WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
            })?;
        Ok(())
    }

    async fn enable(&self, id: &str, enabled: bool) -> CoreResult<()> {
        let updated_at = Utc::now().to_rfc3339();
        sqlx::query("UPDATE rules SET enabled = ?, updated_at = ? WHERE id = ?")
            .bind(enabled)
            .bind(&updated_at)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
            })?;
        Ok(())
    }
}

#[allow(dead_code)]
fn row_to_rule(row: &sqlx::sqlite::SqliteRow) -> sentinel_core::traits::Rule {
    let rule_json: String = row.get("rule_json");
    serde_json::from_str(&rule_json).unwrap_or_default()
}

/// SQLite alert repository
pub struct SqliteAlertRepository {
    pool: SqlitePool,
}

impl SqliteAlertRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl AlertRepository for SqliteAlertRepository {
    async fn create(&self, alert: &sentinel_core::traits::Alert) -> CoreResult<()> {
        let context_json = serde_json::to_string(&alert.context)
            .map_err(|e| SentinelError::Serialization(e.into()))?;
        let id_str = alert.id.to_string();
        let correlation_id_str = alert.correlation_id.to_string();
        let risk_score = alert.risk_score as i64;
        let severity = alert.severity as i32;
        let state = alert.state as i32;
        let created_at = alert.created_at.to_rfc3339();
        let updated_at = alert.updated_at.to_rfc3339();
        let acknowledged_at = alert.acknowledged_at.map(|d| d.to_rfc3339());
        let events_str = alert
            .events
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(",");

        sqlx::query(
            r#"
            INSERT INTO alerts (id, rule_id, correlation_id, risk_score, severity, state, created_at, updated_at, acknowledged_by, acknowledged_at, events, context, ai_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id_str)
        .bind(&alert.rule_id)
        .bind(&correlation_id_str)
        .bind(risk_score)
        .bind(severity)
        .bind(state)
        .bind(&created_at)
        .bind(&updated_at)
        .bind(&alert.acknowledged_by)
        .bind(&acknowledged_at)
        .bind(&events_str)
        .bind(&context_json)
        .bind(&alert.ai_summary)
        .execute(&self.pool)
        .await
        .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;

        Ok(())
    }

    async fn get(&self, id: &AlertId) -> CoreResult<Option<sentinel_core::traits::Alert>> {
        let id_str = id.to_string();
        let row = sqlx::query("SELECT * FROM alerts WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
            })?;

        Ok(row.map(|r| row_to_alert(&r)))
    }

    async fn update_state(
        &self,
        id: &AlertId,
        state: sentinel_core::traits::AlertState,
        comment: Option<String>,
    ) -> CoreResult<()> {
        let now = Utc::now().to_rfc3339();
        let id_str = id.to_string();
        let state_i = state as i32;
        let (ack_by, ack_at) = if matches!(state, sentinel_core::traits::AlertState::Acknowledged) {
            (comment, Some(now.clone()))
        } else {
            (None, None)
        };
        sqlx::query("UPDATE alerts SET state = ?, updated_at = ?, acknowledged_by = ?, acknowledged_at = ? WHERE id = ?")
            .bind(state_i)
            .bind(&now)
            .bind(&ack_by)
            .bind(&ack_at)
            .bind(&id_str)
            .execute(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;

        Ok(())
    }

    async fn query(
        &self,
        query: sentinel_core::traits::AlertQuery,
    ) -> CoreResult<Vec<sentinel_core::traits::Alert>> {
        let mut sql = String::from("SELECT * FROM alerts WHERE 1=1");
        let mut params: Vec<String> = Vec::new();

        if let Some(ref state) = query.state {
            sql.push_str(" AND state = ?");
            params.push(format!("{}", *state as i32));
        }
        if let Some(min_sev) = query.min_severity {
            sql.push_str(" AND severity >= ?");
            params.push(format!("{}", min_sev as u8));
        }
        if let Some(ref start) = query.start_time {
            sql.push_str(" AND created_at >= ?");
            params.push(start.to_rfc3339());
        }
        if let Some(ref end) = query.end_time {
            sql.push_str(" AND created_at <= ?");
            params.push(end.to_rfc3339());
        }
        sql.push_str(" ORDER BY created_at DESC");

        sql.push_str(" LIMIT ? OFFSET ?");
        params.push(format!("{}", query.limit));
        params.push(format!("{}", query.offset));

        let mut q = sqlx::query(&sql);
        for p in &params {
            q = q.bind(p);
        }

        let rows = q.fetch_all(&self.pool).await.map_err(|e| {
            SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
        })?;

        Ok(rows.iter().map(|r| row_to_alert(r)).collect())
    }

    async fn count(&self, query: &sentinel_core::traits::AlertQuery) -> CoreResult<u64> {
        let mut sql = String::from("SELECT COUNT(*) as cnt FROM alerts WHERE 1=1");
        let mut params: Vec<String> = Vec::new();

        if let Some(ref state) = query.state {
            sql.push_str(" AND state = ?");
            params.push(format!("{}", *state as i32));
        }

        let mut q = sqlx::query(&sql);
        for p in &params {
            q = q.bind(p);
        }

        let row = q.fetch_one(&self.pool).await.map_err(|e| {
            SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
        })?;

        Ok(row.get::<i64, _>("cnt") as u64)
    }
}

#[allow(dead_code)]
fn row_to_alert(row: &sqlx::sqlite::SqliteRow) -> sentinel_core::traits::Alert {
    use sentinel_core::traits::{Alert, AlertState};
    use sentinel_core::Ulid;

    let id_str: String = row.get("id");

    Alert {
        id: Ulid::from_string(&id_str).unwrap_or_default(),
        rule_id: row.get("rule_id"),
        correlation_id: {
            let cid: String = row.get("correlation_id");
            Ulid::from_string(&cid).unwrap_or_default()
        },
        risk_score: row.get::<i32, _>("risk_score") as u32,
        severity: row_to_severity(row),
        state: match row.get::<i32, _>("state") {
            1 => AlertState::Acknowledged,
            2 => AlertState::Investigating,
            3 => AlertState::ResolvedTruePositive,
            4 => AlertState::ResolvedFalsePositive,
            5 => AlertState::Suppressed,
            _ => AlertState::New,
        },
        created_at: {
            let s: String = row.get("created_at");
            s.parse().unwrap_or_default()
        },
        updated_at: {
            let s: String = row.get("updated_at");
            s.parse().unwrap_or_default()
        },
        acknowledged_by: row.get("acknowledged_by"),
        acknowledged_at: {
            let s: Option<String> = row.get("acknowledged_at");
            s.and_then(|s| s.parse().ok())
        },
        events: {
            let s: String = row.get("events");
            if s.is_empty() {
                vec![]
            } else {
                s.split(',')
                    .filter_map(|id| Ulid::from_string(id.trim()).ok())
                    .collect()
            }
        },
        context: {
            let s: String = row.get("context");
            serde_json::from_str(&s).unwrap_or(serde_json::Value::Null)
        },
        ai_summary: row.get("ai_summary"),
    }
}

fn row_to_severity(row: &sqlx::sqlite::SqliteRow) -> sentinel_core::Severity {
    match row.get::<i32, _>("severity") {
        1 => sentinel_core::Severity::Debug,
        2 => sentinel_core::Severity::Info,
        3 => sentinel_core::Severity::Notice,
        4 => sentinel_core::Severity::Warning,
        5 => sentinel_core::Severity::Error,
        6 => sentinel_core::Severity::Critical,
        7 => sentinel_core::Severity::Alert,
        8 => sentinel_core::Severity::Emergency,
        _ => sentinel_core::Severity::default(),
    }
}

/// SQLite config repository
pub struct SqliteConfigRepository {
    pool: SqlitePool,
}

impl SqliteConfigRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ConfigRepository for SqliteConfigRepository {
    async fn get(&self, key: &str) -> CoreResult<Option<ConfigValue>> {
        let row = sqlx::query("SELECT value FROM config WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
            })?;

        row.map(|r| {
            let value: String = r.get("value");
            serde_json::from_str::<serde_json::Value>(&value)
                .map(ConfigValue::from)
                .map_err(|e| SentinelError::Serialization(e.into()))
        })
        .transpose()
    }

    async fn set(&self, key: &str, value: &ConfigValue) -> CoreResult<()> {
        let json =
            serde_json::to_string(value).map_err(|e| SentinelError::Serialization(e.into()))?;

        let updated_at = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(key)
        .bind(&json)
        .bind(&updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;

        Ok(())
    }

    async fn delete(&self, key: &str) -> CoreResult<()> {
        sqlx::query("DELETE FROM config WHERE key = ?")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
            })?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> CoreResult<Vec<(String, ConfigValue)>> {
        let pattern = format!("{}%", prefix);
        let rows = sqlx::query("SELECT key, value FROM config WHERE key LIKE ?")
            .bind(&pattern)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
            })?;

        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let value: String = r.get("value");
                let key: String = r.get("key");
                let v: serde_json::Value = serde_json::from_str(&value).ok()?;
                Some((key, ConfigValue::from(v)))
            })
            .collect())
    }
}

pub struct SqliteChainRepository {
    pool: SqlitePool,
}

impl SqliteChainRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ChainRepository for SqliteChainRepository {
    async fn save_chain(&self, chain: &AttackChain) -> CoreResult<()> {
        let tactics_json = serde_json::to_string(&chain.tactics)
            .map_err(|e| SentinelError::Serialization(e.into()))?;
        let techniques_json = serde_json::to_string(&chain.techniques)
            .map_err(|e| SentinelError::Serialization(e.into()))?;
        let status = chain.status as i32;

        sqlx::query(
            r#"
            INSERT INTO correlation_chains (id, start_time, end_time, risk_score, tactics, techniques, event_count, state, kill_chain_coverage)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                end_time = excluded.end_time,
                risk_score = excluded.risk_score,
                tactics = excluded.tactics,
                techniques = excluded.techniques,
                event_count = excluded.event_count,
                state = excluded.state,
                kill_chain_coverage = excluded.kill_chain_coverage,
                updated_at = datetime('now')
            "#,
        )
        .bind(&chain.id)
        .bind(chain.start_time.to_rfc3339())
        .bind(chain.end_time.to_rfc3339())
        .bind(chain.risk_score as i64)
        .bind(&tactics_json)
        .bind(&techniques_json)
        .bind(chain.event_count as i64)
        .bind(status)
        .bind(chain.kill_chain_coverage)
        .execute(&self.pool)
        .await
        .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;

        Ok(())
    }

    async fn get_chain(&self, id: &str) -> CoreResult<Option<AttackChain>> {
        let row = sqlx::query("SELECT * FROM correlation_chains WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
            })?;

        Ok(row.map(|r| row_to_chain(&r)))
    }

    async fn query_chains(&self, query: ChainQuery) -> CoreResult<Vec<AttackChain>> {
        let mut sql = String::from("SELECT * FROM correlation_chains WHERE 1=1");
        let mut params: Vec<String> = Vec::new();

        if let Some(ref start) = query.start_time {
            sql.push_str(" AND start_time >= ?");
            params.push(start.to_rfc3339());
        }
        if let Some(ref end) = query.end_time {
            sql.push_str(" AND end_time <= ?");
            params.push(end.to_rfc3339());
        }
        if let Some(status) = query.status {
            sql.push_str(" AND state = ?");
            params.push(format!("{}", status as i32));
        }
        if let Some(min_risk) = query.min_risk {
            sql.push_str(" AND risk_score >= ?");
            params.push(format!("{}", min_risk));
        }

        sql.push_str(" ORDER BY risk_score DESC LIMIT ?");
        params.push(format!("{}", query.limit));

        let mut q = sqlx::query(&sql);
        for p in &params {
            q = q.bind(p);
        }

        let rows = q.fetch_all(&self.pool).await.map_err(|e| {
            SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string()))
        })?;

        Ok(rows.iter().map(|r| row_to_chain(r)).collect())
    }
}

fn row_to_chain(row: &sqlx::sqlite::SqliteRow) -> AttackChain {
    let tactics_str: String = row.get("tactics");
    let techniques_str: String = row.get("techniques");
    let start_time_str: String = row.get("start_time");
    let end_time_str: String = row.get("end_time");

    AttackChain {
        id: row.get("id"),
        start_time: start_time_str.parse().unwrap_or_default(),
        end_time: end_time_str.parse().unwrap_or_default(),
        risk_score: row.get::<i32, _>("risk_score") as u32,
        tactics: serde_json::from_str(&tactics_str).unwrap_or_default(),
        techniques: serde_json::from_str(&techniques_str).unwrap_or_default(),
        event_count: row.get::<i32, _>("event_count") as u32,
        status: match row.get::<i32, _>("state") {
            1 => ChainStatus::ActiveAttack,
            2 => ChainStatus::SuspiciousChain,
            3 => ChainStatus::Resolved,
            _ => ChainStatus::Unspecified,
        },
        kill_chain_coverage: row.get::<f64, _>("kill_chain_coverage"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::traits::{EventCursor, EventQuery, EventRepository};
    use sentinel_core::Ulid;
    use sentinel_events::Event;
    use tempfile::tempdir;

    async fn setup() -> (SqliteStorage, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let cfg = SqliteConfig {
            path: path.to_string_lossy().into(),
            wal_mode: true,
            busy_timeout_ms: 5000,
            max_connections: 2,
        };
        let storage = SqliteStorage::new(&cfg).await.unwrap();
        crate::migrations::run_all(storage.pool()).await.unwrap();
        (storage, dir)
    }

    fn make_event(id: &str, r#type: &str, severity: i32) -> Arc<Event> {
        Arc::new(Event {
            id: id.into(),
            r#type: r#type.into(),
            source: "test".into(),
            severity,
            risk_score: 75,
            host_id: "host-1".into(),
            schema_version: 1,
            tags: vec!["test".into()],
            process: Some(sentinel_events::ProcessContext {
                name: "test.exe".into(),
                pid: 42,
                command_line: "test.exe --verbose".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn test_insert_and_query_event() {
        let (storage, _dir) = setup().await;
        let repo = storage.events().await;

        let event = make_event("ev-001", "sentinel.process.create", 5);
        repo.append(&[event.clone()]).await.unwrap();

        let q = EventQuery { limit: 10, ..Default::default() };
        let mut cursor = repo.query(q).await.unwrap();
        let cursor_mut: &mut dyn EventCursor = Arc::get_mut(&mut cursor).unwrap();
        assert_eq!(cursor_mut.total_count(), 1);

        let retrieved = cursor_mut.next().await.unwrap().unwrap();
        assert_eq!(retrieved.id, "ev-001");
        assert_eq!(retrieved.r#type, "sentinel.process.create");
        assert_eq!(retrieved.severity, 5);
        assert_eq!(retrieved.risk_score, 75);
        assert_eq!(retrieved.tags, vec!["test"]);
    }

    #[tokio::test]
    async fn test_insert_and_get_event() {
        let (storage, _dir) = setup().await;
        let repo = storage.events().await;

        let ev_id = Ulid::new();
        let event = make_event(&ev_id.to_string(), "sentinel.network.connect", 3);
        repo.append(&[event.clone()]).await.unwrap();

        let retrieved = repo.get(&ev_id).await.unwrap().unwrap();
        assert_eq!(retrieved.id, ev_id.to_string());
        assert_eq!(retrieved.r#type, "sentinel.network.connect");
    }

    #[tokio::test]
    async fn test_event_count() {
        let (storage, _dir) = setup().await;
        let repo = storage.events().await;

        for i in 0..3 {
            let ev = make_event(&format!("ev-{:02}", i), "sentinel.proc.create", 2);
            repo.append(&[ev]).await.unwrap();
        }

        let q = EventQuery { limit: 100, ..Default::default() };
        let count = repo.count(&q).await.unwrap();
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_event_json_roundtrip_process() {
        let (storage, _dir) = setup().await;
        let repo = storage.events().await;

        let event = make_event("ev-proc", "sentinel.process.create", 5);
        repo.append(&[event.clone()]).await.unwrap();

        let q = EventQuery { limit: 10, ..Default::default() };
        let mut cursor = repo.query(q).await.unwrap();
        let cursor_mut: &mut dyn EventCursor = Arc::get_mut(&mut cursor).unwrap();
        let retrieved = cursor_mut.next().await.unwrap().unwrap();
        let proc = retrieved.process.as_ref().unwrap();
        assert_eq!(proc.name, "test.exe");
        assert_eq!(proc.pid, 42);
        assert_eq!(proc.command_line, "test.exe --verbose");
    }
}

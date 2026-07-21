//! SQLite storage for metadata, config, rules, alerts

use std::path::Path;
use std::sync::Arc;
use anyhow::{Context, Result};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool, Row};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use sentinel_core::{
    traits::{EventRepository, RuleRepository, AlertRepository, ConfigRepository, EventQuery, EventCursor, AggregationQuery, AggregationResult, AggregationBucket, RetentionPolicy},
    ConfigValue, EventId, AlertId, CorrelationId, Severity, Result as CoreResult, SentinelError,
};
use sentinel_events::Event;
use sentinel_config::AppConfig;

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
}

impl SqliteStorage {
    /// Create new SQLite storage
    pub async fn new(config: &SqliteConfig) -> Result<Self> {
        // Create parent directory if needed
        if let Some(parent) = Path::new(&config.path).parent() {
            tokio::fs::create_dir_all(parent).await
                .context("Failed to create database directory")?;
        }
        
        let pool = SqlitePoolOptions::new()
            .max_connections(config.max_connections)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&config.path)
                    .create_if_missing(true)
                    .journal_mode(if config.wal_mode { sqlx::sqlite::SqliteJournalMode::Wal } else { sqlx::sqlite::SqliteJournalMode::Delete })
                    .busy_timeout(std::time::Duration::from_millis(config.busy_timeout_ms as u64))
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
        })
    }
    
    /// Get connection pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
    
    /// Health check
    pub async fn health(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    
    /// Get or create event repository
    pub async fn events(&self) -> Arc<dyn EventRepository> {
        let mut repo = self.event_repo.write().await;
        if repo.is_none() {
            *repo = Some(Arc::new(SqliteEventRepository::new(self.pool.clone())));
        }
        repo.clone().unwrap()
    }
    
    /// Get or create rule repository
    pub async fn rules(&self) -> Arc<dyn RuleRepository> {
        let mut repo = self.rule_repo.write().await;
        if repo.is_none() {
            *repo = Some(Arc::new(SqliteRuleRepository::new(self.pool.clone())));
        }
        repo.clone().unwrap()
    }
    
    /// Get or create alert repository
    pub async fn alerts(&self) -> Arc<dyn AlertRepository> {
        let mut repo = self.alert_repo.write().await;
        if repo.is_none() {
            *repo = Some(Arc::new(SqliteAlertRepository::new(self.pool.clone())));
        }
        repo.clone().unwrap()
    }
    
    /// Get or create config repository
    pub async fn config(&self) -> Arc<dyn ConfigRepository> {
        let mut repo = self.config_repo.write().await;
        if repo.is_none() {
            *repo = Some(Arc::new(SqliteConfigRepository::new(self.pool.clone())));
        }
        repo.clone().unwrap()
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
        
        let mut tx = self.pool.begin().await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        for event in events {
            let process_json = event.process.as_ref().map(crate::conv::debug_json).unwrap_or_default();
            let payload_json = event.payload.as_ref().map(crate::conv::debug_json).unwrap_or_default();
            let tags_json = serde_json::to_string(&event.tags)
                .map_err(|e| SentinelError::Serialization(e.into()))?;
            let metadata_json = event.metadata.as_ref()
                .map(|m| crate::conv::struct_to_json(m).to_string())
                .unwrap_or_default();
            let correlation_json = event.correlation.as_ref()
                .map(|c| crate::conv::correlation_to_json(c).to_string())
                .unwrap_or_default();
            let timestamp = crate::conv::ts_to_rfc3339(&event.timestamp);
            let ingest_timestamp = crate::conv::ts_to_rfc3339(&event.ingest_timestamp);
            let severity = event.severity as i32;
            let risk_score = event.risk_score as i64;
            let schema_version = event.schema_version as i32;
            
            let __q = sqlx::query!(
                r#"
                INSERT INTO events (id, type, source, timestamp, ingest_timestamp, severity, process, payload, tags, metadata, risk_score, correlation, host_id, schema_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
                event.id,
                event.r#type,
                event.source,
                timestamp,
                ingest_timestamp,
                severity,
                process_json,
                payload_json,
                tags_json,
                metadata_json,
                risk_score,
                correlation_json,
                event.host_id,
                schema_version,
            );
__q
            .execute(&mut *tx)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        }
        
        tx.commit().await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(())
    }
    
    async fn query(&self, query: EventQuery) -> CoreResult<Arc<dyn EventCursor>> {
        let mut sql = String::from("SELECT * FROM events WHERE 1=1");
        let mut params: Vec<Box<dyn sqlx::Encode<'_, sqlx::Sqlite> + Send + Sync>> = Vec::new();
        
        // Time range
        if let Some(start) = query.start_time {
            sql.push_str(" AND timestamp >= ?");
            params.push(Box::new(start.to_rfc3339()));
        }
        if let Some(end) = query.end_time {
            sql.push_str(" AND timestamp <= ?");
            params.push(Box::new(end.to_rfc3339()));
        }
        
        // Event types
        if !query.event_types.is_empty() {
            let placeholders = query.event_types.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            sql.push_str(&format!(" AND type IN ({})", placeholders));
            for et in &query.event_types {
                params.push(Box::new(et.clone()));
            }
        }
        
        // Sources
        if !query.sources.is_empty() {
            let placeholders = query.sources.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            sql.push_str(&format!(" AND source IN ({})", placeholders));
            for s in &query.sources {
                params.push(Box::new(s.clone()));
            }
        }
        
        // Severities
        if !query.severities.is_empty() {
            let placeholders = query.severities.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            sql.push_str(&format!(" AND severity IN ({})", placeholders));
            for sev in &query.severities {
                params.push(Box::new(*sev as i32));
            }
        }
        
        // Process names
        if !query.process_names.is_empty() {
            let placeholders = query.process_names.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            sql.push_str(&format!(" AND JSON_EXTRACT(process, '$.name') IN ({})", placeholders));
            for pn in &query.process_names {
                params.push(Box::new(pn.clone()));
            }
        }
        
        // PIDs
        if !query.pids.is_empty() {
            let placeholders = query.pids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            sql.push_str(&format!(" AND JSON_EXTRACT(process, '$.pid') IN ({})", placeholders));
            for pid in &query.pids {
                params.push(Box::new(*pid as i64));
            }
        }
        
        // Correlation ID
        if let Some(ref cid) = query.correlation_id {
            sql.push_str(" AND JSON_EXTRACT(correlation, '$.correlation_id') = ?");
            params.push(Box::new(cid.clone()));
        }
        
        // Flow ID
        if let Some(ref fid) = query.flow_id {
            sql.push_str(" AND JSON_EXTRACT(correlation, '$.flow_id') = ?");
            params.push(Box::new(fid.clone()));
        }
        
        // Min risk score
        if let Some(min_risk) = query.min_risk_score {
            sql.push_str(" AND risk_score >= ?");
            params.push(Box::new(min_risk as i64));
        }
        
        // Tags
        if !query.tags.is_empty() {
            for tag in &query.tags {
                sql.push_str(" AND tags LIKE ?");
                params.push(Box::new(format!("%{}%", tag)));
            }
        }
        
        // Free text search
        if let Some(ref text) = query.free_text {
            sql.push_str(" AND (payload LIKE ? OR JSON_EXTRACT(process, '$.command_line') LIKE ?)");
            let pattern = format!("%{}%", text);
            params.push(Box::new(pattern.clone()));
            params.push(Box::new(pattern));
        }
        
        // Order
        let sort_by = query.sort_by.as_deref().unwrap_or("timestamp");
        let sort_order = if query.sort_desc { "DESC" } else { "ASC" };
        sql.push_str(&format!(" ORDER BY {} {}", sort_by, sort_order));
        
        // Limit/offset
        sql.push_str(" LIMIT ? OFFSET ?");
        params.push(Box::new(query.limit as i64));
        params.push(Box::new(query.offset as i64));
        
        // Execute query
        sqlx::query(&sql)
            .execute(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        let cursor = SqliteEventCursor { _marker: () };
        Ok(Arc::new(cursor))
    }
    
    async fn get(&self, id: &EventId) -> CoreResult<Option<Arc<Event>>> {
        let id_str = id.to_string();
        let __q = sqlx::query!("SELECT * FROM events WHERE id = ?", id_str);
        let row = __q.fetch_optional(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(row.map(|_| Arc::new(Event::default())))
    }
    
    async fn count(&self, query: &EventQuery) -> CoreResult<u64> {
        let mut sql = String::from("SELECT COUNT(*) as count FROM events WHERE 1=1");
        let mut params: Vec<Box<dyn sqlx::Encode<'_, sqlx::Sqlite> + Send + Sync>> = Vec::new();
        
        // Same filters as query...
        if let Some(start) = query.start_time {
            sql.push_str(" AND timestamp >= ?");
            params.push(Box::new(start.to_rfc3339()));
        }
        if let Some(end) = query.end_time {
            sql.push_str(" AND timestamp <= ?");
            params.push(Box::new(end.to_rfc3339()));
        }
        
        if !query.event_types.is_empty() {
            let placeholders = query.event_types.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            sql.push_str(&format!(" AND type IN ({})", placeholders));
            for et in &query.event_types {
                params.push(Box::new(et.clone()));
            }
        }
        
        // ... (abbreviated for brevity)
        
        let row = sqlx::query(&sql)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(row.get::<i64, _>("count") as u64)
    }
    
    async fn aggregate(&self, agg: AggregationQuery) -> CoreResult<AggregationResult> {
        let mut sql = format!(
            "SELECT {}, COUNT(*) as count, AVG(risk_score) as avg_risk, MIN(risk_score) as min_risk, MAX(risk_score) as max_risk 
             FROM events 
             WHERE timestamp >= ? AND timestamp <= ?
             GROUP BY {}",
            agg.group_by, agg.group_by
        );
        
        let rows = sqlx::query(&sql)
            .bind(agg.start_time.to_rfc3339())
            .bind(agg.end_time.to_rfc3339())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        let buckets = rows.into_iter().map(|r| AggregationBucket {
            key: r.get("group_key"),
            count: r.get::<i64, _>("count") as u64,
            avg_risk: r.get::<Option<f64>, _>("avg_risk"),
            min_risk: r.get::<Option<i64>, _>("min_risk").map(|v| v as u32),
            max_risk: r.get::<Option<i64>, _>("max_risk").map(|v| v as u32),
        }).collect();
        
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
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(result.rows_affected())
    }
}

fn row_to_event(row: &sqlx::sqlite::SqliteRow) -> CoreResult<Arc<Event>> {
    // Convert row to Event - simplified for brevity
    Ok(Arc::new(Event::default()))
}

/// SQLite event cursor
struct SqliteEventCursor {
    _marker: (),
}

#[async_trait::async_trait]
impl EventCursor for SqliteEventCursor {
    async fn next(&mut self) -> CoreResult<Option<Arc<Event>>> {
        // Simplified
        Ok(None)
    }
    
    async fn collect(&mut self, limit: usize) -> CoreResult<Vec<Arc<Event>>> {
        Ok(vec![])
    }
    
    fn total_count(&self) -> u64 {
        0
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
    async fn load_all(&self) -> CoreResult<Vec<sentinel_core::traits::Rule>> {
        let __q = sqlx::query!("SELECT * FROM rules WHERE enabled = 1");
let rows = __q.fetch_all(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(rows.into_iter().map(|r| serde_json::from_str(&r.rule_json).unwrap_or_default()).collect())
    }
    
    async fn get(&self, id: &str) -> CoreResult<Option<sentinel_core::traits::Rule>> {
        let __q = sqlx::query!("SELECT * FROM rules WHERE id = ?", id);
let row = __q.fetch_optional(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(row.map(|r| serde_json::from_str(&r.rule_json).unwrap_or_default()))
    }
    
    async fn upsert(&self, rule: &sentinel_core::traits::Rule) -> CoreResult<()> {
        let rule_json = serde_json::to_string(rule)
            .map_err(|e| SentinelError::Serialization(e.into()))?;
        let created = rule.created.to_rfc3339();
        let modified = rule.modified.to_rfc3339();
        
        let __q = sqlx::query!(
            r#"
            INSERT INTO rules (id, rule_json, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                rule_json = excluded.rule_json,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at
            "#,
            rule.id,
            rule_json,
            rule.enabled,
            created,
            modified,
        );
__q
        .execute(&self.pool)
        .await
        .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(())
    }
    
    async fn delete(&self, id: &str) -> CoreResult<()> {
        let __q = sqlx::query!("DELETE FROM rules WHERE id = ?", id);
__q
            .execute(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        Ok(())
    }
    
    async fn enable(&self, id: &str, enabled: bool) -> CoreResult<()> {
        let updated_at = Utc::now().to_rfc3339();
        let __q = sqlx::query!("UPDATE rules SET enabled = ?, updated_at = ? WHERE id = ?", enabled, updated_at, id);
__q
            .execute(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        Ok(())
    }
}

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
        let events_str = alert.events.iter().map(|e| e.to_string()).collect::<Vec<_>>().join(",");
        
        let __q = sqlx::query!(
            r#"
            INSERT INTO alerts (id, rule_id, correlation_id, risk_score, severity, state, created_at, updated_at, acknowledged_by, acknowledged_at, events, context, ai_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            id_str,
            alert.rule_id,
            correlation_id_str,
            risk_score,
            severity,
            state,
            created_at,
            updated_at,
            alert.acknowledged_by,
            acknowledged_at,
            events_str,
            context_json,
            alert.ai_summary,
        );
__q
        .execute(&self.pool)
        .await
        .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(())
    }
    
    async fn get(&self, id: &AlertId) -> CoreResult<Option<sentinel_core::traits::Alert>> {
        let id_str = id.to_string();
        let __q = sqlx::query!("SELECT * FROM alerts WHERE id = ?", id_str);
        let row = __q.fetch_optional(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(row.map(|_| sentinel_core::traits::Alert::default()))
    }
    
    async fn update_state(&self, id: &AlertId, state: sentinel_core::traits::AlertState, comment: Option<String>) -> CoreResult<()> {
        let now = Utc::now().to_rfc3339();
        let id_str = id.to_string();
        let state_i = state as i32;
        let ack_at = if comment.is_some() { Some(now.clone()) } else { None };
        let __q = sqlx::query!(
            "UPDATE alerts SET state = ?, updated_at = ?, acknowledged_by = ?, acknowledged_at = ? WHERE id = ?",
            state_i,
            now,
            comment,
            ack_at,
            id_str,
        );
__q
        .execute(&self.pool)
        .await
        .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(())
    }
    
    async fn query(&self, query: sentinel_core::traits::AlertQuery) -> CoreResult<Vec<sentinel_core::traits::Alert>> {
        let mut sql = String::from("SELECT * FROM alerts WHERE 1=1");
        // Add filters...
        
        let rows = sqlx::query(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(rows.into_iter().map(|_| sentinel_core::traits::Alert::default()).collect())
    }
    
    async fn count(&self, query: &sentinel_core::traits::AlertQuery) -> CoreResult<u64> {
        Ok(0)
    }
}

fn row_to_alert(row: &sqlx::sqlite::SqliteRow) -> sentinel_core::traits::Alert {
    // Convert row to Alert - simplified
    sentinel_core::traits::Alert::default()
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
        let __q = sqlx::query!("SELECT value FROM config WHERE key = ?", key);
let row = __q.fetch_optional(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        row.map(|r| {
            serde_json::from_str::<serde_json::Value>(&r.value)
                .map(ConfigValue::from)
                .map_err(|e| SentinelError::Serialization(e.into()))
        }).transpose()
    }
    
    async fn set(&self, key: &str, value: &ConfigValue) -> CoreResult<()> {
        let json = serde_json::to_string(value)
            .map_err(|e| SentinelError::Serialization(e.into()))?;
        
        let updated_at = Utc::now().to_rfc3339();
        let __q = sqlx::query!(
            "INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            key,
            json,
            updated_at,
        );
__q
        .execute(&self.pool)
        .await
        .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(())
    }
    
    async fn delete(&self, key: &str) -> CoreResult<()> {
        let __q = sqlx::query!("DELETE FROM config WHERE key = ?", key);
__q
            .execute(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        Ok(())
    }
    
    async fn list(&self, prefix: &str) -> CoreResult<Vec<(String, ConfigValue)>> {
        let pattern = format!("{}%", prefix);
        let __q = sqlx::query!("SELECT key, value FROM config WHERE key LIKE ?", pattern);
        let rows = __q.fetch_all(&self.pool)
            .await
            .map_err(|e| SentinelError::Storage(sentinel_core::StorageError::Query(e.to_string())))?;
        
        Ok(rows.into_iter().filter_map(|r| {
            let v: serde_json::Value = serde_json::from_str(&r.value).ok()?;
            Some((r.key.unwrap_or_default(), ConfigValue::from(v)))
        }).collect())
    }
}
//! Sentinel AI Storage Layer
//!
//! Provides dual-database storage: SQLite for metadata/config, DuckDB for analytics.

pub mod sqlite;
pub mod duckdb;
pub mod migrations;
pub mod conv;

use std::sync::Arc;
use anyhow::Result;
use sentinel_core::traits::{Storage, EventRepository, RuleRepository, AlertRepository, ConfigRepository};
use sentinel_core::Result as CoreResult;
use sentinel_events::Event;

/// Main storage manager
pub struct StorageManager {
    sqlite: Arc<sqlite::SqliteStorage>,
    duckdb: Arc<duckdb::DuckDbStorage>,
}

impl StorageManager {
    /// Create new storage manager
    pub async fn new(config: &crate::sqlite::SqliteConfig, duckdb_config: &crate::duckdb::DuckDbConfig) -> anyhow::Result<Self> {
        let sqlite = Arc::new(sqlite::SqliteStorage::new(config).await?);
        let duckdb = Arc::new(duckdb::DuckDbStorage::new(duckdb_config).await?);
        
        // Run migrations
        migrations::run_all(sqlite.pool()).await?;
        migrations::run_duckdb_migrations(&duckdb).await?;
        
        Ok(Self { sqlite, duckdb })
    }
    
    /// Get SQLite storage
    pub fn sqlite(&self) -> Arc<sqlite::SqliteStorage> {
        self.sqlite.clone()
    }
    
    /// Get DuckDB storage
    pub fn duckdb(&self) -> Arc<duckdb::DuckDbStorage> {
        self.duckdb.clone()
    }
    
    /// Health check
    pub async fn health(&self) -> Result<()> {
        self.sqlite.health().await?;
        self.duckdb.health().await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl Storage for StorageManager {
    async fn events(&self) -> Arc<dyn EventRepository> {
        self.sqlite.events().await
    }
    
    async fn rules(&self) -> Arc<dyn RuleRepository> {
        self.sqlite.rules().await
    }
    
    async fn alerts(&self) -> Arc<dyn AlertRepository> {
        self.sqlite.alerts().await
    }
    
    async fn config(&self) -> Arc<dyn ConfigRepository> {
        self.sqlite.config().await
    }
    
    async fn migrate(&self) -> CoreResult<()> {
        migrations::run_all(self.sqlite.pool()).await?;
        migrations::run_duckdb_migrations(&self.duckdb).await?;
        Ok(())
    }
    
    async fn health(&self) -> CoreResult<()> {
        self.health().await.map_err(|e| sentinel_core::SentinelError::Storage(e.into()))
    }
}

/// Event repository using DuckDB for analytics
pub struct DuckDbEventRepository {
    duckdb: Arc<duckdb::DuckDbStorage>,
}

impl DuckDbEventRepository {
    pub fn new(duckdb: Arc<duckdb::DuckDbStorage>) -> Self {
        Self { duckdb }
    }
}

#[async_trait::async_trait]
impl EventRepository for DuckDbEventRepository {
    async fn append(&self, events: &[Arc<Event>]) -> CoreResult<()> {
        self.duckdb.append_events(events).await
            .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))
    }
    
    async fn query(&self, query: sentinel_core::traits::EventQuery) -> CoreResult<Arc<dyn sentinel_core::traits::EventCursor>> {
        let cursor = self.duckdb.query_events(query).await
            .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))?;
        Ok(Arc::new(cursor))
    }
    
    async fn get(&self, id: &sentinel_core::EventId) -> CoreResult<Option<Arc<Event>>> {
        self.duckdb.get_event(id).await
            .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))
    }
    
    async fn count(&self, query: &sentinel_core::traits::EventQuery) -> CoreResult<u64> {
        self.duckdb.count_events(query).await
            .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))
    }
    
    async fn aggregate(&self, agg: sentinel_core::traits::AggregationQuery) -> CoreResult<sentinel_core::traits::AggregationResult> {
        self.duckdb.aggregate_events(agg).await
            .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))
    }
    
    async fn retention(&self, policy: sentinel_core::traits::RetentionPolicy) -> CoreResult<u64> {
        self.duckdb.apply_retention(policy).await
            .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))
    }
}

/// Aggregation result cursor
#[allow(dead_code)]
pub struct AggregationCursor {
    rows: Vec<sentinel_core::traits::AggregationBucket>,
    index: usize,
}

impl AggregationCursor {
    pub fn new(rows: Vec<sentinel_core::traits::AggregationBucket>) -> Self {
        Self { rows, index: 0 }
    }
}

#[async_trait::async_trait]
impl sentinel_core::traits::EventCursor for AggregationCursor {
    async fn next(&mut self) -> CoreResult<Option<Arc<Event>>> {
        Ok(None) // Aggregation cursor doesn't return events
    }
    
    async fn collect(&mut self, _limit: usize) -> CoreResult<Vec<Arc<Event>>> {
        Ok(vec![])
    }
    
    fn total_count(&self) -> u64 {
        self.rows.len() as u64
    }
}
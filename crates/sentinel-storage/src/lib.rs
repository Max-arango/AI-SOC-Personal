//! Sentinel AI Storage Layer
//!
//! SQLite for metadata/config/events/alerts.
//! DuckDB for analytics (optional, behind `duckdb` feature flag).

pub mod conv;
#[cfg(feature = "duckdb")]
pub mod duckdb;
pub mod migrations;
pub mod sqlite;

use std::sync::Arc;

use sentinel_core::traits::{
    AlertRepository, ConfigRepository, EventRepository, RuleRepository, Storage,
};
use sentinel_core::Result as CoreResult;
use sentinel_events::Event;

/// Main storage manager — SQLite-only by default.
/// Enable `duckdb` feature for analytics engine.
pub struct StorageManager {
    sqlite: Arc<sqlite::SqliteStorage>,
    #[cfg(feature = "duckdb")]
    duckdb: Arc<duckdb::DuckDbStorage>,
}

impl StorageManager {
    /// Create new storage manager (SQLite only)
    pub async fn new(config: &crate::sqlite::SqliteConfig) -> anyhow::Result<Self> {
        let sqlite = Arc::new(sqlite::SqliteStorage::new(config).await?);
        migrations::run_all(sqlite.pool()).await?;

        #[cfg(feature = "duckdb")]
        {
            let duckdb_config = crate::duckdb::DuckDbConfig::default();
            let duckdb = Arc::new(duckdb::DuckDbStorage::new(&duckdb_config).await?);
            migrations::run_duckdb_migrations(&duckdb).await?;
            Ok(Self {
                sqlite,
                duckdb,
            })
        }
        #[cfg(not(feature = "duckdb"))]
        {
            Ok(Self { sqlite })
        }
    }

    pub fn sqlite(&self) -> Arc<sqlite::SqliteStorage> {
        self.sqlite.clone()
    }

    #[cfg(feature = "duckdb")]
    pub fn duckdb(&self) -> Arc<duckdb::DuckDbStorage> {
        self.duckdb.clone()
    }

    pub async fn health(&self) -> anyhow::Result<()> {
        self.sqlite.health().await?;
        #[cfg(feature = "duckdb")]
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
        #[cfg(feature = "duckdb")]
        migrations::run_duckdb_migrations(&self.duckdb).await?;

        Ok(())
    }

    async fn health(&self) -> CoreResult<()> {
        self.health()
            .await
            .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))
    }
}

// ── DuckDB analytics (optional) ──────────────────────────────

#[cfg(feature = "duckdb")]
mod duckdb_analytics {
    use super::*;
    use sentinel_core::traits::{AggregationQuery, AggregationResult, EventCursor, EventQuery};
    use std::sync::Arc;

    pub struct DuckDbEventRepository {
        duckdb: Arc<crate::duckdb::DuckDbStorage>,
    }

    impl DuckDbEventRepository {
        pub fn new(duckdb: Arc<crate::duckdb::DuckDbStorage>) -> Self {
            Self { duckdb }
        }
    }

    #[async_trait::async_trait]
    impl EventRepository for DuckDbEventRepository {
        async fn append(&self, events: &[Arc<Event>]) -> CoreResult<()> {
            self.duckdb
                .append_events(events)
                .await
                .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))
        }

        async fn query(
            &self,
            query: EventQuery,
        ) -> CoreResult<Arc<dyn EventCursor>> {
            let cursor = self
                .duckdb
                .query_events(query)
                .await
                .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))?;
            Ok(Arc::new(cursor))
        }

        async fn get(
            &self,
            id: &sentinel_core::EventId,
        ) -> CoreResult<Option<Arc<Event>>> {
            self.duckdb
                .get_event(id)
                .await
                .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))
        }

        async fn count(&self, query: &EventQuery) -> CoreResult<u64> {
            self.duckdb
                .count_events(query)
                .await
                .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))
        }

        async fn aggregate(&self, agg: AggregationQuery) -> CoreResult<AggregationResult> {
            self.duckdb
                .aggregate_events(agg)
                .await
                .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))
        }

        async fn retention(
            &self,
            policy: sentinel_core::traits::RetentionPolicy,
        ) -> CoreResult<u64> {
            self.duckdb
                .apply_retention(policy)
                .await
                .map_err(|e| sentinel_core::SentinelError::Storage(e.into()))
        }
    }
}
#[cfg(feature = "duckdb")]
pub use duckdb_analytics::DuckDbEventRepository;

#[cfg(feature = "duckdb")]
pub struct AggregationCursor {
    rows: Vec<sentinel_core::traits::AggregationBucket>,
    index: usize,
}

#[cfg(feature = "duckdb")]
impl AggregationCursor {
    pub fn new(rows: Vec<sentinel_core::traits::AggregationBucket>) -> Self {
        Self { rows, index: 0 }
    }
}

#[cfg(feature = "duckdb")]
#[async_trait::async_trait]
impl sentinel_core::traits::EventCursor for AggregationCursor {
    async fn next(&mut self) -> CoreResult<Option<Arc<Event>>> {
        Ok(None)
    }

    async fn collect(&mut self, _limit: usize) -> CoreResult<Vec<Arc<Event>>> {
        Ok(vec![])
    }

    fn total_count(&self) -> u64 {
        self.rows.len() as u64
    }
}

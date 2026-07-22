//! Database migrations for Sentinel AI

use anyhow::Result;
use sqlx::SqlitePool;
use tracing::info;

/// Check whether a migration version has already been applied.
async fn is_applied(pool: &SqlitePool, version: i64) -> Result<bool> {
    let row = sqlx::query("SELECT 1 AS one FROM migrations WHERE version = ?")
        .bind(version)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

/// Record a migration version as applied.
async fn record(pool: &SqlitePool, version: i64, name: &str) -> Result<()> {
    sqlx::query("INSERT INTO migrations (version, name) VALUES (?, ?)")
        .bind(version)
        .bind(name)
        .execute(pool)
        .await?;
    Ok(())
}

/// Execute a schema statement, ignoring "duplicate column"-style benign errors
/// is intentionally NOT done here: schema statements must succeed cleanly.
async fn exec(pool: &SqlitePool, sql: &str) -> Result<()> {
    sqlx::query(sql).execute(pool).await?;
    Ok(())
}

/// Run all SQLite migrations
pub async fn run_all(pool: &SqlitePool) -> Result<()> {
    info!("Running SQLite migrations");

    // Create migrations table
    exec(
        pool,
        r#"
        CREATE TABLE IF NOT EXISTS migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        "#,
    )
    .await?;

    // Migration 1: Initial schema
    migrate_v1(pool).await?;

    // Migration 2: Add indexes
    migrate_v2(pool).await?;

    // Migration 3: Add alerts table
    migrate_v3(pool).await?;

    // Migration 4: Add rules table
    migrate_v4(pool).await?;

    // Migration 5: Add config table
    migrate_v5(pool).await?;

    // Migration 6: Add process tree table
    migrate_v6(pool).await?;

    // Migration 7: Add correlation chains table
    migrate_v7(pool).await?;

    info!("All SQLite migrations completed");
    Ok(())
}

/// Migration 1: Initial events table
async fn migrate_v1(pool: &SqlitePool) -> Result<()> {
    if is_applied(pool, 1).await? {
        return Ok(());
    }

    info!("Applying migration 1: Initial schema");

    exec(
        pool,
        r#"
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            source TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            ingest_timestamp TEXT NOT NULL,
            severity INTEGER NOT NULL,
            process TEXT,
            payload TEXT NOT NULL,
            tags TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}',
            risk_score INTEGER NOT NULL DEFAULT 0,
            correlation TEXT NOT NULL DEFAULT '{}',
            host_id TEXT NOT NULL,
            schema_version INTEGER NOT NULL DEFAULT 1
        )
        "#,
    )
    .await?;

    // Create indexes
    exec(pool, "CREATE INDEX idx_events_timestamp ON events(timestamp)").await?;
    exec(pool, "CREATE INDEX idx_events_type ON events(type)").await?;
    exec(pool, "CREATE INDEX idx_events_source ON events(source)").await?;
    exec(pool, "CREATE INDEX idx_events_severity ON events(severity)").await?;
    exec(pool, "CREATE INDEX idx_events_risk_score ON events(risk_score)").await?;
    exec(pool, "CREATE INDEX idx_events_correlation_id ON events(JSON_EXTRACT(correlation, '$.correlation_id'))").await?;
    exec(pool, "CREATE INDEX idx_events_flow_id ON events(JSON_EXTRACT(correlation, '$.flow_id'))").await?;
    exec(pool, "CREATE INDEX idx_events_process_name ON events(JSON_EXTRACT(process, '$.name'))").await?;

    // Record migration
    record(pool, 1, "initial_schema").await?;

    Ok(())
}

/// Migration 2: Additional indexes
async fn migrate_v2(pool: &SqlitePool) -> Result<()> {
    if is_applied(pool, 2).await? {
        return Ok(());
    }

    info!("Applying migration 2: Additional indexes");

    exec(pool, "CREATE INDEX idx_events_host_id ON events(host_id)").await?;
    exec(pool, "CREATE INDEX idx_events_pid ON events(JSON_EXTRACT(process, '$.pid'))").await?;

    record(pool, 2, "additional_indexes").await?;

    Ok(())
}

/// Migration 3: Alerts table
async fn migrate_v3(pool: &SqlitePool) -> Result<()> {
    if is_applied(pool, 3).await? {
        return Ok(());
    }

    info!("Applying migration 3: Alerts table");

    exec(
        pool,
        r#"
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            severity INTEGER NOT NULL,
            state INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            acknowledged_by TEXT,
            acknowledged_at TEXT,
            events TEXT NOT NULL DEFAULT '',
            context TEXT NOT NULL DEFAULT '{}',
            ai_summary TEXT
        )
        "#,
    )
    .await?;

    exec(pool, "CREATE INDEX idx_alerts_state ON alerts(state)").await?;
    exec(pool, "CREATE INDEX idx_alerts_severity ON alerts(severity)").await?;
    exec(pool, "CREATE INDEX idx_alerts_created_at ON alerts(created_at)").await?;
    exec(pool, "CREATE INDEX idx_alerts_correlation_id ON alerts(correlation_id)").await?;
    exec(pool, "CREATE INDEX idx_alerts_rule_id ON alerts(rule_id)").await?;

    record(pool, 3, "alerts_table").await?;

    Ok(())
}

/// Migration 4: Rules table
async fn migrate_v4(pool: &SqlitePool) -> Result<()> {
    if is_applied(pool, 4).await? {
        return Ok(());
    }

    info!("Applying migration 4: Rules table");

    exec(
        pool,
        r#"
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            rule_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .await?;

    exec(pool, "CREATE INDEX idx_rules_enabled ON rules(enabled)").await?;

    record(pool, 4, "rules_table").await?;

    Ok(())
}

/// Migration 5: Config table
async fn migrate_v5(pool: &SqlitePool) -> Result<()> {
    if is_applied(pool, 5).await? {
        return Ok(());
    }

    info!("Applying migration 5: Config table");

    exec(
        pool,
        r#"
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        "#,
    )
    .await?;

    record(pool, 5, "config_table").await?;

    Ok(())
}

/// Migration 6: Process tree table
async fn migrate_v6(pool: &SqlitePool) -> Result<()> {
    if is_applied(pool, 6).await? {
        return Ok(());
    }

    info!("Applying migration 6: Process tree table");

    exec(
        pool,
        r#"
        CREATE TABLE IF NOT EXISTS process_tree (
            pid INTEGER PRIMARY KEY,
            ppid INTEGER,
            name TEXT NOT NULL,
            path TEXT,
            command_line TEXT,
            user_sid TEXT,
            username TEXT,
            domain TEXT,
            is_elevated INTEGER NOT NULL DEFAULT 0,
            is_system INTEGER NOT NULL DEFAULT 0,
            start_time TEXT NOT NULL,
            end_time TEXT,
            host_id TEXT NOT NULL
        )
        "#,
    )
    .await?;

    exec(pool, "CREATE INDEX idx_process_tree_ppid ON process_tree(ppid)").await?;
    exec(pool, "CREATE INDEX idx_process_tree_name ON process_tree(name)").await?;
    exec(pool, "CREATE INDEX idx_process_tree_start_time ON process_tree(start_time)").await?;

    record(pool, 6, "process_tree_table").await?;

    Ok(())
}

/// Migration 7: Correlation chains table
async fn migrate_v7(pool: &SqlitePool) -> Result<()> {
    if is_applied(pool, 7).await? {
        return Ok(());
    }

    info!("Applying migration 7: Correlation chains table");

    exec(
        pool,
        r#"
        CREATE TABLE IF NOT EXISTS correlation_chains (
            id TEXT PRIMARY KEY,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            tactics TEXT NOT NULL DEFAULT '[]',
            techniques TEXT NOT NULL DEFAULT '[]',
            event_count INTEGER NOT NULL DEFAULT 0,
            state INTEGER NOT NULL DEFAULT 0,
            kill_chain_coverage REAL NOT NULL DEFAULT 0.0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        "#,
    )
    .await?;

    exec(
        pool,
        r#"
        CREATE TABLE IF NOT EXISTS chain_events (
            chain_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            edge_type TEXT NOT NULL,
            confidence REAL NOT NULL,
            evidence TEXT,
            PRIMARY KEY (chain_id, event_id),
            FOREIGN KEY (chain_id) REFERENCES correlation_chains(id)
        )
        "#,
    )
    .await?;

    exec(pool, "CREATE INDEX idx_chain_events_chain_id ON chain_events(chain_id)").await?;
    exec(pool, "CREATE INDEX idx_chain_events_event_id ON chain_events(event_id)").await?;

    record(pool, 7, "correlation_chains").await?;

    Ok(())
}

/// Run DuckDB migrations
pub async fn run_duckdb_migrations(_duckdb: &crate::duckdb::DuckDbStorage) -> Result<()> {
    info!("Running DuckDB migrations");

    // DuckDB uses the same schema but optimized for analytics
    // Events table is created automatically by the DuckDB storage
    // We just need to ensure the schema is compatible

    info!("DuckDB migrations completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_migrations() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&db_path)
                    .create_if_missing(true),
            )
            .await
            .unwrap();

        run_all(&pool).await.unwrap();

        // Verify tables exist
        let tables: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table'")
            .fetch_all(&pool)
            .await
            .unwrap();

        assert!(tables.contains(&"events".to_string()));
        assert!(tables.contains(&"alerts".to_string()));
        assert!(tables.contains(&"rules".to_string()));
        assert!(tables.contains(&"config".to_string()));
        assert!(tables.contains(&"process_tree".to_string()));
        assert!(tables.contains(&"correlation_chains".to_string()));
        assert!(tables.contains(&"chain_events".to_string()));
        assert!(tables.contains(&"migrations".to_string()));
    }
}

//! Configuration migration system

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

/// Current configuration version
pub const CURRENT_CONFIG_VERSION: u32 = 1;

/// Migrate configuration to current version
pub fn migrate(config: &mut super::AppConfig) -> Result<()> {
    let version = get_version(config);
    
    if version >= CURRENT_CONFIG_VERSION {
        return Ok(());
    }
    
    info!("Migrating configuration from version {} to {}", version, CURRENT_CONFIG_VERSION);
    
    for v in (version + 1)..=CURRENT_CONFIG_VERSION {
        migrate_to_version(config, v)
            .with_context(|| format!("Failed to migrate to version {}", v))?;
    }
    
    set_version(config, CURRENT_CONFIG_VERSION);
    info!("Configuration migration complete");
    
    Ok(())
}

fn get_version(config: &super::AppConfig) -> u32 {
    // Try to get version from core config or default to 0
    config.core.host_id.parse().unwrap_or(0)
}

fn set_version(config: &mut super::AppConfig, version: u32) {
    // Store version in host_id field if empty, or use a dedicated field
    if config.core.host_id.is_empty() {
        config.core.host_id = version.to_string();
    }
}

fn migrate_to_version(config: &mut super::AppConfig, version: u32) -> Result<()> {
    match version {
        1 => migrate_to_v1(config),
        _ => Ok(()),
    }
}

fn migrate_to_v1(config: &mut super::AppConfig) -> Result<()> {
    // Version 1: Initial version, no migration needed
    // Ensure all required fields have defaults
    if config.core.instance_name.is_empty() {
        config.core.instance_name = "Sentinel AI".to_string();
    }
    
    if config.grpc.address.is_empty() {
        config.grpc.address = "127.0.0.1:7777".to_string();
    }
    
    if config.storage.sqlite_path.is_empty() {
        config.storage.sqlite_path = "data/sentinel.db".to_string();
    }
    
    if config.storage.duckdb_path.is_empty() {
        config.storage.duckdb_path = "data/events.duckdb".to_string();
    }
    
    // Migrate old rule engine config if present
    if config.rule_engine.rules_directories.is_empty() {
        config.rule_engine.rules_directories = vec![
            "/etc/sentinel/rules/builtin".to_string(),
            "/etc/sentinel/rules/custom".to_string(),
            "~/.config/sentinel/rules/custom".to_string(),
        ];
    }
    
    // Migrate old collector configs
    if config.collectors.process.exclude_paths.is_empty() {
        config.collectors.process.exclude_paths = vec![
            "C:\\Windows\\System32\\*".to_string(),
            "C:\\Program Files\\*".to_string(),
            "/usr/bin/*".to_string(),
            "/bin/*".to_string(),
            "/sbin/*".to_string(),
            "/lib*".to_string(),
        ];
    }
    
    if config.collectors.network.exclude_ports.is_empty() {
        config.collectors.network.exclude_ports = vec![53, 67, 68, 123, 1900, 5353, 5355];
    }
    
    // Migrate AI engine config
    if config.ai_engine.model.is_empty() {
        config.ai_engine.model = "llama-3.2-3b-instruct".to_string();
    }
    
    if config.ai_engine.fallback_models.is_empty() {
        config.ai_engine.fallback_models = vec![
            "llama-3.1-8b-instruct".to_string(),
            "qwen2.5-7b-instruct".to_string(),
        ];
    }
    
    Ok(())
}

/// Trait for versioned configuration sections
pub trait VersionedConfig: Serialize + for<'de> Deserialize<'de> {
    const VERSION: u32;
    
    fn migrate(_value: &mut Value) -> Result<()> {
        Ok(())
    }
}

/// Helper for migrating individual config sections
pub fn migrate_section<T: VersionedConfig>(section: &mut T) -> Result<()> {
    let mut value = serde_json::to_value(&*section)?;
    T::migrate(&mut value)?;
    *section = serde_json::from_value(value)?;
    Ok(())
}

/// Migration plan for complex migrations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub from_version: u32,
    pub to_version: u32,
    pub steps: Vec<MigrationStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStep {
    pub name: String,
    pub description: String,
    pub automatic: bool,
}

impl MigrationPlan {
    pub fn new(from: u32, to: u32) -> Self {
        Self {
            from_version: from,
            to_version: to,
            steps: Vec::new(),
        }
    }
    
    pub fn add_step(mut self, name: &str, description: &str, automatic: bool) -> Self {
        self.steps.push(MigrationStep {
            name: name.to_string(),
            description: description.to_string(),
            automatic,
        });
        self
    }
}

/// Run migration plan with user confirmation for manual steps
pub async fn run_migration_plan(
    plan: &MigrationPlan,
    _config: &mut super::AppConfig,
    confirm: bool,
) -> Result<()> {
    for step in &plan.steps {
        if step.automatic {
            info!("Running automatic migration step: {}", step.name);
            // Automatic steps would be implemented here
        } else {
            warn!("Manual migration step required: {} - {}", step.name, step.description);
            if confirm {
                // In a real implementation, this would prompt the user
                info!("Skipping manual step (auto-confirm enabled): {}", step.name);
            } else {
                return Err(anyhow::anyhow!("Manual migration step required: {}", step.name));
            }
        }
    }
    Ok(())
}
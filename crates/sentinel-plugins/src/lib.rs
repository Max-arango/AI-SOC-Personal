//! Sentinel AI plugins crate.
//!
//! Provides a minimal `PluginManager` implementation. Plugin loading,
//! execution and configuration are stubbed out for now; real plugin
//! discovery and sandboxing will be added in later iterations.

use std::collections::HashMap;

use async_trait::async_trait;
use sentinel_core::traits::PluginManager as PluginManagerTrait;
use sentinel_core::Result;
use tokio::sync::RwLock;

/// In-memory plugin manager.
pub struct PluginManager {
    #[allow(dead_code)]
    plugins: RwLock<HashMap<String, sentinel_core::traits::PluginInfo>>,
}

impl PluginManager {
    /// Create a new, empty plugin manager.
    pub fn new() -> Self {
        Self { plugins: RwLock::new(HashMap::new()) }
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PluginManagerTrait for PluginManager {
    async fn load(&self, _plugin_id: &str) -> Result<()> {
        Ok(())
    }

    async fn unload(&self, _plugin_id: &str) -> Result<()> {
        Ok(())
    }

    async fn configure(&self, _plugin_id: &str, _config: serde_json::Value) -> Result<()> {
        Ok(())
    }

    async fn execute_action(
        &self,
        _plugin_id: &str,
        _action: &str,
        _params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        Ok(serde_json::Value::Null)
    }

    fn list(&self) -> Vec<sentinel_core::traits::PluginInfo> {
        Vec::new()
    }

    fn get(&self, _plugin_id: &str) -> Option<sentinel_core::traits::PluginInfo> {
        None
    }
}

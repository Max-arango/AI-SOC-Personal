use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub sharing: SharingConfig,
    #[serde(default)]
    pub fleet_queries: FleetQueryConfig,
    #[serde(default)]
    pub ml: MlConfig,
    #[serde(default)]
    pub notifications: NotificationConfig,
    #[serde(default)]
    pub siem: SiemConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingConfig {
    #[serde(default = "default_anonymization")]
    pub command_lines: AnonymizationLevel,
    #[serde(default = "default_anonymization")]
    pub file_paths: AnonymizationLevel,
    #[serde(default = "default_anonymization")]
    pub network_ips: AnonymizationLevel,
    #[serde(default = "default_hashed")]
    pub user_names: AnonymizationLevel,
    #[serde(default = "default_full")]
    pub process_names: AnonymizationLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetQueryConfig {
    #[serde(default = "default_true")]
    pub require_approval: bool,
    #[serde(default = "default_true")]
    pub auto_approve_localhost: bool,
    #[serde(default = "default_max_rows")]
    pub max_rows_per_query: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlConfig {
    #[serde(default)]
    pub federated_learning: bool,
    #[serde(default = "default_epsilon")]
    pub differential_privacy_epsilon: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    #[serde(default = "default_true")]
    pub silent_push_only: bool,
    #[serde(default = "default_true")]
    pub local_websocket_fallback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub redact_pii: bool,
    #[serde(default)]
    pub field_whitelist: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnonymizationLevel {
    Full,
    Redacted,
    Anonymized,
    Hashed,
    None,
}

impl AnonymizationLevel {
    pub fn is_shared(&self) -> bool {
        !matches!(self, Self::None)
    }
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            mode: "personal".into(),
            sharing: SharingConfig::default(),
            fleet_queries: FleetQueryConfig::default(),
            ml: MlConfig::default(),
            notifications: NotificationConfig::default(),
            siem: SiemConfig::default(),
        }
    }
}

impl Default for SharingConfig {
    fn default() -> Self {
        Self {
            command_lines: AnonymizationLevel::Redacted,
            file_paths: AnonymizationLevel::Anonymized,
            network_ips: AnonymizationLevel::Anonymized,
            user_names: AnonymizationLevel::Hashed,
            process_names: AnonymizationLevel::Full,
        }
    }
}

impl Default for FleetQueryConfig {
    fn default() -> Self {
        Self { require_approval: true, auto_approve_localhost: true, max_rows_per_query: 1000 }
    }
}

impl Default for MlConfig {
    fn default() -> Self {
        Self { federated_learning: false, differential_privacy_epsilon: 8.0 }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self { silent_push_only: true, local_websocket_fallback: true }
    }
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self { enabled: false, redact_pii: true, field_whitelist: vec![] }
    }
}

fn default_mode() -> String {
    "personal".into()
}
fn default_anonymization() -> AnonymizationLevel {
    AnonymizationLevel::Redacted
}
fn default_hashed() -> AnonymizationLevel {
    AnonymizationLevel::Hashed
}
fn default_full() -> AnonymizationLevel {
    AnonymizationLevel::Full
}
fn default_true() -> bool {
    true
}
fn default_max_rows() -> usize {
    1000
}
fn default_epsilon() -> f64 {
    8.0
}

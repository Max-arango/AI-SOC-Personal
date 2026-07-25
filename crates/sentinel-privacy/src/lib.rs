use sentinel_events::Event;

use crate::config::PrivacyConfig;
use crate::filter::PrivacyFilter;

pub mod config;
pub mod filter;

pub struct PrivacyEngine {
    config: PrivacyConfig,
    filter: PrivacyFilter,
}

impl PrivacyEngine {
    pub fn new(config: PrivacyConfig) -> Self {
        let filter = PrivacyFilter::new(config.sharing.clone());
        Self { config, filter }
    }

    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: PrivacyConfig = toml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn is_enterprise(&self) -> bool {
        self.config.mode == "enterprise"
    }

    pub fn config(&self) -> &PrivacyConfig {
        &self.config
    }

    pub fn filter(&self) -> &PrivacyFilter {
        &self.filter
    }

    pub fn sanitize_event(&self, event: &Event) -> Event {
        let mut sanitized = event.clone();

        if let Some(ref proc) = event.process {
            let mut sp = proc.clone();
            sp.command_line = self.filter.redact_command_line(&sp.command_line);
            sp.path = self.filter.anonymize_path(&sp.path);
            if let Some(ref user) = proc.user {
                let mut su = user.clone();
                su.username = self.filter.hash_username(&su.username);
                su.sid = self.filter.hash_username(&su.sid);
                sp.user = Some(su);
            }
            sanitized.process = Some(sp);
        }

        sanitized.id = event.id.clone();
        sanitized
    }

    pub fn should_share_event(&self, event: &Event) -> bool {
        if !self.is_enterprise() {
            return false;
        }
        event.severity >= 3
    }
}

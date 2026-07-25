use sha2::{Digest, Sha256};
use std::path::Path;

use crate::config::{AnonymizationLevel, SharingConfig};

pub struct PrivacyFilter {
    sharing: SharingConfig,
    home_dir: String,
}

impl PrivacyFilter {
    pub fn new(sharing: SharingConfig) -> Self {
        let home = dirs::home_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/home/user".into());

        Self {
            sharing,
            home_dir: home,
        }
    }

    pub fn with_home_dir(sharing: SharingConfig, home_dir: String) -> Self {
        Self {
            sharing,
            home_dir,
        }
    }

    pub fn redact_command_line(&self, cmd: &str) -> String {
        match &self.sharing.command_lines {
            AnonymizationLevel::Full => cmd.into(),
            AnonymizationLevel::None => String::new(),
            AnonymizationLevel::Redacted => Self::do_redact_command_line(cmd, &self.home_dir),
            AnonymizationLevel::Anonymized => Self::do_anonymize_path(cmd, &self.home_dir),
            AnonymizationLevel::Hashed => Self::do_hash(cmd),
        }
    }

    pub fn anonymize_path(&self, path: &str) -> String {
        match &self.sharing.file_paths {
            AnonymizationLevel::Full => path.into(),
            AnonymizationLevel::None => String::new(),
            AnonymizationLevel::Redacted | AnonymizationLevel::Anonymized => {
                Self::do_anonymize_path(path, &self.home_dir)
            }
            AnonymizationLevel::Hashed => Self::do_hash(path),
        }
    }

    pub fn anonymize_ip(&self, ip: &str) -> String {
        match &self.sharing.network_ips {
            AnonymizationLevel::Full => ip.into(),
            AnonymizationLevel::None => String::new(),
            AnonymizationLevel::Anonymized | AnonymizationLevel::Redacted => {
                if ip.contains(':') {
                    format!("{}:****", ip.split(':').next().unwrap_or("x"))
                } else {
                    let parts: Vec<&str> = ip.split('.').collect();
                    if parts.len() == 4 {
                        format!("{}.{}.x.x", parts[0], parts[1])
                    } else {
                        "x.x.x.x".into()
                    }
                }
            }
            AnonymizationLevel::Hashed => Self::do_hash(ip),
        }
    }

    pub fn hash_username(&self, username: &str) -> String {
        match &self.sharing.user_names {
            AnonymizationLevel::Full => username.into(),
            AnonymizationLevel::None => String::new(),
            AnonymizationLevel::Hashed | AnonymizationLevel::Redacted | AnonymizationLevel::Anonymized => {
                Self::do_hash(username)
            }
        }
    }

    pub fn filter_process_name(&self, name: &str) -> String {
        match &self.sharing.process_names {
            AnonymizationLevel::Full => name.into(),
            AnonymizationLevel::None => String::new(),
            AnonymizationLevel::Redacted | AnonymizationLevel::Anonymized | AnonymizationLevel::Hashed => {
                Self::do_hash(name)
            }
        }
    }

    pub fn is_enterprise_mode(&self) -> bool {
        true
    }

    fn do_redact_command_line(cmd: &str, home_dir: &str) -> String {
        let mut result = cmd.to_string();
        result = result.replace(home_dir, "$HOME");

        let flag_values = [
            "--password", "--token", "--api-key", "--secret",
            "--key", "-password", "password", "passwd",
        ];

        for flag in &flag_values {
            let pattern_eq = format!("{}=", flag);
            let pattern_space = format!("{} ", flag);
            let pos = result.find(&pattern_eq).or_else(|| result.find(&pattern_space));
            if let Some(pos) = pos {
                let val_start = pos + flag.len() + 1;
                if val_start < result.len() {
                    let val_end = result[val_start..]
                        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                        .map(|p| val_start + p)
                        .unwrap_or(result.len());
                    let prefix = &result[..val_start];
                    let suffix = &result[val_end..];
                    result = format!("{}***{}", prefix, suffix);
                }
            }
        }

        result
    }

    fn do_anonymize_path(path: &str, home_dir: &str) -> String {
        let p = Path::new(path);

        let path_str = if p.starts_with(home_dir) {
            format!(
                "$HOME/{}",
                p.strip_prefix(home_dir)
                    .map(|r| r.to_string_lossy())
                    .unwrap_or_default()
            )
        } else if p.starts_with("/etc") {
            format!(
                "/etc/{}",
                p.strip_prefix("/etc")
                    .map(|r| r.to_string_lossy())
                    .unwrap_or_default()
            )
        } else if p.starts_with("/tmp") {
            format!(
                "/tmp/{}",
                p.strip_prefix("/tmp")
                    .map(|r| r.to_string_lossy())
                    .unwrap_or_default()
            )
        } else if p.starts_with("/var") {
            format!(
                "/var/{}",
                p.strip_prefix("/var")
                    .map(|r| r.to_string_lossy())
                    .unwrap_or_default()
            )
        } else {
            let hash = do_hash_first_8_bytes(path);
            format!("/other/{}", hash)
        };

        if path_str.len() > 256 {
            format!("{}...", &path_str[..253])
        } else {
            path_str
        }
    }

    fn do_hash(input: &str) -> String {
        do_hash_first_8_bytes(input)
    }
}

fn do_hash_first_8_bytes(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_filter() -> PrivacyFilter {
        PrivacyFilter::new(SharingConfig::default())
    }

    #[test]
    fn test_redact_command_line_hides_home() {
        let filter = test_filter();
        let result = filter.redact_command_line("/home/fellcrack/malware.sh --password=secret123");
        assert!(result.contains("$HOME"));
        assert!(!result.contains("secret123"));
        assert!(result.contains("***"));
    }

    #[test]
    fn test_anonymize_path() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
        let filter = PrivacyFilter::with_home_dir(SharingConfig::default(), home.clone());
        let path = format!("{}/documents/private.txt", home);
        let result = filter.anonymize_path(&path);
        assert!(result.starts_with("$HOME"));
    }

    #[test]
    fn test_anonymize_ip() {
        let filter = test_filter();
        let result = filter.anonymize_ip("192.168.1.100");
        assert!(result.contains("x.x"));
        assert!(!result.contains("100"));
    }

    #[test]
    fn test_hash_username() {
        let filter = test_filter();
        let result = filter.hash_username("alice");
        assert_ne!(result, "alice");
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn test_full_mode_preserves_data() {
        let filter = PrivacyFilter::new(SharingConfig {
            command_lines: AnonymizationLevel::Full,
            file_paths: AnonymizationLevel::Full,
            network_ips: AnonymizationLevel::Full,
            user_names: AnonymizationLevel::Full,
            process_names: AnonymizationLevel::Full,
        });
        assert_eq!(
            filter.redact_command_line("ls /tmp"),
            "ls /tmp"
        );
        assert_eq!(filter.anonymize_ip("8.8.8.8"), "8.8.8.8");
        assert_eq!(filter.hash_username("bob"), "bob");
    }
}

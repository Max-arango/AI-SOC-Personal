//! Secrets management for Sentinel AI
//!
//! Handles encryption/decryption of sensitive configuration values using age.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use tracing::{debug, info, warn};

use age::{Decryptor, Encryptor, Identity, x25519};

/// Secrets manager for handling encrypted configuration values
#[derive(Clone)]
pub struct SecretsManager {
    identity: Option<x25519::Identity>,
    recipient: Option<x25519::Recipient>,
    secrets_path: Option<std::path::PathBuf>,
}

impl SecretsManager {
    /// Create a new secrets manager
    pub fn new() -> Self {
        Self {
            identity: None,
            recipient: None,
            secrets_path: None,
        }
    }
    
    /// Initialize with a key file
    pub async fn with_key_file<P: AsRef<Path>>(key_path: P) -> Result<Self> {
        let key_content = fs::read_to_string(&key_path).await
            .with_context(|| format!("Failed to read key file: {}", key_path.as_ref().display()))?;
        
        let identity = key_content.parse::<x25519::Identity>()
            .map_err(|e| anyhow::anyhow!("Failed to parse age identity: {}", e))?;
        
        let recipient = identity.to_public();
        
        Ok(Self {
            identity: Some(identity),
            recipient: Some(recipient),
            secrets_path: Some(key_path.as_ref().to_path_buf()),
        })
    }
    
    /// Initialize with inline key (for testing)
    pub fn with_key(identity_str: &str) -> Result<Self> {
        let identity = identity_str.parse::<x25519::Identity>()
            .map_err(|e| anyhow::anyhow!("Failed to parse age identity: {}", e))?;
        let recipient = identity.to_public();
        
        Ok(Self {
            identity: Some(identity),
            recipient: Some(recipient),
            secrets_path: None,
        })
    }
    
    /// Generate a new key pair
    pub fn generate_key() -> (String, String) {
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public();
        (
            identity.to_string().expose_secret().to_string(),
            recipient.to_string(),
        )
    }
    
    /// Encrypt a secret value
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let recipient = self.recipient.as_ref()
            .context("No recipient configured for encryption")?;
        
        let encryptor = Encryptor::with_recipients(vec![Box::new(recipient.clone())])
            .ok_or_else(|| anyhow::anyhow!("No recipients provided for encryption"))?;
        let mut encrypted = vec![];
        {
            let mut writer = encryptor.wrap_output(&mut encrypted)?;
            std::io::Write::write_all(&mut writer, plaintext.as_bytes())?;
            writer.finish()?;
        }
        
        // Encode as base64 for storage
        Ok(base64::encode(encrypted))
    }
    
    /// Decrypt a secret value
    pub fn decrypt(&self, ciphertext: &str) -> Result<String> {
        let identity = self.identity.as_ref()
            .context("No identity configured for decryption")?;
        
        // Decode from base64
        let encrypted = base64::decode(ciphertext)
            .context("Failed to decode base64")?;
        
        let decryptor = Decryptor::new(encrypted.as_slice())
            .context("Failed to create decryptor")?;
        
        let mut decrypted = vec![];
        match decryptor {
            Decryptor::Recipients(d) => {
                let mut reader = d
                    .decrypt(std::iter::once(identity as &dyn Identity))
                    .context("Failed to decrypt")?;
                std::io::Read::read_to_end(&mut reader, &mut decrypted)?;
            }
            _ => anyhow::bail!("Passphrase-based age decryption is not supported"),
        }
        
        String::from_utf8(decrypted)
            .context("Decrypted data is not valid UTF-8")
    }
    
    /// Check if a value appears to be encrypted (base64 age format)
    pub fn is_encrypted(value: &str) -> bool {
        // Age encrypted data starts with "age-encryption.org/v1" when base64 decoded
        // But we can check for base64 format and reasonable length
        if value.len() < 50 {
            return false;
        }
        base64::decode(value).is_ok()
    }
    
    /// Decrypt all secrets in a configuration object
    pub async fn decrypt_config(&self, config: &mut super::AppConfig) -> Result<()> {
        if self.identity.is_none() {
            debug!("No decryption identity available, skipping secret decryption");
            return Ok(());
        }
        
        let json = serde_json::to_value(&*config)?;
        let decrypted = self.decrypt_value(&json)?;
        *config = serde_json::from_value(decrypted)?;
        
        Ok(())
    }
    
    /// Recursively decrypt values in a JSON object
    fn decrypt_value(&self, value: &Value) -> Result<Value> {
        match value {
            Value::String(s) => {
                if Self::is_encrypted(s) {
                    match self.decrypt(s) {
                        Ok(decrypted) => Ok(Value::String(decrypted)),
                        Err(e) => {
                            warn!("Failed to decrypt secret: {}", e);
                            Ok(value.clone())
                        }
                    }
                } else {
                    Ok(value.clone())
                }
            }
            Value::Object(map) => {
                let mut new_map = Map::new();
                for (k, v) in map {
                    new_map.insert(k.clone(), self.decrypt_value(v)?);
                }
                Ok(Value::Object(new_map))
            }
            Value::Array(arr) => {
                let mut new_arr = Vec::new();
                for v in arr {
                    new_arr.push(self.decrypt_value(v)?);
                }
                Ok(Value::Array(new_arr))
            }
            _ => Ok(value.clone()),
        }
    }
    
    /// Encrypt sensitive fields in configuration
    pub fn encrypt_sensitive_fields(&self, config: &mut super::AppConfig) -> Result<()> {
        if self.recipient.is_none() {
            debug!("No encryption recipient available, skipping secret encryption");
            return Ok(());
        }
        
        // Fields that should be encrypted
        let sensitive_paths = vec![
            "virustotal.api_key",
            "abuseipdb.api_key",
            "otx.api_key",
            "shodan.api_key",
            "hybrid_analysis.api_key",
            "discord.webhook_url",
            "telegram.bot_token",
            "slack.webhook_url",
            "slack.bot_token",
            "email.smtp_password",
            "home_assistant.long_lived_token",
            "openai.api_key",
        ];
        
        let json = serde_json::to_value(&*config)?;
        let encrypted = self.encrypt_paths(&json, &sensitive_paths)?;
        *config = serde_json::from_value(encrypted)?;
        
        Ok(())
    }
    
    /// Encrypt specific paths in a JSON object
    fn encrypt_paths(&self, value: &Value, paths: &[&str]) -> Result<Value> {
        let mut result = value.clone();
        
        for path in paths {
            self.encrypt_path(&mut result, path)?;
        }
        
        Ok(result)
    }
    
    fn encrypt_path(&self, value: &mut Value, path: &str) -> Result<()> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = value;
        
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                // Last part - encrypt the value
                if let Value::Object(ref mut map) = current {
                    if let Some(v) = map.get_mut(*part) {
                        if let Value::String(s) = v {
                            if !Self::is_encrypted(s) && !s.is_empty() {
                                *v = Value::String(self.encrypt(s)?);
                            }
                        }
                    }
                }
            } else {
                // Navigate deeper
                if let Value::Object(ref mut map) = current {
                    if let Some(v) = map.get_mut(*part) {
                        current = v;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// Load secrets from a separate secrets file
    pub async fn load_secrets_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let content = fs::read_to_string(&path).await
            .with_context(|| format!("Failed to read secrets file: {}", path.as_ref().display()))?;
        
        // Parse as TOML
        let secrets: HashMap<String, String> = toml::from_str(&content)
            .context("Failed to parse secrets file")?;
        
        // Store for later use
        // In a real implementation, we'd store these securely
        info!("Loaded {} secrets from file", secrets.len());
        
        Ok(())
    }
    
    /// Save secrets to a file (encrypted)
    pub async fn save_secrets_file<P: AsRef<Path>>(
        &self,
        path: P,
        secrets: &HashMap<String, String>,
    ) -> Result<()> {
        let mut encrypted_secrets = HashMap::new();
        
        for (key, value) in secrets {
            encrypted_secrets.insert(key.clone(), self.encrypt(value)?);
        }
        
        let content = toml::to_string(&encrypted_secrets)
            .context("Failed to serialize secrets")?;
        
        fs::write(&path, content).await
            .with_context(|| format!("Failed to write secrets file: {}", path.as_ref().display()))?;
        
        info!("Saved {} encrypted secrets to file", secrets.len());
        Ok(())
    }
}

impl Default for SecretsManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Secure string wrapper that zeroizes on drop
pub type SecureString = SecretString;

/// Trait for types that contain secrets
pub trait HasSecrets {
    fn encrypt_secrets(&mut self, manager: &SecretsManager) -> Result<()>;
    fn decrypt_secrets(&mut self, manager: &SecretsManager) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation() {
        let (identity, recipient) = SecretsManager::generate_key();
        assert!(!identity.is_empty());
        assert!(!recipient.is_empty());
        assert!(identity.starts_with("AGE-SECRET-KEY-"));
        assert!(recipient.starts_with("age1"));
    }
    
    #[test]
    fn test_encrypt_decrypt() {
        let (identity, recipient) = SecretsManager::generate_key();
        let manager = SecretsManager::with_key(&identity).unwrap();
        
        let plaintext = "my-secret-api-key-12345";
        let encrypted = manager.encrypt(plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        
        let decrypted = manager.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_is_encrypted() {
        let (identity, _) = SecretsManager::generate_key();
        let manager = SecretsManager::with_key(&identity).unwrap();
        
        let plaintext = "not-encrypted";
        let encrypted = manager.encrypt(plaintext).unwrap();
        
        assert!(!SecretsManager::is_encrypted(plaintext));
        assert!(SecretsManager::is_encrypted(&encrypted));
    }
}
//! Sentinel AI Engine
//!
//! Local-first AI integration via Ollama for explaining security alerts,
//! summarising event chains, and providing investigation guidance.
//! All inference runs entirely on-device.

use std::collections::HashMap;
use std::sync::Arc;

use ollama_rs::generation::completion::request::GenerationRequest;
use ollama_rs::models::ModelOptions;
use ollama_rs::Ollama;
use tokio::sync::Mutex;
use tracing::warn;

use sentinel_core::traits::Alert;
use sentinel_events::Event;

// ── Configuration ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AiConfig {
    pub host: String,
    pub port: u16,
    pub model: String,
    pub temperature: f32,
    pub timeout_secs: u64,
    pub enabled: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            host: "localhost".into(),
            port: 11434,
            model: "gemma4:latest".into(),
            temperature: 0.3,
            timeout_secs: 30,
            enabled: true,
        }
    }
}

// ── Provider trait ─────────────────────────────────────────────────

#[async_trait::async_trait]
pub trait AiProvider: Send + Sync {
    async fn generate(&self, prompt: &str) -> Result<String, AiError>;
    async fn is_available(&self) -> bool;
}

// ── Ollama provider ────────────────────────────────────────────────

pub struct OllamaProvider {
    ollama: Ollama,
    config: AiConfig,
}

impl OllamaProvider {
    pub fn new(config: &AiConfig) -> Self {
        Self { ollama: Ollama::new(config.host.clone(), config.port), config: config.clone() }
    }
}

#[async_trait::async_trait]
impl AiProvider for OllamaProvider {
    async fn generate(&self, prompt: &str) -> Result<String, AiError> {
        let options = ModelOptions::default().temperature(self.config.temperature);

        let request =
            GenerationRequest::new(self.config.model.clone(), prompt.to_string()).options(options);

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
            self.ollama.generate(request),
        )
        .await
        .map_err(|_| AiError::Timeout)?
        .map_err(|e| AiError::Backend(e.to_string()))?;

        Ok(resp.response)
    }

    async fn is_available(&self) -> bool {
        let request = GenerationRequest::new(self.config.model.clone(), "ping".to_string());
        matches!(
            tokio::time::timeout(std::time::Duration::from_secs(3), self.ollama.generate(request),)
                .await,
            Ok(Ok(_))
        )
    }
}

// ── Context Builder ────────────────────────────────────────────────

pub struct ContextBuilder;

impl ContextBuilder {
    pub fn explain_alert(alert: &Alert, events: &[Arc<Event>]) -> String {
        let summary = Self::summarise_events(events);
        format!(
            "You are a security analyst assistant. Data privacy is critical.\n\n\
             Alert:\n  Rule: {}\n  Risk: {}/1000  Severity: {:?}  Time: {}\n\n\
             Related events:\n{}\n\n\
             Explain in 2-3 sentences: what happened, likely threat or false positive, and what the user should do.",
            alert.rule_id, alert.risk_score, alert.severity, alert.created_at, summary
        )
    }

    pub fn summarise_chain(events: &[Arc<Event>]) -> String {
        format!(
            "Summarise this security event chain in 2-4 sentences.\n\n{}\n\nSummary:",
            Self::summarise_events(events)
        )
    }

    pub fn investigate(alert: &Alert, events: &[Arc<Event>]) -> String {
        format!(
            "Recommend 3-5 concrete investigation steps for:\n  Alert: {} (risk={}/1000)\n\n{}\n\nSteps:",
            alert.rule_id,
            alert.risk_score,
            Self::summarise_events(events)
        )
    }

    fn summarise_events(events: &[Arc<Event>]) -> String {
        if events.is_empty() {
            return "(no related events)".into();
        }
        let mut lines = Vec::new();
        for (i, e) in events.iter().enumerate() {
            let proc = e
                .process
                .as_ref()
                .map(|p| {
                    format!(
                        " [{} pid={} cmd={}]",
                        anonymise_path(&p.name),
                        p.pid,
                        anonymise_command(&p.command_line)
                    )
                })
                .unwrap_or_default();
            lines.push(format!(
                "  {}. [{}] {} (sev={}){}",
                i + 1,
                e.source,
                e.r#type,
                e.severity,
                proc
            ));
        }
        lines.join("\n")
    }
}

fn anonymise_path(s: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
    s.replace(&home, "~")
}

fn anonymise_command(cmd: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".into());
    let cmd = cmd.replace(&home, "~");

    let words: Vec<&str> = cmd.split_whitespace().collect();
    let redacted: Vec<String> = words
        .iter()
        .map(|w| {
            let lower = w.to_lowercase();
            let key_patterns = [
                "token=",
                "password=",
                "secret=",
                "key=",
                "api_key=",
                "token:",
                "password:",
                "secret:",
                "key:",
                "api_key:",
            ];
            for pat in &key_patterns {
                if lower.starts_with(pat) {
                    if let Some(pos) = w.find(|c| c == '=' || c == ':') {
                        return format!("{}REDACTED", &w[..=pos]);
                    }
                }
            }
            w.to_string()
        })
        .collect();
    redacted.join(" ")
}

// ── AI Engine ──────────────────────────────────────────────────────

pub struct AiEngine {
    provider: Box<dyn AiProvider>,
    config: AiConfig,
    cache: Mutex<HashMap<String, String>>,
}

impl AiEngine {
    pub fn new(config: AiConfig, provider: Box<dyn AiProvider>) -> Self {
        Self { provider, config, cache: Mutex::new(HashMap::new()) }
    }

    pub async fn explain_alert(&self, alert: &Alert, events: &[Arc<Event>]) -> String {
        if !self.config.enabled {
            return Self::fallback(alert);
        }
        let prompt = ContextBuilder::explain_alert(alert, events);
        self.cached_generate(&prompt, 128).await
    }

    pub async fn summarise_chain(&self, events: &[Arc<Event>]) -> String {
        if events.is_empty() {
            return "No events to summarise.".into();
        }
        if !self.config.enabled {
            return format!("{} event(s) in chain.", events.len());
        }
        let prompt = ContextBuilder::summarise_chain(events);
        self.cached_generate(&prompt, 64).await
    }

    pub async fn investigate(&self, alert: &Alert, events: &[Arc<Event>]) -> String {
        if !self.config.enabled {
            return "Review the process tree and network connections for this alert.".into();
        }
        let prompt = ContextBuilder::investigate(alert, events);
        self.cached_generate(&prompt, 64).await
    }

    async fn cached_generate(&self, prompt: &str, max_cache: usize) -> String {
        // Simple cache: use truncated prompt as key
        let key = &prompt[..std::cmp::min(prompt.len(), 200)];

        {
            let cache = self.cache.lock().await;
            if let Some(cached) = cache.get(key) {
                return cached.clone();
            }
        }

        match self.provider.generate(prompt).await {
            Ok(response) => {
                let cleaned = sanitise(&response);
                let mut cache = self.cache.lock().await;
                if cache.len() >= max_cache {
                    cache.clear();
                }
                cache.insert(key.to_string(), cleaned.clone());
                cleaned
            },
            Err(e) => {
                warn!("AI generation failed: {e}");
                Self::fallback(&Alert::default())
            },
        }
    }

    fn fallback(alert: &Alert) -> String {
        format!(
            "Alert from rule '{}' (risk {}/1000). Review process tree and network \
             connections for this alert to determine if it is a real threat.",
            alert.rule_id, alert.risk_score
        )
    }
}

fn sanitise(response: &str) -> String {
    let s = response
        .trim()
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();
    if s.len() > 2000 {
        format!("{}…", &s[..1997])
    } else {
        s.to_string()
    }
}

// ── Error ──────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum AiError {
    #[error("backend: {0}")]
    Backend(String),
    #[error("timeout")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymise_path() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/test".into());
        let path = format!("{}/.ssh/id_rsa", home);
        let result = anonymise_path(&path);
        assert!(result.starts_with("~/.ssh/"));
    }

    #[test]
    fn test_anonymise_command_redacts_token() {
        let cmd = "curl -H 'Authorization: token=abc123' https://api.example.com";
        let result = anonymise_command(cmd);
        assert!(!result.contains("abc123"));
    }

    #[test]
    fn test_summarise_empty() {
        assert_eq!(ContextBuilder::summarise_events(&[]), "(no related events)");
    }

    #[test]
    fn test_sanitise() {
        assert_eq!(sanitise("```\nHello\n```"), "Hello");
    }
}

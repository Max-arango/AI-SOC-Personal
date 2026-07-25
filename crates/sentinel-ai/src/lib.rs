use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::warn;

use sentinel_core::traits::Alert;
use sentinel_events::Event;

pub mod providers;
pub use providers::{AiProvider, HttpProvider, OllamaProvider};

#[derive(Debug, Clone)]
pub struct AiConfig {
    pub provider: String,
    pub host: String,
    pub port: u16,
    pub model: String,
    pub temperature: f32,
    pub timeout_secs: u64,
    pub enabled: bool,
    pub api_key: Option<String>,
    pub api_base: Option<String>,
}

impl Default for AiConfig {
    fn default() -> Self {
        let provider = std::env::var("SENTINEL_AI_PROVIDER")
            .unwrap_or_else(|_| "ollama".into());
        let api_key = std::env::var("SENTINEL_AI_API_KEY").ok();
        let api_base = std::env::var("SENTINEL_AI_API_BASE").ok();

        let (model, port) = match provider.as_str() {
            "openrouter" => (
                std::env::var("SENTINEL_AI_MODEL")
                    .unwrap_or_else(|_| "openai/gpt-4o-mini".into()),
                443,
            ),
            "openai" => (
                std::env::var("SENTINEL_AI_MODEL")
                    .unwrap_or_else(|_| "gpt-4o-mini".into()),
                443,
            ),
            _ => (
                std::env::var("SENTINEL_AI_MODEL")
                    .unwrap_or_else(|_| "llama3.2:3b".into()),
                11434,
            ),
        };

        Self {
            provider,
            host: std::env::var("SENTINEL_AI_HOST").unwrap_or_else(|_| "localhost".into()),
            port,
            model,
            temperature: 0.3,
            timeout_secs: 60,
            enabled: std::env::var("SENTINEL_AI_ENABLED")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(true),
            api_key,
            api_base,
        }
    }
}

impl AiConfig {
    pub fn create_provider(&self) -> Box<dyn AiProvider> {
        match self.provider.as_str() {
            "openrouter" => Box::new(HttpProvider::for_openrouter(self)),
            "openai" => Box::new(HttpProvider::for_openai(self)),
            _ => Box::new(OllamaProvider::new(self)),
        }
    }
}

pub struct ContextBuilder;

impl ContextBuilder {
    pub fn explain_alert(alert: &Alert, events: &[Arc<Event>]) -> String {
        let summary = Self::summarise_events(events);
        format!(
            "You are a security analyst assistant.\n\n\
             Alert: Rule={} Risk={}/1000 Severity={:?}\n\n\
             Related events:\n{}\n\n\
             Explain in 2-3 sentences: what happened, likely threat, and recommended action.",
            alert.rule_id, alert.risk_score, alert.severity, summary
        )
    }

    pub fn summarise_chain(events: &[Arc<Event>]) -> String {
        format!(
            "Summarise this security event chain:\n\n{}\n\nSummary:",
            Self::summarise_events(events)
        )
    }

    pub fn investigate(alert: &Alert, events: &[Arc<Event>]) -> String {
        format!(
            "Recommend 3-5 investigation steps for: Alert={} (risk={}/1000)\n\n{}\n\nSteps:",
            alert.rule_id, alert.risk_score, Self::summarise_events(events)
        )
    }

    fn summarise_events(events: &[Arc<Event>]) -> String {
        if events.is_empty() {
            return "(no related events)".into();
        }
        events
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let proc = e
                    .process
                    .as_ref()
                    .map(|p| format!(" [{} pid={}]", anonymise_path(&p.name), p.pid))
                    .unwrap_or_default();
                format!("  {}. [{}] {} (sev={}){}", i + 1, e.source, e.r#type, e.severity, proc)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn anonymise_path(s: &str) -> String {
    std::env::var("HOME")
        .map(|home| s.replace(&home, "~"))
        .unwrap_or_else(|_| s.into())
}

pub struct AiEngine {
    provider: Box<dyn AiProvider>,
    config: AiConfig,
    cache: Mutex<HashMap<String, String>>,
}

impl AiEngine {
    pub fn new(config: AiConfig, provider: Box<dyn AiProvider>) -> Self {
        Self {
            provider,
            config,
            cache: Mutex::new(HashMap::new()),
        }
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
        let prompt = ContextBuilder::summarise_chain(events);
        self.cached_generate(&prompt, 64).await
    }

    pub async fn investigate(&self, alert: &Alert, events: &[Arc<Event>]) -> String {
        if !self.config.enabled {
            return "Review the process tree and network connections.".into();
        }
        let prompt = ContextBuilder::investigate(alert, events);
        self.cached_generate(&prompt, 64).await
    }

    async fn cached_generate(&self, prompt: &str, max_cache: usize) -> String {
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
            }
            Err(e) => {
                warn!("AI generation failed: {e}");
                Self::fallback(&Alert::default())
            }
        }
    }

    fn fallback(alert: &Alert) -> String {
        format!(
            "Alert from rule '{}' (risk {}/1000). Review process tree and network connections.",
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
        format!("{}...", &s[..1997])
    } else {
        s.to_string()
    }
}

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
    fn test_summarise_empty() {
        assert_eq!(
            ContextBuilder::summarise_events(&[]),
            "(no related events)"
        );
    }

    #[test]
    fn test_sanitise() {
        assert_eq!(sanitise("```\nHello\n```"), "Hello");
    }
}

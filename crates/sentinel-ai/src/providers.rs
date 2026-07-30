use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{AiConfig, AiError};

#[async_trait]
pub trait AiProvider: Send + Sync {
    async fn generate(&self, prompt: &str) -> Result<String, AiError>;
    async fn is_available(&self) -> bool;
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatMsg,
}

#[derive(Debug, Deserialize)]
struct ChatMsg {
    content: Option<String>,
}

pub struct OllamaProvider {
    ollama: ollama_rs::Ollama,
    config: AiConfig,
}

impl OllamaProvider {
    pub fn new(config: &AiConfig) -> Self {
        Self {
            ollama: ollama_rs::Ollama::builder()
                .host(config.host.clone())
                .port(config.port)
                .build(),
            config: config.clone(),
        }
    }
}

#[async_trait]
impl AiProvider for OllamaProvider {
    async fn generate(&self, prompt: &str) -> Result<String, AiError> {
        use ollama_rs::generation::completion::request::GenerationRequest;
        use ollama_rs::models::ModelOptions;

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
        use ollama_rs::generation::completion::request::GenerationRequest;
        let request = GenerationRequest::new(self.config.model.clone(), "ping".to_string());
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.ollama.generate(request),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
    }
}

pub struct HttpProvider {
    config: AiConfig,
    api_url: String,
}

impl HttpProvider {
    fn new(config: &AiConfig, api_url: String) -> Self {
        Self {
            config: config.clone(),
            api_url,
        }
    }

    pub fn for_openrouter(config: &AiConfig) -> Self {
        let base = config
            .api_base
            .clone()
            .unwrap_or_else(|| "https://openrouter.ai/api/v1".into());
        Self::new(config, format!("{}/chat/completions", base))
    }

    pub fn for_openai(config: &AiConfig) -> Self {
        let base = config
            .api_base
            .clone()
            .unwrap_or_else(|| "https://api.openai.com/v1".into());
        Self::new(config, format!("{}/chat/completions", base))
    }
}

#[async_trait]
impl AiProvider for HttpProvider {
    async fn generate(&self, prompt: &str) -> Result<String, AiError> {
        let api_key = self
            .config
            .api_key
            .as_deref()
            .unwrap_or("missing-api-key");

        let request = ChatRequest {
            model: self.config.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: "You are a helpful security analyst assistant. Be concise.".into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: prompt.into(),
                },
            ],
            temperature: self.config.temperature,
        };

        let client = reqwest::Client::new();
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
            client
                .post(&self.api_url)
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&request)
                .send(),
        )
        .await
        .map_err(|_| AiError::Timeout)?
        .map_err(|e| AiError::Backend(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!("AI API error: HTTP {status}: {body}");
            return Err(AiError::Backend(format!("HTTP {status}")));
        }

        let chat: ChatResponse = resp
            .json()
            .await
            .map_err(|e| AiError::Backend(e.to_string()))?;

        let content = chat
            .choices
            .first()
            .and_then(|c| c.message.content.as_deref())
            .unwrap_or("(empty response)");

        Ok(content.into())
    }

    async fn is_available(&self) -> bool {
        self.config.api_key.is_some()
    }
}

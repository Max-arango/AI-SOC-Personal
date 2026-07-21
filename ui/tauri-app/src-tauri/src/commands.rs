// Tauri command handlers
use tauri::command;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use sentinel_core::Result as CoreResult;

#[command]
async fn greet(name: String) -> String {
    format!("Hello, {}! Welcome to Sentinel AI.", name)
}

#[command]
async fn get_health(state: tauri::State<'_, Arc<crate::state::AppState>>) -> CoreResult<HealthResponse> {
    state.health().await
}

#[command]
async fn get_status(state: tauri::State<'_, Arc<crate::state::AppState>>) -> CoreResult<StatusResponse> {
    state.status().await
}

#[command]
async fn query_events(
    state: tauri::State<'_, Arc<crate::state::AppState>>,
    query: EventQuery,
) -> CoreResult<EventsResponse> {
    state.query_events(query).await
}

#[command]
async fn get_alerts(
    state: tauri::State<'_, Arc<crate::state::AppState>>,
    query: AlertQuery,
) -> CoreResult<AlertsResponse> {
    state.get_alerts(query).await
}

#[command]
async fn get_processes(
    state: tauri::State<'_, Arc<crate::state::AppState>>,
    query: ProcessQuery,
) -> CoreResult<ProcessesResponse> {
    state.get_processes(query).await
}

#[command]
async fn get_network_connections(
    state: tauri::State<'_, Arc<crate::state::AppState>>,
    query: NetworkQuery,
) -> CoreResult<NetworkResponse> {
    state.get_network_connections(query).await
}

#[command]
async fn explain_alert(
    state: tauri::State<'_, Arc<crate::state::AppState>>,
    alert_id: String,
) -> CoreResult<ExplanationResponse> {
    state.explain_alert(alert_id).await
}

#[command]
async fn chat_ai(
    state: tauri::State<'_, Arc<crate::state::AppState>>,
    message: String,
    conversation_id: Option<String>,
) -> CoreResult<ChatResponse> {
    state.chat_ai(message, conversation_id).await
}

#[command]
async fn get_config(state: tauri::State<'_, Arc<crate::state::AppState>>) -> CoreResult<ConfigResponse> {
    state.get_config().await
}

#[command]
async fn update_config(
    state: tauri::State<'_, Arc<crate::state::AppState>>,
    config: serde_json::Value,
) -> CoreResult<ConfigResponse> {
    state.update_config(config).await
}

// Request/Response types
#[derive(Debug, Deserialize)]
pub struct EventQuery {
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub event_types: Option<Vec<String>>,
    pub sources: Option<Vec<String>>,
    pub min_risk_score: Option<u32>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct EventsResponse {
    pub events: Vec<serde_json::Value>,
    pub total_count: u64,
    pub has_more: bool,
}

#[derive(Debug, Deserialize)]
pub struct AlertQuery {
    pub state: Option<String>,
    pub min_severity: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct AlertsResponse {
    pub alerts: Vec<serde_json::Value>,
    pub total_count: u64,
}

#[derive(Debug, Deserialize)]
pub struct ProcessQuery {
    pub filter: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ProcessesResponse {
    pub processes: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct NetworkQuery {
    pub active_only: Option<bool>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct NetworkResponse {
    pub connections: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub components: serde_json::Value,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub state: String,
    pub uptime: String,
    pub resources: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ExplanationResponse {
    pub explanation: String,
    pub risk_level: String,
    pub immediate_actions: Vec<String>,
    pub investigation_steps: Vec<String>,
    pub prevention_recommendations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ChatResponse {
    pub response: String,
    pub conversation_id: String,
}

#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub config_toml: String,
    pub version: u64,
}
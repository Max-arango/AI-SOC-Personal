use tauri::command;
use serde::{Deserialize, Serialize};
use tauri_plugin_notification::NotificationExt;

type CmdResult<T> = Result<T, String>;

#[command]
pub async fn get_health(state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>) -> CmdResult<HealthResponse> {
    state.health_check().await
}

#[command]
pub async fn get_status(state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>) -> CmdResult<StatusResponse> {
    state.get_status().await
}

#[command]
pub async fn query_events(
    state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>,
    query: EventQuery,
) -> CmdResult<EventsResponse> {
    state.query_events(query).await
}

#[command]
pub async fn get_alerts(
    state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>,
    query: AlertQuery,
) -> CmdResult<AlertsResponse> {
    state.get_alerts(query).await
}

#[command]
pub async fn get_processes(
    state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>,
    query: ProcessQuery,
) -> CmdResult<ProcessesResponse> {
    state.get_processes(query).await
}

#[command]
pub async fn get_network_connections(
    state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>,
    query: NetworkQuery,
) -> CmdResult<NetworkResponse> {
    state.get_network_connections(query).await
}

#[command]
pub async fn explain_alert(
    state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>,
    alert_id: String,
) -> CmdResult<ExplanationResponse> {
    state.explain_alert(alert_id).await
}

#[command]
pub async fn chat_ai(
    state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>,
    message: String,
    conversation_id: Option<String>,
) -> CmdResult<ChatResponse> {
    state.chat_ai(message, conversation_id).await
}

#[command]
pub async fn get_config(state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>) -> CmdResult<ConfigResponse> {
    state.get_config().await
}

#[command]
pub async fn update_config(
    state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>,
    config: serde_json::Value,
) -> CmdResult<ConfigResponse> {
    state.update_config(config).await
}

#[command]
pub async fn get_process_tree(
    state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>,
) -> CmdResult<ProcessTreeResponse> {
    state.get_process_tree().await
}

#[command]
pub async fn get_risk_timeline(
    state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>,
    hours: Option<u32>,
) -> CmdResult<RiskTimelineResponse> {
    state.get_risk_timeline(hours).await
}

#[command]
pub async fn get_mitre_heatmap(
    state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>,
) -> CmdResult<MitreHeatmapResponse> {
    state.get_mitre_heatmap().await
}

#[command]
pub async fn get_network_graph(
    state: tauri::State<'_, std::sync::Arc<crate::state::AppState>>,
) -> CmdResult<NetworkGraphResponse> {
    state.get_network_graph().await
}

#[command]
pub async fn show_notification(
    app: tauri::AppHandle,
    title: String,
    body: String,
) -> CmdResult<()> {
    app.notification()
        .builder()
        .title(title)
        .body(body)
        .show()
        .map_err(|e| e.to_string())?;
    Ok(())
}

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

#[derive(Debug, Serialize)]
pub struct ProcessTreeResponse {
    pub tree: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct RiskTimelineResponse {
    pub points: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct MitreHeatmapResponse {
    pub tactics: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct NetworkGraphResponse {
    pub nodes: Vec<serde_json::Value>,
    pub edges: Vec<serde_json::Value>,
}

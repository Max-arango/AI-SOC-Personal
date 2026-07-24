import { invoke } from '@tauri-apps/api/core';

export interface HealthResponse {
  status: string;
  components: Record<string, string>;
  timestamp: string;
}

export interface StatusResponse {
  state: string;
  uptime: string;
  resources: {
    cpu_percent: number;
    memory_bytes: number;
    event_queue_depth: number;
  };
}

export interface EventQuery {
  start_time?: string;
  end_time?: string;
  event_types?: string[];
  sources?: string[];
  min_risk_score?: number;
  limit?: number;
  offset?: number;
}

export interface EventsResponse {
  events: Record<string, unknown>[];
  total_count: number;
  has_more: boolean;
}

export interface AlertQuery {
  state?: string;
  min_severity?: string;
  limit?: number;
}

export interface AlertItem {
  id: string;
  rule_id: string;
  risk_score: number;
  severity: string;
  state: string;
  created_at: string;
  updated_at: string;
  ai_summary?: string;
  context?: Record<string, unknown>;
}

export interface AlertsResponse {
  alerts: AlertItem[];
  total_count: number;
}

export interface ProcessQuery {
  filter?: string;
  limit?: number;
}

export interface ProcessInfo {
  pid: number;
  ppid?: number;
  name: string;
  exe?: string;
  cmd?: string;
  cpu_usage: number;
  memory_bytes: number;
  user_id?: string;
  start_time?: number;
}

export interface ProcessesResponse {
  processes: ProcessInfo[];
}

export interface NetworkQuery {
  active_only?: boolean;
  limit?: number;
}

export interface NetworkResponse {
  connections: unknown[];
}

export interface ExplanationResponse {
  explanation: string;
  risk_level: string;
  immediate_actions: string[];
  investigation_steps: string[];
  prevention_recommendations: string[];
}

export interface ChatResponse {
  response: string;
  conversation_id: string;
}

export interface ConfigResponse {
  config_toml: string;
  version: number;
}

export async function getHealth(): Promise<HealthResponse> {
  return invoke<HealthResponse>('get_health');
}

export async function getStatus(): Promise<StatusResponse> {
  return invoke<StatusResponse>('get_status');
}

export async function queryEvents(query: EventQuery): Promise<EventsResponse> {
  return invoke<EventsResponse>('query_events', { query });
}

export async function getAlerts(query: AlertQuery): Promise<AlertsResponse> {
  return invoke<AlertsResponse>('get_alerts', { query });
}

export async function getProcesses(query: ProcessQuery): Promise<ProcessesResponse> {
  return invoke<ProcessesResponse>('get_processes', { query });
}

export async function getNetworkConnections(query: NetworkQuery): Promise<NetworkResponse> {
  return invoke<NetworkResponse>('get_network_connections', { query });
}

export async function explainAlert(alertId: string): Promise<ExplanationResponse> {
  return invoke<ExplanationResponse>('explain_alert', { alertId });
}

export async function chatAi(message: string, conversationId?: string): Promise<ChatResponse> {
  return invoke<ChatResponse>('chat_ai', {
    message,
    conversationId: conversationId ?? null,
  });
}

export async function getConfig(): Promise<ConfigResponse> {
  return invoke<ConfigResponse>('get_config');
}

export async function updateConfig(config: unknown): Promise<ConfigResponse> {
  return invoke<ConfigResponse>('update_config', { config });
}

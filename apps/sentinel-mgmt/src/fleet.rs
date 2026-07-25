use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;

#[derive(Debug, Clone)]
pub struct RegisteredAgent {
    pub host_id: String,
    pub hostname: String,
    pub os: String,
    pub version: String,
    pub last_heartbeat: DateTime<Utc>,
    pub status: AgentStatus,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentStatus {
    Online,
    Degraded,
    Offline,
    Unknown,
}

impl AgentStatus {
    fn from_heartbeat_age(age_secs: i64) -> Self {
        match age_secs {
            ..=30 => AgentStatus::Online,
            31..=120 => AgentStatus::Degraded,
            _ => AgentStatus::Offline,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FleetState {
    pub agents: Vec<RegisteredAgent>,
    pub total_events: u64,
    pub total_alerts: u64,
    pub active_threats: u64,
}

pub struct FleetManager {
    agents: RwLock<HashMap<String, RegisteredAgent>>,
}

impl FleetManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            agents: RwLock::new(HashMap::new()),
        })
    }

    pub fn register(&self, agent: RegisteredAgent) {
        self.agents.write().insert(agent.host_id.clone(), agent);
    }

    pub fn heartbeat(&self, host_id: &str) -> bool {
        let mut agents = self.agents.write();
        if let Some(agent) = agents.get_mut(host_id) {
            agent.last_heartbeat = Utc::now();
            agent.status = AgentStatus::Online;
            true
        } else {
            false
        }
    }

    pub fn fleet_state(&self) -> FleetState {
        let agents = self.agents.read();
        let now = Utc::now();
        let agent_list: Vec<RegisteredAgent> = agents
            .values()
            .map(|a| {
                let age = (now - a.last_heartbeat).num_seconds();
                let mut agent = a.clone();
                agent.status = AgentStatus::from_heartbeat_age(age);
                agent
            })
            .collect();

        FleetState {
            agents: agent_list,
            total_events: 0,
            total_alerts: 0,
            active_threats: 0,
        }
    }

    pub fn online_count(&self) -> usize {
        self.fleet_state()
            .agents
            .iter()
            .filter(|a| a.status == AgentStatus::Online)
            .count()
    }
}

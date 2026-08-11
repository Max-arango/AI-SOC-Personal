use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseTier {
    T1Auto,
    T2Confirm,
    T3Quorum,
    T4BreakGlass,
}

impl ResponseTier {
    pub fn requires_human(&self) -> bool {
        matches!(
            self,
            ResponseTier::T2Confirm | ResponseTier::T3Quorum | ResponseTier::T4BreakGlass
        )
    }

    pub fn confirmation_count(&self) -> usize {
        match self {
            ResponseTier::T1Auto => 0,
            ResponseTier::T2Confirm => 1,
            ResponseTier::T3Quorum => 2,
            ResponseTier::T4BreakGlass => 1,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            ResponseTier::T1Auto => "Automatic — no confirmation required",
            ResponseTier::T2Confirm => "Requires 1 admin confirmation",
            ResponseTier::T3Quorum => "Requires 2+ admin confirmations",
            ResponseTier::T4BreakGlass => "Emergency — 1 admin with justification",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdrAction {
    KillProcess {
        pid: u32,
    },
    QuarantineFile {
        path: String,
        hash: Option<String>,
    },
    BlockNetwork {
        ip: String,
        port: Option<u16>,
    },
    IsolateHost {
        auto_revert_seconds: u64,
    },
    CollectSnapshot,
    RemoteShell {
        duration_seconds: u64,
    },
    NotifyAll {
        channels: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrCommand {
    pub id: String,
    pub action: EdrAction,
    pub tier: ResponseTier,
    pub triggered_by: String,
    pub host_id: String,
    pub reason: String,
    pub confirmations: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub executed: bool,
}

impl EdrCommand {
    pub fn new(
        action: EdrAction,
        tier: ResponseTier,
        triggered_by: &str,
        host_id: &str,
        reason: &str,
    ) -> Self {
        let now = chrono::Utc::now();
        let timeout = match tier {
            ResponseTier::T1Auto => 60,
            ResponseTier::T2Confirm => 300,
            ResponseTier::T3Quorum => 600,
            ResponseTier::T4BreakGlass => 1800,
        };

        Self {
            id: crate::Ulid::new().to_string(),
            action,
            tier,
            triggered_by: triggered_by.into(),
            host_id: host_id.into(),
            reason: reason.into(),
            confirmations: vec![],
            created_at: now,
            expires_at: now + chrono::Duration::seconds(timeout),
            executed: false,
        }
    }

    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    pub fn confirm(&mut self, username: &str) {
        if !self.confirmations.contains(&username.to_string()) {
            self.confirmations.push(username.to_string());
        }
    }

    pub fn is_confirmed(&self) -> bool {
        self.confirmations.len() >= self.tier.confirmation_count()
    }

    pub fn requires_confirmation(&self) -> bool {
        self.tier.requires_human()
    }
}

pub struct ResponseEngine {
    pending: parking_lot::RwLock<Vec<EdrCommand>>,
    executed: parking_lot::RwLock<Vec<EdrCommand>>,
}

impl ResponseEngine {
    pub fn new() -> Self {
        Self {
            pending: parking_lot::RwLock::new(Vec::new()),
            executed: parking_lot::RwLock::new(Vec::new()),
        }
    }

    pub fn enqueue(&self, command: EdrCommand) -> String {
        let id = command.id.clone();
        self.pending.write().push(command);
        id
    }

    pub fn confirm(&self, command_id: &str, username: &str) -> Option<EdrCommand> {
        let mut pending = self.pending.write();
        if let Some(cmd) = pending.iter_mut().find(|c| c.id == command_id) {
            cmd.confirm(username);
            if cmd.is_confirmed() && !cmd.requires_confirmation() {
                return Some(cmd.clone());
            }
            if cmd.is_confirmed() {
                let cmd = cmd.clone();
                pending.retain(|c| c.id != command_id);
                return Some(cmd);
            }
        }
        None
    }

    pub fn expire_pending(&self) -> Vec<EdrCommand> {
        let mut pending = self.pending.write();
        let (expired, active): (Vec<_>, Vec<_>) = pending.drain(..).partition(|c| c.is_expired());
        *pending = active;
        expired
    }

    pub fn pending_commands(&self) -> Vec<EdrCommand> {
        self.pending.read().clone()
    }

    pub fn execute(&self, command: EdrCommand) {
        self.executed.write().push(command);
    }
}

impl Default for ResponseEngine {
    fn default() -> Self {
        Self::new()
    }
}

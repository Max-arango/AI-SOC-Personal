//! Sentinel AI Correlation Engine
//!
//! Tracks causal process chains, temporal event windows and data flows
//! across related events. Uses the existing `correlation_chains` and
//! `chain_events` tables from the SQLite migrations.
//!
//! - **Causal**: links events by process parent→child (PID/PPID)
//! - **Temporal**: groups events within a sliding time window
//! - **Flow**: tracks objects (files, registries) across operations

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use sentinel_core::Ulid;
use sentinel_events::Event;
use tracing::info;

// ── Configuration ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Causal chain: maximum age before a chain without new events expires.
    pub chain_timeout_secs: u64,
    /// Temporal window: events within this window of each other are grouped.
    pub temporal_window_secs: u64,
    /// Flow TTL: how long a flow object is tracked after last access.
    pub flow_ttl_secs: u64,
    /// Maximum events per chain before pruning oldest.
    pub max_events_per_chain: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            chain_timeout_secs: 600,   // 10 min
            temporal_window_secs: 300, // 5 min
            flow_ttl_secs: 172800,     // 48 h
            max_events_per_chain: 500,
        }
    }
}

// ── Chain representation ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CorrelationChain {
    pub id: String,
    pub started_at: Instant,
    pub last_event_at: Instant,
    pub events: Vec<Arc<Event>>,
    pub risk_score: u32,
    pub host_id: String,
    /// Process IDs that are part of this chain.
    pub pids: Vec<u32>,
}

impl CorrelationChain {
    pub fn new(event: &Event) -> Self {
        let mut chain = Self {
            id: Ulid::new().to_string(),
            started_at: Instant::now(),
            last_event_at: Instant::now(),
            events: Vec::new(),
            risk_score: 0,
            host_id: event.host_id.clone(),
            pids: Vec::new(),
        };
        chain.add_event(event);
        chain
    }

    pub fn add_event(&mut self, event: &Event) {
        if let Some(ref proc) = event.process {
            self.pids.push(proc.pid);
        }
        self.events.push(Arc::new(event.clone()));
        self.last_event_at = Instant::now();
        if self.events.len() > 500 {
            self.events.remove(0);
        }
    }

    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_event_at.elapsed() > timeout
    }
}

// ── Correlation Engine ─────────────────────────────────────────────

pub struct CorrelationEngine {
    config: CorrelationConfig,
    /// pid → chain_id for causal linking
    pid_index: RwLock<HashMap<u32, String>>,
    /// chain_id → CorrelationChain
    chains: RwLock<HashMap<String, CorrelationChain>>,
    /// Latest event per source for temporal grouping (source → (timestamp, chain_id))
    temporal_index: RwLock<HashMap<String, (Instant, String)>>,
    /// Flow tracking: flow_id → (path/hash, last_access)
    flows: RwLock<HashMap<String, (String, Instant)>>,
}

impl CorrelationEngine {
    pub fn new(config: CorrelationConfig) -> Self {
        Self {
            config,
            pid_index: RwLock::new(HashMap::new()),
            chains: RwLock::new(HashMap::new()),
            temporal_index: RwLock::new(HashMap::new()),
            flows: RwLock::new(HashMap::new()),
        }
    }

    /// Ingest an event and return the correlation chain it was assigned to
    /// (existing or newly created).
    pub fn ingest(&self, event: &Event) -> CorrelationChain {
        // 1 — Try causal linking (same PID or PPID)
        if let Some(ref proc) = event.process {
            // Check if this PID already belongs to a chain
            let chain_found = {
                let index = self.pid_index.read();
                index.get(&proc.pid).cloned()
            };

            if let Some(chain_id) = chain_found {
                let mut chains = self.chains.write();
                if let Some(chain) = chains.get_mut(&chain_id) {
                    chain.add_event(event);
                    // Also index the parent PID if available
                    if proc.ppid > 0 {
                        self.pid_index.write().insert(proc.ppid, chain_id.clone());
                    }
                    return chain.clone();
                }
            }

            // Check if parent PID belongs to any chain (causal link)
            if proc.ppid > 0 {
                let parent_chain = {
                    let index = self.pid_index.read();
                    index.get(&proc.ppid).cloned()
                };

                if let Some(chain_id) = parent_chain {
                    // Link child process to parent's chain
                    self.pid_index.write().insert(proc.pid, chain_id.clone());
                    let mut chains = self.chains.write();
                    if let Some(chain) = chains.get_mut(&chain_id) {
                        chain.add_event(event);
                        return chain.clone();
                    }
                }
            }
        }

        // 2 — Try temporal grouping (same source, close in time)
        let source = &event.source;
        let temporal_match = {
            let index = self.temporal_index.read();
            index.get(source).cloned()
        };

        if let Some((last_time, chain_id)) = temporal_match {
            if last_time.elapsed() < Duration::from_secs(self.config.temporal_window_secs) {
                let mut chains = self.chains.write();
                if let Some(chain) = chains.get_mut(&chain_id) {
                    chain.add_event(event);
                    self.temporal_index
                        .write()
                        .insert(source.clone(), (Instant::now(), chain_id.clone()));
                    return chain.clone();
                }
            }
        }

        // 3 — No match: create new chain
        let chain = CorrelationChain::new(event);
        let chain_id = chain.id.clone();

        if let Some(ref proc) = event.process {
            self.pid_index.write().insert(proc.pid, chain_id.clone());
            if proc.ppid > 0 {
                self.pid_index.write().insert(proc.ppid, chain_id.clone());
            }
        }

        self.temporal_index
            .write()
            .insert(source.clone(), (Instant::now(), chain_id.clone()));

        self.chains.write().insert(chain_id.clone(), chain.clone());

        info!(
            "New correlation chain {} (pid={:?})",
            chain_id,
            event.process.as_ref().map(|p| p.pid)
        );

        chain
    }

    /// Get a clone of all active chains and prune expired ones.
    pub fn active_chains(&self) -> Vec<CorrelationChain> {
        self.prune();
        let chains = self.chains.read();
        chains.values().cloned().collect()
    }

    /// Prune expired chains.
    pub fn prune(&self) {
        let timeout = Duration::from_secs(self.config.chain_timeout_secs);
        let mut chains = self.chains.write();
        let mut pid_index = self.pid_index.write();
        let mut temporal = self.temporal_index.write();

        let expired: Vec<String> = chains
            .iter()
            .filter(|(_, c)| c.is_expired(timeout))
            .map(|(id, _)| id.clone())
            .collect();

        for id in &expired {
            if let Some(chain) = chains.remove(id) {
                for pid in &chain.pids {
                    pid_index.remove(pid);
                }
            }
            temporal.retain(|_, (_, cid)| cid != id);
        }

        if !expired.is_empty() {
            info!("Pruned {} expired correlation chains", expired.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(r#type: &str, source: &str, pid: u32, ppid: u32) -> Event {
        Event {
            id: "ev-1".into(),
            r#type: r#type.into(),
            source: source.into(),
            severity: 3,
            risk_score: 50,
            host_id: "host-1".into(),
            schema_version: 1,
            process: Some(sentinel_events::ProcessContext {
                pid,
                ppid,
                name: "test.exe".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_causal_chain_parent_child() {
        let engine = CorrelationEngine::new(CorrelationConfig::default());
        let parent = make_event("sentinel.process.create", "process", 100, 0);
        let child = make_event("sentinel.process.create", "process", 200, 100);

        let chain1 = engine.ingest(&parent);
        assert_eq!(chain1.pids, vec![100]);
        let chain_id = chain1.id;

        let chain2 = engine.ingest(&child);
        assert_eq!(chain2.id, chain_id, "child should join parent's chain");
        assert_eq!(chain2.pids, vec![100, 200]);
    }

    #[test]
    fn test_temporal_grouping() {
        let engine = CorrelationEngine::new(CorrelationConfig::default());
        let e1 = make_event("sentinel.file.write", "file", 0, 0);
        let e2 = make_event("sentinel.file.modify", "file", 0, 0);

        let c1 = engine.ingest(&e1);
        let c2 = engine.ingest(&e2);
        assert_eq!(c1.id, c2.id, "same-source events should group temporally");
    }
}

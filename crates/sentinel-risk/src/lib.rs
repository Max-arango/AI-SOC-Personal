//! Sentinel AI Risk Engine
//!
//! SIEM-grade risk scoring with temporal decay, configurable thresholds,
//! alert generation, deduplication, and anti-flapping.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use tracing::{debug, info};

// ── Configuration ──────────────────────────────────────────────────

/// Risk engine configuration.
#[derive(Debug, Clone)]
pub struct RiskConfig {
    /// Half-life durations per severity level (in seconds).
    pub half_lives: HashMap<String, u64>,
    /// Alert thresholds for risk scores.
    pub thresholds: RiskThresholds,
    /// Dedup window in seconds. Alerts for the same rule+source within
    /// this window are suppressed.
    pub dedup_window_secs: u64,
    /// Anti-flapping: maximum alerts per rule per hour before suppression.
    pub flapping_max_per_hour: usize,
    /// Default asset criticality multiplier when no asset info is present.
    pub default_asset_multiplier: f64,
}

/// Risk-score thresholds for alert generation.
#[derive(Debug, Clone)]
pub struct RiskThresholds {
    pub low: u32,
    pub medium: u32,
    pub high: u32,
    pub critical: u32,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            half_lives: {
                let mut m = HashMap::new();
                m.insert("Debug".into(), 600);
                m.insert("Info".into(), 1800);
                m.insert("Notice".into(), 1200);
                m.insert("Warning".into(), 900);
                m.insert("Error".into(), 600);
                m.insert("Critical".into(), 300);
                m.insert("Alert".into(), 120);
                m.insert("Emergency".into(), 60);
                m
            },
            thresholds: RiskThresholds { low: 100, medium: 300, high: 600, critical: 900 },
            dedup_window_secs: 300,
            flapping_max_per_hour: 10,
            default_asset_multiplier: 1.0,
        }
    }
}

// ── Alert severity ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub fn from_score(score: u32, thresholds: &RiskThresholds) -> Self {
        if score >= thresholds.critical {
            AlertSeverity::Critical
        } else if score >= thresholds.high {
            AlertSeverity::High
        } else if score >= thresholds.medium {
            AlertSeverity::Medium
        } else {
            AlertSeverity::Low
        }
    }
}

// ── Alert ──────────────────────────────────────────────────────────

/// A generated alert from the risk engine.
#[derive(Debug, Clone)]
pub struct RiskAlert {
    pub rule_id: String,
    pub rule_name: String,
    pub risk_score: u32,
    pub severity: AlertSeverity,
    pub source: String,
    pub event_ids: Vec<String>,
    pub correlation_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub summary: String,
}

// ── Dedup / anti-flapping state ────────────────────────────────────

#[derive(Debug)]
struct DedupEntry {
    last_alert_at: Instant,
}

#[derive(Debug)]
struct FlappingEntry {
    alert_timestamps: Vec<Instant>,
}

// ── Risk Engine ────────────────────────────────────────────────────

/// The risk engine: scores events, applies decay, deduplicates alerts
/// and suppresses flapping.
pub struct RiskEngine {
    config: RiskConfig,
    /// Dedup key: "rule_id:source" → last alert time
    dedup_state: RwLock<HashMap<String, DedupEntry>>,
    /// Flapping key: "rule_id" → recent alert timestamps
    flapping_state: RwLock<HashMap<String, FlappingEntry>>,
    /// Active risk scores per correlation chain (chain_id → (score, last_update))
    scores: RwLock<HashMap<String, (u32, Instant)>>,
}

impl RiskEngine {
    pub fn new(config: RiskConfig) -> Self {
        Self {
            config,
            dedup_state: RwLock::new(HashMap::new()),
            flapping_state: RwLock::new(HashMap::new()),
            scores: RwLock::new(HashMap::new()),
        }
    }

    /// Apply temporal decay to a risk score.
    ///
    /// `decay(score, elapsed_secs, half_life_secs)` =
    ///   score * 0.5 ^ (elapsed_secs / half_life_secs)
    pub fn decay(&self, score: u32, elapsed_secs: u64, half_life_secs: u64) -> u32 {
        if half_life_secs == 0 {
            return score;
        }
        let factor = 0.5f64.powf(elapsed_secs as f64 / half_life_secs as f64);
        (score as f64 * factor) as u32
    }

    /// Calculate the final risk score for a matched rule event, applying
    /// context multipliers and existing chain decay.
    pub fn calculate(
        &self,
        base_score: u32,
        severity_label: &str,
        asset_mult: f64,
        chain_id: Option<&str>,
    ) -> u32 {
        let half_life = self
            .config
            .half_lives
            .get(severity_label)
            .copied()
            .unwrap_or(1800);

        let chain_adjusted = if let Some(cid) = chain_id {
            let scores = self.scores.read();
            if let Some(&(stored_score, stored_at)) = scores.get(cid) {
                let elapsed = stored_at.elapsed().as_secs();
                let decayed = self.decay(stored_score, elapsed, half_life);
                let cumulative = decayed.saturating_add(base_score).min(1000);
                drop(scores);
                self.scores
                    .write()
                    .insert(cid.to_string(), (cumulative, Instant::now()));
                cumulative
            } else {
                drop(scores);
                self.scores
                    .write()
                    .insert(cid.to_string(), (base_score, Instant::now()));
                base_score
            }
        } else {
            base_score
        };

        let with_asset = (chain_adjusted as f64 * asset_mult).min(1000.0) as u32;

        with_asset
    }

    /// Check whether an alert for this rule+source should be generated.
    /// Returns `None` if deduplicated or suppressed by flapping.
    pub fn should_alert(
        &self,
        rule_id: &str,
        rule_name: &str,
        score: u32,
        source: &str,
        event_ids: Vec<String>,
        correlation_id: Option<String>,
    ) -> Option<RiskAlert> {
        let severity = AlertSeverity::from_score(score, &self.config.thresholds);
        if severity == AlertSeverity::Low {
            return None; // below-alert threshold
        }

        // Dedup check
        let dedup_key = format!("{}:{}", rule_id, source);
        {
            let dedup = self.dedup_state.read();
            if let Some(entry) = dedup.get(&dedup_key) {
                if entry.last_alert_at.elapsed()
                    < Duration::from_secs(self.config.dedup_window_secs)
                {
                    debug!("Deduplicated alert for {}", rule_id);
                    return None;
                }
            }
        }

        // Flapping check
        {
            let mut flap = self.flapping_state.write();
            let entry = flap
                .entry(rule_id.to_string())
                .or_insert(FlappingEntry { alert_timestamps: Vec::new() });
            let cutoff = Instant::now() - Duration::from_secs(3600);
            entry.alert_timestamps.retain(|t| *t >= cutoff);
            if entry.alert_timestamps.len() >= self.config.flapping_max_per_hour {
                debug!("Suppressed flapping alert for {}", rule_id);
                return None;
            }
            entry.alert_timestamps.push(Instant::now());
        }

        // Record dedup entry
        self.dedup_state
            .write()
            .insert(dedup_key, DedupEntry { last_alert_at: Instant::now() });

        let summary = format!("{} detected (score={}, severity={:?})", rule_name, score, severity);

        info!("Alert generated: {} (score={}, {:?})", rule_id, score, severity);

        Some(RiskAlert {
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            risk_score: score,
            severity,
            source: source.into(),
            event_ids,
            correlation_id,
            created_at: Utc::now(),
            summary,
        })
    }

    /// Purge expired internal state.
    pub fn prune(&self) {
        let mut scores = self.scores.write();
        scores.retain(|_, (_, at)| at.elapsed().as_secs() < 86400);
        let mut dedup = self.dedup_state.write();
        dedup
            .retain(|_, e| e.last_alert_at.elapsed().as_secs() < self.config.dedup_window_secs * 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decay_halflife() {
        let engine = RiskEngine::new(RiskConfig::default());
        let decayed = engine.decay(100, 600, 600); // exactly 1 half-life
        assert_eq!(decayed, 50);
    }

    #[test]
    fn test_decay_no_time() {
        let engine = RiskEngine::new(RiskConfig::default());
        assert_eq!(engine.decay(100, 0, 600), 100);
    }

    #[test]
    fn test_threshold_low() {
        let score = 50;
        let sev = AlertSeverity::from_score(
            score,
            &RiskThresholds { low: 100, medium: 300, high: 600, critical: 900 },
        );
        assert_eq!(sev, AlertSeverity::Low);
    }

    #[test]
    fn test_threshold_critical() {
        let sev = AlertSeverity::from_score(
            950,
            &RiskThresholds { low: 100, medium: 300, high: 600, critical: 900 },
        );
        assert_eq!(sev, AlertSeverity::Critical);
    }

    #[test]
    fn test_calculate_cumulative() {
        let engine = RiskEngine::new(RiskConfig::default());
        let s1 = engine.calculate(50, "Warning", 1.0, Some("chain-1"));
        assert_eq!(s1, 50);
        let s2 = engine.calculate(30, "Warning", 1.0, Some("chain-1"));
        assert_eq!(s2, 80);
    }

    #[test]
    fn test_should_alert_below_threshold() {
        let engine = RiskEngine::new(RiskConfig::default());
        assert!(engine
            .should_alert("r1", "test", 50, "src", vec![], None)
            .is_none());
    }

    #[test]
    fn test_should_alert_generates() {
        let engine = RiskEngine::new(RiskConfig::default());
        let alert = engine.should_alert("r1", "Test Rule", 700, "src", vec!["ev1".into()], None);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, AlertSeverity::High);
    }

    #[test]
    fn test_dedup_suppresses_second() {
        let engine = RiskEngine::new(RiskConfig::default());
        let a1 = engine.should_alert("r1", "T", 500, "s", vec![], None);
        assert!(a1.is_some());
        let a2 = engine.should_alert("r1", "T", 500, "s", vec![], None);
        assert!(a2.is_none()); // deduplicated
    }
}

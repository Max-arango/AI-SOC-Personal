//! Sentinel AI Rule Engine
//!
//! CEL-based rule evaluation with hot-reload support

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use notify::{Event as NotifyEvent, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use sentinel_core::traits::Rule;
use sentinel_config::RuleEngineConfig;
use sentinel_events::Event;

/// Rule engine for evaluating CEL expressions against events
#[allow(dead_code)]
pub struct RuleEngine {
    config: ArcSwap<RuleEngineConfig>,
    rules: ArcSwap<HashMap<String, CompiledRule>>,
    evaluator_pool: EvaluatorPool,
    suppression_engine: SuppressionEngine,
    action_executor: ActionExecutor,
    metrics: Arc<RuleEngineMetrics>,
    reload_tx: watch::Sender<()>,
    shutdown_tx: watch::Sender<()>,
}

impl RuleEngine {
    /// Create new rule engine
    pub async fn new(config: &RuleEngineConfig) -> Result<Self> {
        let evaluator_pool = EvaluatorPool::new(config.worker_threads);
        let suppression_engine = SuppressionEngine::new();
        let action_executor = ActionExecutor::new();
        let metrics = Arc::new(RuleEngineMetrics::new());
        
        let (reload_tx, _reload_rx) = watch::channel(());
        let (shutdown_tx, _shutdown_rx) = watch::channel(());
        
        let engine = Self {
            config: ArcSwap::new(Arc::new(config.clone())),
            rules: ArcSwap::new(Arc::new(HashMap::new())),
            evaluator_pool,
            suppression_engine,
            action_executor,
            metrics,
            reload_tx,
            shutdown_tx,
        };
        
        // Load initial rules
        engine.load_rules(&config.rules_directories).await?;
        
        // Start hot-reload watcher
        if config.hot_reload {
            engine.start_watcher(&config.rules_directories).await?;
        }
        
        Ok(engine)
    }
    
    /// Load rules from directories
    pub async fn load_rules(&self, directories: &[String]) -> Result<()> {
        let mut compiled_rules = HashMap::new();
        let mut errors = Vec::new();
        
        for dir in directories {
            let path = Path::new(dir);
            if !path.exists() {
                warn!("Rules directory does not exist: {}", path.display());
                continue;
            }
            
            let mut entries = tokio::fs::read_dir(path).await
                .context("Failed to read rules directory")?;
            
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yaml") ||
                   path.extension().and_then(|s| s.to_str()) == Some("yml") {
                    match self.load_rule_file(&path).await {
                        Ok(rule) => {
                            compiled_rules.insert(rule.rule.id.clone(), rule);
                        }
                        Err(e) => {
                            error!("Failed to load rule {}: {}", path.display(), e);
                            errors.push(e.to_string());
                        }
                    }
                }
            }
        }
        
        if !errors.is_empty() && compiled_rules.is_empty() {
            return Err(anyhow::anyhow!("Failed to load any rules: {}", errors.join(", ")));
        }
        
        info!("Loaded {} rules", compiled_rules.len());
        let loaded = compiled_rules.len() as u64;
        self.rules.store(Arc::new(compiled_rules));
        self.metrics.rules_loaded.store(loaded, std::sync::atomic::Ordering::Relaxed);
        self.metrics.rules_enabled.store(
            self.rules.load().values().filter(|r| r.rule.enabled).count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        
        Ok(())
    }
    
    /// Load a single rule file
    async fn load_rule_file(&self, path: &Path) -> Result<CompiledRule> {
        let content = tokio::fs::read_to_string(path).await
            .context("Failed to read rule file")?;

        // Documented rule files wrap the rule under a top-level `rule:` key;
        // tolerate the flat form as well for backwards compatibility.
        #[derive(serde::Deserialize)]
        struct RuleFile {
            rule: Rule,
        }

        let rule: Rule = serde_yaml::from_str::<RuleFile>(&content)
            .map(|f| f.rule)
            .or_else(|_| serde_yaml::from_str::<Rule>(&content))
            .context("Failed to parse rule YAML")?;
        
        // Validate rule
        if rule.id.is_empty() {
            return Err(anyhow::anyhow!("Rule ID is required"));
        }
        if rule.condition.is_empty() {
            return Err(anyhow::anyhow!("Rule condition is required"));
        }
        
        // Compile CEL expression
        let start = Instant::now();
        let program = Arc::new(cel::Program::compile(&rule.condition)
            .map_err(|e| anyhow::anyhow!("Failed to compile CEL expression: {:?}", e))?);
        
        let compile_time = start.elapsed();
        debug!("Compiled rule {} in {:?}", rule.id, compile_time);
        
        // Compile additional conditions
        let mut and_programs = Vec::new();
        for cond in &rule.and_conditions {
            let program = Arc::new(cel::Program::compile(cond)
                .map_err(|e| anyhow::anyhow!("Failed to compile AND condition: {:?}", e))?);
            and_programs.push(program);
        }
        
        let mut or_programs = Vec::new();
        for cond in &rule.or_conditions {
            let program = Arc::new(cel::Program::compile(cond)
                .map_err(|e| anyhow::anyhow!("Failed to compile OR condition: {:?}", e))?);
            or_programs.push(program);
        }
        
        let mut not_programs = Vec::new();
        for cond in &rule.not_conditions {
            let program = Arc::new(cel::Program::compile(cond)
                .map_err(|e| anyhow::anyhow!("Failed to compile NOT condition: {:?}", e))?);
            not_programs.push(program);
        }
        
        // Compile risk multipliers
        let mut multiplier_programs = Vec::new();
        for mult in &rule.risk.multipliers {
            let program = Arc::new(cel::Program::compile(&mult.condition)
                .map_err(|e| anyhow::anyhow!("Failed to compile risk multiplier: {:?}", e))?);
            multiplier_programs.push((program, mult.factor));
        }
        
        // Compile suppressions
        let mut suppression_programs = Vec::new();
        for supp in &rule.suppressions {
            let program = Arc::new(cel::Program::compile(&supp.condition)
                .map_err(|e| anyhow::anyhow!("Failed to compile suppression: {:?}", e))?);
            suppression_programs.push((program, supp.id.clone(), supp.reason.clone()));
        }
        
        Ok(CompiledRule {
            rule,
            main_program: program,
            and_programs,
            or_programs,
            not_programs,
            multiplier_programs,
            suppression_programs,
            compile_time_ms: compile_time.as_millis() as u64,
        })
    }
    
    /// Evaluate an event against all rules
    pub async fn evaluate(&self, event: &Event) -> EvaluationResult {
        let start = Instant::now();
        let rules = self.rules.load();
        
        self.metrics.evaluations_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        let mut matches = Vec::new();
        
        for compiled_rule in rules.values() {
            if !compiled_rule.rule.enabled {
                continue;
            }
            
            // Check suppression first
            let mut suppressed = false;
            for (prog, supp_id, reason) in &compiled_rule.suppression_programs {
                if self.evaluate_program(prog, event).await.unwrap_or(false) {
                    suppressed = true;
                    self.metrics.suppressions_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    debug!("Rule {} suppressed by {}: {}", compiled_rule.rule.id, supp_id, reason);
                    break;
                }
            }
            
            if suppressed {
                continue;
            }
            
            // Evaluate main condition
            let main_match = self.evaluate_program(&compiled_rule.main_program, event).await;
            
            // Evaluate AND conditions
            let and_match = if !compiled_rule.and_programs.is_empty() {
                let mut all_match = true;
                for prog in &compiled_rule.and_programs {
                    if !self.evaluate_program(prog, event).await.unwrap_or(false) {
                        all_match = false;
                        break;
                    }
                }
                all_match
            } else {
                true
            };
            
            // Evaluate OR conditions
            let or_match = if !compiled_rule.or_programs.is_empty() {
                let mut any_match = false;
                for prog in &compiled_rule.or_programs {
                    if self.evaluate_program(prog, event).await.unwrap_or(false) {
                        any_match = true;
                        break;
                    }
                }
                any_match
            } else {
                true
            };
            
            // Evaluate NOT conditions
            let not_match = if !compiled_rule.not_programs.is_empty() {
                let mut none_match = true;
                for prog in &compiled_rule.not_programs {
                    if self.evaluate_program(prog, event).await.unwrap_or(false) {
                        none_match = false;
                        break;
                    }
                }
                none_match
            } else {
                true
            };
            
            if main_match.unwrap_or(false) && and_match && or_match && not_match {
                // Calculate risk score with multipliers
                let risk_score = self.calculate_risk_score(compiled_rule, event).await;
                
                matches.push(RuleMatch {
                    rule_id: compiled_rule.rule.id.clone(),
                    rule_name: compiled_rule.rule.name.clone(),
                    severity: compiled_rule.rule.severity,
                    risk_score,
                    mitre: compiled_rule.rule.mitre.clone(),
                    actions: compiled_rule.rule.actions.clone(),
                    matched_at: chrono::Utc::now(),
                });
                
                self.metrics.matches_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        
        // Execute actions for matches
        for match_result in &matches {
            self.action_executor.execute(match_result, event).await;
        }
        
        let eval_time = start.elapsed();
        self.metrics.avg_eval_time_ms.store(eval_time.as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
        self.metrics.rules_evaluated.store(rules.len() as u64, std::sync::atomic::Ordering::Relaxed);
        
        EvaluationResult {
            matches,
            evaluation_time: eval_time,
            rules_evaluated: rules.len(),
        }
    }
    
    /// Evaluate a CEL program against an event
    async fn evaluate_program(&self, program: &cel::Program, event: &Event) -> Result<bool> {
        let activation = self.create_activation(event);
        let result = program.execute(&activation)
            .map_err(|e| anyhow::anyhow!("CEL evaluation error: {}", e))?;
        
        Ok(matches!(result, cel::Value::Bool(true)))
    }
    
    /// Create CEL activation from event
    fn create_activation(&self, event: &Event) -> cel::Context<'_> {
        let mut ctx = cel::Context::default();

        // ── Top-level event variable ─────────────────────────────────
        ctx.add_variable_from_value("event", event_to_cel_value(event))
            .expect("event variable");

        // ── Convenience variables for common rule patterns ───────────
        ctx.add_variable_from_value("severity", i64::from(event.severity))
            .expect("severity variable");
        ctx.add_variable_from_value("event_type", event.r#type.clone())
            .expect("event_type variable");

        // ── SEVERITY numeric constants (syslog-compatible) ───────────
        ctx.add_variable_from_value("SEVERITY_DEBUG", 0i64).ok();
        ctx.add_variable_from_value("SEVERITY_INFO", 1i64).ok();
        ctx.add_variable_from_value("SEVERITY_NOTICE", 2i64).ok();
        ctx.add_variable_from_value("SEVERITY_WARNING", 3i64).ok();
        ctx.add_variable_from_value("SEVERITY_ERROR", 4i64).ok();
        ctx.add_variable_from_value("SEVERITY_CRITICAL", 5i64).ok();
        ctx.add_variable_from_value("SEVERITY_ALERT", 6i64).ok();
        ctx.add_variable_from_value("SEVERITY_EMERGENCY", 7i64).ok();

        ctx
    }
    
    /// Calculate risk score with multipliers
    async fn calculate_risk_score(&self, compiled_rule: &CompiledRule, event: &Event) -> u32 {
        let base_score = compiled_rule.rule.risk.base_score;
        let confidence = compiled_rule.rule.risk.confidence;
// ── end of CEL helpers ─────────────────────────────────────────────
        
        let mut score = (base_score as f64 * confidence) as u32;
        
        for (prog, factor) in &compiled_rule.multiplier_programs {
            if self.evaluate_program(prog, event).await.unwrap_or(false) {
                score = ((score as f64) * factor).min(1000.0) as u32;
            }
        }
        
        score.min(1000)
    }
    
    /// Start file watcher for hot-reload
    async fn start_watcher(&self, directories: &[String]) -> Result<()> {
        let reload_tx = self.reload_tx.clone();
        
        let (tx, mut rx) = mpsc::channel(100);
        
        let mut watcher: RecommendedWatcher = Watcher::new(
            move |res: Result<NotifyEvent, notify::Error>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        let _ = tx.try_send(());
                    }
                }
            },
            notify::Config::default(),
        )?;
        
        for dir in directories {
            let path = Path::new(dir);
            if path.exists() {
                watcher.watch(path, RecursiveMode::NonRecursive)?;
            }
        }
        
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                tokio::time::sleep(Duration::from_millis(500)).await;
                // Debounce - drain any additional events
                while rx.try_recv().is_ok() {}
                
                info!("Rule file changed, reloading...");
                // Reload would happen here
                let _ = reload_tx.send(());
            }
        });
        
        Ok(())
    }
    
    /// Get current metrics
    pub fn metrics(&self) -> RuleEngineMetricsSnapshot {
        self.metrics.snapshot()
    }
}

/// Compiled rule with CEL programs
#[derive(Clone)]
#[allow(dead_code)]
struct CompiledRule {
    rule: Rule,
    main_program: Arc<cel::Program>,
    and_programs: Vec<Arc<cel::Program>>,
    or_programs: Vec<Arc<cel::Program>>,
    not_programs: Vec<Arc<cel::Program>>,
    multiplier_programs: Vec<(Arc<cel::Program>, f64)>,
    suppression_programs: Vec<(Arc<cel::Program>, String, String)>,
    compile_time_ms: u64,
}

/// Rule match result
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: sentinel_core::Severity,
    pub risk_score: u32,
    pub mitre: Vec<sentinel_core::MitreMapping>,
    pub actions: Vec<sentinel_core::RuleAction>,
    pub matched_at: chrono::DateTime<chrono::Utc>,
}

/// Evaluation result
#[derive(Debug)]
pub struct EvaluationResult {
    pub matches: Vec<RuleMatch>,
    pub evaluation_time: Duration,
    pub rules_evaluated: usize,
}

/// Evaluator pool for parallel evaluation
#[allow(dead_code)]
struct EvaluatorPool {
    workers: usize,
}

impl EvaluatorPool {
    fn new(workers: usize) -> Self {
        Self { workers }
    }
}

/// Suppression engine for rule suppressions
#[allow(dead_code)]
struct SuppressionEngine {
    suppressions: RwLock<HashMap<String, Vec<SuppressionRule>>>,
}

impl SuppressionEngine {
    fn new() -> Self {
        Self {
            suppressions: RwLock::new(HashMap::new()),
        }
    }
    
    #[allow(dead_code)]
    fn check(&self, _rule_id: &str, _event: &Event) -> bool {
        false // Simplified
    }
}

#[derive(Clone)]
#[allow(dead_code)]
struct SuppressionRule {
    id: String,
    condition: String,
    reason: String,
}

/// Action executor
#[allow(dead_code)]
struct ActionExecutor {
    handlers: RwLock<HashMap<sentinel_core::RuleActionType, Box<dyn ActionHandler>>>,
}

impl ActionExecutor {
    fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }
    
    #[allow(clippy::await_holding_lock)]
    async fn execute(&self, match_result: &RuleMatch, event: &Event) {
        for action in &match_result.actions {
            if let Some(handler) = self.handlers.read().get(&action.action_type) {
                if let Err(e) = handler.handle(match_result, event, &action.config).await {
                    error!("Action execution failed: {}", e);
                }
            }
        }
    }
}

#[async_trait::async_trait]
trait ActionHandler: Send + Sync {
    async fn handle(&self, match_result: &RuleMatch, event: &Event, config: &serde_json::Value) -> Result<()>;
}

/// Rule engine metrics
pub struct RuleEngineMetrics {
    pub rules_loaded: std::sync::atomic::AtomicU64,
    pub rules_enabled: std::sync::atomic::AtomicU64,
    pub evaluations_total: std::sync::atomic::AtomicU64,
    pub matches_total: std::sync::atomic::AtomicU64,
    pub suppressions_total: std::sync::atomic::AtomicU64,
    pub avg_eval_time_ms: std::sync::atomic::AtomicU64,
    pub rules_evaluated: std::sync::atomic::AtomicU64,
}

impl RuleEngineMetrics {
    fn new() -> Self {
        Self {
            rules_loaded: std::sync::atomic::AtomicU64::new(0),
            rules_enabled: std::sync::atomic::AtomicU64::new(0),
            evaluations_total: std::sync::atomic::AtomicU64::new(0),
            matches_total: std::sync::atomic::AtomicU64::new(0),
            suppressions_total: std::sync::atomic::AtomicU64::new(0),
            avg_eval_time_ms: std::sync::atomic::AtomicU64::new(0),
            rules_evaluated: std::sync::atomic::AtomicU64::new(0),
        }
    }
    
    fn snapshot(&self) -> RuleEngineMetricsSnapshot {
        RuleEngineMetricsSnapshot {
            rules_loaded: self.rules_loaded.load(std::sync::atomic::Ordering::Relaxed),
            rules_enabled: self.rules_enabled.load(std::sync::atomic::Ordering::Relaxed),
            evaluations_total: self.evaluations_total.load(std::sync::atomic::Ordering::Relaxed),
            matches_total: self.matches_total.load(std::sync::atomic::Ordering::Relaxed),
            suppressions_total: self.suppressions_total.load(std::sync::atomic::Ordering::Relaxed),
            avg_eval_time_ms: self.avg_eval_time_ms.load(std::sync::atomic::Ordering::Relaxed),
            rules_evaluated: self.rules_evaluated.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleEngineMetricsSnapshot {
    pub rules_loaded: u64,
    pub rules_enabled: u64,
    pub evaluations_total: u64,
    pub matches_total: u64,
    pub suppressions_total: u64,
    pub avg_eval_time_ms: u64,
    pub rules_evaluated: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_rule_loading() {
        let dir = tempdir().unwrap();
        let rule_file = dir.path().join("test_rule.yaml");
        
        let rule_content = r#"
rule:
  id: "test-001"
  version: 1
  name: "Test Rule"
  description: "Test rule for unit tests"
  author: "test"
  created: "2026-01-01T00:00:00Z"
  modified: "2026-01-01T00:00:00Z"
  enabled: true
  category: "test"
  severity: "HIGH"
  risk:
    base_score: 50
    confidence: 0.8
  condition: 'event.type == "test.event"'
  actions:
    - type: "alert"
      config: {}
"#;
        
        tokio::fs::write(&rule_file, rule_content).await.unwrap();
        
        let config = RuleEngineConfig {
            rules_directories: vec![dir.path().to_string_lossy().to_string()],
            hot_reload: false,
            validation_on_load: true,
            max_rules: 10000,
            evaluation_timeout_ms: 50,
            worker_threads: 2,
            default_multipliers: vec![],
        };
        
        let engine = RuleEngine::new(&config).await.unwrap();
        let metrics = engine.metrics();
        
        assert_eq!(metrics.rules_loaded, 1);
        assert_eq!(metrics.rules_enabled, 1);
    }
}
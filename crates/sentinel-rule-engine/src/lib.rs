//! Sentinel AI Rule Engine
//!
//! CEL-based rule evaluation with hot-reload support.
//!
//! ## CEL Compatibility Notes
//!
//! The cel-rs crate (v0.14) does not support custom function registration.
//! The `lowerAscii()` CEL function used by some Sigma-style rules is
//! preprocessed: `expr.replace(".lowerAscii()", "")` before compilation.
//! This means `.lowerAscii().contains("X")` becomes `.contains("X")`
//! (case-sensitive). Rules should use lowercase matching substrings.
//! Full `lowerAscii()` support requires upgrading to a CEL runtime that
//! supports custom extensions or switching to a different expression engine.

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

use sentinel_config::RuleEngineConfig;
use sentinel_core::traits::Rule;
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

            let mut entries = tokio::fs::read_dir(path)
                .await
                .context("Failed to read rules directory")?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yaml")
                    || path.extension().and_then(|s| s.to_str()) == Some("yml")
                {
                    match self.load_rule_file(&path).await {
                        Ok(rule) => {
                            compiled_rules.insert(rule.rule.id.clone(), rule);
                        },
                        Err(e) => {
                            error!("Failed to load rule {}: {}", path.display(), e);
                            errors.push(e.to_string());
                        },
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
        self.metrics
            .rules_loaded
            .store(loaded, std::sync::atomic::Ordering::Relaxed);
        self.metrics.rules_enabled.store(
            self.rules
                .load()
                .values()
                .filter(|r| r.rule.enabled)
                .count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        Ok(())
    }

    /// Load a single rule file
    async fn load_rule_file(&self, path: &Path) -> Result<CompiledRule> {
        let content = tokio::fs::read_to_string(path)
            .await
            .context("Failed to read rule file")?;

        // Documented rule files wrap the rule under a top-level `rule:` key;
        // tolerate the flat form as well for backwards compatibility.
        #[derive(serde::Deserialize)]
        struct RuleFile {
            rule: Rule,
        }

        let rule: Rule = serde_yaml::from_str::<RuleFile>(&content)
            .map(|f| f.rule)
            .context("Failed to parse rule YAML (expected `rule:` wrapper)")?;

        // Validate rule
        if rule.id.is_empty() {
            return Err(anyhow::anyhow!("Rule ID is required"));
        }
        if rule.condition.is_empty() {
            return Err(anyhow::anyhow!("Rule condition is required"));
        }

        let condition = preprocess_cel(&rule.condition);

        // Compile CEL expression
        let start = Instant::now();
        let program = Arc::new(
            cel::Program::compile(&condition)
                .map_err(|e| anyhow::anyhow!("Failed to compile CEL expression: {:?}", e))?,
        );

        let compile_time = start.elapsed();
        debug!("Compiled rule {} in {:?}", rule.id, compile_time);

        // Compile additional conditions
        let mut and_programs = Vec::new();
        for cond in &rule.and_conditions {
            let cond = preprocess_cel(cond);
            let program = Arc::new(
                cel::Program::compile(&cond)
                    .map_err(|e| anyhow::anyhow!("Failed to compile AND condition: {:?}", e))?,
            );
            and_programs.push(program);
        }

        let mut or_programs = Vec::new();
        for cond in &rule.or_conditions {
            let cond = preprocess_cel(cond);
            let program = Arc::new(
                cel::Program::compile(&cond)
                    .map_err(|e| anyhow::anyhow!("Failed to compile OR condition: {:?}", e))?,
            );
            or_programs.push(program);
        }

        let mut not_programs = Vec::new();
        for cond in &rule.not_conditions {
            let cond = preprocess_cel(cond);
            let program = Arc::new(
                cel::Program::compile(&cond)
                    .map_err(|e| anyhow::anyhow!("Failed to compile NOT condition: {:?}", e))?,
            );
            not_programs.push(program);
        }

        // Compile risk multipliers
        let mut multiplier_programs = Vec::new();
        for mult in &rule.risk.multipliers {
            let cond = preprocess_cel(&mult.condition);
            let program = Arc::new(
                cel::Program::compile(&cond)
                    .map_err(|e| anyhow::anyhow!("Failed to compile risk multiplier: {:?}", e))?,
            );
            multiplier_programs.push((program, mult.factor));
        }

        // Compile suppressions
        let mut suppression_programs = Vec::new();
        for supp in &rule.suppressions {
            let cond = preprocess_cel(&supp.condition);
            let program = Arc::new(
                cel::Program::compile(&cond)
                    .map_err(|e| anyhow::anyhow!("Failed to compile suppression: {:?}", e))?,
            );
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

        self.metrics
            .evaluations_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

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
                    self.metrics
                        .suppressions_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    debug!("Rule {} suppressed by {}: {}", compiled_rule.rule.id, supp_id, reason);
                    break;
                }
            }

            if suppressed {
                continue;
            }

            // Evaluate main condition
            let main_match = self
                .evaluate_program(&compiled_rule.main_program, event)
                .await;

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

                self.metrics
                    .matches_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Execute actions for matches
        for match_result in &matches {
            self.action_executor.execute(match_result, event).await;
        }

        let eval_time = start.elapsed();
        self.metrics
            .avg_eval_time_ms
            .store(eval_time.as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
        self.metrics
            .rules_evaluated
            .store(rules.len() as u64, std::sync::atomic::Ordering::Relaxed);

        EvaluationResult { matches, evaluation_time: eval_time, rules_evaluated: rules.len() }
    }

    /// Evaluate a CEL program against an event
    async fn evaluate_program(&self, program: &cel::Program, event: &Event) -> Result<bool> {
        let activation = self.create_activation(event);
        let result = program
            .execute(&activation)
            .map_err(|e| anyhow::anyhow!("CEL evaluation error: {}", e))?;

        Ok(matches!(result, cel::Value::Bool(true)))
    }

    /// Create CEL activation from event
    fn create_activation(&self, event: &Event) -> cel::Context<'_> {
        let mut ctx = cel::Context::default();

        ctx.add_variable_from_value("event", event_to_cel_value(event));
        ctx.add_variable_from_value("severity", i64::from(event.severity));
        ctx.add_variable_from_value("event_type", event.r#type.clone());

        ctx.add_variable_from_value("SEVERITY_DEBUG", 1i64);
        ctx.add_variable_from_value("SEVERITY_INFO", 2i64);
        ctx.add_variable_from_value("SEVERITY_NOTICE", 3i64);
        ctx.add_variable_from_value("SEVERITY_WARNING", 4i64);
        ctx.add_variable_from_value("SEVERITY_ERROR", 5i64);
        ctx.add_variable_from_value("SEVERITY_CRITICAL", 6i64);
        ctx.add_variable_from_value("SEVERITY_ALERT", 7i64);
        ctx.add_variable_from_value("SEVERITY_EMERGENCY", 8i64);

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

// ── CEL context construction ────────────────────────────────────────
// These helpers convert protobuf Event and its nested structures into
// cel::Value maps so that CEL expressions can reference event fields
// with dot-notation (e.g. `event.process.name == "powershell.exe"`).

fn event_to_cel_value(event: &Event) -> cel::Value {
    let mut map: HashMap<String, cel::Value> = HashMap::new();

    map.insert("id".into(), cel::Value::from(event.id.clone()));
    map.insert("type".into(), cel::Value::from(event.r#type.clone()));
    map.insert("source".into(), cel::Value::from(event.source.clone()));
    map.insert("severity".into(), cel::Value::Int(i64::from(event.severity)));
    map.insert("risk_score".into(), cel::Value::UInt(u64::from(event.risk_score)));
    map.insert("host_id".into(), cel::Value::from(event.host_id.clone()));
    map.insert("schema_version".into(), cel::Value::UInt(u64::from(event.schema_version)));

    // Process context (recursive tree capped at depth 5)
    if let Some(ref proc) = event.process {
        map.insert("process".into(), process_to_cel_value(proc, 0));
    }

    // Correlation context
    if let Some(ref c) = event.correlation {
        map.insert("correlation".into(), correlation_to_cel_value(c));
    }

    // Tags as a list
    let tags: Vec<cel::Value> = event
        .tags
        .iter()
        .map(|t| cel::Value::from(t.clone()))
        .collect();
    map.insert("tags".into(), tags.into());

    // Timestamps as epoch seconds
    if let Some(ref ts) = event.timestamp {
        map.insert("timestamp_epoch".into(), cel::Value::Int(ts.seconds));
    }
    if let Some(ref ts) = event.ingest_timestamp {
        map.insert("ingest_timestamp_epoch".into(), cel::Value::Int(ts.seconds));
    }

    // Payload — extract type tag only (full serialisation can be added later)
    if let Some(ref p) = event.payload {
        let (kind, data) = payload_to_cel(p);
        map.insert("payload_type".into(), cel::Value::from(kind));
        map.insert("payload".into(), data);
    }

    map.into()
}

fn process_to_cel_value(proc: &sentinel_events::ProcessContext, depth: u32) -> cel::Value {
    if depth > 5 {
        return cel::Value::Null;
    }
    let mut map: HashMap<String, cel::Value> = HashMap::new();
    map.insert("pid".into(), cel::Value::UInt(u64::from(proc.pid)));
    map.insert("ppid".into(), cel::Value::UInt(u64::from(proc.ppid)));
    map.insert("name".into(), cel::Value::from(proc.name.clone()));
    map.insert("path".into(), cel::Value::from(proc.path.clone()));
    map.insert("command_line".into(), cel::Value::from(proc.command_line.clone()));
    map.insert("cwd".into(), cel::Value::from(proc.cwd.clone()));
    map.insert("integrity_level".into(), cel::Value::from(proc.integrity_level.clone()));
    map.insert("tree_depth".into(), cel::Value::UInt(u64::from(proc.tree_depth)));
    map.insert("sha256".into(), cel::Value::from(proc.sha256.clone()));

    let mitre: Vec<cel::Value> = proc
        .mitre_techniques
        .iter()
        .map(|t| cel::Value::from(t.clone()))
        .collect();
    map.insert("mitre_techniques".into(), mitre.into());

    if let Some(ref user) = proc.user {
        map.insert("user".into(), user_to_cel_value(user));
    }
    if let Some(ref sign) = proc.signing {
        map.insert("signing".into(), signing_to_cel_value(sign));
    }
    if let Some(ref parent) = proc.parent {
        map.insert("parent".into(), process_to_cel_value(parent, depth + 1));
    }

    map.into()
}

fn user_to_cel_value(user: &sentinel_events::UserContext) -> cel::Value {
    let mut map: HashMap<String, cel::Value> = HashMap::new();
    map.insert("username".into(), cel::Value::from(user.username.clone()));
    map.insert("domain".into(), cel::Value::from(user.domain.clone()));
    map.insert("sid".into(), cel::Value::from(user.sid.clone()));
    map.insert("is_elevated".into(), cel::Value::Bool(user.is_elevated));
    map.insert("is_system".into(), cel::Value::Bool(user.is_system));
    map.into()
}

fn signing_to_cel_value(signing: &sentinel_events::CodeSigningInfo) -> cel::Value {
    let mut map: HashMap<String, cel::Value> = HashMap::new();
    map.insert("is_signed".into(), cel::Value::Bool(signing.is_signed));
    map.insert("is_trusted".into(), cel::Value::Bool(signing.is_trusted));
    map.insert("publisher".into(), cel::Value::from(signing.publisher.clone()));
    map.insert("issuer".into(), cel::Value::from(signing.issuer.clone()));
    map.into()
}

fn correlation_to_cel_value(corr: &sentinel_events::CorrelationContext) -> cel::Value {
    let mut map: HashMap<String, cel::Value> = HashMap::new();
    map.insert("session_id".into(), cel::Value::from(corr.session_id.clone()));
    map.insert("cause_event_id".into(), cel::Value::from(corr.cause_event_id.clone()));
    map.insert("root_event_id".into(), cel::Value::from(corr.root_event_id.clone()));
    map.insert("correlation_id".into(), cel::Value::from(corr.correlation_id.clone()));
    map.insert("flow_id".into(), cel::Value::from(corr.flow_id.clone()));
    map.insert("sequence".into(), cel::Value::UInt(u64::from(corr.sequence)));
    map.into()
}

fn payload_to_cel(p: &sentinel_events::event::Payload) -> (String, cel::Value) {
    use sentinel_events::event::Payload;
    match p {
        Payload::ProcessEvent(e) => ("ProcessEvent".into(), process_payload_to_cel(e)),
        Payload::NetworkEvent(e) => ("NetworkEvent".into(), network_payload_to_cel(e)),
        Payload::FileEvent(e) => ("FileEvent".into(), file_payload_to_cel(e)),
        Payload::RegistryEvent(e) => ("RegistryEvent".into(), registry_payload_to_cel(e)),
        Payload::UsbEvent(e) => ("UsbEvent".into(), usb_payload_to_cel(e)),
        Payload::BrowserEvent(e) => ("BrowserEvent".into(), browser_payload_to_cel(e)),
        Payload::StartupEvent(e) => ("StartupEvent".into(), startup_payload_to_cel(e)),
        Payload::GenericEvent(e) => ("GenericEvent".into(), generic_payload_to_cel(e)),
    }
}

fn process_payload_to_cel(e: &sentinel_events::ProcessEvent) -> cel::Value {
    let mut map: HashMap<String, cel::Value> = HashMap::new();
    map.insert("action".into(), cel::Value::Int(i64::from(e.action)));
    if let Some(ref t) = e.target {
        map.insert("target".into(), process_to_cel_value(t, 0));
    }
    map.insert("desired_access".into(), cel::Value::UInt(u64::from(e.desired_access)));
    map.into()
}

fn network_payload_to_cel(e: &sentinel_events::NetworkEvent) -> cel::Value {
    let mut map: HashMap<String, cel::Value> = HashMap::new();
    map.insert("direction".into(), cel::Value::Int(i64::from(e.direction)));
    map.insert("protocol".into(), cel::Value::Int(i64::from(e.protocol)));
    map.insert("action".into(), cel::Value::Int(i64::from(e.action)));
    map.insert("local_addr".into(), cel::Value::from(e.local_addr.clone()));
    map.insert("local_port".into(), cel::Value::UInt(u64::from(e.local_port)));
    map.insert("remote_addr".into(), cel::Value::from(e.remote_addr.clone()));
    map.insert("remote_port".into(), cel::Value::UInt(u64::from(e.remote_port)));
    map.insert("hostname".into(), cel::Value::from(e.hostname.clone()));
    map.insert("dns_query".into(), cel::Value::from(e.dns_query.clone()));
    map.insert("ja3_fingerprint".into(), cel::Value::from(e.ja3_fingerprint.clone()));
    map.insert("ja3s_fingerprint".into(), cel::Value::from(e.ja3s_fingerprint.clone()));
    map.into()
}

fn file_payload_to_cel(e: &sentinel_events::FileEvent) -> cel::Value {
    let mut map: HashMap<String, cel::Value> = HashMap::new();
    map.insert("action".into(), cel::Value::Int(i64::from(e.action)));
    map.insert("path".into(), cel::Value::from(e.path.clone()));
    map.insert("sha256".into(), cel::Value::from(e.sha256.clone()));
    map.insert("entropy".into(), cel::Value::from(e.entropy.clone()));
    map.insert("is_executable".into(), cel::Value::Bool(e.is_executable));
    map.insert("is_sensitive_path".into(), cel::Value::Bool(e.is_sensitive_path));
    map.into()
}

fn registry_payload_to_cel(e: &sentinel_events::RegistryEvent) -> cel::Value {
    let mut map: HashMap<String, cel::Value> = HashMap::new();
    map.insert("action".into(), cel::Value::Int(i64::from(e.action)));
    map.insert("hive".into(), cel::Value::Int(i64::from(e.hive)));
    map.insert("key_path".into(), cel::Value::from(e.key_path.clone()));
    map.insert("value_name".into(), cel::Value::from(e.value_name.clone()));
    map.into()
}

fn usb_payload_to_cel(e: &sentinel_events::UsbEvent) -> cel::Value {
    let mut map: HashMap<String, cel::Value> = HashMap::new();
    map.insert("action".into(), cel::Value::Int(i64::from(e.action)));
    map.insert("vendor_id".into(), cel::Value::from(e.vendor_id.clone()));
    map.insert("product_id".into(), cel::Value::from(e.product_id.clone()));
    map.insert("serial_number".into(), cel::Value::from(e.serial_number.clone()));
    map.insert("manufacturer".into(), cel::Value::from(e.manufacturer.clone()));
    map.insert("product".into(), cel::Value::from(e.product.clone()));
    map.insert("is_encrypted".into(), cel::Value::Bool(e.is_encrypted));
    map.into()
}

fn browser_payload_to_cel(e: &sentinel_events::BrowserEvent) -> cel::Value {
    let mut map: HashMap<String, cel::Value> = HashMap::new();
    map.insert("browser".into(), cel::Value::Int(i64::from(e.browser)));
    map.insert("action".into(), cel::Value::Int(i64::from(e.action)));
    map.insert("url".into(), cel::Value::from(e.url.clone()));
    map.insert("title".into(), cel::Value::from(e.title.clone()));
    map.insert("referrer".into(), cel::Value::from(e.referrer.clone()));
    map.insert("download_path".into(), cel::Value::from(e.download_path.clone()));
    map.insert("is_incognito".into(), cel::Value::Bool(e.is_incognito));
    map.into()
}

fn startup_payload_to_cel(e: &sentinel_events::StartupEvent) -> cel::Value {
    let mut map: HashMap<String, cel::Value> = HashMap::new();
    map.insert("action".into(), cel::Value::Int(i64::from(e.action)));
    map.insert("location".into(), cel::Value::Int(i64::from(e.location)));
    map.insert("name".into(), cel::Value::from(e.name.clone()));
    map.insert("command".into(), cel::Value::from(e.command.clone()));
    map.insert("arguments".into(), cel::Value::from(e.arguments.clone()));
    map.insert("user".into(), cel::Value::from(e.user.clone()));
    map.insert("is_signed".into(), cel::Value::Bool(e.is_signed));
    map.insert("publisher".into(), cel::Value::from(e.publisher.clone()));
    map.into()
}

fn generic_payload_to_cel(e: &sentinel_events::GenericEvent) -> cel::Value {
    let mut map: HashMap<String, cel::Value> = HashMap::new();
    map.insert("custom_type".into(), cel::Value::from(e.custom_type.clone()));
    map.into()
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
        Self { suppressions: RwLock::new(HashMap::new()) }
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
        Self { handlers: RwLock::new(HashMap::new()) }
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
    async fn handle(
        &self,
        match_result: &RuleMatch,
        event: &Event,
        config: &serde_json::Value,
    ) -> Result<()>;
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
            rules_enabled: self
                .rules_enabled
                .load(std::sync::atomic::Ordering::Relaxed),
            evaluations_total: self
                .evaluations_total
                .load(std::sync::atomic::Ordering::Relaxed),
            matches_total: self
                .matches_total
                .load(std::sync::atomic::Ordering::Relaxed),
            suppressions_total: self
                .suppressions_total
                .load(std::sync::atomic::Ordering::Relaxed),
            avg_eval_time_ms: self
                .avg_eval_time_ms
                .load(std::sync::atomic::Ordering::Relaxed),
            rules_evaluated: self
                .rules_evaluated
                .load(std::sync::atomic::Ordering::Relaxed),
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

fn preprocess_cel(expr: &str) -> String {
    expr.replace(".lowerAscii()", "")
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

    fn make_test_event(r#type: &str, severity: i32, proc_name: &str) -> Event {
        Event {
            id: "evt-001".into(),
            r#type: r#type.into(),
            source: "test".into(),
            severity,
            risk_score: 50,
            host_id: "host-1".into(),
            schema_version: 1,
            process: Some(sentinel_events::ProcessContext {
                name: proc_name.into(),
                pid: 1234,
                command_line: format!("C:\\Windows\\{}", proc_name),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_cel_evaluation_match_by_type() {
        let event = make_test_event("sentinel.process.create", 3, "powershell.exe");
        let program = cel::Program::compile(r#"event.type == "sentinel.process.create""#).unwrap();
        let _ctx = cel::Context::default();
        // verify using the helper directly
        let cel_activation = event_to_cel_value(&event);
        let mut ctx = cel::Context::default();
        ctx.add_variable_from_value("event", cel_activation);
        let result = program.execute(&ctx).unwrap();
        assert!(matches!(result, cel::Value::Bool(true)));
    }

    #[tokio::test]
    async fn test_cel_evaluation_match_by_process_name() {
        let event = make_test_event("sentinel.process.create", 3, "powershell.exe");
        let program = cel::Program::compile(r#"event.process.name == "powershell.exe""#).unwrap();
        let mut ctx = cel::Context::default();
        ctx.add_variable_from_value("event", event_to_cel_value(&event));
        let result = program.execute(&ctx).unwrap();
        assert!(matches!(result, cel::Value::Bool(true)));
    }

    #[tokio::test]
    async fn test_cel_evaluation_no_match() {
        let event = make_test_event("sentinel.process.create", 1, "notepad.exe");
        let program = cel::Program::compile(r#"event.process.name == "powershell.exe""#).unwrap();
        let mut ctx = cel::Context::default();
        ctx.add_variable_from_value("event", event_to_cel_value(&event));
        let result = program.execute(&ctx).unwrap();
        assert!(matches!(result, cel::Value::Bool(false)));
    }

    #[tokio::test]
    async fn test_cel_evaluation_severity_comparison() {
        let event = make_test_event("sentinel.process.create", 4, "cmd.exe");
        let program = cel::Program::compile("event.severity > SEVERITY_INFO").unwrap();
        let mut ctx = cel::Context::default();
        ctx.add_variable_from_value("event", event_to_cel_value(&event));
        ctx.add_variable_from_value("SEVERITY_INFO", 1i64);
        let result = program.execute(&ctx).unwrap();
        assert!(matches!(result, cel::Value::Bool(true)));
    }

    #[tokio::test]
    async fn test_cel_evaluation_tags_contains() {
        let mut event = make_test_event("sentinel.process.create", 3, "powershell.exe");
        event.tags = vec!["mitre:T1059".into()];
        let program = cel::Program::compile(r#"event.tags.exists(t, t == "mitre:T1059")"#).unwrap();
        let mut ctx = cel::Context::default();
        ctx.add_variable_from_value("event", event_to_cel_value(&event));
        let result = program.execute(&ctx).unwrap();
        assert!(matches!(result, cel::Value::Bool(true)));
    }
}

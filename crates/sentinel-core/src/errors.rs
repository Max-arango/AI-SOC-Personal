//! Error types for Sentinel AI

use thiserror::Error;

/// Result type alias
pub type Result<T> = std::result::Result<T, SentinelError>;

/// Main error type for Sentinel AI
#[derive(Error, Debug)]
pub enum SentinelError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Event bus error: {0}")]
    EventBus(#[from] EventBusError),

    #[error("Rule engine error: {0}")]
    RuleEngine(#[from] RuleEngineError),

    #[error("Collector error: {0}")]
    Collector(#[from] CollectorError),

    #[error("Plugin error: {0}")]
    Plugin(#[from] PluginError),

    #[error("AI engine error: {0}")]
    AiEngine(#[from] AiEngineError),

    #[error("Correlation engine error: {0}")]
    Correlation(#[from] CorrelationError),

    #[error("Risk engine error: {0}")]
    Risk(#[from] RiskError),

    #[error("API error: {0}")]
    Api(#[from] ApiError),

    #[error("OS abstraction error: {0}")]
    OsAbstraction(#[from] OsAbstractionError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    #[error("Channel send error: {0}")]
    ChannelSend(String),

    #[error("Channel recv error: {0}")]
    ChannelRecv(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Migration error: {0}")]
    Migration(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Health check failed: {0}")]
    HealthCheck(String),
}

impl From<anyhow::Error> for SentinelError {
    fn from(e: anyhow::Error) -> Self {
        SentinelError::Internal(e.to_string())
    }
}

impl SentinelError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            SentinelError::Io(_)
                | SentinelError::Timeout(_)
                | SentinelError::ResourceExhausted(_)
                | SentinelError::ChannelSend(_)
                | SentinelError::ChannelRecv(_)
        )
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, SentinelError::NotFound(_))
    }

    pub fn is_validation(&self) -> bool {
        matches!(self, SentinelError::Validation(_))
    }
}

/// Configuration errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Config file not found: {0}")]
    NotFound(String),

    #[error("Config parse error: {0}")]
    Parse(String),

    #[error("Config validation error: {0}")]
    Validation(String),

    #[error("Config migration error: {0}")]
    Migration(String),

    #[error("Secret decryption error: {0}")]
    SecretDecryption(String),

    #[error("Environment variable error: {0}")]
    EnvVar(String),

    #[error("Hot reload error: {0}")]
    HotReload(String),
}

/// Storage errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database connection error: {0}")]
    Connection(String),

    #[error("Query error: {0}")]
    Query(String),

    #[error("Migration error: {0}")]
    Migration(String),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Constraint violation: {0}")]
    Constraint(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Retention policy error: {0}")]
    Retention(String),
}

impl From<anyhow::Error> for StorageError {
    fn from(e: anyhow::Error) -> Self {
        StorageError::Query(e.to_string())
    }
}

/// Event bus errors
#[derive(Error, Debug)]
pub enum EventBusError {
    #[error("Channel full: {0}")]
    ChannelFull(String),

    #[error("Subscription error: {0}")]
    Subscription(String),

    #[error("Backpressure critical: {0}")]
    BackpressureCritical(String),

    #[error("Event too large: {size} > {max}")]
    EventTooLarge {
        size: usize,
        max: usize,
    },

    #[error("No subscribers for event type: {0}")]
    NoSubscribers(String),
}

/// Rule engine errors
#[derive(Error, Debug)]
pub enum RuleEngineError {
    #[error("CEL compilation error: {0}")]
    CelCompilation(String),

    #[error("CEL evaluation error: {0}")]
    CelEvaluation(String),

    #[error("Rule not found: {0}")]
    RuleNotFound(String),

    #[error("Rule validation error: {0}")]
    Validation(String),

    #[error("Action execution error: {0}")]
    ActionExecution(String),

    #[error("Suppression error: {0}")]
    Suppression(String),
}

/// Collector errors
#[derive(Error, Debug)]
pub enum CollectorError {
    #[error("Collector not found: {0}")]
    NotFound(String),

    #[error("Collector already running: {0}")]
    AlreadyRunning(String),

    #[error("Collector start failed: {0}")]
    StartFailed(String),

    #[error("Collector stop failed: {0}")]
    StopFailed(String),

    #[error("OS API error: {0}")]
    OsApi(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Event generation error: {0}")]
    EventGeneration(String),

    #[error("Unsupported platform")]
    UnsupportedPlatform,
}

/// Plugin errors
#[derive(Error, Debug)]
pub enum PluginError {
    #[error("Plugin not found: {0}")]
    NotFound(String),

    #[error("Plugin already loaded: {0}")]
    AlreadyLoaded(String),

    #[error("Plugin load failed: {0}")]
    LoadFailed(String),

    #[error("Plugin unload failed: {0}")]
    UnloadFailed(String),

    #[error("Plugin initialization failed: {0}")]
    InitFailed(String),

    #[error("Plugin execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Capability denied: {0}")]
    CapabilityDenied(String),

    #[error("Plugin communication error: {0}")]
    Communication(String),

    #[error("Plugin sandbox violation: {0}")]
    SandboxViolation(String),

    #[error("Invalid plugin manifest: {0}")]
    InvalidManifest(String),
}

/// AI engine errors
#[derive(Error, Debug)]
pub enum AiEngineError {
    #[error("Model not available: {0}")]
    ModelNotAvailable(String),

    #[error("Model load failed: {0}")]
    ModelLoadFailed(String),

    #[error("Inference failed: {0}")]
    InferenceFailed(String),

    #[error("Context building failed: {0}")]
    ContextBuildingFailed(String),

    #[error("Response validation failed: {0}")]
    ResponseValidationFailed(String),

    #[error("Guardrail violation: {0}")]
    GuardrailViolation(String),

    #[error("Provider error: {0}")]
    ProviderError(String),

    #[error("Token limit exceeded: {0}")]
    TokenLimitExceeded(String),
}

/// Correlation engine errors
#[derive(Error, Debug)]
pub enum CorrelationError {
    #[error("Chain not found: {0}")]
    ChainNotFound(String),

    #[error("Graph corruption: {0}")]
    GraphCorruption(String),

    #[error("Flow tracking error: {0}")]
    FlowTracking(String),

    #[error("Chain analysis failed: {0}")]
    ChainAnalysis(String),
}

/// Risk engine errors
#[derive(Error, Debug)]
pub enum RiskError {
    #[error("Scoring failed: {0}")]
    ScoringFailed(String),

    #[error("Alert generation failed: {0}")]
    AlertGeneration(String),

    #[error("Threshold configuration error: {0}")]
    ThresholdConfig(String),

    #[error("Temporal decay error: {0}")]
    TemporalDecay(String),
}

/// API errors
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Authorization failed: {0}")]
    Authorization(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Method not allowed: {0}")]
    MethodNotAllowed(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

/// OS abstraction errors
#[derive(Error, Debug)]
pub enum OsAbstractionError {
    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("API call failed: {0}")]
    ApiCallFailed(String),

    #[error("Insufficient privileges: {0}")]
    InsufficientPrivileges(String),

    #[error("Resource not found: {0}")]
    ResourceNotFound(String),

    #[error("Platform-specific error: {0}")]
    PlatformSpecific(String),
}

/// Serialization errors
#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Protobuf error: {0}")]
    Protobuf(#[from] prost::DecodeError),

    #[error("TOML error: {0}")]
    Toml(#[from] toml::ser::Error),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("Bincode error: {0}")]
    Bincode(#[from] bincode::Error),
}

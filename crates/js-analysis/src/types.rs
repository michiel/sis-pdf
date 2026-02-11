#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeKind {
    PdfReader,
    Browser,
    Node,
    Bun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    Strict,
    Compat,
    DeceptionHardened,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePhase {
    Open,
    Idle,
    Click,
    Form,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProfile {
    pub kind: RuntimeKind,
    pub vendor: String,
    pub version: String,
    pub mode: RuntimeMode,
}

impl RuntimeProfile {
    pub fn id(&self) -> String {
        format!("{}:{}:{}:{}", self.kind.as_str(), self.vendor, self.version, self.mode.as_str())
    }
}

impl RuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeKind::PdfReader => "pdf_reader",
            RuntimeKind::Browser => "browser",
            RuntimeKind::Node => "node",
            RuntimeKind::Bun => "bun",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleContext {
    NpmPreinstall,
    NpmInstall,
    NpmPostinstall,
    BunInstall,
}

impl LifecycleContext {
    pub fn as_str(self) -> &'static str {
        match self {
            LifecycleContext::NpmPreinstall => "npm.preinstall",
            LifecycleContext::NpmInstall => "npm.install",
            LifecycleContext::NpmPostinstall => "npm.postinstall",
            LifecycleContext::BunInstall => "bun.install",
        }
    }
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeMode::Strict => "strict",
            RuntimeMode::Compat => "compat",
            RuntimeMode::DeceptionHardened => "deception_hardened",
        }
    }
}

impl RuntimePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimePhase::Open => "open",
            RuntimePhase::Idle => "idle",
            RuntimePhase::Click => "click",
            RuntimePhase::Form => "form",
        }
    }
}

impl Default for RuntimeProfile {
    fn default() -> Self {
        Self {
            kind: RuntimeKind::PdfReader,
            vendor: "adobe".to_string(),
            version: "11".to_string(),
            mode: RuntimeMode::Compat,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DynamicSignals {
    pub replay_id: String,
    pub runtime_profile: String,
    pub calls: Vec<String>,
    pub call_args: Vec<String>,
    pub urls: Vec<String>,
    pub domains: Vec<String>,
    pub errors: Vec<String>,
    pub prop_reads: Vec<String>,
    pub prop_writes: Vec<String>,
    pub prop_deletes: Vec<String>,
    pub reflection_probes: Vec<String>,
    pub dynamic_code_calls: Vec<String>,
    pub heap_allocations: Vec<String>,
    pub heap_views: Vec<String>,
    pub heap_accesses: Vec<String>,
    pub heap_allocation_count: usize,
    pub heap_view_count: usize,
    pub heap_access_count: usize,
    pub call_count: usize,
    pub unique_calls: usize,
    pub unique_prop_reads: usize,
    pub elapsed_ms: Option<u128>,
    pub truncation: DynamicTruncationSummary,
    pub phases: Vec<DynamicPhaseSummary>,
    pub delta_summary: Option<DynamicDeltaSummary>,
    pub behavioral_patterns: Vec<BehaviorPattern>,
    pub execution_stats: ExecutionStats,
}

#[derive(Debug, Clone, Default)]
pub struct DynamicTruncationSummary {
    pub calls_dropped: usize,
    pub call_args_dropped: usize,
    pub prop_reads_dropped: usize,
    pub errors_dropped: usize,
    pub urls_dropped: usize,
    pub domains_dropped: usize,
    pub heap_allocations_dropped: usize,
    pub heap_views_dropped: usize,
    pub heap_accesses_dropped: usize,
}

#[derive(Debug, Clone)]
pub struct DynamicPhaseSummary {
    pub phase: String,
    pub call_count: usize,
    pub prop_read_count: usize,
    pub error_count: usize,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone)]
pub struct DynamicDeltaSummary {
    pub phase: String,
    pub trigger_calls: Vec<String>,
    pub generated_snippets: usize,
    pub added_identifier_count: usize,
    pub added_string_literal_count: usize,
    pub added_call_count: usize,
    pub new_identifiers: Vec<String>,
    pub new_string_literals: Vec<String>,
    pub new_calls: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BehaviorPattern {
    pub name: String,
    pub confidence: f64,
    pub evidence: String,
    pub severity: String,
    pub metadata: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ExecutionStats {
    pub total_function_calls: usize,
    pub unique_function_calls: usize,
    pub variable_promotions: usize,
    pub error_recoveries: usize,
    pub successful_recoveries: usize,
    pub execution_depth: usize,
    pub loop_iteration_limit_hits: usize,
    pub adaptive_loop_iteration_limit: usize,
    pub adaptive_loop_profile: String,
    pub downloader_scheduler_hardening: bool,
    pub probe_loop_short_circuit_hits: usize,
}

#[derive(Debug, Clone)]
pub struct TimeoutContext {
    pub runtime_profile: String,
    pub phase: Option<String>,
    pub elapsed_ms: Option<u128>,
    pub budget_ratio: Option<f64>,
}

#[derive(Debug, Clone)]
pub enum DynamicOutcome {
    Executed(Box<DynamicSignals>),
    TimedOut { timeout_ms: u128, context: TimeoutContext },
    Skipped { reason: String, limit: usize, actual: usize },
}

#[derive(Debug, Clone)]
pub struct DynamicOptions {
    pub max_bytes: usize,
    pub timeout_ms: u128,
    pub max_arg_preview: usize,
    pub max_call_args: usize,
    pub max_urls: usize,
    pub max_domains: usize,
    pub max_args_per_call: usize,
    pub phase_timeout_ms: u128,
    pub phases: Vec<RuntimePhase>,
    pub runtime_profile: RuntimeProfile,
    pub lifecycle_context: Option<LifecycleContext>,
}

impl Default for DynamicOptions {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024,
            timeout_ms: 5_000,
            max_arg_preview: 240,
            max_call_args: 64,
            max_urls: 48,
            max_domains: 48,
            max_args_per_call: 8,
            phase_timeout_ms: 1_250,
            phases: vec![
                RuntimePhase::Open,
                RuntimePhase::Idle,
                RuntimePhase::Click,
                RuntimePhase::Form,
            ],
            runtime_profile: RuntimeProfile::default(),
            lifecycle_context: None,
        }
    }
}

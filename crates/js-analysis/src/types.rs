#[derive(Debug, Clone)]
pub struct DynamicSignals {
    pub calls: Vec<String>,
    pub call_args: Vec<String>,
    pub urls: Vec<String>,
    pub domains: Vec<String>,
    pub errors: Vec<String>,
    pub prop_reads: Vec<String>,
    pub call_count: usize,
    pub unique_calls: usize,
    pub unique_prop_reads: usize,
    pub elapsed_ms: Option<u128>,
    pub behavioral_patterns: Vec<BehaviorPattern>,
    pub execution_stats: ExecutionStats,
}

#[derive(Debug, Clone)]
pub struct BehaviorPattern {
    pub name: String,
    pub confidence: f64,
    pub evidence: String,
    pub severity: String,
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ExecutionStats {
    pub total_function_calls: usize,
    pub unique_function_calls: usize,
    pub variable_promotions: usize,
    pub error_recoveries: usize,
    pub successful_recoveries: usize,
    pub execution_depth: usize,
}

#[derive(Debug, Clone)]
pub enum DynamicOutcome {
    Executed(Box<DynamicSignals>),
    TimedOut {
        timeout_ms: u128,
    },
    Skipped {
        reason: String,
        limit: usize,
        actual: usize,
    },
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
        }
    }
}

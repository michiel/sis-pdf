use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Heuristic,
    Probable,
    Strong,
}

#[derive(Debug, Clone)]
pub struct FontFinding {
    pub kind: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub meta: HashMap<String, String>,
}

#[derive(Debug, Default)]
pub struct StaticAnalysisOutcome {
    pub findings: Vec<FontFinding>,
    pub risk_score: u32,
}

#[derive(Debug, Default)]
pub struct DynamicAnalysisOutcome {
    pub findings: Vec<FontFinding>,
    pub timed_out: bool,
}

#[derive(Debug, Clone)]
pub struct FontAnalysisConfig {
    pub enabled: bool,
    pub dynamic_enabled: bool,
    pub dynamic_timeout_ms: u64,
}

impl Default for FontAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dynamic_enabled: false,
            dynamic_timeout_ms: 120,
        }
    }
}

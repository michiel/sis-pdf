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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FontAnalysisConfig {
    /// Enable font analysis
    pub enabled: bool,

    /// Enable dynamic analysis (requires 'dynamic' feature)
    pub dynamic_enabled: bool,

    /// Timeout for dynamic analysis in milliseconds
    pub dynamic_timeout_ms: u64,

    /// Maximum number of charstring operators before flagging as suspicious
    pub max_charstring_ops: u64,

    /// Maximum stack depth before flagging as suspicious
    pub max_stack_depth: usize,

    /// Maximum number of fonts to analyze per PDF
    pub max_fonts: usize,

    /// Allow network access for external font fetching (disabled by default)
    pub network_access: bool,
}

impl Default for FontAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dynamic_enabled: false,
            dynamic_timeout_ms: 5000, // 5 seconds
            max_charstring_ops: 50_000,
            max_stack_depth: 256,
            max_fonts: 100,
            network_access: false,
        }
    }
}

impl FontAnalysisConfig {
    /// Load configuration from TOML string
    pub fn from_toml(toml: &str) -> Result<Self, String> {
        toml::from_str(toml).map_err(|e| format!("Failed to parse TOML: {}", e))
    }

    /// Load configuration from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("Failed to parse JSON: {}", e))
    }

    /// Load configuration from YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        serde_yaml::from_str(yaml).map_err(|e| format!("Failed to parse YAML: {}", e))
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("Failed to serialize to JSON: {}", e))
    }

    /// Convert to YAML string
    pub fn to_yaml(&self) -> Result<String, String> {
        serde_yaml::to_string(self).map_err(|e| format!("Failed to serialize to YAML: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = FontAnalysisConfig::default();
        assert!(config.enabled);
        assert!(!config.dynamic_enabled);
        assert_eq!(config.dynamic_timeout_ms, 5000);
        assert_eq!(config.max_charstring_ops, 50_000);
        assert_eq!(config.max_stack_depth, 256);
        assert_eq!(config.max_fonts, 100);
        assert!(!config.network_access);
    }

    #[test]
    fn test_config_from_json() {
        let json = r#"{
            "enabled": true,
            "dynamic_enabled": true,
            "dynamic_timeout_ms": 10000,
            "max_charstring_ops": 100000,
            "max_stack_depth": 512,
            "max_fonts": 50,
            "network_access": false
        }"#;

        let config = FontAnalysisConfig::from_json(json).unwrap();
        assert!(config.enabled);
        assert!(config.dynamic_enabled);
        assert_eq!(config.dynamic_timeout_ms, 10000);
        assert_eq!(config.max_charstring_ops, 100000);
        assert_eq!(config.max_stack_depth, 512);
        assert_eq!(config.max_fonts, 50);
    }

    #[test]
    fn test_config_from_yaml() {
        let yaml = r#"
enabled: true
dynamic_enabled: false
dynamic_timeout_ms: 3000
max_charstring_ops: 25000
max_stack_depth: 128
max_fonts: 200
network_access: false
"#;

        let config = FontAnalysisConfig::from_yaml(yaml).unwrap();
        assert!(config.enabled);
        assert!(!config.dynamic_enabled);
        assert_eq!(config.dynamic_timeout_ms, 3000);
        assert_eq!(config.max_charstring_ops, 25000);
        assert_eq!(config.max_stack_depth, 128);
        assert_eq!(config.max_fonts, 200);
    }

    #[test]
    fn test_config_to_json() {
        let config = FontAnalysisConfig::default();
        let json = config.to_json().unwrap();
        assert!(json.contains("\"enabled\""));
        assert!(json.contains("\"dynamic_enabled\""));
    }

    #[test]
    fn test_config_to_yaml() {
        let config = FontAnalysisConfig::default();
        let yaml = config.to_yaml().unwrap();
        assert!(yaml.contains("enabled:"));
        assert!(yaml.contains("dynamic_enabled:"));
    }

    #[test]
    fn test_config_roundtrip_json() {
        let config = FontAnalysisConfig::default();
        let json = config.to_json().unwrap();
        let config2 = FontAnalysisConfig::from_json(&json).unwrap();
        assert_eq!(config.enabled, config2.enabled);
        assert_eq!(config.dynamic_enabled, config2.dynamic_enabled);
        assert_eq!(config.max_stack_depth, config2.max_stack_depth);
    }
}

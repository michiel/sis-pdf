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
    Certain,
    Strong,
    Probable,
    Tentative,
    Weak,
    Heuristic,
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

    /// Enable CVE signature matching
    #[serde(default)]
    pub signature_matching_enabled: bool,

    /// Path to signature directory (defaults to embedded signatures)
    #[serde(default)]
    pub signature_directory: Option<String>,
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
            signature_matching_enabled: true,
            signature_directory: None, // Use embedded signatures
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
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize to JSON: {}", e))
    }

    /// Convert to YAML string
    pub fn to_yaml(&self) -> Result<String, String> {
        serde_yaml::to_string(self).map_err(|e| format!("Failed to serialize to YAML: {}", e))
    }

    /// Load CVE signatures based on configuration
    #[cfg(feature = "dynamic")]
    pub fn load_signatures(&self) -> Result<Vec<crate::signatures::Signature>, String> {
        if !self.signature_matching_enabled {
            return Ok(Vec::new());
        }

        if let Some(directory) = &self.signature_directory {
            // Load from custom directory
            crate::signatures::load_signatures_from_directory(directory)
        } else {
            // Load embedded signatures
            crate::signatures::load_embedded_signatures()
        }
    }

    #[cfg(not(feature = "dynamic"))]
    pub fn load_signatures(&self) -> Result<Vec<crate::signatures::Signature>, String> {
        Err("Signature matching requires 'dynamic' feature".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn require_result<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{}: {:?}", context, err),
        }
    }

    fn config_from_json(json: &str) -> FontAnalysisConfig {
        require_result(FontAnalysisConfig::from_json(json), "load config from JSON")
    }

    fn config_from_yaml(yaml: &str) -> FontAnalysisConfig {
        require_result(FontAnalysisConfig::from_yaml(yaml), "load config from YAML")
    }

    fn config_to_json(config: &FontAnalysisConfig) -> String {
        require_result(config.to_json(), "serialize config to JSON")
    }

    fn config_to_yaml(config: &FontAnalysisConfig) -> String {
        require_result(config.to_yaml(), "serialize config to YAML")
    }

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

        let config = config_from_json(json);
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

        let config = config_from_yaml(yaml);
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
        let json = config_to_json(&config);
        assert!(json.contains("\"enabled\""));
        assert!(json.contains("\"dynamic_enabled\""));
    }

    #[test]
    fn test_config_to_yaml() {
        let config = FontAnalysisConfig::default();
        let yaml = config_to_yaml(&config);
        assert!(yaml.contains("enabled:"));
        assert!(yaml.contains("dynamic_enabled:"));
    }

    #[test]
    fn test_config_roundtrip_json() {
        let config = FontAnalysisConfig::default();
        let json = config_to_json(&config);
        let config2 = config_from_json(&json);
        assert_eq!(config.enabled, config2.enabled);
        assert_eq!(config.dynamic_enabled, config2.dynamic_enabled);
        assert_eq!(config.max_stack_depth, config2.max_stack_depth);
    }

    #[test]
    fn test_signature_config_fields() {
        let config = FontAnalysisConfig::default();
        assert!(config.signature_matching_enabled);
        assert_eq!(config.signature_directory, None);
    }

    #[test]
    fn test_signature_config_from_json() {
        let json = r#"{
            "enabled": true,
            "dynamic_enabled": true,
            "dynamic_timeout_ms": 5000,
            "max_charstring_ops": 50000,
            "max_stack_depth": 256,
            "max_fonts": 100,
            "network_access": false,
            "signature_matching_enabled": false,
            "signature_directory": "/custom/path"
        }"#;

        let config = config_from_json(json);
        assert!(!config.signature_matching_enabled);
        assert_eq!(config.signature_directory, Some("/custom/path".to_string()));
    }

    #[test]
    #[cfg(feature = "dynamic")]
    fn test_load_signatures_disabled() {
        let config = FontAnalysisConfig { signature_matching_enabled: false, ..Default::default() };

        let signatures = require_result(config.load_signatures(), "load signatures disabled");
        assert_eq!(signatures.len(), 0);
    }

    #[test]
    #[cfg(feature = "dynamic")]
    fn test_load_signatures_from_embedded() {
        let config = FontAnalysisConfig::default();

        // This should succeed and load signatures from the embedded directory
        let signatures = require_result(config.load_signatures(), "load embedded signatures");
        // We expect at least the 3 signatures we migrated
        assert!(signatures.len() >= 3, "Expected at least 3 signatures, got {}", signatures.len());
    }
}

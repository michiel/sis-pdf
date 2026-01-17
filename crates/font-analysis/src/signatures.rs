/// CVE signature system for automated vulnerability detection

use crate::model::{Confidence, FontFinding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// CVE signature loaded from YAML/JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub cve_id: String,
    pub description: String,
    pub severity: SignatureSeverity,
    pub pattern: SignaturePattern,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SignatureSeverity {
    pub fn to_severity(&self) -> Severity {
        match self {
            SignatureSeverity::Info => Severity::Info,
            SignatureSeverity::Low => Severity::Low,
            SignatureSeverity::Medium => Severity::Medium,
            SignatureSeverity::High | SignatureSeverity::Critical => Severity::High,
        }
    }
}

/// Pattern matching specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignaturePattern {
    /// Table length mismatch
    TableLengthMismatch {
        table1: String,
        table2: String,
        condition: String, // e.g., "table1.length < 4 * table2.num_metrics"
    },
    /// Offset out of bounds
    OffsetOutOfBounds {
        table: String,
        field: String,
        bounds: String, // e.g., "file_length"
    },
    /// Operator sequence in charstrings
    OperatorSequence {
        operators: Vec<String>,
        min_count: usize,
    },
    /// Table size exceeds limit
    TableSizeExceeds {
        table: String,
        max_size: usize,
    },
    /// Glyph count mismatch
    GlyphCountMismatch {
        source1: String, // e.g., "maxp"
        source2: String, // e.g., "cff2"
        condition: String, // e.g., "source1 > source2"
    },
}

/// Signature registry
pub struct SignatureRegistry {
    signatures: Vec<Signature>,
}

impl SignatureRegistry {
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    /// Load signatures from YAML file
    pub fn load_from_yaml(yaml: &str) -> Result<Self, String> {
        let signatures: Vec<Signature> =
            serde_yaml::from_str(yaml).map_err(|e| format!("Failed to parse YAML: {}", e))?;

        Ok(Self { signatures })
    }

    /// Load signatures from JSON file
    pub fn load_from_json(json: &str) -> Result<Self, String> {
        let signatures: Vec<Signature> =
            serde_json::from_str(json).map_err(|e| format!("Failed to parse JSON: {}", e))?;

        Ok(Self { signatures })
    }

    /// Add a signature
    pub fn add(&mut self, signature: Signature) {
        self.signatures.push(signature);
    }

    /// Get all signatures
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Match signatures against font context (requires dynamic feature)
    #[cfg(feature = "dynamic")]
    pub fn match_signatures(
        &self,
        context: &crate::dynamic::FontContext,
    ) -> Vec<FontFinding> {
        let mut findings = Vec::new();

        for sig in &self.signatures {
            if let Some(finding) = self.try_match_signature(sig, context) {
                findings.push(finding);
            }
        }

        findings
    }

    #[cfg(feature = "dynamic")]
    fn try_match_signature(
        &self,
        sig: &Signature,
        context: &crate::dynamic::FontContext,
    ) -> Option<FontFinding> {
        let matched = match &sig.pattern {
            SignaturePattern::TableLengthMismatch { table1, table2, condition } => {
                self.check_table_length_mismatch(context, table1, table2, condition)
            }
            SignaturePattern::GlyphCountMismatch { source1, source2, condition } => {
                self.check_glyph_count_mismatch(context, source1, source2, condition)
            }
            SignaturePattern::TableSizeExceeds { table, max_size } => {
                self.check_table_size_exceeds(context, table, *max_size)
            }
            _ => false,
        };

        if matched {
            let mut meta = HashMap::new();
            meta.insert("cve".to_string(), sig.cve_id.clone());
            for (i, ref_url) in sig.references.iter().enumerate() {
                meta.insert(format!("reference_{}", i), ref_url.clone());
            }

            Some(FontFinding {
                kind: format!("font.{}", sig.cve_id.to_lowercase().replace('-', "_")),
                severity: sig.severity.to_severity(),
                confidence: Confidence::Strong,
                title: format!("{}: Vulnerability detected", sig.cve_id),
                description: sig.description.clone(),
                meta,
            })
        } else {
            None
        }
    }

    #[cfg(feature = "dynamic")]
    fn check_table_length_mismatch(
        &self,
        context: &crate::dynamic::FontContext,
        table1: &str,
        table2: &str,
        _condition: &str,
    ) -> bool {
        // Simple implementation for hmtx/hhea case
        if table1 == "hmtx" && table2 == "hhea" {
            if let (Some(num_h_metrics), Some(hmtx_length)) = (context.num_h_metrics, context.hmtx_length) {
                let required = (num_h_metrics as usize) * 4;
                return hmtx_length < required;
            }
        }
        false
    }

    #[cfg(feature = "dynamic")]
    fn check_glyph_count_mismatch(
        &self,
        context: &crate::dynamic::FontContext,
        source1: &str,
        source2: &str,
        condition: &str,
    ) -> bool {
        // Check maxp > cff2 case
        if source1 == "maxp" && source2 == "cff2" && condition.contains(">") {
            if let (Some(maxp_count), Some(cff_count)) = (context.glyph_count_maxp, context.glyph_count_cff) {
                return (maxp_count as usize) > cff_count;
            }
        }
        false
    }

    #[cfg(feature = "dynamic")]
    fn check_table_size_exceeds(
        &self,
        context: &crate::dynamic::FontContext,
        table: &str,
        max_size: usize,
    ) -> bool {
        context.tables.iter()
            .find(|t| t.tag == table)
            .map(|t| t.length > max_size)
            .unwrap_or(false)
    }
}

impl Default for SignatureRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_from_yaml() {
        let yaml = r#"
- cve_id: CVE-2025-27163
  description: "hmtx/hhea table length mismatch"
  severity: high
  pattern:
    type: table_length_mismatch
    table1: hmtx
    table2: hhea
    condition: "table1.length < 4 * table2.num_metrics"
  references:
    - "https://nvd.nist.gov/vuln/detail/CVE-2025-27163"
"#;

        let registry = SignatureRegistry::load_from_yaml(yaml).unwrap();
        assert_eq!(registry.signatures().len(), 1);
        assert_eq!(registry.signatures()[0].cve_id, "CVE-2025-27163");
    }

    #[test]
    fn test_load_from_json() {
        let json = r#"[
            {
                "cve_id": "CVE-2025-27164",
                "description": "CFF2/maxp glyph count mismatch",
                "severity": "high",
                "pattern": {
                    "type": "glyph_count_mismatch",
                    "source1": "maxp",
                    "source2": "cff2",
                    "condition": "source1 > source2"
                },
                "references": []
            }
        ]"#;

        let registry = SignatureRegistry::load_from_json(json).unwrap();
        assert_eq!(registry.signatures().len(), 1);
        assert_eq!(registry.signatures()[0].cve_id, "CVE-2025-27164");
    }

    #[test]
    fn test_signature_severity_conversion() {
        assert!(matches!(SignatureSeverity::Low.to_severity(), Severity::Low));
        assert!(matches!(SignatureSeverity::High.to_severity(), Severity::High));
        assert!(matches!(SignatureSeverity::Critical.to_severity(), Severity::High));
    }
}

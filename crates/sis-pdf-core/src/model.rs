use serde::{Deserialize, Serialize};
use sis_pdf_pdf::span::Span;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum AttackSurface {
    FileStructure,
    XRefTrailer,
    ObjectStreams,
    StreamsAndFilters,
    Actions,
    JavaScript,
    Forms,
    EmbeddedFiles,
    RichMedia3D,
    Images,
    CryptoSignatures,
    Metadata,
    ContentPhishing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Confidence {
    Certain,
    Strong,
    Probable,
    Tentative,
    Weak,
    Heuristic,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Certain => "certain",
            Confidence::Strong => "strong",
            Confidence::Probable => "probable",
            Confidence::Tentative => "tentative",
            Confidence::Weak => "weak",
            Confidence::Heuristic => "heuristic",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Impact {
    Critical,
    High,
    Medium,
    Low,
    None,
    /// Impact has not been assessed for this finding.
    /// Used as the non-optional default; prefer an explicit value where possible.
    Unknown,
}

impl Impact {
    pub fn as_str(&self) -> &'static str {
        match self {
            Impact::Critical => "critical",
            Impact::High => "high",
            Impact::Medium => "medium",
            Impact::Low => "low",
            Impact::None => "none",
            Impact::Unknown => "unknown",
        }
    }
}

fn default_impact() -> Impact {
    Impact::Unknown
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceSource {
    File,
    Decoded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSpan {
    pub source: EvidenceSource,
    pub offset: u64,
    pub length: u32,
    pub origin: Option<Span>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub surface: AttackSurface,
    pub kind: String,
    pub severity: Severity,
    pub confidence: Confidence,
    #[serde(default = "default_impact")]
    pub impact: Impact,
    pub title: String,
    pub description: String,
    pub objects: Vec<String>,
    pub evidence: Vec<EvidenceSpan>,
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub positions: Vec<String>,
    #[serde(default)]
    pub meta: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_initiation: Option<String>,
    #[serde(default)]
    pub yara: Option<YaraAnnotation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraAnnotation {
    pub rule_name: String,
    pub tags: Vec<String>,
    pub strings: Vec<String>,
    pub namespace: Option<String>,
}

impl Default for Finding {
    fn default() -> Self {
        Self {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: String::new(),
            severity: Severity::Info,
            confidence: Confidence::Heuristic,
            impact: Impact::Unknown,
            title: String::new(),
            description: String::new(),
            objects: Vec::new(),
            evidence: Vec::new(),
            remediation: None,
            positions: Vec::new(),
            meta: HashMap::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
        }
    }
}

impl Finding {
    /// Returns `true` if the metadata key exists and its value is the string `"true"`.
    pub fn meta_bool(&self, key: &str) -> bool {
        self.meta.get(key).map(|v| v == "true").unwrap_or(false)
    }

    /// Returns the metadata value parsed as `f64`, or `None` if absent or unparseable.
    pub fn meta_f64(&self, key: &str) -> Option<f64> {
        self.meta.get(key).and_then(|v| v.parse().ok())
    }

    /// Returns the metadata value parsed as `u32`, or `None` if absent or unparseable.
    pub fn meta_u32(&self, key: &str) -> Option<u32> {
        self.meta.get(key).and_then(|v| v.parse().ok())
    }

    /// Returns the metadata value parsed as `usize`, or `None` if absent or unparseable.
    pub fn meta_usize(&self, key: &str) -> Option<usize> {
        self.meta.get(key).and_then(|v| v.parse().ok())
    }

    /// Returns the metadata value as a `&str`, or `None` if absent.
    pub fn meta_str(&self, key: &str) -> Option<&str> {
        self.meta.get(key).map(String::as_str)
    }

    pub fn template(
        surface: AttackSurface,
        kind: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Finding {
            surface,
            kind: kind.into(),
            severity,
            confidence,
            title: title.into(),
            description: description.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct FindingBuilder {
    finding: Finding,
}

impl FindingBuilder {
    pub fn template(
        surface: AttackSurface,
        kind: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self { finding: Finding::template(surface, kind, severity, confidence, title, description) }
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.finding.id = id.into();
        self
    }

    pub fn impact(mut self, impact: Impact) -> Self {
        self.finding.impact = impact;
        self
    }

    pub fn meta<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.finding.meta.insert(key.into(), value.into());
        self
    }

    pub fn extend_meta<K, V, I>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (key, value) in entries {
            self.finding.meta.insert(key.into(), value.into());
        }
        self
    }

    pub fn objects<I>(mut self, objects: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        self.finding.objects.extend(objects);
        self
    }

    pub fn evidence(mut self, spans: impl IntoIterator<Item = EvidenceSpan>) -> Self {
        self.finding.evidence.extend(spans);
        self
    }

    pub fn action_type(mut self, action_type: impl Into<String>) -> Self {
        self.finding.action_type = Some(action_type.into());
        self
    }

    pub fn action_target(mut self, action_target: impl Into<String>) -> Self {
        self.finding.action_target = Some(action_target.into());
        self
    }

    pub fn action_initiation(mut self, initiation: impl Into<String>) -> Self {
        self.finding.action_initiation = Some(initiation.into());
        self
    }

    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.finding.remediation = Some(remediation.into());
        self
    }

    pub fn positions<I>(mut self, positions: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        self.finding.positions.extend(positions);
        self
    }

    pub fn build(self) -> Finding {
        self.finding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::EvidenceBuilder;
    use serde_json::json;

    #[test]
    fn builder_populates_metadata() -> serde_json::Result<()> {
        let finding = FindingBuilder::template(
            AttackSurface::Actions,
            "test_kind",
            Severity::High,
            Confidence::Certain,
            "Test",
            "Test description",
        )
        .impact(Impact::High)
        .objects(vec!["1 0 obj".into()])
        .meta("meta.cve", "CVE-2025-27363")
        .action_type("Launch")
        .action_target("cmd.exe")
        .action_initiation("automatic")
        .evidence(EvidenceBuilder::new().file_offset(0, 4, "test").build())
        .build();

        let serialized = serde_json::to_value(&finding)?;
        assert_eq!(serialized["impact"], json!("High"));
        assert_eq!(serialized["action_type"], json!("Launch"));
        assert_eq!(serialized["meta"]["meta.cve"], json!("CVE-2025-27363"));
        Ok(())
    }
}

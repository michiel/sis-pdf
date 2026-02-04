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
}

impl Impact {
    pub fn as_str(&self) -> &'static str {
        match self {
            Impact::Critical => "critical",
            Impact::High => "high",
            Impact::Medium => "medium",
            Impact::Low => "low",
            Impact::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum ReaderProfile {
    Acrobat,
    Pdfium,
    Preview,
}

impl ReaderProfile {
    pub const ALL: [ReaderProfile; 3] =
        [ReaderProfile::Acrobat, ReaderProfile::Pdfium, ReaderProfile::Preview];

    pub fn name(&self) -> &'static str {
        match self {
            ReaderProfile::Acrobat => "acrobat",
            ReaderProfile::Pdfium => "pdfium",
            ReaderProfile::Preview => "preview",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaderImpact {
    pub profile: ReaderProfile,
    pub surface: AttackSurface,
    pub severity: Severity,
    pub impact: Impact,
    pub note: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<Impact>,
    pub title: String,
    pub description: String,
    pub objects: Vec<String>,
    pub evidence: Vec<EvidenceSpan>,
    pub remediation: Option<String>,
    #[serde(default)]
    pub position: Option<String>,
    #[serde(default)]
    pub positions: Vec<String>,
    #[serde(default)]
    pub meta: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reader_impacts: Vec<ReaderImpact>,
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
            impact: None,
            title: String::new(),
            description: String::new(),
            objects: Vec::new(),
            evidence: Vec::new(),
            remediation: None,
            position: None,
            positions: Vec::new(),
            meta: HashMap::new(),
            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
        }
    }
}

impl Finding {
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
        self.finding.impact = Some(impact);
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

    pub fn reader_impact(mut self, impact: ReaderImpact) -> Self {
        self.finding.reader_impacts.push(impact);
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

    pub fn position(mut self, position: impl Into<String>) -> Self {
        self.finding.position = Some(position.into());
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
    fn builder_populates_metadata_and_reader_impact() -> serde_json::Result<()> {
        let reader_impact = ReaderImpact {
            profile: ReaderProfile::Acrobat,
            surface: AttackSurface::Actions,
            severity: Severity::High,
            impact: Impact::High,
            note: Some("Test note".into()),
        };

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
        .reader_impact(reader_impact.clone())
        .evidence(EvidenceBuilder::new().file_offset(0, 4, "test").build())
        .build();

        let serialized = serde_json::to_value(&finding)?;
        assert_eq!(serialized["impact"], json!("High"));
        assert_eq!(serialized["action_type"], json!("Launch"));
        assert_eq!(serialized["reader_impacts"][0]["surface"], json!("Actions"));
        assert_eq!(serialized["reader_impacts"][0]["profile"], json!("Acrobat"));
        assert_eq!(serialized["reader_impacts"][0]["note"], json!(reader_impact.note));
        assert_eq!(serialized["meta"]["meta.cve"], json!("CVE-2025-27363"));
        Ok(())
    }
}

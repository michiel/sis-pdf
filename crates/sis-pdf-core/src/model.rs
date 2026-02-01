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
    pub const ALL: [ReaderProfile; 3] = [
        ReaderProfile::Acrobat,
        ReaderProfile::Pdfium,
        ReaderProfile::Preview,
    ];

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
        let mut base = Finding::default();
        base.surface = surface;
        base.kind = kind.into();
        base.severity = severity;
        base.confidence = confidence;
        base.title = title.into();
        base.description = description.into();
        base
    }
}

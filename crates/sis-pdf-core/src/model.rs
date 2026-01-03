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
    CryptoSignatures,
    Metadata,
    ContentPhishing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum Confidence {
    Heuristic,
    Probable,
    Strong,
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
    pub title: String,
    pub description: String,
    pub objects: Vec<String>,
    pub evidence: Vec<EvidenceSpan>,
    pub remediation: Option<String>,
    #[serde(default)]
    pub meta: HashMap<String, String>,
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

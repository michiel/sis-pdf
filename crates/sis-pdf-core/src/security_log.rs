use crate::model::Severity;
use std::fmt;
use tracing::Level;

#[derive(Debug, Clone, Copy)]
pub enum SecurityDomain {
    PdfStructure,
    Javascript,
    EmbeddedFile,
    Xref,
    Encryption,
    ObjectStream,
    Cache,
    Parser,
    Detection,
    Ml,
}

impl SecurityDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityDomain::PdfStructure => "pdf.structure",
            SecurityDomain::Javascript => "pdf.javascript",
            SecurityDomain::EmbeddedFile => "pdf.embedded_file",
            SecurityDomain::Xref => "pdf.xref",
            SecurityDomain::Encryption => "pdf.encryption",
            SecurityDomain::ObjectStream => "pdf.object_stream",
            SecurityDomain::Cache => "runtime.cache",
            SecurityDomain::Parser => "runtime.parser",
            SecurityDomain::Detection => "runtime.detection",
            SecurityDomain::Ml => "ml.inference",
        }
    }
}

impl fmt::Display for SecurityDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SecurityEvent<'a> {
    pub level: Level,
    pub domain: SecurityDomain,
    pub severity: Severity,
    pub kind: &'a str,
    pub policy: Option<&'a str>,
    pub object_id: Option<&'a str>,
    pub object_type: Option<&'a str>,
    pub vector: Option<&'a str>,
    pub technique: Option<&'a str>,
    pub confidence: Option<f32>,
    pub message: &'a str,
}

impl<'a> SecurityEvent<'a> {
    pub fn emit(self) {
        match self.level {
            Level::TRACE => tracing::event!(
                Level::TRACE,
                security = true,
                domain = %self.domain,
                severity = ?self.severity,
                kind = self.kind,
                policy = self.policy,
                object_id = self.object_id,
                object_type = self.object_type,
                vector = self.vector,
                technique = self.technique,
                confidence = self.confidence,
                "{message}",
                message = self.message
            ),
            Level::DEBUG => tracing::event!(
                Level::DEBUG,
                security = true,
                domain = %self.domain,
                severity = ?self.severity,
                kind = self.kind,
                policy = self.policy,
                object_id = self.object_id,
                object_type = self.object_type,
                vector = self.vector,
                technique = self.technique,
                confidence = self.confidence,
                "{message}",
                message = self.message
            ),
            Level::INFO => tracing::event!(
                Level::INFO,
                security = true,
                domain = %self.domain,
                severity = ?self.severity,
                kind = self.kind,
                policy = self.policy,
                object_id = self.object_id,
                object_type = self.object_type,
                vector = self.vector,
                technique = self.technique,
                confidence = self.confidence,
                "{message}",
                message = self.message
            ),
            Level::WARN => tracing::event!(
                Level::WARN,
                security = true,
                domain = %self.domain,
                severity = ?self.severity,
                kind = self.kind,
                policy = self.policy,
                object_id = self.object_id,
                object_type = self.object_type,
                vector = self.vector,
                technique = self.technique,
                confidence = self.confidence,
                "{message}",
                message = self.message
            ),
            Level::ERROR => tracing::event!(
                Level::ERROR,
                security = true,
                domain = %self.domain,
                severity = ?self.severity,
                kind = self.kind,
                policy = self.policy,
                object_id = self.object_id,
                object_type = self.object_type,
                vector = self.vector,
                technique = self.technique,
                confidence = self.confidence,
                "{message}",
                message = self.message
            ),
        }
    }
}

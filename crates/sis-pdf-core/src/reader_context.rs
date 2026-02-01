use crate::model::{AttackSurface, Finding, Severity};

#[derive(Clone, Copy)]
pub enum ReaderProfile {
    Acrobat,
    Pdfium,
    Preview,
}

impl ReaderProfile {
    const ALL: [ReaderProfile; 3] = [Self::Acrobat, Self::Pdfium, Self::Preview];

    fn name(&self) -> &'static str {
        match self {
            ReaderProfile::Acrobat => "acrobat",
            ReaderProfile::Pdfium => "pdfium",
            ReaderProfile::Preview => "preview",
        }
    }
}

fn cap_severity(base: Severity, cap: Severity) -> Severity {
    std::cmp::min(base, cap)
}

fn severity_for_profile(
    profile: ReaderProfile,
    surface: AttackSurface,
    base: Severity,
) -> Severity {
    match profile {
        ReaderProfile::Acrobat => base,
        ReaderProfile::Pdfium => match surface {
            AttackSurface::JavaScript => cap_severity(base, Severity::Medium),
            AttackSurface::EmbeddedFiles => cap_severity(base, Severity::High),
            _ => base,
        },
        ReaderProfile::Preview => match surface {
            AttackSurface::JavaScript => cap_severity(base, Severity::Low),
            AttackSurface::Actions => cap_severity(base, Severity::Medium),
            AttackSurface::EmbeddedFiles => cap_severity(base, Severity::Medium),
            _ => base,
        },
    }
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

pub fn annotate_reader_context(finding: &mut Finding) {
    for profile in ReaderProfile::ALL {
        let severity = severity_for_profile(profile, finding.surface, finding.severity);
        finding.meta.insert(
            format!("reader.impact.{}", profile.name()),
            severity.as_str().to_string(),
        );
    }
}

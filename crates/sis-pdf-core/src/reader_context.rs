use crate::model::{AttackSurface, Finding, Impact, ReaderImpact, ReaderProfile, Severity};

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
    let mut impacts = Vec::new();
    for profile in ReaderProfile::ALL {
        let severity = severity_for_profile(profile, finding.surface, finding.severity);
        let impact = impact_from_severity(severity);
        if profile != ReaderProfile::Acrobat && severity != finding.severity {
            let note = Some(format!(
                "Severity capped to {} for {} due to reader limits",
                severity.as_str(),
                profile.name()
            ));
            impacts.push(ReaderImpact {
                profile,
                surface: finding.surface,
                severity,
                impact,
                note,
            });
        } else {
            impacts.push(ReaderImpact {
                profile,
                surface: finding.surface,
                severity,
                impact,
                note: None,
            });
        }
        finding.meta.insert(
            format!("reader.impact.{}", profile.name()),
            severity.as_str().to_string(),
        );
    }
    finding.meta.insert(
        "reader.impact.summary".into(),
        impacts
            .iter()
            .map(|impact| {
                format!(
                    "{}:{}/{}",
                    impact.profile.name(),
                    impact.severity.as_str(),
                    impact.impact.to_string().to_lowercase()
                )
            })
            .collect::<Vec<_>>()
            .join(","),
    );
    finding.reader_impacts = impacts;
}

fn impact_from_severity(severity: Severity) -> Impact {
    match severity {
        Severity::Critical => Impact::Critical,
        Severity::High => Impact::High,
        Severity::Medium => Impact::Medium,
        Severity::Low => Impact::Low,
        Severity::Info => Impact::None,
    }
}

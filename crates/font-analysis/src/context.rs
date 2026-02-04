/// Context-aware severity adjustment for font analysis findings
///
/// Adjusts finding severity based on the source and environment context.
use crate::model::{FontFinding, Severity};
use tracing::{debug, instrument};

/// Analysis context describing the source and environment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum AnalysisContext {
    /// Font from a trusted source (e.g., system fonts, signed PDFs)
    TrustedSource,

    /// PDF with valid digital signature
    SignedPDF,

    /// Font from untrusted user input
    #[default]
    UntrustedInput,

    /// Server-side processing (stricter rules)
    Server,

    /// Desktop application (more permissive)
    Desktop,
}


impl AnalysisContext {
    /// Adjust severity based on context
    #[instrument(skip(self, finding), fields(kind = %finding.kind, original_severity = ?finding.severity))]
    pub fn adjust_severity(&self, finding: &mut FontFinding) {
        let original = finding.severity;

        finding.severity = match self {
            AnalysisContext::TrustedSource => {
                // Downgrade findings from trusted sources
                match original {
                    Severity::High => Severity::Medium,
                    Severity::Medium => Severity::Low,
                    other => other,
                }
            }
            AnalysisContext::SignedPDF => {
                // Slightly downgrade if PDF is signed (but still be cautious)
                match original {
                    Severity::Medium => Severity::Low,
                    other => other,
                }
            }
            AnalysisContext::UntrustedInput => {
                // No change - use original severity
                original
            }
            AnalysisContext::Server => {
                // Escalate on server contexts (more strict)
                match original {
                    Severity::Low => Severity::Medium,
                    Severity::Medium => Severity::High,
                    other => other,
                }
            }
            AnalysisContext::Desktop => {
                // Slight downgrade on desktop (more permissive)
                match original {
                    Severity::High => Severity::Medium,
                    other => other,
                }
            }
        };

        if finding.severity != original {
            debug!(
                context = ?self,
                original = ?original,
                adjusted = ?finding.severity,
                "Severity adjusted based on context"
            );
        }
    }

    /// Adjust all findings in a collection
    pub fn adjust_findings(&self, findings: &mut [FontFinding]) {
        for finding in findings {
            self.adjust_severity(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Confidence;
    use std::collections::HashMap;

    fn make_test_finding(severity: Severity) -> FontFinding {
        FontFinding {
            kind: "test.finding".to_string(),
            severity,
            confidence: Confidence::Probable,
            title: "Test Finding".to_string(),
            description: "Test description".to_string(),
            meta: HashMap::new(),
        }
    }

    #[test]
    fn test_trusted_source_downgrades() {
        let ctx = AnalysisContext::TrustedSource;

        let mut finding = make_test_finding(Severity::High);
        ctx.adjust_severity(&mut finding);
        assert_eq!(finding.severity, Severity::Medium);

        let mut finding = make_test_finding(Severity::Medium);
        ctx.adjust_severity(&mut finding);
        assert_eq!(finding.severity, Severity::Low);

        let mut finding = make_test_finding(Severity::Low);
        ctx.adjust_severity(&mut finding);
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn test_server_context_escalates() {
        let ctx = AnalysisContext::Server;

        let mut finding = make_test_finding(Severity::Low);
        ctx.adjust_severity(&mut finding);
        assert_eq!(finding.severity, Severity::Medium);

        let mut finding = make_test_finding(Severity::Medium);
        ctx.adjust_severity(&mut finding);
        assert_eq!(finding.severity, Severity::High);

        let mut finding = make_test_finding(Severity::High);
        ctx.adjust_severity(&mut finding);
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn test_untrusted_input_no_change() {
        let ctx = AnalysisContext::UntrustedInput;

        let mut finding = make_test_finding(Severity::High);
        ctx.adjust_severity(&mut finding);
        assert_eq!(finding.severity, Severity::High);

        let mut finding = make_test_finding(Severity::Low);
        ctx.adjust_severity(&mut finding);
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn test_adjust_findings_batch() {
        let ctx = AnalysisContext::Server;

        let mut findings = vec![
            make_test_finding(Severity::Low),
            make_test_finding(Severity::Medium),
            make_test_finding(Severity::High),
        ];

        ctx.adjust_findings(&mut findings);

        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[1].severity, Severity::High);
        assert_eq!(findings[2].severity, Severity::High);
    }
}

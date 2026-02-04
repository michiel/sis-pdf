use sis_pdf_core::model::{AttackSurface, Confidence, Finding, ReaderProfile, Severity};
use sis_pdf_core::reader_context::annotate_reader_context;

#[test]
fn reader_context_caps_severity_for_javascript() {
    let mut finding = Finding::template(
        AttackSurface::JavaScript,
        "reader.context.test",
        Severity::High,
        Confidence::Strong,
        "Reader context caps",
        "Verify severity caps per profile",
    );

    annotate_reader_context(&mut finding);

    assert_eq!(finding.reader_impacts.len(), 3);
    assert_eq!(finding.reader_impacts[0].profile, ReaderProfile::Acrobat);
    assert_eq!(finding.reader_impacts[0].severity, Severity::High);
    assert_eq!(finding.reader_impacts[1].profile, ReaderProfile::Pdfium);
    assert_eq!(finding.reader_impacts[1].severity, Severity::Medium);
    assert_eq!(finding.reader_impacts[2].profile, ReaderProfile::Preview);
    assert_eq!(finding.reader_impacts[2].severity, Severity::Low);

    assert!(finding.reader_impacts[1].note.as_deref().unwrap_or("").contains("pdfium"));
    assert!(finding.reader_impacts[2].note.as_deref().unwrap_or("").contains("preview"));

    assert_eq!(
        finding.meta.get("reader.impact.summary"),
        Some(&"acrobat:high/high,pdfium:medium/medium,preview:low/low".to_string())
    );
    assert_eq!(finding.meta.get("reader.impact.pdfium"), Some(&"medium".to_string()));
}

#[test]
fn reader_context_notes_only_when_severity_changes() {
    let mut finding = Finding::template(
        AttackSurface::Metadata,
        "reader.context.metadata",
        Severity::Medium,
        Confidence::Probable,
        "Reader context metadata",
        "No caps should apply",
    );

    annotate_reader_context(&mut finding);

    assert_eq!(finding.reader_impacts.len(), 3);
    assert!(finding.reader_impacts.iter().all(|impact| impact.severity == Severity::Medium));
    assert!(finding.reader_impacts.iter().all(|impact| impact.note.is_none()));
    assert_eq!(
        finding.meta.get("reader.impact.summary"),
        Some(&"acrobat:medium/medium,pdfium:medium/medium,preview:medium/medium".to_string())
    );
}

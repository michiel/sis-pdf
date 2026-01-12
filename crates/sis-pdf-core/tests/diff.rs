use sis_pdf_core::diff::{diff_summary, diff_with_lopdf};
use sis_pdf_pdf::{parse_pdf, ParseOptions};

#[test]
fn diff_summary_matches_findings() {
    let bytes = include_bytes!("fixtures/annot_uri.pdf");
    let graph = parse_pdf(
        bytes,
        ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 5_000_000,
            max_objects: 500_000,
            max_objstm_total_bytes: 256 * 1024 * 1024,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        },
    )
    .expect("parse synthetic.pdf");
    let summary = diff_summary(bytes, &graph).expect("diff summary");
    let diff_result = diff_with_lopdf(bytes, &graph);
    let findings = diff_result.findings;

    let object_diff = findings
        .iter()
        .any(|f| f.kind == "parser_object_count_diff");
    let trailer_diff = findings
        .iter()
        .any(|f| f.kind == "parser_trailer_count_diff");

    assert_eq!(
        summary.primary_objects != summary.secondary_objects,
        object_diff
    );
    assert_eq!(
        summary.primary_trailers != summary.secondary_trailers,
        trailer_diff
    );
}

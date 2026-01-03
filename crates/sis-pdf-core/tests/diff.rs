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
        },
    )
    .expect("parse synthetic.pdf");
    let summary = diff_summary(bytes, &graph).expect("diff summary");
    let findings = diff_with_lopdf(bytes, &graph);

    let object_diff = findings
        .iter()
        .any(|f| f.kind == "parser_object_count_diff");
    let trailer_diff = findings
        .iter()
        .any(|f| f.kind == "parser_trailer_count_diff");

    assert_eq!(summary.primary_objects != summary.secondary_objects, object_diff);
    assert_eq!(summary.primary_trailers != summary.secondary_trailers, trailer_diff);
}

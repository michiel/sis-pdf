mod common;

use common::default_scan_opts;
use sis_pdf_detectors::default_detectors;

#[test]
fn incremental_xref_findings_emit_graph_evasion_metadata() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/filters/action_incremental.pdf");
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");

    let xref_conflict = report
        .findings
        .iter()
        .find(|finding| finding.kind == "xref_conflict")
        .expect("xref_conflict finding");
    assert_eq!(
        xref_conflict.meta.get("graph.evasion_kind").map(String::as_str),
        Some("xref_conflict")
    );
    assert_eq!(
        xref_conflict.meta.get("chain.capability").map(String::as_str),
        Some("graph_xref_evasion")
    );
    assert!(xref_conflict
        .meta
        .get("graph.depth")
        .and_then(|value| value.parse::<u32>().ok())
        .is_some_and(|depth| depth >= 1));

    let incremental = report
        .findings
        .iter()
        .find(|finding| finding.kind == "incremental_update_chain")
        .expect("incremental_update_chain finding");
    assert_eq!(
        incremental.meta.get("graph.evasion_kind").map(String::as_str),
        Some("incremental_overlay")
    );
    assert_eq!(
        incremental.meta.get("chain.capability").map(String::as_str),
        Some("graph_incremental_overlay")
    );
    assert!(incremental
        .meta
        .get("graph.conflict_count")
        .and_then(|value| value.parse::<u32>().ok())
        .is_some_and(|count| count >= 1));
}

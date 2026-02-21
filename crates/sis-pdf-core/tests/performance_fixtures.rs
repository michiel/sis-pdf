use sis_pdf_core::runner::run_scan_with_detectors;
use sis_pdf_core::scan::{FontAnalysisOptions, ImageAnalysisOptions, ProfileFormat, ScanOptions};
use sis_pdf_core::structure_overlay::{build_structure_overlay, StructureOverlayBuildOptions};
use sis_pdf_detectors::default_detectors;
use sis_pdf_pdf::{parse_pdf, ParseOptions};
use std::path::PathBuf;
use std::time::Instant;

fn scan_fixture(name: &str) -> sis_pdf_core::report::Report {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures");
    path.push(name);
    let bytes = std::fs::read(&path).expect("fixture exists");
    let opts = ScanOptions {
        deep: true,
        max_decode_bytes: 32 * 1024 * 1024,
        max_total_decoded_bytes: 256 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        batch_parallel: false,
        diff_parser: true,
        max_objects: 500_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        strict: false,
        strict_summary: false,
        ir: false,
        ml_config: None,
        font_analysis: FontAnalysisOptions::default(),
        image_analysis: ImageAnalysisOptions::default(),
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
        correlation: Default::default(),
        yara_scope: None,
    };
    run_scan_with_detectors(&bytes, opts, &default_detectors()).expect("scan succeeds")
}

#[test]
fn vera_pdf_metadata_trailer_findings() {
    let report = scan_fixture("veraPDF-6-6-2-3-1-t01-fail-r.pdf");
    let kinds: Vec<&str> = report.findings.iter().map(|f| f.kind.as_str()).collect();
    for expected in ["pdf.trailer_inconsistent", "content_image_only_page"] {
        assert!(kinds.contains(&expected), "{} missing", expected);
    }
}

#[test]
fn unknown_filter_bundle() {
    let report = scan_fixture("unknown-filter-4387ba48.pdf");
    let kinds: Vec<&str> = report.findings.iter().map(|f| f.kind.as_str()).collect();
    for expected in ["embedded_payload_carved", "pdf.trailer_inconsistent"] {
        assert!(kinds.contains(&expected), "{} missing", expected);
    }
    assert!(
        kinds.contains(&"declared_filter_invalid") || kinds.contains(&"label_mismatch_stream_type"),
        "expected filter mismatch finding, got {:?}",
        kinds
    );
}

#[test]
fn qpdf_bad30_findings() {
    let report = scan_fixture("qpdf-bad30.pdf");
    let kinds: Vec<&str> = report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains(&"parser_trailer_count_diff"));
    assert!(kinds.contains(&"pdf.trailer_inconsistent"));
    assert!(kinds.contains(&"undeclared_compression_present"));
}

#[test]
fn structure_overlay_p2_build_budget() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/corpus_captured/modern-renderer-revision-8d42d425.pdf");
    let bytes = std::fs::read(&path).expect("fixture exists");

    let scan_opts = ScanOptions {
        deep: true,
        max_decode_bytes: 32 * 1024 * 1024,
        max_total_decoded_bytes: 256 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        batch_parallel: false,
        diff_parser: false,
        max_objects: 500_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        strict: false,
        strict_summary: false,
        ir: false,
        ml_config: None,
        font_analysis: FontAnalysisOptions::default(),
        image_analysis: ImageAnalysisOptions::default(),
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
        correlation: Default::default(),
        yara_scope: None,
    };

    let graph = parse_pdf(
        &bytes,
        ParseOptions {
            recover_xref: scan_opts.recover_xref,
            deep: scan_opts.deep,
            strict: scan_opts.strict,
            max_objstm_bytes: scan_opts.max_decode_bytes,
            max_objects: scan_opts.max_objects,
            max_objstm_total_bytes: scan_opts.max_total_decoded_bytes,
            carve_stream_objects: scan_opts.deep,
            max_carved_objects: 2_000,
            max_carved_bytes: scan_opts.max_decode_bytes,
        },
    )
    .expect("parse fixture");

    let ctx = sis_pdf_core::scan::ScanContext::new(&bytes, graph, scan_opts);
    let start = Instant::now();
    let overlay = build_structure_overlay(&ctx, StructureOverlayBuildOptions::default());
    let elapsed_ms = start.elapsed().as_millis() as u64;

    assert!(!overlay.nodes.is_empty(), "overlay should include pseudo nodes");
    assert!(!overlay.edges.is_empty(), "overlay should include forensic edges");
    assert!(elapsed_ms <= 100, "overlay build exceeded 100 ms budget: {} ms", elapsed_ms);
}

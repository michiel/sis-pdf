use sis_pdf_core::scan::{
    CorrelationOptions, FontAnalysisOptions, ImageAnalysisOptions, ProfileFormat, ScanOptions,
};
use sis_pdf_pdf::{parse_pdf, ParseOptions};

fn base_opts(deep: bool) -> ScanOptions {
    ScanOptions {
        deep,
        max_decode_bytes: 8 * 1024 * 1024,
        max_total_decoded_bytes: 64 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        batch_parallel: false,
        diff_parser: false,
        max_objects: 100_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        yara_scope: None,
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
        correlation: CorrelationOptions::default(),
    }
}

fn has_finding(report: &sis_pdf_core::report::Report, kind: &str) -> bool {
    report.findings.iter().any(|f| f.kind == kind)
}

#[test]
fn cve_2009_0658_jbig2_static() {
    let bytes = include_bytes!("fixtures/images/cve-2009-0658-jbig2.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, base_opts(false), &detectors)
        .expect("scan should succeed");
    assert!(has_finding(&report, "image.jbig2_present"));
}

#[test]
fn cve_2018_4990_jpx_dynamic() {
    let bytes = include_bytes!("fixtures/images/cve-2018-4990-jpx.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, base_opts(true), &detectors)
        .expect("scan should succeed");
    assert!(has_finding(&report, "image.jpx_present"));
    assert!(has_finding(&report, "image.jpx_malformed"));
}

#[test]
fn cve_2010_0188_xfa_tiff_static() {
    let bytes = include_bytes!("fixtures/images/cve-2010-0188-xfa-tiff.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, base_opts(false), &detectors)
        .expect("scan should succeed");
    assert!(has_finding(&report, "image.xfa_image_present"));
}

#[test]
fn cve_2021_30860_jbig2_dynamic() {
    let bytes = include_bytes!("fixtures/images/cve-2021-30860-jbig2.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, base_opts(true), &detectors)
        .expect("scan should succeed");
    assert!(has_finding(&report, "image.jbig2_present"));
    assert!(has_finding(&report, "image.decode_too_large"));
    assert!(has_finding(&report, "image.extreme_dimensions"));
    assert!(has_finding(&report, "image.pixel_count_excessive"));
    assert!(has_finding(&report, "image.zero_click_jbig2"));
    let zero_click = report
        .findings
        .iter()
        .find(|f| f.kind == "image.zero_click_jbig2")
        .expect("image.zero_click_jbig2 finding");
    assert_eq!(
        zero_click.meta.get("cve"),
        Some(&"CVE-2021-30860".to_string())
    );
    assert_eq!(
        zero_click.meta.get("attack_surface"),
        Some(&"Image codecs / zero-click JBIG2".to_string())
    );
}

#[test]
fn cve_2009_0658_jbig2_dynamic_malformed() {
    let bytes = include_bytes!("fixtures/images/cve-2009-0658-jbig2.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, base_opts(true), &detectors)
        .expect("scan should succeed");
    assert!(has_finding(&report, "image.jbig2_present"));
    assert!(has_finding(&report, "image.jbig2_malformed"));
}

#[test]
fn feature_vector_counts_images() {
    let bytes = include_bytes!("fixtures/images/cve-2009-0658-jbig2.pdf");
    let graph = parse_pdf(
        bytes,
        ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 8 * 1024 * 1024,
            max_objects: 100_000,
            max_objstm_total_bytes: 64 * 1024 * 1024,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        },
    )
    .expect("parse");
    let ctx = sis_pdf_core::scan::ScanContext::new(bytes, graph, base_opts(false));
    let features = sis_pdf_core::features::FeatureExtractor::extract(&ctx);
    assert_eq!(features.images.image_count, 1);
    assert_eq!(features.images.jbig2_count, 1);
    assert_eq!(features.images.risky_image_count, 1);
}

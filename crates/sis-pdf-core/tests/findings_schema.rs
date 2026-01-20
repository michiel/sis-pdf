use sis_pdf_core::scan::{FontAnalysisOptions, ProfileFormat, ScanOptions};

fn opts() -> ScanOptions {
    ScanOptions {
        deep: true,
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
        image_analysis: sis_pdf_core::scan::ImageAnalysisOptions::default(),
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
    }
}

#[test]
fn findings_schema_validation() {
    let fixtures = [
        "tests/fixtures/embedded/embedded_exe_cve_2018_4990.pdf",
        "tests/fixtures/actions/launch_cve_2010_1240.pdf",
        "tests/fixtures/xfa/xfa_submit_sensitive.pdf",
        "tests/fixtures/media/swf_cve_2011_0611.pdf",
        "tests/fixtures/encryption/high_entropy_stream.pdf",
        "tests/fixtures/filters/filter_unusual_chain.pdf",
    ];

    for fixture in fixtures {
        let bytes = std::fs::read(fixture_path(fixture)).expect("fixture read");
        let detectors = sis_pdf_detectors::default_detectors();
        let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, opts(), &detectors)
            .expect("scan should succeed");

        for finding in &report.findings {
            assert!(!finding.kind.is_empty());
            assert!(!finding.title.is_empty());
            assert!(!finding.description.is_empty());
            assert!(!finding.objects.is_empty());
            for span in &finding.evidence {
                assert!(span.length <= u32::MAX);
            }
            let value = serde_json::to_value(finding).expect("finding serialise");
            let obj = value.as_object().expect("finding json object");
            for key in ["kind", "title", "description", "severity", "confidence", "objects"] {
                assert!(obj.contains_key(key), "missing key {}", key);
            }
        }
    }
}

fn fixture_path(rel: &str) -> std::path::PathBuf {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    root.join(rel)
}

use sis_pdf_core::scan::ScanOptions;

#[test]
fn review_items_002_detectors_trigger() {
    let bytes = include_bytes!("fixtures/review_items_002.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let opts = ScanOptions {
        deep: true,
        max_decode_bytes: 8 * 1024 * 1024,
        max_total_decoded_bytes: 64 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        diff_parser: false,
        max_objects: 100_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        yara_scope: None,
        strict: false,
        ml_config: None,
    };
    let report = sis_pdf_core::runner::run_scan_with_detectors(bytes, opts, &detectors)
        .expect("scan should succeed");
    let kinds: std::collections::HashSet<&str> =
        report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains("supply_chain_staged_payload"));
    assert!(kinds.contains("supply_chain_update_vector"));
    assert!(kinds.contains("crypto_weak_algo"));
    assert!(kinds.contains("crypto_cert_anomaly"));
    assert!(kinds.contains("crypto_mining_js"));
    assert!(kinds.contains("quantum_vulnerable_crypto"));
}

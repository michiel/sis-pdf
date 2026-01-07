use sis_pdf_core::scan::ScanOptions;

#[test]
fn detects_signature_and_encryption() {
    let sig = include_bytes!("fixtures/signature.pdf");
    let enc = include_bytes!("fixtures/encrypt.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let opts = ScanOptions {
        deep: false,
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
        ir: false,
        ml_config: None,
    };

    let sig_report = sis_pdf_core::runner::run_scan_with_detectors(sig, opts.clone(), &detectors)
        .expect("signature scan should succeed");
    let sig_kinds: std::collections::HashSet<&str> =
        sig_report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(sig_kinds.contains("signature_present"));

    let enc_report = sis_pdf_core::runner::run_scan_with_detectors(enc, opts, &detectors)
        .expect("encryption scan should succeed");
    let enc_kinds: std::collections::HashSet<&str> =
        enc_report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert!(enc_kinds.contains("encryption_present"));
}

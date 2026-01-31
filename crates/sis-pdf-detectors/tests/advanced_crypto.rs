mod common;
use common::default_scan_opts;
use sis_pdf_detectors::default_detectors;

#[test]
fn crypto_weak_algo_includes_algorithm_meta() {
    let bytes = include_bytes!(
        "../../sis-pdf-core/tests/fixtures/encryption/weak_encryption_cve_2019_7089.pdf"
    );
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &detectors)
            .expect("scan");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "crypto_weak_algo")
        .expect("expected crypto_weak_algo finding");
    assert_eq!(
        finding.meta.get("crypto.algorithm").map(String::as_str),
        Some("RC4-40")
    );
    assert_eq!(
        finding.meta.get("crypto.key_length").map(String::as_str),
        Some("40")
    );
}

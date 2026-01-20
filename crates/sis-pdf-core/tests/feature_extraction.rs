use sis_pdf_core::features::FeatureExtractor;
use sis_pdf_core::scan::{FontAnalysisOptions, ProfileFormat, ScanOptions};

fn fixture_path(rel: &str) -> std::path::PathBuf {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    root.join("tests/fixtures").join(rel)
}

fn extract_features(rel: &str) -> sis_pdf_core::features::FeatureVector {
    let bytes = std::fs::read(fixture_path(rel)).expect("fixture read");
    let opts = ScanOptions {
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
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
    };
    FeatureExtractor::extract_from_bytes(&bytes, &opts).expect("extract features")
}

#[test]
fn test_xfa_features_extraction() {
    let features = extract_features("xfa/xfa_submit_sensitive.pdf");
    assert!(features.xfa.present);
    assert!(features.xfa.script_count > 0);
    assert!(features.xfa.submit_url_count > 0);
    assert!(features.xfa.sensitive_field_count > 0);
    assert!(features.xfa.max_payload_bytes > 0);
}

#[test]
fn test_encryption_features_extraction() {
    let features = extract_features("encryption/weak_encryption_cve_2019_7089.pdf");
    assert!(features.encryption.present);
    assert_eq!(features.encryption.encrypt_dict_count, 1);
    assert_eq!(features.encryption.key_length_bits, 40);
    assert!(features.encryption.weak_key);
}

#[test]
fn test_filter_features_extraction() {
    let features = extract_features("filters/filter_obfuscation_cve_2010_2883.pdf");
    assert_eq!(features.filters.filter_chain_count, 1);
    assert_eq!(features.filters.max_filter_chain_depth, 2);
    assert_eq!(features.filters.invalid_order_count, 0);
    assert_eq!(features.filters.duplicate_filter_count, 0);
}

#[test]
fn test_content_features_extended() {
    let features = extract_features("embedded/embedded_exe_cve_2018_4990.pdf");
    assert!(features.content.embedded_file_count > 0);
    assert!(features.content.embedded_executable_count > 0);
    assert_eq!(features.content.embedded_script_count, 0);
    assert_eq!(features.content.embedded_archive_count, 0);
}

#[test]
fn test_rich_media_swf_features() {
    let features = extract_features("media/swf_cve_2011_0611.pdf");
    assert!(features.content.rich_media_count > 0);
    assert!(features.content.rich_media_swf_count > 0);
}

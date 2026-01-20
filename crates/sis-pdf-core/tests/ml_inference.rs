use std::path::PathBuf;

use sis_pdf_core::ml_inference::{run_ml_inference, MlInferenceConfig};
use sis_pdf_core::scan::{FontAnalysisOptions, ProfileFormat, ScanContext, ScanOptions};

fn load_context() -> anyhow::Result<ScanContext<'static>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic.pdf");
    let bytes = std::fs::read(path)?;
    let bytes = Box::leak(bytes.into_boxed_slice());
    let graph = sis_pdf_pdf::parse_pdf(
        bytes,
        sis_pdf_pdf::ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 32 * 1024 * 1024,
            max_objects: 500_000,
            max_objstm_total_bytes: 256 * 1024 * 1024,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        },
    )?;
    let opts = ScanOptions {
        deep: false,
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
        yara_scope: None,
        focus_depth: 0,
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
    Ok(ScanContext::new(bytes, graph, opts))
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ml")
        .join(name)
}

#[test]
fn test_ml_inference_smoke() -> anyhow::Result<()> {
    let ctx = load_context()?;
    let findings = Vec::new();
    let config = MlInferenceConfig {
        model_path: fixture_path("model.json"),
        baseline_path: Some(fixture_path("baseline.json")),
        calibration_path: Some(fixture_path("calibration.json")),
        threshold: 0.5,
        explain: true,
        use_extended_features: true,
        explain_advanced: false,
    };
    let result = run_ml_inference(&ctx, &findings, &config)?;
    assert!(result.prediction.calibrated_score >= 0.0);
    assert!(result.prediction.calibrated_score <= 1.0);
    let explanation = result.explanation.expect("explanation");
    assert!(!explanation.feature_attribution.is_empty());
    Ok(())
}

#[test]
fn test_ml_inference_advanced() -> anyhow::Result<()> {
    let ctx = load_context()?;
    let findings = Vec::new();
    let config = MlInferenceConfig {
        model_path: fixture_path("model.json"),
        baseline_path: Some(fixture_path("baseline.json")),
        calibration_path: None,
        threshold: 0.4,
        explain: true,
        use_extended_features: true,
        explain_advanced: true,
    };
    let result = run_ml_inference(&ctx, &findings, &config)?;
    let explanation = result.explanation.expect("explanation");
    assert!(explanation.counterfactual.is_some());
    Ok(())
}

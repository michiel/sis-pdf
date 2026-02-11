use std::path::PathBuf;

use js_analysis::corpus_regression::{evaluate_corpus, CorpusThresholds};

#[cfg(all(feature = "js-sandbox", feature = "js-ast"))]
#[test]
fn corpus_regression_synthetic_pack_meets_thresholds() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/corpus");

    let report = evaluate_corpus(&path, CorpusThresholds::default())
        .expect("corpus regression report should evaluate");

    assert_eq!(report.summary.malicious_total, 60);
    assert_eq!(report.summary.benign_total, 60);
    assert!(report.passes_thresholds());
    assert!(report.summary.execution_rate >= 0.75);
    assert!(report.summary.true_positive_rate >= 0.85);
    assert!(report.summary.false_positive_rate < 0.05);
}

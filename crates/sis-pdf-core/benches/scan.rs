use criterion::{criterion_group, criterion_main, Criterion};
use sis_pdf_core::scan::{FontAnalysisOptions, ProfileFormat, ScanOptions};
fn bench_scan(c: &mut Criterion) {
    let bytes = include_bytes!("../tests/fixtures/synthetic.pdf");
    let detectors = sis_pdf_detectors::default_detectors();
    let opts = ScanOptions {
        strict: false,
        strict_summary: false,
        ir: false,
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
        ml_config: None,
        font_analysis: FontAnalysisOptions::default(),
        profile: false,
        profile_format: ProfileFormat::Text,
    };
    c.bench_function("sis_pdf_scan_synthetic", |b| {
        b.iter(|| sis_pdf_core::runner::run_scan_with_detectors(bytes, opts, &detectors).unwrap())
    });
}
criterion_group!(benches, bench_scan);
criterion_main!(benches);

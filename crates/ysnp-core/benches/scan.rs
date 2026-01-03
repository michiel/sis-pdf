use criterion::{criterion_group, criterion_main, Criterion};
use ysnp_core::scan::ScanOptions;

fn bench_scan(c: &mut Criterion) {
    let bytes = include_bytes!("../tests/fixtures/synthetic.pdf");
    let detectors = ysnp_detectors::default_detectors();
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
    };
    c.bench_function("ysnp_scan_synthetic", |b| {
        b.iter(|| ysnp_core::runner::run_scan_with_detectors(bytes, opts, &detectors).unwrap())
    });
}

criterion_group!(benches, bench_scan);
criterion_main!(benches);

#![no_main]

use image_analysis::{dynamic, static_analysis, ImageDynamicOptions, ImageStaticOptions};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = sis_pdf_pdf::parse_pdf(
        data,
        sis_pdf_pdf::ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 1_000_000,
            max_objects: 20_000,
            max_objstm_total_bytes: 5_000_000,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        },
    );

    let Ok(graph) = parsed else {
        return;
    };

    let _ = static_analysis::analyze_static_images(&graph, &ImageStaticOptions::default());
    let _ = dynamic::analyze_dynamic_images(
        &graph,
        &ImageDynamicOptions {
            max_pixels: 100_000_000,
            max_decode_bytes: 2 * 1024 * 1024,
            timeout_ms: 50,
            total_budget_ms: 200,
            skip_threshold: 100,
        },
    );
});

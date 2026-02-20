#![no_main]
use libfuzzer_sys::fuzz_target;

// Exercises the carve_stream_objects code path, which is not reached by
// any other fuzz target. When enabled, the parser attempts to extract
// indirect objects embedded inside stream data — a recovery mode used
// for heavily corrupted or obfuscated PDFs.
// Limits are tighter than graph.rs to bound memory use during carving.
fuzz_target!(|data: &[u8]| {
    let _ = sis_pdf_pdf::parse_pdf(
        data,
        sis_pdf_pdf::ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 512_000,
            max_objects: 5_000,
            max_objstm_total_bytes: 1_000_000,
            carve_stream_objects: true,
            max_carved_objects: 500,
            max_carved_bytes: 1_000_000,
        },
    );
});

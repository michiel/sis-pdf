#![no_main]
use libfuzzer_sys::fuzz_target;

// Exercises decode_stream_with_meta, which is not reached by any other
// fuzz target. Unlike decode_stream, this path tracks deferred filters
// (DCT/JPEG2000/JBIG2/CCITT), detects filter-content mismatches, and
// returns structured decode metadata — all of which are distinct code
// paths with their own bounds and state machines.
fuzz_target!(|data: &[u8]| {
    use sis_pdf_pdf::decode::{DecodeLimits, decode_stream_with_meta};
    use sis_pdf_pdf::object::PdfAtom;

    let opts = sis_pdf_pdf::ParseOptions {
        recover_xref: true,
        deep: false,
        strict: false,
        max_objstm_bytes: 512_000,
        max_objects: 2_000,
        max_objstm_total_bytes: 1_000_000,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };

    if let Ok(graph) = sis_pdf_pdf::parse_pdf(data, opts) {
        let limits = DecodeLimits::default();
        for entry in &graph.objects {
            if let PdfAtom::Stream(stream) = &entry.atom {
                let _ = decode_stream_with_meta(data, stream, limits);
            }
        }
    }
});

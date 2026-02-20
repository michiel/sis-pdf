#![no_main]
use libfuzzer_sys::fuzz_target;

// Exercises the parser with strict=true, which enables the deviation
// recording paths (invalid escapes, name errors, number format problems,
// missing keywords, etc.) that are not reachable in non-strict mode.
//
// Tests three scenarios per input:
//   1. Single-object parse at offset 0, strict.
//   2. Single-object parse at a fuzzer-controlled offset within the same
//      bytes, strict — exercises mid-stream recovery and offset arithmetic.
//   3. Full scan with strict=true — exercises the outer loop and deviation
//      accumulation across many objects.
fuzz_target!(|data: &[u8]| {
    let _ = sis_pdf_pdf::parser::parse_indirect_object_at(data, 0, true);

    if data.len() >= 4 {
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let offset = offset.min(data.len() - 1);
        let _ = sis_pdf_pdf::parser::parse_indirect_object_at(data, offset, true);
    }

    let _ = sis_pdf_pdf::parser::scan_indirect_objects(data, true, 1_000);
});

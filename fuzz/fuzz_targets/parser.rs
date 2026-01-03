#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sis_pdf_pdf::parser::parse_indirect_object_at(data, 0);
});

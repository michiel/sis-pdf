#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ysnp_pdf::parser::scan_indirect_objects(data);
});

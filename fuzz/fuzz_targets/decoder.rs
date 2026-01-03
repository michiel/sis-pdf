#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ysnp_pdf::decode::decode_ascii_hex(data);
});

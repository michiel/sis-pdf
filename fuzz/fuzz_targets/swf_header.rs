#![no_main]
use libfuzzer_sys::fuzz_target;

// Exercises SWF header parsing, including the RECT bit-field calculation
// (nbits from high 5 bits of byte 8) and fixed-point frame rate decoding.
// parse_swf_header returns None for non-SWF signatures, so the fuzzer
// will discover inputs that satisfy FWS/CWS/ZWS and then stress the
// bounds arithmetic inside rect_byte_len.
fuzz_target!(|data: &[u8]| {
    let _ = sis_pdf_pdf::swf::parse_swf_header(data);
});

#![no_main]
use libfuzzer_sys::fuzz_target;

// Exercises both XFA extraction functions on the same input.
// Both scan the first 512 KB of untrusted bytes for XML-like tags and
// perform base64 decoding, data-URI splitting, and CDATA stripping.
fuzz_target!(|data: &[u8]| {
    let _ = sis_pdf_pdf::xfa::extract_xfa_script_payloads(data);
    let _ = sis_pdf_pdf::xfa::extract_xfa_image_payloads(data);
});

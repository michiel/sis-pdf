#![no_main]
use libfuzzer_sys::fuzz_target;

// Exercises JavaScript static signal extraction, which runs 30+ pattern
// detectors (obfuscation, encoding layers, eval construction, memory
// exploits, anti-analysis, exfiltration) and iterative base64 decoding
// up to MAX_DECODE_LAYERS_HARD=8 layers at 256 KB each.
fuzz_target!(|data: &[u8]| {
    let _ = js_analysis::extract_js_signals(data);
});

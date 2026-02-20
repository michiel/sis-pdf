#![no_main]
use libfuzzer_sys::fuzz_target;

// Exercises static font analysis: WOFF/WOFF2 detection and decompression,
// Type 1 eexec decoding, static signature scanning, variable font analysis
// (OpenType variations via skrifa), and colour font table analysis.
// Dynamic analysis (thread-based, configurable timeout) is explicitly
// disabled to keep fuzzer iterations deterministic and fast.
fuzz_target!(|data: &[u8]| {
    let config = font_analysis::FontAnalysisConfig {
        dynamic_enabled: false,
        ..font_analysis::FontAnalysisConfig::default()
    };
    let _ = font_analysis::analyse_font(data, &config);
});

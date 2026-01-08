//! Test static JavaScript analysis on hostile payloads
//!
//! Usage: cargo run --release --features js-sandbox --example test_static -- <js_file>

use js_analysis::static_analysis::extract_js_signals;
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <js_file>", args[0]);
        eprintln!();
        eprintln!("Performs static analysis on a JavaScript file to detect malicious patterns");
        std::process::exit(1);
    }

    let js_file = Path::new(&args[1]);

    let js_code = match fs::read(js_file) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Failed to read {}: {}", js_file.display(), e);
            std::process::exit(1);
        }
    };

    eprintln!("Analyzing: {}", js_file.display());
    eprintln!("Size: {} bytes", js_code.len());
    eprintln!();

    let signals = extract_js_signals(&js_code);

    // Group signals by category
    let mut shellcode = Vec::new();
    let mut memory_corruption = Vec::new();
    let mut anti_analysis = Vec::new();
    let mut exfiltration = Vec::new();
    let mut obfuscation = Vec::new();
    let mut pdf_exploit = Vec::new();
    let mut c2 = Vec::new();
    let mut unicode = Vec::new();
    let mut crypto = Vec::new();
    let mut other = Vec::new();

    for (key, value) in &signals {
        if value == "true" {
            if key.contains("shellcode") || key.contains("nop_sled") {
                shellcode.push(key.as_str());
            } else if key.contains("type_confusion") || key.contains("integer_overflow")
                || key.contains("array_manipulation") || key.contains("use_after_free")
                || key.contains("rop_chain") {
                memory_corruption.push(key.as_str());
            } else if key.contains("debugger") || key.contains("sandbox_evasion")
                || key.contains("exception_abuse") || key.contains("time_bomb")
                || key.contains("geofencing") {
                anti_analysis.push(key.as_str());
            } else if key.contains("form_manipulation") || key.contains("credential")
                || key.contains("encoded_transmission") {
                exfiltration.push(key.as_str());
            } else if key.contains("control_flow") || key.contains("opaque_predicate")
                || key.contains("identifier_mangling") || key.contains("unicode_obfuscation")
                || key.contains("custom_decoder") || key.contains("function_introspection") {
                obfuscation.push(key.as_str());
            } else if key.contains("font_exploitation") || key.contains("annotation_abuse")
                || key.contains("xfa_exploitation") {
                pdf_exploit.push(key.as_str());
            } else if key.contains("dga") || key.contains("beaconing") {
                c2.push(key.as_str());
            } else if key.contains("rtl_override") || key.contains("homoglyph") {
                unicode.push(key.as_str());
            } else if key.contains("cryptomining") || key.contains("wasm_mining") {
                crypto.push(key.as_str());
            } else {
                other.push(key.as_str());
            }
        }
    }

    let mut total_detections = 0;

    if !shellcode.is_empty() {
        eprintln!("🔴 SHELLCODE & EXPLOIT PAYLOADS:");
        for signal in &shellcode {
            eprintln!("  ✓ {}", signal);
        }
        total_detections += shellcode.len();
        eprintln!();
    }

    if !memory_corruption.is_empty() {
        eprintln!("🔴 MEMORY CORRUPTION PRIMITIVES:");
        for signal in &memory_corruption {
            eprintln!("  ✓ {}", signal);
        }
        total_detections += memory_corruption.len();
        eprintln!();
    }

    if !pdf_exploit.is_empty() {
        eprintln!("🔴 PDF-SPECIFIC EXPLOITATION:");
        for signal in &pdf_exploit {
            eprintln!("  ✓ {}", signal);
        }
        total_detections += pdf_exploit.len();
        eprintln!();
    }

    if !anti_analysis.is_empty() {
        eprintln!("🟡 ANTI-ANALYSIS TECHNIQUES:");
        for signal in &anti_analysis {
            eprintln!("  ✓ {}", signal);
        }
        total_detections += anti_analysis.len();
        eprintln!();
    }

    if !exfiltration.is_empty() {
        eprintln!("🟡 DATA EXFILTRATION:");
        for signal in &exfiltration {
            eprintln!("  ✓ {}", signal);
        }
        total_detections += exfiltration.len();
        eprintln!();
    }

    if !c2.is_empty() {
        eprintln!("🟡 COMMAND & CONTROL:");
        for signal in &c2 {
            eprintln!("  ✓ {}", signal);
        }
        total_detections += c2.len();
        eprintln!();
    }

    if !obfuscation.is_empty() {
        eprintln!("🟠 ADVANCED OBFUSCATION:");
        for signal in &obfuscation {
            eprintln!("  ✓ {}", signal);
        }
        total_detections += obfuscation.len();
        eprintln!();
    }

    if !unicode.is_empty() {
        eprintln!("🟠 UNICODE ABUSE:");
        for signal in &unicode {
            eprintln!("  ✓ {}", signal);
        }
        total_detections += unicode.len();
        eprintln!();
    }

    if !crypto.is_empty() {
        eprintln!("🟢 CRYPTOMINING:");
        for signal in &crypto {
            eprintln!("  ✓ {}", signal);
        }
        total_detections += crypto.len();
        eprintln!();
    }

    if !other.is_empty() {
        eprintln!("ℹ️  OTHER DETECTIONS:");
        for signal in &other {
            eprintln!("  ✓ {}", signal);
        }
        total_detections += other.len();
        eprintln!();
    }

    if total_detections == 0 {
        eprintln!("✅ No malicious patterns detected");
    } else {
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        eprintln!("Total detections: {}", total_detections);
    }
}

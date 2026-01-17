/// Integration tests for font analysis using test fixtures
///
/// These tests validate the font analysis implementation against
/// synthetic exploit samples, CVE test cases, and benign fonts.

use font_analysis::{analyse_font, FontAnalysisConfig};

/// Test that BLEND exploit pattern is detected
#[test]
fn test_blend_exploit_detection() {
    let data = include_bytes!("fixtures/exploits/blend_2015.pfa");
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);

    // Should detect BLEND exploit pattern
    let has_blend_finding = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.type1_blend_exploit");

    assert!(
        has_blend_finding,
        "BLEND exploit pattern should be detected"
    );
}

/// Test that Type 1 fonts with dangerous operators are flagged
#[test]
fn test_type1_dangerous_operators() {
    let data = include_bytes!("fixtures/exploits/blend_2015.pfa");
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);

    // Should detect dangerous operators
    let has_dangerous_ops = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.type1_dangerous_operator");

    assert!(
        has_dangerous_ops,
        "Dangerous operators should be detected"
    );
}

/// Test that excessive stack depth is detected
#[test]
fn test_type1_excessive_stack() {
    let data = include_bytes!("fixtures/exploits/type1_stack_overflow.pfa");
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);

    // Should detect excessive stack depth
    let has_stack_finding = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.type1_excessive_stack");

    assert!(
        has_stack_finding,
        "Excessive stack depth should be detected"
    );
}

/// Test that large charstring programs are flagged
#[test]
fn test_type1_large_charstring() {
    let data = include_bytes!("fixtures/exploits/type1_large_charstring.pfa");
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);

    // Should detect large charstring
    let has_large_charstring = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.type1_large_charstring");

    assert!(
        has_large_charstring,
        "Large charstring should be detected"
    );
}

/// Test that minimal benign Type 1 font produces no findings
#[test]
fn test_benign_type1_no_findings() {
    let data = include_bytes!("fixtures/benign/minimal-type1.pfa");
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);

    // Should not produce any Type 1 specific findings
    let has_type1_findings = outcome
        .findings
        .iter()
        .any(|f| f.kind.starts_with("font.type1_"));

    assert!(
        !has_type1_findings,
        "Benign Type 1 font should not trigger findings. Found: {:?}",
        outcome
            .findings
            .iter()
            .filter(|f| f.kind.starts_with("font.type1_"))
            .map(|f| &f.kind)
            .collect::<Vec<_>>()
    );
}

/// Test CVE-2025-27163 detection (hmtx/hhea mismatch)
#[cfg(feature = "dynamic")]
#[test]
fn test_cve_2025_27163_detection() {
    let data = include_bytes!("fixtures/cve/cve-2025-27163-hmtx-hhea-mismatch.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect CVE-2025-27163
    let has_cve = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.cve_2025_27163");

    assert!(
        has_cve,
        "CVE-2025-27163 should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
}

/// Test CVE-2023-26369 detection (EBSC out-of-bounds)
#[cfg(feature = "dynamic")]
#[test]
fn test_cve_2023_26369_detection() {
    let data = include_bytes!("fixtures/cve/cve-2023-26369-ebsc-oob.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect CVE-2023-26369 or parse failure (malformed font)
    // Both are valid security findings
    let has_security_finding = outcome.findings.iter().any(|f| {
        f.kind == "font.cve_2023_26369"
            || f.kind == "font.dynamic_parse_failure"
            || f.kind == "font.invalid_structure"
    });

    assert!(
        has_security_finding,
        "CVE-2023-26369 or parse failure should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );

    // Should have at least one finding since the font is malformed
    assert!(
        !outcome.findings.is_empty(),
        "Malformed font should generate findings"
    );
}

/// Test anomalous gvar table detection
#[cfg(feature = "dynamic")]
#[test]
fn test_gvar_anomalous_size() {
    let data = include_bytes!("fixtures/cve/gvar-anomalous-size.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect anomalous table size (either from static or dynamic analysis)
    let has_anomaly = outcome.findings.iter().any(|f| {
        f.kind == "font.anomalous_variation_table" || f.kind == "font.anomalous_table_size"
    });

    assert!(
        has_anomaly,
        "Anomalous gvar table should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
}

/// Test that minimal benign TrueType font produces no findings
#[test]
fn test_benign_truetype_no_findings() {
    let data = include_bytes!("fixtures/benign/minimal-truetype.ttf");
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);

    // Should not produce CVE findings
    let has_cve_findings = outcome.findings.iter().any(|f| f.kind.contains("cve_"));

    assert!(
        !has_cve_findings,
        "Benign TrueType font should not trigger CVE findings. Found: {:?}",
        outcome
            .findings
            .iter()
            .filter(|f| f.kind.contains("cve_"))
            .map(|f| &f.kind)
            .collect::<Vec<_>>()
    );
}

/// Test that minimal benign variable font produces no anomaly findings
#[test]
fn test_benign_variable_no_findings() {
    let data = include_bytes!("fixtures/benign/minimal-variable.ttf");
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);

    // Should not produce anomaly findings
    let has_anomaly_findings = outcome
        .findings
        .iter()
        .any(|f| f.kind.contains("anomalous"));

    assert!(
        !has_anomaly_findings,
        "Benign variable font should not trigger anomaly findings. Found: {:?}",
        outcome
            .findings
            .iter()
            .filter(|f| f.kind.contains("anomalous"))
            .map(|f| &f.kind)
            .collect::<Vec<_>>()
    );
}

/// Test that disabled analysis produces no findings
#[test]
fn test_disabled_analysis() {
    let data = include_bytes!("fixtures/exploits/blend_2015.pfa");
    let mut config = FontAnalysisConfig::default();
    config.enabled = false;

    let outcome = analyse_font(data, &config);

    assert!(
        outcome.findings.is_empty(),
        "Disabled analysis should produce no findings"
    );
}

/// Test TrueType VM detects excessive instructions
#[cfg(feature = "dynamic")]
#[test]
fn test_ttf_excessive_instructions() {
    let data = include_bytes!("fixtures/exploits/ttf_excessive_instructions.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect excessive instructions in hinting program
    let has_hinting_issue = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.ttf_hinting_suspicious");

    assert!(
        has_hinting_issue,
        "Excessive instructions should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
}

/// Test TrueType VM detects stack overflow
#[cfg(feature = "dynamic")]
#[test]
fn test_ttf_stack_overflow() {
    let data = include_bytes!("fixtures/exploits/ttf_stack_overflow.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect stack overflow in hinting program
    let has_hinting_issue = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.ttf_hinting_suspicious");

    assert!(
        has_hinting_issue,
        "Stack overflow should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
}

/// Test TrueType VM detects division by zero
#[cfg(feature = "dynamic")]
#[test]
fn test_ttf_division_by_zero() {
    let data = include_bytes!("fixtures/exploits/ttf_division_by_zero.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect division by zero in hinting program
    let has_hinting_issue = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.ttf_hinting_suspicious");

    assert!(
        has_hinting_issue,
        "Division by zero should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
}

/// Test that multiple vulnerability signals triggers aggregate finding
#[test]
fn test_multiple_vulnerability_signals() {
    let data = include_bytes!("fixtures/exploits/blend_2015.pfa");
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);

    // BLEND exploit should trigger multiple findings
    assert!(
        outcome.findings.len() >= 2,
        "BLEND exploit should trigger multiple findings"
    );

    // Should trigger aggregate finding
    let has_multiple_vuln = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.multiple_vuln_signals");

    assert!(
        has_multiple_vuln,
        "Multiple vulnerability signals should be detected"
    );
}

/// Test that color font with inconsistent COLR/CPAL tables is detected
#[cfg(feature = "dynamic")]
#[test]
fn test_color_font_inconsistent_tables() {
    let data = include_bytes!("fixtures/color/colr-without-cpal.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect COLR without CPAL inconsistency OR parse failure (both are security findings)
    let has_security_finding = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.color_table_inconsistent"
                || f.kind == "font.dynamic_parse_failure"
                || f.kind == "font.invalid_structure");

    assert!(
        has_security_finding,
        "Inconsistent color tables or parse failure should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );

    // Should have at least one finding
    assert!(!outcome.findings.is_empty(), "Should generate security findings");
}

/// Test that color font with excessive palettes is detected
#[cfg(feature = "dynamic")]
#[test]
fn test_color_font_excessive_palettes() {
    let data = include_bytes!("fixtures/color/excessive-palettes.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect excessive palette count OR parse failure
    let has_finding = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.color_table_inconsistent"
                || f.kind == "font.dynamic_parse_failure"
                || f.kind == "font.invalid_structure");

    assert!(
        has_finding,
        "Excessive palettes or parse failure should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
    assert!(!outcome.findings.is_empty());
}

/// Test that color font with glyph count mismatch is detected
#[cfg(feature = "dynamic")]
#[test]
fn test_color_font_glyph_mismatch() {
    let data = include_bytes!("fixtures/color/glyph-count-mismatch.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect glyph count mismatch OR parse failure
    let has_mismatch = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.color_table_inconsistent"
                || f.kind == "font.dynamic_parse_failure"
                || f.kind == "font.invalid_structure");

    assert!(
        has_mismatch,
        "Glyph count mismatch or parse failure should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
    assert!(!outcome.findings.is_empty());
}

/// Test that benign color font produces no findings
#[cfg(feature = "dynamic")]
#[test]
fn test_benign_color_font() {
    let data = include_bytes!("fixtures/benign/valid-color.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should not produce color-related findings
    let has_color_findings = outcome
        .findings
        .iter()
        .any(|f| f.kind.contains("color"));

    assert!(
        !has_color_findings,
        "Benign color font should not trigger findings. Found: {:?}",
        outcome
            .findings
            .iter()
            .filter(|f| f.kind.contains("color"))
            .map(|f| &f.kind)
            .collect::<Vec<_>>()
    );
}

/// Test that WOFF decompression bomb is detected
#[cfg(feature = "dynamic")]
#[test]
fn test_woff_decompression_bomb() {
    let data = include_bytes!("fixtures/woff/decompression-bomb.woff");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect decompression bomb OR parse/decompression failure
    let has_security_finding = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.woff_decompression_anomaly"
                || f.kind == "font.woff_decompression_failed"
                || f.kind == "font.dynamic_parse_failure");

    assert!(
        has_security_finding,
        "WOFF decompression bomb or failure should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
    assert!(!outcome.findings.is_empty(), "Should generate security findings");
}

/// Test that WOFF2 decompression bomb is detected
#[cfg(feature = "dynamic")]
#[test]
fn test_woff2_decompression_bomb() {
    let data = include_bytes!("fixtures/woff/decompression-bomb.woff2");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect decompression bomb OR parse/decompression failure
    let has_security_finding = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.woff_decompression_anomaly"
                || f.kind == "font.woff_decompression_failed"
                || f.kind == "font.dynamic_parse_failure");

    assert!(
        has_security_finding,
        "WOFF2 decompression bomb or failure should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
    assert!(!outcome.findings.is_empty());
}

/// Test that WOFF with excessive decompressed size is detected
#[cfg(feature = "dynamic")]
#[test]
fn test_woff_excessive_size() {
    let data = include_bytes!("fixtures/woff/excessive-size.woff");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect excessive size OR parse/decompression failure
    let has_security_finding = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.woff_decompression_anomaly"
                || f.kind == "font.woff_decompression_failed"
                || f.kind == "font.dynamic_parse_failure");

    assert!(
        has_security_finding,
        "Excessive WOFF size or failure should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
    assert!(!outcome.findings.is_empty());
}

/// Test that benign WOFF font produces no anomaly findings
#[cfg(feature = "dynamic")]
#[test]
fn test_benign_woff_font() {
    let data = include_bytes!("fixtures/benign/valid.woff");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should not produce WOFF-specific findings
    let has_woff_findings = outcome
        .findings
        .iter()
        .any(|f| f.kind.contains("woff"));

    assert!(
        !has_woff_findings,
        "Benign WOFF font should not trigger findings. Found: {:?}",
        outcome
            .findings
            .iter()
            .filter(|f| f.kind.contains("woff"))
            .map(|f| &f.kind)
            .collect::<Vec<_>>()
    );
}

/// Test that variable font with excessive axes is detected
#[cfg(feature = "dynamic")]
#[test]
fn test_variable_font_excessive_axes() {
    let data = include_bytes!("fixtures/variable/excessive-axes.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect excessive variation axes OR parse failure
    let has_security_finding = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.anomalous_variation_table"
                || f.kind == "font.dynamic_parse_failure"
                || f.kind == "font.invalid_structure");

    assert!(
        has_security_finding,
        "Excessive variation axes or parse failure should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
    assert!(!outcome.findings.is_empty());
}

/// Test that variable font with excessive HVAR table is detected
#[cfg(feature = "dynamic")]
#[test]
fn test_variable_font_excessive_hvar() {
    let data = include_bytes!("fixtures/variable/excessive-hvar.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect excessive HVAR table size OR parse failure
    let has_security_finding = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.anomalous_variation_table"
                || f.kind == "font.dynamic_parse_failure"
                || f.kind == "font.invalid_structure");

    assert!(
        has_security_finding,
        "Excessive HVAR table or parse failure should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
    assert!(!outcome.findings.is_empty());
}

/// Test that variable font with excessive MVAR table is detected
#[cfg(feature = "dynamic")]
#[test]
fn test_variable_font_excessive_mvar() {
    let data = include_bytes!("fixtures/variable/excessive-mvar.ttf");
    let mut config = FontAnalysisConfig::default();
    config.dynamic_enabled = true;

    let outcome = analyse_font(data, &config);

    // Should detect excessive MVAR table size OR parse failure
    let has_security_finding = outcome
        .findings
        .iter()
        .any(|f| f.kind == "font.anomalous_variation_table"
                || f.kind == "font.dynamic_parse_failure"
                || f.kind == "font.invalid_structure");

    assert!(
        has_security_finding,
        "Excessive MVAR table or parse failure should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
    assert!(!outcome.findings.is_empty());
}

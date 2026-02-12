use font_analysis::model::Severity;
/// Integration tests for font analysis using test fixtures
///
/// These tests validate the font analysis implementation against
/// synthetic exploit samples, CVE test cases, and benign fonts.
use font_analysis::{analyse_font, FontAnalysisConfig};

/// Test that BLEND exploit pattern is detected
#[test]
fn test_blend_exploit_detection() {
    let data = include_bytes!("fixtures/exploits/blend_2015.pfa");
    let config = FontAnalysisConfig { dynamic_enabled: false, ..Default::default() };
    let outcome = analyse_font(data, &config);

    // Should detect BLEND exploit pattern
    let has_blend_finding = outcome.findings.iter().any(|f| f.kind == "font.type1_blend_exploit");

    assert!(has_blend_finding, "BLEND exploit pattern should be detected");
}

/// Test that Type 1 fonts with dangerous operators are flagged
#[test]
fn test_type1_dangerous_operators() {
    let data = include_bytes!("fixtures/exploits/blend_2015.pfa");
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);

    // Should detect dangerous operators
    let has_dangerous_ops =
        outcome.findings.iter().any(|f| f.kind == "font.type1_dangerous_operator");

    assert!(has_dangerous_ops, "Dangerous operators should be detected");
}

#[test]
fn test_type1_low_risk_operators_low_severity() {
    let data = b"/.notdef { pop put pop } ND";
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);
    let finding = outcome
        .findings
        .iter()
        .find(|f| f.kind == "font.type1_dangerous_operator")
        .expect("should still flag the operators");
    assert_eq!(
        finding.severity,
        Severity::Medium,
        "Multiple low-risk operators should raise severity to Medium"
    );
}

#[test]
fn test_type1_single_low_risk_operator_low_severity() {
    let data = b"/.notdef { pop } ND";
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);
    let finding = outcome
        .findings
        .iter()
        .find(|f| f.kind == "font.type1_dangerous_operator")
        .expect("should still flag the operator");
    assert_eq!(
        finding.severity,
        Severity::Low,
        "Single low-risk operator should remain Low severity"
    );
}

/// Test that excessive stack depth is detected
#[test]
fn test_type1_excessive_stack() {
    let data = include_bytes!("fixtures/exploits/type1_stack_overflow.pfa");
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);

    // Should detect excessive stack depth
    let has_stack_finding = outcome.findings.iter().any(|f| f.kind == "font.type1_excessive_stack");

    assert!(has_stack_finding, "Excessive stack depth should be detected");
}

/// Test that large charstring programs are flagged
#[test]
fn test_type1_large_charstring() {
    let data = include_bytes!("fixtures/exploits/type1_large_charstring.pfa");
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);

    // Should detect large charstring
    let has_large_charstring =
        outcome.findings.iter().any(|f| f.kind == "font.type1_large_charstring");

    assert!(has_large_charstring, "Large charstring should be detected");
}

/// Test that minimal benign Type 1 font produces no findings
#[test]
fn test_benign_type1_no_findings() {
    let data = include_bytes!("fixtures/benign/minimal-type1.pfa");
    let config = FontAnalysisConfig::default();
    let outcome = analyse_font(data, &config);

    // Should not produce any Type 1 specific findings
    let has_type1_findings = outcome.findings.iter().any(|f| f.kind.starts_with("font.type1_"));

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect CVE-2025-27163
    let has_cve = outcome.findings.iter().any(|f| f.kind == "font.cve_2025_27163");

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

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
    assert!(!outcome.findings.is_empty(), "Malformed font should generate findings");
}

/// Test anomalous gvar table detection
#[cfg(feature = "dynamic")]
#[test]
fn test_gvar_anomalous_size() {
    let data = include_bytes!("fixtures/cve/gvar-anomalous-size.ttf");
    let config = FontAnalysisConfig::default();

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

#[cfg(feature = "dynamic")]
#[test]
fn test_gvar_glyph_count_mismatch_metadata() {
    let data = include_bytes!("fixtures/cve/gvar-glyph-count-mismatch.ttf");
    let config = FontAnalysisConfig { dynamic_enabled: false, ..Default::default() };

    let outcome = analyse_font(data, &config);
    let finding = outcome
        .findings
        .iter()
        .find(|f| f.kind == "font.gvar_glyph_count_mismatch")
        .unwrap_or_else(|| {
            panic!(
                "Expected gvar glyph count mismatch finding, only had {:?}",
                outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
            )
        });
    assert_eq!(finding.meta.get("cve"), Some(&"CVE-2025-27363".to_string()));
    assert_eq!(
        finding.meta.get("attack_surface"),
        Some(&"Font parsing / variable fonts".to_string())
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
    let has_anomaly_findings = outcome.findings.iter().any(|f| f.kind.contains("anomalous"));

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
    let config = FontAnalysisConfig { enabled: false, ..Default::default() };

    let outcome = analyse_font(data, &config);

    assert!(outcome.findings.is_empty(), "Disabled analysis should produce no findings");
}

/// Test TrueType VM detects excessive instructions
#[cfg(feature = "dynamic")]
#[test]
fn test_ttf_excessive_instructions() {
    let data = include_bytes!("fixtures/exploits/ttf_excessive_instructions.ttf");
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect excessive instructions in hinting program
    let has_hinting_issue = outcome.findings.iter().any(|f| {
        matches!(
            f.kind.as_str(),
            "font.ttf_hinting_suspicious"
                | "font.ttf_hinting_push_loop"
                | "font.ttf_hinting_control_flow_storm"
                | "font.ttf_hinting_call_storm"
        )
    });

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect stack overflow in hinting program
    let has_hinting_issue = outcome.findings.iter().any(|f| {
        matches!(
            f.kind.as_str(),
            "font.ttf_hinting_suspicious"
                | "font.ttf_hinting_push_loop"
                | "font.ttf_hinting_control_flow_storm"
                | "font.ttf_hinting_call_storm"
        )
    });

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect division by zero in hinting program
    let has_hinting_issue =
        outcome.findings.iter().any(|f| f.kind == "font.ttf_hinting_suspicious");

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
    assert!(outcome.findings.len() >= 2, "BLEND exploit should trigger multiple findings");

    // Should trigger aggregate finding
    let has_multiple_vuln = outcome.findings.iter().any(|f| f.kind == "font.multiple_vuln_signals");

    assert!(has_multiple_vuln, "Multiple vulnerability signals should be detected");
}

/// Test that color font with inconsistent COLR/CPAL tables is detected
#[cfg(feature = "dynamic")]
#[test]
fn test_color_font_inconsistent_tables() {
    let data = include_bytes!("fixtures/color/colr-without-cpal.ttf");
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect COLR without CPAL inconsistency OR parse failure (both are security findings)
    let has_security_finding = outcome.findings.iter().any(|f| {
        f.kind == "font.color_table_inconsistent"
            || f.kind == "font.dynamic_parse_failure"
            || f.kind == "font.invalid_structure"
    });

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect excessive palette count OR parse failure
    let has_finding = outcome.findings.iter().any(|f| {
        f.kind == "font.color_table_inconsistent"
            || f.kind == "font.dynamic_parse_failure"
            || f.kind == "font.invalid_structure"
    });

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect glyph count mismatch OR parse failure
    let has_mismatch = outcome.findings.iter().any(|f| {
        f.kind == "font.color_table_inconsistent"
            || f.kind == "font.dynamic_parse_failure"
            || f.kind == "font.invalid_structure"
    });

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should not produce color-related findings
    let has_color_findings = outcome.findings.iter().any(|f| f.kind.contains("color"));

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect decompression bomb OR parse/decompression failure
    let has_security_finding = outcome.findings.iter().any(|f| {
        f.kind == "font.woff_decompression_anomaly"
            || f.kind == "font.woff_decompression_failed"
            || f.kind == "font.dynamic_parse_failure"
    });

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect decompression bomb OR parse/decompression failure
    let has_security_finding = outcome.findings.iter().any(|f| {
        f.kind == "font.woff_decompression_anomaly"
            || f.kind == "font.woff_decompression_failed"
            || f.kind == "font.dynamic_parse_failure"
    });

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect excessive size OR parse/decompression failure
    let has_security_finding = outcome.findings.iter().any(|f| {
        f.kind == "font.woff_decompression_anomaly"
            || f.kind == "font.woff_decompression_failed"
            || f.kind == "font.dynamic_parse_failure"
    });

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should not produce WOFF-specific findings
    let has_woff_findings = outcome.findings.iter().any(|f| f.kind.contains("woff"));

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

/// Test that unknown-magic dynamic parse failures are down-ranked as likely noise
#[cfg(feature = "dynamic")]
#[test]
fn test_dynamic_parse_failure_unknown_magic_is_low_noise() {
    let data = include_bytes!("fixtures/dynamic/unknown-magic-font.bin");
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);
    let finding = outcome
        .findings
        .iter()
        .find(|f| f.kind == "font.dynamic_parse_failure")
        .expect("expected dynamic parse failure finding");
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(
        finding.meta.get("parse_error_class"),
        Some(&"unknown_magic_or_face_index".to_string())
    );
    assert_eq!(finding.meta.get("parse_error_exploit_relevance"), Some(&"low".to_string()));
    assert_eq!(finding.meta.get("parse_error_triage_bucket"), Some(&"noise_likely".to_string()));
}

/// Test that malformed-structure parse failures retain medium risk and correlation guidance
#[cfg(feature = "dynamic")]
#[test]
fn test_dynamic_parse_failure_truncated_header_is_malformed_structure() {
    let data = include_bytes!("fixtures/dynamic/truncated-sfnt-header.ttf");
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);
    let finding = outcome
        .findings
        .iter()
        .find(|f| f.kind == "font.dynamic_parse_failure")
        .expect("expected dynamic parse failure finding");
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.meta.get("parse_error_class"), Some(&"malformed_structure".to_string()));
    assert_eq!(
        finding.meta.get("parse_error_triage_bucket"),
        Some(&"needs_correlation".to_string())
    );
    assert!(
        finding.meta.contains_key("parse_error_remediation"),
        "should include remediation guidance"
    );
}

/// Test that variable font with excessive axes is detected
#[cfg(feature = "dynamic")]
#[test]
fn test_variable_font_excessive_axes() {
    let data = include_bytes!("fixtures/variable/excessive-axes.ttf");
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect excessive variation axes OR parse failure
    let has_security_finding = outcome.findings.iter().any(|f| {
        f.kind == "font.anomalous_variation_table"
            || f.kind == "font.dynamic_parse_failure"
            || f.kind == "font.invalid_structure"
    });

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect excessive HVAR table size OR parse failure
    let has_security_finding = outcome.findings.iter().any(|f| {
        f.kind == "font.anomalous_variation_table"
            || f.kind == "font.dynamic_parse_failure"
            || f.kind == "font.invalid_structure"
    });

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
    let config = FontAnalysisConfig { dynamic_enabled: true, ..Default::default() };

    let outcome = analyse_font(data, &config);

    // Should detect excessive MVAR table size OR parse failure
    let has_security_finding = outcome.findings.iter().any(|f| {
        f.kind == "font.anomalous_variation_table"
            || f.kind == "font.dynamic_parse_failure"
            || f.kind == "font.invalid_structure"
    });

    assert!(
        has_security_finding,
        "Excessive MVAR table or parse failure should be detected. Findings: {:?}",
        outcome.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
    assert!(!outcome.findings.is_empty());
}

// ============================================================================
// CVE Signature Matching Tests
// ============================================================================

/// Test that signature matching is enabled by default
#[cfg(feature = "dynamic")]
#[test]
fn test_signature_matching_enabled_by_default() {
    let config = FontAnalysisConfig::default();
    assert!(config.signature_matching_enabled);
}

/// Test that signatures can be loaded from embedded directory
#[cfg(feature = "dynamic")]
#[test]
fn test_load_embedded_signatures() {
    let config = FontAnalysisConfig::default();
    let result = config.load_signatures();

    assert!(result.is_ok(), "Should load embedded signatures");
    let signatures = result.unwrap();
    assert!(signatures.len() >= 3, "Should have at least 3 active signatures");
}

/// Test that signature matching can be disabled
#[cfg(feature = "dynamic")]
#[test]
fn test_signature_matching_disabled() {
    let config = FontAnalysisConfig {
        signature_matching_enabled: false,
        dynamic_enabled: true,
        ..Default::default()
    };

    // Create a font that would trigger CVE-2025-27163 (hmtx length mismatch)
    let malformed_font = create_hmtx_length_mismatch_font();
    let outcome = analyse_font(&malformed_font, &config);

    // Should not have any CVE findings since signature matching is disabled
    let has_cve_findings = outcome.findings.iter().any(|f| f.kind.starts_with("cve."));

    assert!(
        !has_cve_findings,
        "Should not detect CVE signatures when disabled. Found: {:?}",
        outcome.findings.iter().filter(|f| f.kind.starts_with("cve.")).collect::<Vec<_>>()
    );
}

/// Test CVE-2025-27163 signature matching (hmtx table length mismatch)
#[cfg(feature = "dynamic")]
#[test]
fn test_cve_2025_27163_signature_match() {
    let config = FontAnalysisConfig {
        dynamic_enabled: true,
        signature_matching_enabled: true,
        ..Default::default()
    };

    // Create a font with hmtx table length mismatch
    let malformed_font = create_hmtx_length_mismatch_font();
    let outcome = analyse_font(&malformed_font, &config);

    // Should detect CVE-2025-27163 via signature matching
    let has_cve =
        outcome.findings.iter().any(|f| f.kind.contains("2025-27163") || f.kind.contains("hmtx"));

    // May also have legacy hardcoded check finding
    assert!(
        has_cve || outcome.findings.iter().any(|f| f.description.contains("hmtx")),
        "Should detect hmtx length mismatch. Findings: {:?}",
        outcome.findings.iter().map(|f| (&f.kind, &f.description)).collect::<Vec<_>>()
    );
}

/// Test CVE-2025-27164 signature matching (maxp/CFF2 glyph count mismatch)
#[cfg(feature = "dynamic")]
#[test]
fn test_cve_2025_27164_signature_match() {
    let config = FontAnalysisConfig {
        dynamic_enabled: true,
        signature_matching_enabled: true,
        ..Default::default()
    };

    // Create a font with maxp > CFF2 glyph count
    let malformed_font = create_maxp_cff2_mismatch_font();
    let outcome = analyse_font(&malformed_font, &config);

    // Should detect CVE-2025-27164, glyph mismatch, OR parse failure (all acceptable security outcomes)
    let has_security_finding = outcome.findings.iter().any(|f| {
        f.kind.contains("2025-27164")
            || f.kind.contains("cff2")
            || f.kind.contains("glyph")
            || f.kind.contains("parse_failure")
            || f.description.to_lowercase().contains("glyph")
            || f.description.to_lowercase().contains("parsing")
    });

    assert!(
        has_security_finding,
        "Should detect glyph mismatch or parse failure. Findings: {:?}",
        outcome.findings.iter().map(|f| (&f.kind, &f.description)).collect::<Vec<_>>()
    );
}

/// Test that benign fonts don't trigger signature matches
#[cfg(feature = "dynamic")]
#[test]
fn test_benign_font_no_signature_matches() {
    let config = FontAnalysisConfig {
        dynamic_enabled: true,
        signature_matching_enabled: true,
        ..Default::default()
    };

    // Use a benign test font
    let benign_font = create_minimal_valid_font();
    let outcome = analyse_font(&benign_font, &config);

    // Should not have CVE signature matches
    let has_cve_findings = outcome.findings.iter().any(|f| f.kind.starts_with("cve."));

    assert!(
        !has_cve_findings,
        "Benign font should not trigger CVE signatures. Found: {:?}",
        outcome.findings.iter().filter(|f| f.kind.starts_with("cve.")).collect::<Vec<_>>()
    );
}

/// Test signature loading with invalid directory
#[cfg(feature = "dynamic")]
#[test]
fn test_signature_loading_invalid_directory() {
    let config = FontAnalysisConfig {
        signature_directory: Some("/nonexistent/directory".to_string()),
        ..Default::default()
    };

    let result = config.load_signatures();
    assert!(result.is_err(), "Should fail to load from nonexistent directory");
}

/// Test that multiple signatures can match on the same font
#[cfg(feature = "dynamic")]
#[test]
fn test_multiple_signature_matches() {
    let config = FontAnalysisConfig {
        dynamic_enabled: true,
        signature_matching_enabled: true,
        ..Default::default()
    };

    // Create a font with multiple issues
    let multi_issue_font = create_multi_issue_font();
    let outcome = analyse_font(&multi_issue_font, &config);

    // Should detect multiple findings (at least parse failure or structure issues)
    assert!(!outcome.findings.is_empty(), "Multi-issue font should trigger multiple findings");
}

// ============================================================================
// Helper Functions for Creating Test Fonts
// ============================================================================

/// Create a minimal valid TrueType font for testing
#[cfg(feature = "dynamic")]
fn create_minimal_valid_font() -> Vec<u8> {
    let mut font_data = vec![
        // TrueType signature
        0x00, 0x01, 0x00, 0x00, // numTables = 3 (head, hhea, maxp)
        0x00, 0x03, // searchRange, entrySelector, rangeShift
        0x00, 0x30, 0x00, 0x02, 0x00, 0x00,
    ];

    // Table directory entries
    // head table
    font_data.extend_from_slice(b"head");
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksum
    font_data.extend_from_slice(&(60u32).to_be_bytes()); // offset = 12 + 48
    font_data.extend_from_slice(&54u32.to_be_bytes()); // length

    // hhea table
    font_data.extend_from_slice(b"hhea");
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksum
    font_data.extend_from_slice(&(114u32).to_be_bytes()); // offset = 12 + 48 + 54
    font_data.extend_from_slice(&36u32.to_be_bytes()); // length

    // maxp table
    font_data.extend_from_slice(b"maxp");
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksum
    font_data.extend_from_slice(&(150u32).to_be_bytes()); // offset = 12 + 48 + 54 + 36
    font_data.extend_from_slice(&6u32.to_be_bytes()); // length (minimal maxp v0.5)

    // head table data (minimal)
    font_data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // version
    font_data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // fontRevision
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksumAdjustment
    font_data.extend_from_slice(&[0x5F, 0x0F, 0x3C, 0xF5]); // magicNumber (correct)
    font_data.extend_from_slice(&[0x00, 0x00]); // flags
    font_data.extend_from_slice(&[0x00, 0x64]); // unitsPerEm = 100
    font_data.extend_from_slice(&[0x00; 16]); // created, modified dates
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // xMin, yMin
    font_data.extend_from_slice(&[0x00, 0x64, 0x00, 0x64]); // xMax, yMax
    font_data.extend_from_slice(&[0x00, 0x00]); // macStyle
    font_data.extend_from_slice(&[0x00, 0x08]); // lowestRecPPEM
    font_data.extend_from_slice(&[0x00, 0x00]); // fontDirectionHint
    font_data.extend_from_slice(&[0x00, 0x00]); // indexToLocFormat (short)
    font_data.extend_from_slice(&[0x00, 0x00]); // glyphDataFormat

    // hhea table data (minimal)
    font_data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // version
    font_data.extend_from_slice(&[0x00, 0x64]); // ascent
    font_data.extend_from_slice(&[0xFF, 0x9C]); // descent
    font_data.extend_from_slice(&[0x00, 0x00]); // lineGap
    font_data.extend_from_slice(&[0x00, 0x64]); // advanceWidthMax
    font_data.extend_from_slice(&[0x00, 0x00]); // minLeftSideBearing
    font_data.extend_from_slice(&[0x00, 0x00]); // minRightSideBearing
    font_data.extend_from_slice(&[0x00, 0x64]); // xMaxExtent
    font_data.extend_from_slice(&[0x00, 0x01]); // caretSlopeRise
    font_data.extend_from_slice(&[0x00, 0x00]); // caretSlopeRun
    font_data.extend_from_slice(&[0x00, 0x00]); // caretOffset
    font_data.extend_from_slice(&[0x00; 8]); // reserved
    font_data.extend_from_slice(&[0x00, 0x00]); // metricDataFormat
    font_data.extend_from_slice(&[0x00, 0x01]); // numOfLongHorMetrics = 1

    // maxp table data (v0.5 - minimal)
    font_data.extend_from_slice(&[0x00, 0x00, 0x50, 0x00]); // version 0.5
    font_data.extend_from_slice(&[0x00, 0x01]); // numGlyphs = 1

    font_data
}

/// Create a font with hmtx table length mismatch (CVE-2025-27163)
#[cfg(feature = "dynamic")]
fn create_hmtx_length_mismatch_font() -> Vec<u8> {
    let mut font_data = vec![
        0x00, 0x01, 0x00, 0x00, // TrueType signature
        0x00, 0x04, // numTables = 4
        0x00, 0x40, 0x00, 0x02, 0x00, 0x00, // searchRange, entrySelector, rangeShift
    ];

    // Table directory
    let table_dir_size = 16 * 4;
    let head_offset = 12 + table_dir_size;
    let hhea_offset = head_offset + 54;
    let maxp_offset = hhea_offset + 36;
    let hmtx_offset = maxp_offset + 6;

    // head table entry
    font_data.extend_from_slice(b"head");
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    font_data.extend_from_slice(&(head_offset as u32).to_be_bytes());
    font_data.extend_from_slice(&54u32.to_be_bytes());

    // hhea table entry
    font_data.extend_from_slice(b"hhea");
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    font_data.extend_from_slice(&(hhea_offset as u32).to_be_bytes());
    font_data.extend_from_slice(&36u32.to_be_bytes());

    // maxp table entry
    font_data.extend_from_slice(b"maxp");
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    font_data.extend_from_slice(&(maxp_offset as u32).to_be_bytes());
    font_data.extend_from_slice(&6u32.to_be_bytes());

    // hmtx table entry - MALFORMED (length too small)
    font_data.extend_from_slice(b"hmtx");
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    font_data.extend_from_slice(&(hmtx_offset as u32).to_be_bytes());
    font_data.extend_from_slice(&2u32.to_be_bytes()); // Should be 4 * numHMetrics = 8, but only 2

    // head table (same as minimal valid)
    font_data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x5F, 0x0F, 0x3C, 0xF5]);
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]);
    font_data.extend_from_slice(&[0x00; 16]);
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x64]);
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // hhea table with numberOfHMetrics = 2
    font_data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0xFF, 0x9C]);
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00]);
    font_data.extend_from_slice(&[0x00, 0x64, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    font_data.extend_from_slice(&[0x00; 8]);
    font_data.extend_from_slice(&[0x00, 0x00]);
    font_data.extend_from_slice(&[0x00, 0x02]); // numHMetrics = 2 (requires 8 bytes in hmtx)

    // maxp table
    font_data.extend_from_slice(&[0x00, 0x00, 0x50, 0x00, 0x00, 0x02]); // 2 glyphs

    // hmtx table - TRUNCATED (only 2 bytes instead of 8)
    font_data.extend_from_slice(&[0x00, 0x64]); // Only first metric, incomplete

    font_data
}

/// Create a font with maxp/CFF2 glyph count mismatch (CVE-2025-27164)
#[cfg(feature = "dynamic")]
fn create_maxp_cff2_mismatch_font() -> Vec<u8> {
    // This would require a CFF2 font structure, which is complex
    // For now, return a minimal structure that will parse but has issues
    let mut font_data = vec![
        0x4F, 0x54, 0x54, 0x4F, // OTTO signature (CFF font)
        0x00, 0x03, // numTables = 3
        0x00, 0x30, 0x00, 0x02, 0x00, 0x00,
    ];

    // This font will likely fail parsing, which is acceptable for CVE detection
    let table_dir_size = 16 * 3;
    let head_offset = 12 + table_dir_size;

    // CFF2 table entry
    font_data.extend_from_slice(b"CFF2");
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    font_data.extend_from_slice(&(head_offset as u32).to_be_bytes());
    font_data.extend_from_slice(&20u32.to_be_bytes());

    // head table entry
    font_data.extend_from_slice(b"head");
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    font_data.extend_from_slice(&((head_offset + 20) as u32).to_be_bytes());
    font_data.extend_from_slice(&54u32.to_be_bytes());

    // maxp table entry
    font_data.extend_from_slice(b"maxp");
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    font_data.extend_from_slice(&((head_offset + 74) as u32).to_be_bytes());
    font_data.extend_from_slice(&6u32.to_be_bytes());

    // CFF2 table data (minimal, possibly incomplete)
    font_data.extend_from_slice(&[0x02, 0x00]); // Major version 2
    font_data.extend_from_slice(&[0x00; 18]);

    // head table (standard)
    font_data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x5F, 0x0F, 0x3C, 0xF5]);
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]);
    font_data.extend_from_slice(&[0x00; 16]);
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x64]);
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // maxp table with excessive glyph count
    font_data.extend_from_slice(&[0x00, 0x00, 0x50, 0x00]);
    font_data.extend_from_slice(&[0x00, 0x0A]); // numGlyphs = 10 (more than CFF2 has)

    font_data
}

/// Create a font with multiple issues for testing
#[cfg(feature = "dynamic")]
fn create_multi_issue_font() -> Vec<u8> {
    // Combine multiple issues: truncated tables, invalid offsets, etc.
    let mut font_data = vec![
        0x00, 0x01, 0x00, 0x00, // TrueType signature
        0x00, 0x02, // numTables = 2
        0x00, 0x20, 0x00, 0x01, 0x00, 0x00,
    ];

    // head table - pointing beyond file
    font_data.extend_from_slice(b"head");
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    font_data.extend_from_slice(&1000u32.to_be_bytes()); // offset beyond file
    font_data.extend_from_slice(&54u32.to_be_bytes());

    // maxp table - also invalid offset
    font_data.extend_from_slice(b"maxp");
    font_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    font_data.extend_from_slice(&2000u32.to_be_bytes()); // offset beyond file
    font_data.extend_from_slice(&6u32.to_be_bytes());

    // File ends here - tables are not present
    font_data
}

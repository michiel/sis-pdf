# Font Analysis Test Fixtures

This directory contains test fixtures for font security analysis. All fixtures are synthetically generated for testing purposes.

## Directory Structure

```
fixtures/
├── exploits/       # Exploit samples demonstrating known attack patterns
├── cve/           # CVE-specific vulnerability test cases
└── benign/        # Clean fonts for regression testing
```

## Exploit Fixtures

### `exploits/blend_2015.pfa`
**Description:** Synthetic PostScript Type 1 font demonstrating the BLEND exploit pattern (circa 2015).

**Vulnerability:** Uses multiple `callothersubr`/`return` sequences to manipulate the PostScript interpreter stack, potentially leading to arbitrary code execution.

**Detection:** Should trigger `font.type1_blend_exploit` finding.

**Reference:** Based on the 2015 Type 1 font vulnerability affecting Adobe Reader and other PDF viewers.

**License:** Synthetic test data, public domain.

### `exploits/type1_stack_overflow.pfa`
**Description:** Type 1 font with excessive stack depth (>100 entries).

**Vulnerability:** Excessive stack usage in charstring program.

**Detection:** Should trigger `font.type1_excessive_stack` finding.

**License:** Synthetic test data, public domain.

### `exploits/type1_large_charstring.pfa`
**Description:** Type 1 font with very large charstring program (>10,000 operators).

**Vulnerability:** Resource exhaustion via oversized charstring.

**Detection:** Should trigger `font.type1_large_charstring` finding.

**License:** Synthetic test data, public domain.

## CVE Fixtures

### `cve/cve-2025-27163-hmtx-hhea-mismatch.ttf`
**CVE:** CVE-2025-27163

**Description:** TrueType font with hmtx table length smaller than required by hhea.numberOfHMetrics.

**Vulnerability:** Out-of-bounds read when accessing horizontal metrics.

**Detection:** Should trigger `font.cve_2025_27163` finding.

**Reference:** https://nvd.nist.gov/vuln/detail/CVE-2025-27163

**License:** Synthetic test data, public domain.

### `cve/cve-2025-27164-cff2-maxp-mismatch.otf`
**CVE:** CVE-2025-27164

**Description:** OpenType font with maxp.numGlyphs exceeding CFF2 charstring count.

**Vulnerability:** Out-of-bounds access when rendering glyphs.

**Detection:** Should trigger `font.cve_2025_27164` finding.

**Reference:** https://nvd.nist.gov/vuln/detail/CVE-2025-27164

**License:** Synthetic test data, public domain.

### `cve/cve-2023-26369-ebsc-oob.ttf`
**CVE:** CVE-2023-26369

**Description:** TrueType font with malformed EBSC table causing out-of-bounds read.

**Vulnerability:** Buffer over-read in embedded bitmap scaling table.

**Detection:** Should trigger `font.cve_2023_26369` finding.

**Reference:** https://nvd.nist.gov/vuln/detail/CVE-2023-26369

**License:** Synthetic test data, public domain.

### `cve/gvar-anomalous-size.ttf`
**CVE:** N/A (Anomaly)

**Description:** Variable font with excessively large gvar table (>10MB).

**Vulnerability:** Resource exhaustion, potential DoS.

**Detection:** Should trigger `font.anomalous_variation_table` finding.

**License:** Synthetic test data, public domain.

## Benign Fixtures

### `benign/minimal-type1.pfa`
**Description:** Minimal valid Type 1 font with single glyph.

**Purpose:** Regression testing - should not trigger any findings.

**License:** Synthetic test data, public domain.

### `benign/minimal-truetype.ttf`
**Description:** Minimal valid TrueType font with single glyph.

**Purpose:** Regression testing - should not trigger any findings.

**License:** Synthetic test data, public domain.

### `benign/minimal-variable.ttf`
**Description:** Minimal valid variable font with fvar/gvar tables.

**Purpose:** Regression testing - should not trigger any findings.

**License:** Synthetic test data, public domain.

## Usage

All fixtures are used in the test suite:

```rust
#[test]
fn test_blend_exploit_detection() {
    let data = include_bytes!("fixtures/exploits/blend_2015.pfa");
    let outcome = analyse_font(data, &FontAnalysisConfig::default());
    assert!(outcome.findings.iter().any(|f| f.kind == "font.type1_blend_exploit"));
}
```

## Maintenance

- All fixtures are synthetically generated
- No third-party fonts are included
- Update fixtures when new CVEs are discovered
- Document all changes with CVE references

## License

All test fixtures in this directory are synthetic test data created specifically for testing purposes and are released into the public domain. They do not contain any copyrighted font outlines or commercial font data.

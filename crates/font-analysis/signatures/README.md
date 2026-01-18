# Active CVE Signatures

This directory contains reviewed and active CVE signatures used for automated vulnerability detection.

## Status

- **Active Signatures**: 3
- **Pending Review**: 658 (in `../signatures-pending/`)

## Active Signatures

### CVE-2018-9410
**File**: `cve-2018-9410.yaml`
**Severity**: Medium
**Pattern**: `offset_out_of_bounds`

Android Minikin fvar table axis_records out-of-bounds read vulnerability. Detects when the fvar table's axis_records field offset extends beyond table boundaries, causing information disclosure through out-of-bounds memory reads.

**References**:
- https://nvd.nist.gov/vuln/detail/CVE-2018-9410
- https://source.android.com/security/bulletin/2018-07-01

### CVE-2025-27163
**File**: `cve-2025-27163.yaml`
**Severity**: High
**Pattern**: `table_length_mismatch`

hmtx table length smaller than required based on hhea.numberOfHMetrics. When the hmtx table length is insufficient (less than `numberOfHMetrics * 4` bytes), parsers performing out-of-bounds reads can access invalid memory, leading to crashes or information disclosure.

**References**:
- https://nvd.nist.gov/vuln/detail/CVE-2025-27163

### CVE-2025-27164
**File**: `cve-2025-27164.yaml`
**Severity**: High
**Pattern**: `glyph_count_mismatch`

maxp.numGlyphs exceeds CFF2 charstring count, leading to buffer overflow. When maxp table declares more glyphs than exist in the CFF2 charstring array, renderers attempting to access glyphs beyond the array bounds cause buffer overflows or out-of-bounds reads.

**References**:
- https://nvd.nist.gov/vuln/detail/CVE-2025-27164

## Signature Format

All signatures follow the standardized YAML format:

```yaml
- cve_id: CVE-YYYY-NNNNN
  description: Brief vulnerability description
  severity: low|medium|high|critical
  signature_rationale: |
    Detailed explanation of:
    - How the vulnerability works
    - Why this pattern detects it
    - What font structures are checked
  match_logic: all|any
  patterns:
    - type: pattern_type
      # pattern-specific fields
  references:
    - https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN
```

## Adding New Signatures

New signatures should be:

1. **Researched**: Thoroughly analyze the CVE
2. **Documented**: Include comprehensive `signature_rationale`
3. **Tested**: Verify detection and check for false positives
4. **Reviewed**: Peer review before activation

See [../SIGNATURE_GUIDE.md](../SIGNATURE_GUIDE.md) for complete documentation.

## Pattern Type Distribution

Current signatures use:
- `offset_out_of_bounds`: 1 signature (CVE-2018-9410)
- `table_length_mismatch`: 1 signature (CVE-2025-27163)
- `glyph_count_mismatch`: 1 signature (CVE-2025-27164)

## Testing

All active signatures are tested in the test suite:

```bash
cargo test --package font-analysis --lib signatures --features dynamic
```

Integration tests verify:
- Signature loading from directory
- Pattern matching against FontContext
- Finding generation with correct severity
- No false positives on benign fonts

## Maintenance

### Regular Reviews

- Verify signatures remain accurate as font parsers evolve
- Update patterns if CVE details are refined
- Add new patterns if vulnerability variants discovered

### Deprecation

Signatures should be deprecated (moved to `deprecated/`) when:
- CVE is disputed or withdrawn
- Pattern causes excessive false positives
- Better detection method is available
- Affected software is no longer in use

## Performance

Signature matching overhead:
- **3 signatures**: <1ms per font
- **Linear scaling**: ~0.3ms per 100 signatures
- **Caching**: Signatures loaded once at startup

## Documentation

- **[../SIGNATURE_GUIDE.md](../SIGNATURE_GUIDE.md)**: Complete guide to writing signatures
- **[../README.md](../README.md)**: Font analysis crate documentation
- **[../signatures-pending/README.md](../signatures-pending/README.md)**: Pending signature review process

## Contact

For questions about specific signatures or to report issues:
- Create an issue in the project tracker
- Include CVE ID and specific concerns
- Provide test cases if possible

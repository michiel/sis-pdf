# Font CVE Signature Guide

This guide explains how to create, test, and maintain CVE signatures for automated vulnerability detection in the font analysis system.

## Table of Contents

- [Overview](#overview)
- [Signature Schema](#signature-schema)
- [Pattern Types](#pattern-types)
- [Writing Signatures](#writing-signatures)
- [Testing Signatures](#testing-signatures)
- [Best Practices](#best-practices)
- [Examples](#examples)

## Overview

The signature system enables automated detection of known font vulnerabilities by matching structural patterns against font file characteristics. Each signature defines:

- **What vulnerability** it detects (CVE ID, description, severity)
- **Why this pattern** detects it (signature_rationale)
- **How to match** the vulnerability (one or more patterns)
- **References** to CVE databases and security advisories

## Signature Schema

### Basic Structure

```yaml
- cve_id: CVE-YYYY-NNNNN
  description: Brief description of the vulnerability
  severity: low|medium|high|critical
  signature_rationale: |
    Detailed explanation of why this signature detects the vulnerability.
    Include information about:
    - The root cause of the vulnerability
    - What malformed structures trigger it
    - How the pattern detects the issue
  match_logic: all|any
  patterns:
    - type: pattern_type
      # pattern-specific fields
  references:
    - https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN
```

### Required Fields

- **cve_id**: CVE identifier (e.g., `CVE-2024-12345`)
- **description**: One-line vulnerability description
- **severity**: `info`, `low`, `medium`, `high`, or `critical`
- **patterns**: Array of one or more pattern objects (or use `pattern` for single pattern)

### Optional Fields

- **signature_rationale**: Explains why this signature detects the vulnerability (recommended)
- **match_logic**: `all` (AND) or `any` (OR) - defaults to `all`
- **references**: URLs to CVE databases, advisories, patches

### Match Logic

- **all**: All patterns must match (AND logic) - use for multi-condition vulnerabilities
- **any**: At least one pattern must match (OR logic) - use for variant detection

## Pattern Types

### 1. TableLengthMismatch

Detects when a table's declared length doesn't match expected size based on metadata.

```yaml
type: table_length_mismatch
table1: hmtx              # Table with actual length
table2: hhea              # Table with metadata
condition: "table1.length < 4 * table2.num_metrics"
```

**Use Cases:**
- hmtx table too short for declared metrics
- glyf table size inconsistent with loca offsets
- COLR/CPAL size mismatches

**Condition Syntax:**
- `table1.length` - Actual table length in bytes
- `table2.num_metrics` - Metadata field (varies by table)
- Operators: `<`, `>`, `==`, `!=`, `<=`, `>=`
- Arithmetic: `+`, `-`, `*`, `/`

### 2. GlyphCountMismatch

Detects inconsistencies in glyph count between different font tables.

```yaml
type: glyph_count_mismatch
source1: maxp             # First glyph count source
source2: cff2             # Second glyph count source
condition: "source1 > source2"
```

**Valid Sources:**
- `maxp` - maxp table numGlyphs
- `cff` - CFF charstrings count
- `cff2` - CFF2 charstrings count
- `glyf` - glyf table glyph count
- `loca` - loca table entries - 1

**Common Patterns:**
- `maxp > cff2` - Buffer overflow when accessing CFF2 glyphs
- `maxp > glyf` - Out-of-bounds glyph access
- `loca != maxp + 1` - Incorrect loca table size

### 3. OffsetOutOfBounds

Detects when table field offsets exceed valid boundaries.

```yaml
type: offset_out_of_bounds
table: fvar               # Table containing the offset
field: axis_records       # Field with offset
bounds: table_length      # Boundary to check against
```

**Valid Bounds:**
- `table_length` - End of current table
- `file_length` - End of entire font file
- `parent_length` - End of parent structure

**Use Cases:**
- fvar axis_records beyond table end
- GPOS/GSUB lookup offsets out of bounds
- CFF DICT offset validation

### 4. TableSizeExceeds

Detects tables that exceed safe size limits.

```yaml
type: table_size_exceeds
table: HVAR               # Table to check
max_size: 5242880         # Maximum safe size in bytes (5MB)
```

**Common Limits:**
- HVAR: 5MB
- MVAR: 1MB
- GPOS/GSUB: 10MB
- glyf: 50MB

### 5. OperatorSequence

Detects suspicious sequences of operators in charstring/bytecode.

```yaml
type: operator_sequence
operators: ["0x0C", "0x0D"]  # Hex opcodes to detect
min_count: 5                  # Minimum occurrences
```

**Use Cases:**
- Repeated blend operators (Type 1)
- Stack manipulation patterns
- Infinite loop detection

### 6. IntegerOverflow

Detects arithmetic operations that could overflow.

```yaml
type: integer_overflow
operation: multiply       # Operation type
operand1: num_glyphs     # First operand field
operand2: glyph_size     # Second operand field
max_value: "u32::MAX"    # Maximum safe value
```

**Operations:**
- `multiply` - Checks `operand1 * operand2`
- `add` - Checks `operand1 + operand2`

**Operand Fields:**
- `num_glyphs`, `glyph_size`, `num_metrics`, `table_length`, etc.
- Any numeric field from FontContext

### 7. InvalidMagic

Detects corrupted or invalid magic numbers in table headers.

```yaml
type: invalid_magic
table: head               # Table to validate
offset: 12                # Byte offset of magic number
expected: "0x5F0F3CF5"    # Expected magic value
```

**Common Magic Numbers:**
- head: `0x5F0F3CF5` at offset 12
- CFF: version 1 or 2 at offset 0
- OTTO: `OTTO` signature at file offset 0

### 8. RecursionDepthExceeds

Detects excessive nesting in recursive structures.

```yaml
type: recursion_depth_exceeds
structure: composite_glyph  # Structure type
max_depth: 16               # Maximum safe nesting
```

**Structures:**
- `composite_glyph` - Nested glyph components
- `gsub_lookup` - GSUB lookup nesting
- `gpos_lookup` - GPOS lookup nesting

### 9. CircularReference

Detects circular references in font structures.

```yaml
type: circular_reference
table: glyf                      # Table with references
reference_field: component_glyph_index  # Field creating cycle
```

**Detection:**
- Uses DFS cycle detection algorithm
- Checks table_references graph in FontContext
- Detects self-references and circular chains

### 10. BufferOverflow

Detects potential buffer overflows from offset/size combinations.

```yaml
type: buffer_overflow
table: hmtx               # Table containing offset/size
offset_field: metrics_offset  # Offset field
size_field: metrics_size      # Size field
bounds: file_length           # Maximum boundary
```

**Checks:** `offset + size > bounds`

### 11. InvalidTableReference

Detects missing or invalid table cross-references.

```yaml
type: invalid_table_reference
source_table: GSUB        # Table making reference
reference_field: coverage_offset  # Field with offset
required: true            # Whether reference must exist
```

**Use Cases:**
- GSUB/GPOS coverage table validation
- CFF FD index validation
- COLR layer references

### 12. InvalidInstructionSequence

Detects dangerous TrueType instruction sequences.

```yaml
type: invalid_instruction_sequence
table: fpgm               # Table containing instructions
invalid_opcodes: ["0xFF", "0xC0"]  # Invalid opcode bytes
invalid_sequences: ["0x2B,0x2B"]   # Dangerous sequences (CALL,CALL)
```

**Detectable Issues:**
- Undefined opcodes (>= 0xC0)
- Stack overflow sequences (consecutive CALLs)
- Infinite loop patterns

## Writing Signatures

### Step 1: Research the CVE

1. Read the CVE description and references
2. Understand the root cause
3. Identify what structural anomaly triggers the vulnerability
4. Determine which font tables/fields are involved

### Step 2: Choose Pattern Types

Select pattern types that match the vulnerability:

- **Table structure issues** → TableLengthMismatch, TableSizeExceeds
- **Glyph count problems** → GlyphCountMismatch
- **Offset validation** → OffsetOutOfBounds, BufferOverflow
- **Recursive structures** → RecursionDepthExceeds, CircularReference
- **Magic numbers** → InvalidMagic
- **Instruction streams** → OperatorSequence, InvalidInstructionSequence

### Step 3: Write the Signature

```yaml
- cve_id: CVE-2024-12345
  description: Out of bounds read in fvar table axis processing
  severity: medium
  signature_rationale: |
    This vulnerability occurs when the fvar table's axis_records field
    offset extends beyond the table boundaries. Parsers that don't
    validate this offset perform out-of-bounds reads, leading to
    information disclosure.
  match_logic: all
  patterns:
    - type: offset_out_of_bounds
      table: fvar
      field: axis_records
      bounds: table_length
  references:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-12345
```

### Step 4: Test the Signature

1. Create a test font that triggers the vulnerability
2. Load the signature into a test
3. Verify it matches the malformed font
4. Verify it doesn't match benign fonts (false positive check)

### Step 5: Document the Rationale

Write a clear `signature_rationale` that explains:
- What the vulnerability is
- Why this pattern detects it
- What conditions trigger the match

## Testing Signatures

### Unit Test Example

```rust
#[test]
fn test_cve_2024_12345_signature() {
    let yaml = r#"
- cve_id: CVE-2024-12345
  description: fvar offset out of bounds
  severity: medium
  signature_rationale: |
    Detects when fvar axis_records offset exceeds table length.
  match_logic: all
  patterns:
    - type: offset_out_of_bounds
      table: fvar
      field: axis_records
      bounds: table_length
  references:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-12345
"#;

    let signatures: Vec<Signature> = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(signatures.len(), 1);

    let sig = &signatures[0];
    sig.validate().unwrap();
    assert_eq!(sig.cve_id, "CVE-2024-12345");
}
```

### Integration Test Example

```rust
#[test]
fn test_cve_2024_12345_detection() {
    // Create malformed font with fvar offset OOB
    let malformed_font = create_malformed_fvar_font();

    // Load signature
    let config = FontAnalysisConfig::default();
    let signatures = config.load_signatures().unwrap();

    // Parse font and match
    let context = parse_font(&malformed_font).unwrap();
    let registry = SignatureRegistry::new();
    for sig in signatures {
        registry.add(sig);
    }

    let findings = registry.match_signatures(&context);

    // Verify CVE detected
    assert!(findings.iter().any(|f| f.kind.contains("CVE-2024-12345")));
}
```

## Best Practices

### 1. Be Specific

- Use precise conditions, not overly broad patterns
- Prefer multiple specific patterns over one generic pattern
- Target the exact anomaly that triggers the vulnerability

### 2. Avoid False Positives

- Test against benign fonts
- Use `match_logic: all` for multi-condition checks
- Set reasonable thresholds (don't flag all large tables)

### 3. Document Thoroughly

- Always include `signature_rationale`
- Explain the vulnerability mechanism
- Link to authoritative references

### 4. Follow Naming Conventions

- Use lowercase CVE IDs: `cve-2024-12345`
- Descriptive field names: `axis_records` not `field1`
- Consistent severity levels

### 5. Version Control

- One CVE per file: `cve-2024-12345.yaml`
- Keep signatures in `signatures/` directory
- Pending signatures in `signatures-pending/`

### 6. Severity Guidelines

- **Critical**: RCE, memory corruption with known exploits
- **High**: Memory corruption, buffer overflows, DoS
- **Medium**: Information disclosure, out-of-bounds reads
- **Low**: Minor anomalies, unusual structures
- **Info**: Suspicious patterns without confirmed impact

## Examples

### Example 1: Simple Table Length Mismatch

```yaml
- cve_id: CVE-2025-27163
  description: hmtx table length mismatch leading to OOB read
  severity: high
  signature_rationale: |
    The hmtx table must contain at least numberOfHMetrics * 4 bytes.
    When the table is smaller, parsers perform out-of-bounds reads.
  match_logic: all
  patterns:
    - type: table_length_mismatch
      table1: hmtx
      table2: hhea
      condition: "table1.length < 4 * table2.num_metrics"
  references:
    - https://nvd.nist.gov/vuln/detail/CVE-2025-27163
```

### Example 2: Glyph Count Mismatch

```yaml
- cve_id: CVE-2025-27164
  description: maxp glyph count exceeds CFF2 charstrings
  severity: high
  signature_rationale: |
    When maxp.numGlyphs exceeds CFF2 charstring count, renderers
    accessing glyphs beyond the array cause buffer overflows.
  match_logic: all
  patterns:
    - type: glyph_count_mismatch
      source1: maxp
      source2: cff2
      condition: "source1 > source2"
  references:
    - https://nvd.nist.gov/vuln/detail/CVE-2025-27164
```

### Example 3: Multiple Patterns with ANY Logic

```yaml
- cve_id: CVE-2024-99999
  description: Variable font table anomalies
  severity: medium
  signature_rationale: |
    Multiple variable font tables can trigger similar vulnerabilities.
    This signature detects excessive sizes in any variation table.
  match_logic: any
  patterns:
    - type: table_size_exceeds
      table: HVAR
      max_size: 5242880
    - type: table_size_exceeds
      table: MVAR
      max_size: 1048576
    - type: table_size_exceeds
      table: VVAR
      max_size: 5242880
  references:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-99999
```

### Example 4: Complex Multi-Pattern Signature

```yaml
- cve_id: CVE-2018-9410
  description: Android Minikin fvar axis out-of-bounds read
  severity: medium
  signature_rationale: |
    This vulnerability occurs in Android's Minikin library when
    analyzeAxes processes variable fonts. The function reads axis
    records from the fvar table without validating offsets stay
    within boundaries. Malformed fvar tables trigger OOB reads.
  match_logic: all
  patterns:
    - type: offset_out_of_bounds
      table: fvar
      field: axis_records
      bounds: table_length
  references:
    - https://nvd.nist.gov/vuln/detail/CVE-2018-9410
    - https://source.android.com/security/bulletin/2018-07-01
```

## Signature Lifecycle

### 1. Creation

- Research CVE
- Write signature YAML
- Add to `signatures-pending/`
- Document in signature_rationale

### 2. Testing

- Create unit test
- Test against PoC font (if available)
- Verify no false positives on benign fonts
- Validate YAML schema

### 3. Review

- Peer review for accuracy
- Check pattern specificity
- Verify severity level
- Confirm references

### 4. Activation

- Move from `signatures-pending/` to `signatures/`
- Add to signature index
- Update test suite

### 5. Maintenance

- Update if CVE details change
- Refine if false positives occur
- Deprecate if pattern superseded

## Troubleshooting

### Signature Not Matching

1. **Verify pattern syntax**: Check YAML is valid
2. **Check FontContext**: Ensure required fields are populated
3. **Test pattern logic**: Use unit test to isolate issue
4. **Validate conditions**: Print operand values to debug

### False Positives

1. **Tighten conditions**: Make pattern more specific
2. **Add secondary pattern**: Use `match_logic: all`
3. **Adjust thresholds**: Increase size limits if too low
4. **Check edge cases**: Test against diverse font corpus

### Signature Load Failures

1. **Validate YAML**: Check syntax with YAML validator
2. **Check schema**: Ensure all required fields present
3. **Verify pattern type**: Must match enum variant exactly
4. **Test in isolation**: Load single signature to debug

## Resources

- [NVD CVE Database](https://nvd.nist.gov/)
- [OpenType Specification](https://learn.microsoft.com/en-us/typography/opentype/spec/)
- [TrueType Reference](https://developer.apple.com/fonts/TrueType-Reference-Manual/)
- [CFF Specification](https://adobe-type-tools.github.io/font-tech-notes/pdfs/5176.CFF.pdf)

## Contributing

To contribute new signatures:

1. Create signature in `signatures-pending/`
2. Write comprehensive tests
3. Document in signature_rationale
4. Submit for review
5. Respond to feedback

For questions or issues, refer to the main project documentation.

# Pending CVE Signatures - Manual Review Required

This directory contains 658 CVE signature files that require manual review and pattern definition before they can be used for vulnerability detection.

## Status

- **Total Pending**: 658 signatures
- **Reviewed & Active**: 3 signatures (in `../signatures/`)

## What Needs to Be Done

Each signature file in this directory has a placeholder pattern that must be replaced with a specific detection pattern:

```yaml
pattern:
  type: manual
  note: "This signature requires manual review and pattern definition..."
```

### Review Process

For each CVE signature, you must:

1. **Analyze the CVE**
   - Read the NVD description and references
   - Understand the vulnerability mechanism
   - Identify which font tables/structures are involved
   - Determine what validation is missing

2. **Choose Appropriate Pattern Type**

   Available pattern types (see `../SIGNATURE_GUIDE.md` for complete documentation):

   - `table_length_mismatch` - Compare lengths between two tables
   - `glyph_count_mismatch` - Compare glyph counts from different sources
   - `offset_out_of_bounds` - Verify offsets are within bounds
   - `table_size_exceeds` - Check if table exceeds size limit
   - `operator_sequence` - Match charstring operator sequences
   - `integer_overflow` - Detect arithmetic overflow conditions
   - `invalid_magic` - Validate magic numbers in table headers
   - `recursion_depth_exceeds` - Check for excessive nesting
   - `circular_reference` - Detect circular reference chains
   - `buffer_overflow` - Detect offset+size exceeding bounds
   - `invalid_table_reference` - Validate cross-table references
   - `invalid_instruction_sequence` - Detect dangerous TrueType bytecode

   See [SIGNATURE_GUIDE.md](../SIGNATURE_GUIDE.md) for detailed pattern documentation and examples.

3. **Add Signature Rationale**

   Add a `signature_rationale` field explaining:
   - How the vulnerability works
   - Why this pattern detects it
   - What font structures are checked

4. **Replace the Pattern**

   Example transformation:

   ```yaml
   # Before (placeholder)
   pattern:
     type: manual
     note: "This signature requires manual review..."

   # After (specific pattern)
   signature_rationale: |
     This vulnerability occurs when the analyzeAxes function reads axis records
     from the fvar table without validating offsets stay within table boundaries.
     Out-of-bounds reads lead to information disclosure.
   pattern:
     type: offset_out_of_bounds
     table: fvar
     field: axis_records
     bounds: table_length
   ```

5. **Test the Signature**
   - Test against known vulnerable samples (if available)
   - Verify no false positives on benign fonts
   - Ensure detection accuracy

6. **Move to Active Signatures**

   Once reviewed and tested, move the file to `../signatures/`

## Example: Completed Review

See `../signatures/cve-2018-9410.yaml` for an example of a completed signature with:
- Specific `offset_out_of_bounds` pattern
- Detailed `signature_rationale` field
- Clear detection logic

## Pattern Type Coverage

The signature system includes 12 comprehensive pattern types covering most font vulnerability classes. If you encounter a CVE that doesn't fit any existing pattern, consider:

1. **Combining patterns** - Use `match_logic: all` for multi-condition vulnerabilities
2. **Extending existing patterns** - Add parameters to existing types
3. **Creating new pattern types** - Update `signatures.rs` with new variants
4. **Documenting the gap** - Note which CVEs need new pattern types

## Tools

Use the `cve-update` tool to fetch new CVEs:
```bash
cargo build --release -p cve-update
./target/release/cve-update
```

See `../../tools/cve-update/README.md` for details.

## Progress Tracking

Consider tracking review progress:
- Create issues for complex CVEs requiring research
- Tag CVEs by affected component (FreeType, HarfBuzz, etc.)
- Group similar vulnerabilities for batch review

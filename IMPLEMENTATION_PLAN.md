# Font Analysis Enhancement Implementation Plan

This plan implements comprehensive font security analysis for `sis-pdf` using Rust-native crates. All work happens within the existing `crates/font-analysis/` crate, which already provides basic static and dynamic analysis infrastructure.

## Scope

**In Scope:**
- Type 1 (PostScript) font analysis and BLEND exploit detection
- Enhanced TrueType/CFF dynamic analysis with CVE-specific checks
- Variable font and color font support
- CVE signature system with automated updates
- Font/JavaScript correlation
- External font reference detection
- Instrumentation and configurable analysis budgets

**Out of Scope (Future Work):**
- ML-based risk scoring models (noted in Stage 4, deferred)
- Optional FFI to FreeType (sandboxed C library integration)
- Fuzz testing infrastructure (AFL/libAFL integration)
- Dedicated fuzzing harnesses and continuous fuzzing

## Existing Infrastructure

**Current `crates/font-analysis/` Structure:**
- `lib.rs` - Main entry point with `analyse_font()` function
- `model.rs` - Data structures (`FontAnalysisConfig`, `DynamicAnalysisOutcome`, `FontFinding`)
- `static_scan.rs` - Static analysis module
- `dynamic.rs` - Dynamic analysis with timeout handling (currently minimal)
- `tests/` - Test suite

**Already Available:**
- `skrifa` (v0.40) - Available under `dynamic` feature flag
- Timeout mechanism using `std::sync::mpsc` and thread spawning
- `FontAnalysisConfig` with `enabled`, `dynamic_enabled`, `dynamic_timeout_ms`, `max_fonts`
- Finding generation infrastructure

## Dependencies

**New Crates to Add:**
- `postscript` - Type 1 font parsing and charstring decoding
- `ttf-parser` (≥0.15) - Safe TrueType/OpenType parsing with variable font support
- `allsorts` - Advanced parsing including WOFF/WOFF2 and color fonts
- `reqwest` - HTTP client for CVE feed fetching (tools only)
- `once_cell` - Lazy static initialization for rule registry

**Existing Crates (from workspace):**
- `serde`, `serde_yaml`, `serde_json` - Configuration and signature parsing
- `tracing` - Structured logging and instrumentation
- `thiserror` - Error type definitions
- `regex` - Pattern matching for CVE filtering

---

## Stage 1: Type 1 Font Analysis

**Goal:** Add comprehensive PostScript Type 1 font analysis to detect the BLEND exploit and other Type 1 vulnerabilities.

**Success Criteria:**
- [ ] Type 1 fonts correctly identified from `/Subtype` and stream headers
- [ ] eexec decryption working for encrypted charstrings
- [ ] Charstring parsing extracts all operators and operands
- [ ] Dangerous operators (`callothersubr`, `blend`, `pop`, `return`) flagged
- [ ] Stack depth tracking detects excessive usage (>100 entries)
- [ ] Large charstring programs flagged (>10,000 ops)
- [ ] New findings emitted: `font.type1_dangerous_operator`, `font.type1_excessive_stack`, `font.type1_large_charstring`

**Tests:**
- Unit tests with benign Type 1 fonts from Adobe Core 14
- **Exploit fixture:** Synthetic BLEND exploit (2015) sample in `tests/fixtures/exploits/blend_2015.pfb`
- **CVE fixtures:** Type 1 fonts with known vulnerabilities in `tests/fixtures/cve/`
- Edge cases: minimal font, maximum operators, deeply nested calls
- Integration test: PDF with embedded Type 1 font producing expected findings
- Regression tests ensure no false positives on Adobe Source fonts

**Implementation Tasks:**

### 1.1 Type 1 Detection Module
- **File:** `crates/font-analysis/src/type1/mod.rs`
- Implement `is_type1_font(font_dict: &PdfDict, stream: &[u8]) -> bool`
- Check `/Subtype` is `/Type1`
- Scan first 1KB for `%!PS-AdobeFont`, `FontType 1`, `.notdef`
- Add tests for identification accuracy

### 1.2 eexec Decryption
- **File:** `crates/font-analysis/src/type1/eexec.rs`
- Implement Type 1 eexec algorithm (XOR with rolling seed)
- Use `postscript` crate or implement manually
- Handle both binary and ASCII hex encoding
- Return decrypted charstring data

### 1.3 Charstring Analysis
- **File:** `crates/font-analysis/src/type1/charstring.rs`
- Parse charstrings using `postscript::type1`
- Implement `CharstringAnalyzer` struct:
  - `max_stack_depth: usize`
  - `total_operators: usize`
  - `dangerous_ops: Vec<(usize, String)>` - (position, operator name)
- Walk operators, track stack simulation
- Flag dangerous operators: `callothersubr`, `pop`, `return`, `put`, `store`, `blend`
- Detect BLEND exploit pattern: multiple `callothersubr`/`return` sequences

### 1.4 Finding Generation
- **File:** `crates/font-analysis/src/type1/findings.rs`
- Implement `analyze_type1(font_data: &[u8]) -> Vec<Finding>`
- Generate findings with evidence pointing to operator locations
- Severity mapping:
  - `font.type1_dangerous_operator` → HIGH
  - `font.type1_excessive_stack` → MEDIUM
  - `font.type1_large_charstring` → LOW

### 1.5 Test Fixture Creation
- **Directory:** `crates/font-analysis/tests/fixtures/`
- Create or acquire test fixtures:
  - **BLEND exploit:** Synthesize Type 1 font with multiple `callothersubr`/`return` sequences
  - **Adobe Core 14:** Extract benign Type 1 fonts (Times-Roman, Helvetica, etc.)
  - **Stack overflow:** Create Type 1 font with >100 stack depth
  - **Large charstring:** Generate font with >10,000 operator charstring
- Document fixture sources and CVE/exploit references in `tests/fixtures/README.md`
- Add LICENSE.txt for redistributed fonts

### 1.6 Integration
- **File:** `crates/font-analysis/src/lib.rs`
- Modify `analyse_font()` to dispatch to `type1::analyze_type1()` when Type 1 detected
- Merge Type 1 findings with existing static/dynamic findings
- Update `docs/findings.md` with new finding definitions

**Status:** Not Started

---

## Stage 2: Enhanced Dynamic Analysis & CVE Detection

**Goal:** Replace no-op dynamic analysis with instrumented parser implementing specific CVE checks and signature-based detection.

**Success Criteria:**
- [ ] Dynamic parser using `skrifa`/`ttf-parser` reports parse failures as findings
- [ ] TrueType hinting programs executed with instruction budget
- [ ] Variable font table validation (CVE-2025-27163/27164 checks)
- [ ] CVE signature system loads YAML/JSON signatures
- [ ] Signatures match against parsed font context
- [ ] Automated CVE feed fetcher retrieves NVD updates

**Tests:**
- Fonts with parse errors trigger `font.dynamic_parse_failure`
- **CVE-2025-27163 fixture:** `tests/fixtures/cve/cve-2025-27163-hmtx-hhea-mismatch.ttf` (hmtx/hhea mismatch)
- **CVE-2025-27164 fixture:** `tests/fixtures/cve/cve-2025-27164-cff2-maxp-mismatch.otf` (CFF2/maxp mismatch)
- **CVE-2023-26369 fixture:** `tests/fixtures/cve/cve-2023-26369-ebsc-oob.ttf` (EBSC out-of-bounds)
- **Additional CVE fixtures:** All known font CVEs from 2020-present in `tests/fixtures/cve/`
- Signature matching correctly identifies vulnerable fonts from fixture suite
- Malformed font files trigger appropriate error handling
- Benign variable fonts pass all validation checks

**Implementation Tasks:**

### 2.1 Dynamic Parser Foundation
- **File:** `crates/font-analysis/src/dynamic/mod.rs`
- Replace no-op implementation with `skrifa` or `ttf-parser` integration
- Implement `DynamicParser` struct with `parse(data: &[u8]) -> Result<FontContext>`
- Capture parse errors and convert to `font.dynamic_parse_failure` findings
- Build `FontContext` struct containing:
  - Parsed tables (glyf, hmtx, hhea, maxp, CFF2, gvar, avar, EBSC)
  - Table sizes and offsets
  - Glyph counts from various sources

### 2.2 TrueType VM Interpreter
- **File:** `crates/font-analysis/src/dynamic/ttf_vm.rs`
- Implement minimal TrueType virtual machine for hinting programs
- Stack-based interpreter limited to arithmetic ops
- Instruction budget: 50,000 ops per glyph
- Stack depth limit: 256 entries
- Flag unusual loops or excessive calls
- Emit `font.ttf_hinting_suspicious` on anomalies

### 2.3 Variable Font Validation
- **File:** `crates/font-analysis/src/dynamic/variable_fonts.rs`
- Implement CVE-specific checks:
  - **CVE-2025-27163:** `hmtx.len() >= 4 * hhea.numberOfHMetrics`
  - **CVE-2025-27164:** `maxp.num_glyphs <= cff2.charstrings.len()`
  - **CVE-2023-26369:** `gvar.GlyphVariationData_size >= 4 + total_tvh_size`
  - **EBSC OOB:** Verify EBSC offsets don't exceed table bounds
- Generate findings: `font.cve_2025_27163`, `font.cve_2025_27164`, etc.

### 2.4 CVE Signature System
- **File:** `crates/font-analysis/src/signatures.rs` (new module)
- Define `Signature` struct:
  ```rust
  struct Signature {
      cve_id: String,
      description: String,
      severity: Severity,
      pattern: SignaturePattern,
  }
  ```
- `SignaturePattern` enum:
  - `TableLengthMismatch { table1, table2, condition }`
  - `OffsetOutOfBounds { table, offset_field, bounds }`
  - `OperatorSequence { operators: Vec<String> }`
- Load signatures from YAML/JSON at build time via `build.rs`
- Implement `match_signatures(ctx: &FontContext) -> Vec<Finding>`

### 2.5 CVE Feed Automation
- **File:** `tools/cve-update/src/main.rs` (new binary)
- Use `reqwest` to fetch NVD JSON feeds
- Filter for font-related CVEs (keywords: font, TrueType, CFF, Adobe, FreeType, Skia)
- Parse CVE descriptions and generate signature templates
- Output YAML signatures to `crates/font-analysis/signatures/`
- Run as GitHub Action on weekly schedule

### 2.6 CVE Test Fixture Creation
- **Directory:** `crates/font-analysis/tests/fixtures/cve/`
- Synthesize or acquire fonts triggering specific CVEs:
  - **CVE-2025-27163:** TrueType with `hmtx` length < `4 * hhea.numberOfHMetrics`
  - **CVE-2025-27164:** OpenType/CFF2 with `maxp.num_glyphs` > `charstrings.len()`
  - **CVE-2023-26369:** TrueType with EBSC offsets exceeding table bounds
  - **Additional CVEs:** Create fixtures for all CVEs from 2020-present
- Use font generation tools (fonttools, fontforge) to create malformed fonts
- Document each CVE with references to NVD/advisories in fixture README
- Ensure fixtures trigger exactly one CVE (no multiple issues per file)

**Status:** Not Started

---

## Stage 3: Advanced Format Support & Correlation

**Goal:** Support variable fonts, color fonts, WOFF/WOFF2, and correlate font findings with JavaScript/external references.

**Success Criteria:**
- [ ] Variable font tables (avar, gvar, HVAR, MVAR) parsed and validated
- [ ] Color font tables (COLR, CPAL) validated for consistency
- [ ] WOFF/WOFF2 decompression and conversion to SFNT working
- [ ] External font references (remote URIs) detected and flagged
- [ ] Font+JavaScript correlation produces composite findings
- [ ] Findings include: `font.anomalous_variation_table`, `font.color_table_inconsistent`, `font.external_reference`, `pdf.font_js_correlation`

**Tests:**
- **Variable font fixtures:** `tests/fixtures/variable/valid-avar.ttf`, `tests/fixtures/variable/invalid-gvar-size.ttf`
- **Color font fixtures:** `tests/fixtures/color/valid-colr-cpal.ttf`, `tests/fixtures/color/oob-palette-index.ttf`
- **WOFF/WOFF2 fixtures:** `tests/fixtures/woff/compressed.woff2`, `tests/fixtures/woff/malformed-header.woff`
- WOFF2 decompression produces valid SFNT for analysis
- PDF with `/URI` font reference in `tests/fixtures/pdf/external-font-ref.pdf` flagged
- Correlation fixture: `tests/fixtures/pdf/type1-exploit-with-js-heapspray.pdf` triggers composite finding

**Implementation Tasks:**

### 3.1 Variable Font Analysis
- **File:** `crates/font-analysis/src/variable_fonts.rs`
- Use `ttf-parser` ≥0.15 for parsing avar, gvar, HVAR, MVAR tables
- Validation rules:
  - Header lengths match expected sizes
  - Variation axis indices within glyph count
  - Deltas don't cause integer overflow
  - `gvar` data size not excessively large (>10MB)
- Generate findings for anomalies

### 3.2 Color Font Analysis
- **File:** `crates/font-analysis/src/color_fonts.rs`
- Use `allsorts` to parse COLR and CPAL tables
- Check:
  - Palette indices in bounds
  - Layer count matches glyph count
  - Color values are valid RGBA
- Emit `font.color_table_inconsistent` on errors

### 3.3 WOFF/WOFF2 Support
- **File:** `crates/font-analysis/src/woff.rs`
- Use `allsorts` WOFF/WOFF2 parser
- Decompress and convert to SFNT
- Check for decompressor vulnerabilities (integer overflow in size calculations)
- Pass SFNT to existing analysis pipeline

### 3.4 External Font Reference Detection
- **File:** `crates/sis-pdf-detectors/src/font_external_ref.rs`
- Scan PDF dictionaries for:
  - `/GoToR`, `/URI`, `/Launch` actions with font references
  - `/FontFile*` pointing to external `/FS /URL`
  - `/F` in `FileSpecification` with remote URI
- Validate URIs using `url` crate
- Emit `font.external_reference` with HIGH severity
- Optional: fetch remote font if network access enabled (config flag)

### 3.5 Font/JavaScript Correlation
- **File:** `crates/sis-pdf-core/src/runner.rs`
- Extend existing correlation logic in `run_scan_with_detectors()`
- After all detectors run, check for combinations:
  - Font HIGH severity + JavaScript heap spray/shellcode → `pdf.font_js_correlation` (CRITICAL)
  - Font MEDIUM + JavaScript obfuscation → escalate to HIGH
- Use `indexmap` for efficient finding lookup by kind

**Status:** Not Started

---

## Stage 4: Instrumentation & Configuration

**Goal:** Add instrumentation hooks, execution budgets, and user-configurable thresholds for analysis behavior.

**Success Criteria:**
- [ ] `tracing` instrumentation captures all operations in interpreters
- [ ] Instruction budget prevents infinite loops in Type 1/TTF VM
- [ ] Timeout mechanism aborts long-running analysis
- [ ] `FontAnalysisConfig` struct loads from YAML/JSON
- [ ] Configuration options: `max_charstring_ops`, `max_stack_depth`, `enable_dynamic_analysis`, `dynamic_timeout_ms`
- [ ] Context-aware severity: trusted sources downgraded, untrusted escalated
- [ ] Findings: `font.dynamic_timeout`, `font.budget_exceeded`

**Tests:**
- Infinite loop font triggers timeout
- Excessive operations trigger budget exceeded
- Config loading from YAML works
- Severity adjustment based on context

**Implementation Tasks:**

### 4.1 Instrumentation Hooks
- **File:** `crates/font-analysis/src/instrumentation.rs`
- Integrate `tracing` spans for:
  - Parser entry/exit
  - Interpreter operations (Type 1, TTF VM)
  - Memory reads/writes (in VM context)
  - Control flow (calls, returns, loops)
- Optional: `tokio-tracing-console` integration for debugging
- Add spans to existing code in `type1_analysis` and `dynamic/ttf_vm`

### 4.2 Execution Budgets
- **File:** `crates/font-analysis/src/budget.rs`
- Implement `ExecutionBudget` struct:
  ```rust
  struct ExecutionBudget {
      max_instructions: u64,
      max_stack_depth: usize,
      deadline: Instant,
  }
  ```
- Check budget on each VM operation
- Abort and emit `font.budget_exceeded` when exceeded
- Default budgets:
  - Type 1: 50,000 instructions
  - TTF VM: 50,000 instructions per glyph
  - Stack depth: 256
  - Timeout: 5 seconds per font

### 4.3 Configuration System
- **File:** `crates/font-analysis/src/config.rs`
- Define `FontAnalysisConfig`:
  ```rust
  pub struct FontAnalysisConfig {
      pub enabled: bool,
      pub dynamic_enabled: bool,
      pub dynamic_timeout_ms: u64,
      pub max_charstring_ops: u64,
      pub max_stack_depth: usize,
      pub max_fonts: usize,
      pub network_access: bool,
  }
  ```
- Implement `Default` with conservative values
- Load from TOML/JSON via `serde`
- Integrate with existing `ScanOptions` in `crates/sis-pdf-core/src/scan.rs`

### 4.4 Context-Aware Severity
- **File:** `crates/font-analysis/src/context.rs`
- Define `AnalysisContext` enum:
  ```rust
  enum AnalysisContext {
      TrustedSource,
      SignedPDF,
      UntrustedInput,
      Server,
      Desktop,
  }
  ```
- Implement severity adjustment logic:
  - Trusted → downgrade MEDIUM to LOW
  - Untrusted → escalate LOW to MEDIUM
  - Server context → more strict
- Apply adjustments before emitting findings

### 4.5 ML-Based Scoring (Deferred - Future Work)

**Note:** ML-based risk scoring is out of scope for this implementation plan but noted for future work.

**Future Considerations:**
- Simple weighted sum of finding severities as interim solution
- Feature extraction: glyph count, table entropy, instruction counts, stack depth
- Model training using `linfa` or external tools on labeled corpus
- Integration point: after all findings collected, compute `ml_risk_score`

**Status:** Not Started

---

## Stage 5: Automation & Documentation

**Goal:** Integrate CVE updates into CI and document all new features.

**Success Criteria:**
- [ ] GitHub Action runs CVE update weekly
- [ ] New findings documented in `docs/findings.md`
- [ ] Example binary demonstrates font analysis API
- [ ] README updated with font analysis capabilities
- [ ] All new modules have documentation comments

**Tests:**
- CI workflow executes successfully
- Documentation builds without errors
- Example compiles and runs
- All unit tests pass

**Implementation Tasks:**

### 5.1 CI Integration
- **File:** `.github/workflows/cve-update.yml`
- Schedule: weekly on Monday 00:00 UTC
- Steps:
  1. Run `tools/cve-update` to fetch NVD feeds
  2. Generate new signatures
  3. Create PR if signatures changed
  4. Auto-label for security team review

### 5.2 Documentation Updates
- **File:** `docs/findings.md`
- Add sections for new findings:
  - Type 1 findings (3 new)
  - CVE-specific findings (4+ new)
  - Variable/color font findings (2 new)
  - Correlation findings (1 new)
- Include: severity, description, remediation, examples

### 5.3 Examples
- **File:** `examples/font_analysis.rs`
- Demonstrate:
  - Loading a PDF with embedded fonts
  - Running font analysis
  - Interpreting findings
  - Configuring thresholds
- Include sample PDFs in `examples/samples/`

### 5.4 README Updates
- **File:** `README.md`
- Add "Font Security Analysis" section
- List supported formats: Type 1, TrueType, CFF, Variable, Color, WOFF/WOFF2
- Mention CVE signature system
- Link to findings documentation

**Status:** Not Started

---

## Out of Scope (Future Work)

### Optional FFI to FreeType

**Rationale:** Deferred to maintain Rust-only stack and avoid sandboxing complexity.

**Future Considerations:**
- Conditional compilation behind `freetype` feature flag
- Sandboxing using `rustix` + `seccomp` for restricted execution
- Capture segfaults and translate to findings
- Useful for: extremely rare font features unsupported by Rust crates

**Implementation Notes (if pursued later):**
- Wrap FreeType calls in separate process or thread
- Use seccomp to restrict syscalls (read, write, exit only)
- Monitor with `ptrace` or signal handlers
- Convert crashes to `font.freetype_crash` findings

### Fuzz Testing Infrastructure

**Rationale:** Deferred due to CI resource requirements and complexity. Manual testing with malformed fonts covers immediate needs.

**Future Considerations:**
- AFL or libAFL integration for coverage-guided fuzzing
- Dedicated fuzzing harnesses: `fuzz/fuzz_targets/dynamic_font_parser.rs`, `type1_charstring.rs`, `variable_font_parser.rs`
- CI integration with time-limited runs (10 minutes per target)
- Crash reproduction and automated issue filing
- Corpus management with public font collections

**Implementation Notes (if pursued later):**
- Use `cargo-afl` or `cargo-fuzz` for harness setup
- Seed corpus with Google Fonts, Adobe Source, and known CVE test cases
- Mutation strategies: bit flips, table size manipulation, operator injection
- Target: 1 million executions per week for comprehensive coverage
- Report crashes as GitHub issues with reproducers

---

## Testing Strategy

### Test Fixture Suite

All test fixtures organized in `crates/font-analysis/tests/fixtures/`:

**Exploits:**
- `exploits/blend_2015.pfb` - BLEND exploit (PostScript Type 1, 2015)
- `exploits/type1_stack_overflow.pfb` - Excessive stack depth Type 1 font
- `exploits/ttf_hinting_loop.ttf` - TrueType infinite loop hinting program

**CVE Test Cases (2020-Present):**
- `cve/cve-2023-26369-ebsc-oob.ttf` - EBSC table out-of-bounds write
- `cve/cve-2025-27163-hmtx-hhea-mismatch.ttf` - hmtx/hhea length mismatch
- `cve/cve-2025-27164-cff2-maxp-mismatch.otf` - CFF2/maxp glyph count mismatch
- `cve/cve-YYYY-NNNNN-*.{ttf,otf,pfb}` - Additional CVEs as discovered

**Format Coverage:**
- `type1/adobe-core14/*.pfb` - Benign Type 1 fonts from Adobe Core 14
- `variable/valid-*.ttf` - Valid variable fonts with avar, gvar, HVAR, MVAR
- `variable/invalid-*.ttf` - Malformed variable fonts (size, offset, index errors)
- `color/valid-*.ttf` - Valid COLR/CPAL color fonts
- `color/invalid-*.ttf` - Malformed color fonts (OOB palette, invalid layers)
- `woff/*.woff` - WOFF compressed fonts
- `woff/*.woff2` - WOFF2 compressed fonts (valid and malformed)
- `truetype/benign-*.ttf` - Standard TrueType fonts
- `opentype/benign-*.otf` - Standard CFF OpenType fonts

**PDF Integration:**
- `pdf/type1-embedded.pdf` - PDF with embedded Type 1 font
- `pdf/external-font-ref.pdf` - PDF with `/URI` remote font reference
- `pdf/type1-exploit-with-js-heapspray.pdf` - Correlation test case
- `pdf/variable-font-embedded.pdf` - PDF with variable font

**Benign Regression Suite:**
- `benign/google-fonts-sample/*.ttf` - Sample from Google Fonts (no false positives)
- `benign/adobe-source/*.otf` - Adobe Source fonts (no false positives)

### Unit Tests
- Each module has `#[cfg(test)] mod tests` with 80%+ coverage
- Test benign, malicious, and edge-case fonts from fixture suite
- Property-based testing using `proptest` for charstring parsing
- All fixtures have corresponding test assertions

### Integration Tests
- `tests/font_analysis_integration.rs` - End-to-end tests with fixtures
- `tests/cve_detection.rs` - All CVE fixtures trigger correct findings
- `tests/exploit_detection.rs` - All exploit fixtures detected
- `tests/benign_regression.rs` - No false positives on benign suite
- `tests/format_coverage.rs` - All format types parsed correctly

### Performance Benchmarks
- `benches/font_analysis.rs` using Criterion
- Measure: parse time, analysis time, memory usage
- Baseline: <100ms per font, <50MB peak memory

---

## Dependencies & Risks

### Technical Risks
1. **Crate maturity:** `postscript` crate may be unmaintained
   - Mitigation: Fork and maintain if necessary, or implement Type 1 parsing manually
2. **False positives:** Heuristics may flag benign fonts
   - Mitigation: Tune thresholds via config, collect feedback from users
3. **CVE signature accuracy:** Automated signature generation may miss nuances
   - Mitigation: Manual review of generated signatures, community contributions

### External Dependencies
- NVD API availability for CVE feeds
- GitHub Advisory Database as backup source
- Font test corpora (Google Fonts, Adobe, etc.)

### Resource Requirements
- CI compute time: +5 minutes/week for CVE updates
- Storage: ~100MB for CVE signatures and test fonts
- Development time: ~8-12 weeks for 5 stages (2-3 weeks per stage)

---

## Success Metrics

- **Coverage:** 80%+ code coverage for new modules
- **Detection:** Successfully detects all known font CVEs in test suite
- **Performance:** <100ms per font analysis, no regression in existing scan times
- **False Positive Rate:** <5% on benign font corpus (Google Fonts sample)
- **Documentation:** 100% of new findings documented in `docs/findings.md`

---

## References

- [BLEND Exploit (2015)](https://www.exploit-db.com/exploits/37976)
- [CVE-2025-27163](https://nvd.nist.gov/) - hmtx/hhea mismatch
- [CVE-2025-27164](https://nvd.nist.gov/) - CFF2/maxp mismatch
- [CVE-2023-26369](https://nvd.nist.gov/) - EBSC OOB write
- [OpenType Specification](https://docs.microsoft.com/en-us/typography/opentype/spec/)
- [PostScript Type 1 Font Format](https://adobe-type-tools.github.io/font-tech-notes/pdfs/T1_SPEC.pdf)

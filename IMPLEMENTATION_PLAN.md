# Font Analysis Enhancement Implementation Plan

This plan implements comprehensive font security analysis for `sis-pdf` using Rust-native crates. The work addresses critical gaps in Type 1 font analysis, dynamic parsing, CVE detection, and emerging font format support.

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

## Dependencies

**New Crates Required:**
- `postscript` - Type 1 font parsing and charstring decoding
- `ttf-parser` (≥0.15) - Safe TrueType/OpenType parsing with variable font support
- `allsorts` - Advanced parsing including WOFF/WOFF2 and color fonts
- `skrifa` or `fontations/read-fonts` - Memory-safe parsing (Chrome's font engine)
- `libafl` or `cargo-afl` - Fuzzing infrastructure
- `arbitrary` - Test input generation for fuzzing
- `reqwest` - HTTP client for CVE feed fetching
- `once_cell` - Lazy static initialization for rule registry

**Existing Crates:**
- `serde`, `serde_yaml`, `serde_json` - Configuration and signature parsing
- `tracing` - Structured logging and instrumentation
- `tokio` - Async runtime for timeouts
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
- Synthetic BLEND exploit sample triggering heuristics
- Edge cases: minimal font, maximum operators, deeply nested calls
- Integration test: PDF with embedded Type 1 font producing expected findings

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

### 1.5 Integration
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
- [ ] Fuzz harness runs under AFL/libAFL

**Tests:**
- Fonts with parse errors trigger `font.dynamic_parse_failure`
- CVE-2025-27163 test case (hmtx/hhea mismatch) detected
- CVE-2025-27164 test case (CFF2/maxp mismatch) detected
- CVE-2023-26369 test case (EBSC OOB) detected
- Fuzzer discovers at least one input causing timeout/budget exceeded
- Signature matching correctly identifies known vulnerable fonts

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
- **File:** `crates/font-signatures/src/lib.rs` (new crate)
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
- Output YAML signatures to `crates/font-signatures/signatures/`
- Run as GitHub Action on weekly schedule

### 2.6 Fuzz Testing Infrastructure
- **File:** `fuzz/fuzz_targets/dynamic_font_parser.rs`
- Create AFL harness calling `DynamicParser::parse()`
- Use `arbitrary` crate for input generation
- Configure to run 10-minute time-limited fuzzing in CI
- Report crashes and hangs as GitHub issues
- Optional: libAFL integration for coverage-guided fuzzing

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
- Variable font with valid/invalid avar data
- Color font with palette index OOB
- WOFF2 compressed font decompresses correctly
- PDF with `/URI` font reference flagged
- PDF with Type 1 dangerous ops + JavaScript heap spray triggers correlation

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

**Goal:** Integrate CVE updates into CI, add fuzzing automation, and document all new features.

**Success Criteria:**
- [ ] GitHub Action runs CVE update weekly
- [ ] Fuzzing runs in CI on every PR (time-limited)
- [ ] New findings documented in `docs/findings.md`
- [ ] Example binary demonstrates font analysis API
- [ ] README updated with font analysis capabilities

**Tests:**
- CI workflow executes successfully
- Fuzzing discovers at least one timeout case
- Documentation builds without errors
- Example compiles and runs

**Implementation Tasks:**

### 5.1 CI Integration
- **File:** `.github/workflows/cve-update.yml`
- Schedule: weekly on Monday 00:00 UTC
- Steps:
  1. Run `tools/cve-update` to fetch NVD feeds
  2. Generate new signatures
  3. Create PR if signatures changed
  4. Auto-label for security team review

### 5.2 Fuzzing Automation
- **File:** `.github/workflows/fuzz.yml`
- Run on: every PR, nightly builds
- Time limit: 10 minutes per target
- Targets: `dynamic_font_parser`, `type1_charstring`, `variable_font_parser`
- Report: upload crash reproducers as artifacts
- Notify: create GitHub issue on new crashes

### 5.3 Documentation Updates
- **File:** `docs/findings.md`
- Add sections for new findings:
  - Type 1 findings (3 new)
  - CVE-specific findings (4+ new)
  - Variable/color font findings (2 new)
  - Correlation findings (1 new)
- Include: severity, description, remediation, examples

### 5.4 Examples
- **File:** `examples/font_analysis.rs`
- Demonstrate:
  - Loading a PDF with embedded fonts
  - Running font analysis
  - Interpreting findings
  - Configuring thresholds
- Include sample PDFs in `examples/samples/`

### 5.5 README Updates
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

---

## Testing Strategy

### Unit Tests
- Each module has `#[cfg(test)] mod tests` with 80%+ coverage
- Test benign, malicious, and edge-case fonts
- Property-based testing using `proptest` for charstring parsing

### Integration Tests
- `tests/font_analysis_integration.rs` with real PDF samples
- CVE test suite with known vulnerable fonts
- Regression tests for false positives

### Fuzzing
- Continuous fuzzing with AFL/libAFL
- Corpus: seed with public font collections (Google Fonts, Adobe)
- Mutation strategies: bit flips, table resizing, operator injection
- Goal: 1 million executions per week

### Performance Benchmarks
- `benches/font_analysis.rs` using Criterion
- Measure: parse time, analysis time, memory usage
- Baseline: <100ms per font, <50MB peak memory

---

## Dependencies & Risks

### Technical Risks
1. **Crate maturity:** `postscript` crate may be unmaintained
   - Mitigation: Fork and maintain if necessary, or implement Type 1 parsing manually
2. **Fuzzing scalability:** AFL may be slow on complex inputs
   - Mitigation: Use libAFL for better performance, limit corpus size
3. **False positives:** Heuristics may flag benign fonts
   - Mitigation: Tune thresholds via config, collect feedback from users

### External Dependencies
- NVD API availability for CVE feeds
- GitHub Advisory Database as backup source
- Font test corpora (Google Fonts, Adobe, etc.)

### Resource Requirements
- CI compute time: +30 minutes/week for fuzzing
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

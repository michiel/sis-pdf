# Implementation Plan: New sis-pdf Analysis Modules

## Executive Summary

This plan delivers six new forensic analysis modules through 10 staged increments, extending `sis-pdf` with deep detection capabilities for embedded files, launch actions, action chains, XFA forms, rich media, encryption weaknesses, and filter chain anomalies.

**Key additions beyond detection:**
- **Query interface integration**: 30+ new query types (e.g., `embedded.executables`, `actions.chains`, `xfa.scripts`)
- **Feature vector integration**: 25+ new ML features across XFA, encryption, and filter domains
- **Performance & safety architecture**: Timeout enforcement, memory budgets, decompression limits
- **CVE regression coverage**: Synthetic fixtures for 6+ CVE patterns with regression tests
- **Forensic workflow support**: Extraction, SAST integration, visualization exports

**Total estimated features**: 76 features (35 base + 16 images + 25 new)

## Goals

- Deliver six new analysis modules in staged, executable increments.
- Maintain safety, accuracy, efficiency, and completeness.
- Use Australian English spelling and structured `tracing` fields.
- Ensure all new findings have test coverage and documentation updates.
- Integrate with query interface (Phases 5-9 from query uplift plan).
- Extend feature extraction pipeline for ML workflows.
- Enforce performance SLOs and safety limits to prevent DOS attacks.

## Scope

Stages cover:
0. Alignment, Scope, and Baseline
0.5. Performance & Safety Architecture
1. Embedded Files and Launch Actions
2. Actions and Triggers
3. XFA Forms
4. Rich Media Content
5. Encryption and Obfuscation
6. Filter Chain Anomaly Detection
7. Documentation and Integration Sweep
7.5. Query Interface Integration
8. Feature Vector Integration
9. Cross-Finding Correlation (optional)

---

## Stage 0: Alignment, Scope, and Baseline

### Scope

Establish shared infrastructure, fixtures, CVE mappings, and baseline tests before implementing detectors.

### Checklist

#### Findings Inventory and ID Allocation

- [x] Review `docs/findings.md` to confirm existing finding IDs and schemas.
- [x] Allocate new finding IDs (see "New Finding IDs" section below).
- [x] Ensure no ID conflicts with existing findings.
- [x] Document finding metadata schema (severity, tags, evidence fields).

#### Finding Metadata Schema

- Required fields: `id`, `kind`, `title`, `description`, `severity`, `confidence`, `surface`, `objects`.
- Evidence: use `EvidenceSpan` entries with `source`, `offset`, `length`, `origin`, and short `note` values.
- Metadata keys:
  - Embedded files: `embedded.filename`, `embedded.sha256`, `embedded.size`, `embedded.magic`, `embedded.double_extension`, `embedded.encrypted_container`.
  - Actions: `payload.key`, `payload.type`, `payload.decoded_len`, `payload.ref_chain`, `action.trigger`, `action.chain_depth`.
  - Launch: `launch.target_type` plus payload metadata from `/F` or `/Win`.
  - XFA: `xfa.submit.url`, `xfa.script.count`, `xfa.field.name`, `xfa.size_bytes`.
  - Encryption/obfuscation: `crypto.algorithm`, `crypto.key_length`, `stream.entropy`, `stream.filters`.
  - Filter chains: `stream.filter_chain`, `stream.filter_depth`.

#### Shared Infrastructure

- [x] Create `crates/sis-pdf-core/src/stream_analysis.rs` with unified stream analysis service:
  - [x] `analyse_stream()` function: single-pass hash, entropy, magic detection (filters pending).
  - [x] `StreamAnalysisResult` struct with `magic_type`, `entropy`, `blake3`, `size_bytes`.
  - [x] `StreamLimits` struct for max-bytes analysis bounds (timeout/ratio pending).
- [x] Create `crates/sis-pdf-core/src/evidence.rs` with `EvidenceBuilder`:
  - [x] Methods: `file_offset()`, `object_ref()`, `decoded_payload()`, `hash()`.
  - [x] Consistent formatting matching existing evidence output (see TODO.md:42-47).
- [x] Create `crates/sis-pdf-core/src/timeout.rs` with `TimeoutChecker` (cooperative timeout pattern from image analysis plan):
  - [x] `TimeoutChecker::new(budget: Duration)` constructor.
  - [x] `check()` method returning `Result<(), TimeoutError>`.
  - [x] Integration examples for detectors.

#### Test Fixtures

- [x] Create `crates/sis-pdf-core/tests/fixtures/embedded/` directory.
- [x] Create `crates/sis-pdf-core/tests/fixtures/actions/` directory.
- [x] Create `crates/sis-pdf-core/tests/fixtures/xfa/` directory.
- [x] Create `crates/sis-pdf-core/tests/fixtures/media/` directory.
- [x] Create `crates/sis-pdf-core/tests/fixtures/encryption/` directory.
- [x] Create `crates/sis-pdf-core/tests/fixtures/filters/` directory.

#### CVE Regression Fixtures

- [x] Create `scripts/generate_analysis_fixtures.py` with functions:
  - [x] `generate_launch_cve_2010_1240()` - PDF with /Launch to cmd.exe
  - [x] `generate_embedded_exe_cve_2018_4990()` - PDF with embedded PE
  - [x] `generate_xfa_cve_2013_2729()` - PDF with XFA SOAP script
  - [x] `generate_swf_cve_2011_0611()` - PDF with malicious SWF structure
  - [x] `generate_weak_encryption_cve_2019_7089()` - PDF with RC4-40
  - [x] `generate_filter_obfuscation_cve_2010_2883()` - PDF with unusual filter chain
- [x] Generate synthetic fixtures (NOT real exploits, valid PDF structure only).
- [x] Add `tests/fixtures/README.md` documenting that fixtures are synthetic.
- [x] Run fixture generation script and commit outputs to repository.

#### Dependency Security Review

- [ ] Deferred: document dependency choices in table format (see "Dependency Security Review" section below).
- [ ] Deferred: pin dependency versions in `Cargo.toml` for XFA parser (`roxmltree = "0.20.0"`).
- [ ] Deferred: document SWF parsing strategy (minimal custom parser, header + magic only).
- [ ] Deferred: document entropy calculation approach (sliding window, no external crates).

#### Fuzzing Infrastructure

- [ ] Create `fuzz/` directory with `Cargo.toml`.
- [ ] Create `fuzz/fuzz_targets/xfa_parser.rs` fuzzing target.
- [ ] Create `fuzz/fuzz_targets/swf_parser.rs` fuzzing target.
- [ ] Create `fuzz/fuzz_targets/filter_chain.rs` fuzzing target.
- [ ] Add `.github/workflows/fuzz.yml` with nightly CI runs (300s per target).
- [ ] Document corpus management and seed file strategy.

#### Test Scaffolding

- [ ] Create `crates/sis-pdf-detectors/tests/embedded_files.rs`.
- [ ] Create `crates/sis-pdf-detectors/tests/launch_actions.rs`.
- [ ] Create `crates/sis-pdf-detectors/tests/action_chains.rs`.
- [ ] Create `crates/sis-pdf-detectors/tests/xfa_forms.rs`.
- [ ] Create `crates/sis-pdf-detectors/tests/rich_media.rs`.
- [ ] Create `crates/sis-pdf-detectors/tests/encryption.rs`.
- [ ] Create `crates/sis-pdf-detectors/tests/filter_chains.rs`.
- [ ] Verify all test files compile and pass (empty tests initially).

#### Baseline Verification

- [x] Run `cargo test --all` and ensure 100% pass rate.
- [ ] Run `cargo clippy --all` and ensure no warnings.
- [ ] Run `cargo build --release` and ensure clean build.
- [ ] Verify no new findings are emitted yet (baseline scan should match current output).

### New Finding IDs

**Stage 1: Embedded Files & Launch (6 findings)**
- `embedded_executable_present` - Embedded file is an executable (PE, ELF, Mach-O)
- `embedded_script_present` - Embedded file is a script (JS, VBS, PS1, BAT)
- `embedded_archive_encrypted` - Embedded ZIP/RAR archive is password-protected
- `embedded_double_extension` - Embedded file has double extension (e.g., document.pdf.exe)
- `launch_external_program` - /Launch action targets external program
- `launch_embedded_file` - /Launch action targets embedded file

**Stage 2: Actions & Triggers (3 findings)**
- `action_chain_complex` - Action chain depth exceeds threshold (default: 3)
- `action_hidden_trigger` - Action triggered by non-obvious event (e.g., /FocusIn)
- `action_automatic_trigger` - Action triggered automatically (/OpenAction, /AA WillClose)

**Stage 3: XFA Forms (4 findings)**
- `xfa_submit` - XFA form contains submit action with target URL
- `xfa_sensitive_field` - XFA form contains sensitive field names (password, ssn, credit)
- `xfa_too_large` - XFA content exceeds size limit (default: 1MB)
- `xfa_script_count_high` - XFA contains excessive script blocks (default: >5)

**Stage 4: Rich Media (2 findings)**
- `swf_embedded` - Embedded SWF (Flash) content detected
- `swf_actionscript_detected` - SWF contains ActionScript tags

**Stage 5: Encryption & Obfuscation (3 findings)**
- `stream_high_entropy` - Stream entropy exceeds threshold (default: 7.5)
- `embedded_encrypted` - Embedded file appears encrypted (high entropy + no known magic)
- `encryption_key_short` - Encryption key length below recommended (e.g., RC4-40)

**Stage 6: Filter Chains (3 findings)**
- `filter_chain_unusual` - Filter combination not in allowlist
- `filter_order_invalid` - Filter order violates PDF specification
- `filter_combination_unusual` - Filter combination is rare/suspicious

**Total new findings: 21**

### Dependency Security Review

| Functionality | Candidate Crates | Selected | Version | CVE Status | Rationale |
|---------------|------------------|----------|---------|------------|-----------|
| XFA XML parsing | `quick-xml`, `roxmltree` | `roxmltree` | `0.20.0` | ✅ No known CVEs | No entity expansion support (safer), simpler API |
| SWF parsing | `swf`, `swf-parser`, custom | Custom | N/A | ✅ No dependencies | Minimal header parser only, avoid full decompression |
| SWF decompression | `flate2` | `flate2` | `1.0` | ✅ Widely audited | Standard zlib wrapper, decompression ratio limits enforced |
| Entropy calculation | Custom (Shannon) | Custom | N/A | ✅ No dependencies | Simple math, sliding window implementation |
| Hash calculation | `sha2` | `sha2` | `0.10` | ✅ RustCrypto audit | Streaming hash, no buffering required |
| Magic detection | `infer`, custom | Custom | N/A | ✅ No dependencies | Simple byte pattern matching, extend existing magic detector |

**Pinning strategy:**
- All dependencies pinned to exact versions in `Cargo.toml`.
- Run `cargo audit` in CI on every commit.
- Monitor RustSec advisory database for updates.

### CVE Regression Mapping

| Stage | Detector | CVEs Addressed | Fixture Name | Regression Test |
|-------|----------|----------------|--------------|-----------------|
| 1 | Launch Action | CVE-2010-1240, CVE-2009-0927, CVE-2013-0640 | `launch_cmd_exe.pdf` | `test_launch_cve_2010_1240()` |
| 1 | Embedded EXE | CVE-2018-4990 | `embedded_pe.pdf` | `test_embedded_exe_cve_2018_4990()` |
| 3 | XFA Scripts | CVE-2013-2729, CVE-2018-4990, CVE-2009-0193 | `xfa_soap_script.pdf` | `test_xfa_cve_2013_2729()` |
| 4 | SWF ActionScript | CVE-2011-0611, CVE-2015-5119 | `swf_malicious.pdf` | `test_swf_cve_2011_0611()` |
| 5 | Weak Encryption | CVE-2019-7089 | `rc4_40_encryption.pdf` | `test_weak_encryption_cve_2019_7089()` |
| 6 | Filter Chain | CVE-2010-2883 | `filter_obfuscation.pdf` | `test_filter_cve_2010_2883()` |

### Acceptance Criteria

- ✅ Shared infrastructure modules (`stream_analysis.rs`, `evidence.rs`, `timeout.rs`) implemented and documented.
- ✅ CVE fixture generation script creates all 6 synthetic fixtures.
- ✅ Fuzzing infrastructure runs successfully with empty corpus.
- ✅ All test scaffolding files compile and pass.
- ✅ Dependency security review table complete and dependencies pinned.
- ✅ Baseline tests pass with 100% success rate.
- ✅ No new findings emitted (detectors not yet implemented).

---

## Stage 0.5: Performance & Safety Architecture

### Scope

Define performance SLOs, memory budgets, timeout strategies, and decompression limits to prevent DOS attacks and ensure reliable operation on malicious PDFs.

### Performance SLOs

| Operation | Target Latency | Maximum Latency | Memory Budget | Timeout Strategy |
|-----------|----------------|-----------------|---------------|------------------|
| Embedded file hash (Stage 1) | <10ms | 50ms | Streaming (no buffer) | 100ms per file |
| Action chain walk (Stage 2) | <50ms | 100ms | 10KB (visited set) | 100ms total, depth 10 |
| XFA XML parse (Stage 3) | <50ms | 100ms | 1MB max XML size | 100ms per form |
| SWF header parse (Stage 4) | <10ms | 50ms | 10MB (header only) | 250ms per stream |
| Entropy calculation (Stage 5) | <20ms | 50ms | 10MB sample size | 50ms per stream |
| Filter chain validation (Stage 6) | <5ms | 10ms | 1KB (chain metadata) | 10ms per chain |

**Instrumentation requirements:**
- Add `tracing` spans for each operation with `operation`, `file_size`, `elapsed_ms` fields.
- Profile output format: JSON lines with `operation`, `duration_ms`, `memory_bytes`, `status` fields.
- Export profiles via `sis scan --profile-output=analysis_profile.jsonl`.

### Safety Limits

#### Decompression Ratio Limits

```rust
pub struct DecompressionLimits {
    pub max_ratio: f64,          // Default: 10.0 (10:1 compression)
    pub max_output_size: usize,  // Default: 100MB
    pub timeout_ms: u64,         // Default: 250ms
}
```

**Enforcement:**
- Track input bytes vs output bytes during decompression.
- Abort if ratio exceeds limit or timeout reached.
- Log warning with object ID and ratio for forensic review.

#### XML Entity Expansion Limits

**Strategy:** Use `roxmltree` which **does not support entity expansion** (inherently safe).

**Validation:**
- Reject XML with DOCTYPE declarations (indicates entity usage attempt).
- Limit XML size to 1MB pre-parse.
- Timeout at 100ms.

#### Memory Budgets

| Component | Budget | Enforcement |
|-----------|--------|-------------|
| Embedded file buffer | Streaming | Never buffer entire file, hash in chunks |
| Action chain visited set | 10KB | Limit to 1000 visited objects (10 bytes/ID) |
| XFA XML DOM | 1MB | Enforced by input size limit + roxmltree defaults |
| SWF decompression | 10MB | Decompress header only, skip body |
| Entropy calculation | 10MB | Sample first 10MB only, sliding window |
| Filter chain metadata | 1KB | Max 10 filters × 100 bytes metadata |

### Timeout Enforcement Strategy

**Decision:** Cooperative timeout checking (same pattern as image analysis plan:105-197).

#### TimeoutChecker Implementation

```rust
// crates/sis-pdf-core/src/timeout.rs

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct TimeoutChecker {
    start: Instant,
    budget: Duration,
    last_check: std::cell::Cell<Instant>,
    check_interval: Duration,
}

impl TimeoutChecker {
    /// Create new timeout checker with specified budget
    pub fn new(budget: Duration) -> Self {
        let now = Instant::now();
        Self {
            start: now,
            budget,
            last_check: std::cell::Cell::new(now),
            check_interval: Duration::from_millis(10), // Check every 10ms
        }
    }

    /// Check if timeout has been exceeded (cooperative check)
    pub fn check(&self) -> Result<(), TimeoutError> {
        let now = Instant::now();

        // Only check time if interval has passed (avoid syscall overhead)
        if now.duration_since(self.last_check.get()) >= self.check_interval {
            self.last_check.set(now);

            if now.duration_since(self.start) > self.budget {
                return Err(TimeoutError {
                    budget: self.budget,
                    elapsed: now.duration_since(self.start),
                });
            }
        }

        Ok(())
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        Instant::now().duration_since(self.start)
    }

    /// Get remaining time
    pub fn remaining(&self) -> Option<Duration> {
        self.budget.checked_sub(self.elapsed())
    }
}

#[derive(Debug, Clone)]
pub struct TimeoutError {
    pub budget: Duration,
    pub elapsed: Duration,
}

impl std::fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "timeout: budget {:?}, elapsed {:?}",
            self.budget, self.elapsed
        )
    }
}

impl std::error::Error for TimeoutError {}
```

#### Integration Pattern for Detectors

```rust
// Example: XFA parser with cooperative timeout checking

pub fn parse_xfa_with_timeout(
    xml_data: &[u8],
    timeout: Duration,
) -> Result<XfaDocument, ParseError> {
    let checker = TimeoutChecker::new(timeout);

    // Check before expensive operations
    checker.check()?;

    let doc = roxmltree::Document::parse(std::str::from_utf8(xml_data)?)?;

    checker.check()?;

    let mut xfa_doc = XfaDocument::default();

    for node in doc.descendants() {
        // Check every N iterations (e.g., every 100 nodes)
        if node.id() % 100 == 0 {
            checker.check()?;
        }

        // Process node...
    }

    Ok(xfa_doc)
}
```

#### Per-Format Pixel/Size Limits

| Format | Limit Type | Limit Value | Rationale |
|--------|------------|-------------|-----------|
| XFA XML | Size | 1MB | Legitimate forms rarely exceed 500KB |
| SWF | Decompressed size | 10MB | Only parse header, skip full decompression |
| Embedded files | Hash streaming | Unlimited | Streaming hash has O(1) memory |
| Entropy calculation | Sample size | 10MB | First 10MB sufficient for entropy estimate |
| Action chains | Depth | 10 levels | Legitimate chains rarely exceed 3 levels |

### Fallback Strategies

**When timeout/limit exceeded:**

1. **Log warning** with structured fields:
   ```rust
   tracing::warn!(
       operation = "xfa_parse",
       object_id = obj_id,
       timeout_ms = timeout.as_millis(),
       "XFA parsing timeout exceeded, skipping analysis"
   );
   ```

2. **Skip analysis** for specific object (don't fail entire scan).

3. **Emit finding** if appropriate:
   ```rust
   emit_finding(FindingId::XfaTooLarge, Severity::Medium, evidence);
   ```

4. **Continue scanning** remaining objects.

**Non-cooperative decoders:**

If external decoder library doesn't support cooperative checking:
- Enforce hard timeout using `std::thread::spawn` + `join_timeout` (fallback only).
- Document non-cooperative decoders in dependency table.
- Consider replacing with cooperative alternatives in future.

### Acceptance Criteria

- ✅ `TimeoutChecker` implemented and unit tested.
- ✅ `DecompressionLimits` struct defined with defaults.
- ✅ Performance SLO table documented.
- ✅ Safety limits table documented.
- ✅ Integration patterns documented with code examples.
- ✅ Fallback strategies documented.
- ✅ Instrumentation requirements specified.

---

## Stage 1: Embedded Files and Launch Actions

### Scope

Detect and enrich embedded file findings with magic type detection, hashing, and double extension checks. Correlate `/Launch` actions with embedded attachments and external program invocations.

### Checklist

#### Embedded File Detection Enhancements

- [ ] Implement `EmbeddedFileDetector` in `crates/sis-pdf-detectors/src/embedded_files.rs`:
  - [ ] Extract embedded file streams from `/EmbeddedFile` and `/EmbeddedFiles` dictionary.
  - [ ] Compute SHA-256 hash using streaming (no buffering entire file).
  - [ ] Extract filename from `/F`, `/UF`, or `/Desc` keys.
  - [ ] Detect magic type using first 512 bytes (PE, ELF, Mach-O, ZIP, JS, VBS, etc.).
  - [x] Detect double extensions (e.g., `document.pdf.exe`, `report.doc.js`).
  - [x] Detect encrypted ZIP archives (PK magic + encryption flag at offset 6).
  - [x] Use `EvidenceBuilder` for consistent evidence formatting.
  - [x] Use `TimeoutChecker` with 100ms budget per file.
  - [ ] Use `stream_analysis::analyze_stream()` for unified analysis.

- [ ] Emit findings:
  - [x] `embedded_executable_present` when magic type is PE/ELF/Mach-O.
  - [x] `embedded_script_present` when magic type is JS/VBS/PS1/BAT or extension indicates script.
  - [x] `embedded_archive_encrypted` when ZIP encryption flag set.
  - [x] `embedded_double_extension` when filename has suspicious pattern.
  - [ ] Include metadata: `hash.sha256`, `filename`, `size_bytes`, `magic_type`, `encrypted` (bool).

#### Launch Action Detection

- [ ] Implement `LaunchActionDetector` in `crates/sis-pdf-detectors/src/launch_actions.rs`:
  - [x] Parse `/Launch` actions in `/Action`, `/AA`, `/OpenAction` dictionaries.
  - [x] Extract target from `/F` (file spec) or `/Win` (Windows launch params).
  - [ ] Correlate launch target with embedded file list (match by filename).
  - [ ] Detect external program launches (cmd.exe, powershell.exe, bash, etc.).
  - [x] Use `EvidenceBuilder` for evidence formatting.

- [ ] Emit findings:
  - [x] `launch_external_program` when target is external executable.
  - [x] `launch_embedded_file` when target matches embedded file.
  - [ ] Include metadata: `target_path`, `target_type` (external|embedded), `embedded_file_hash` (if correlated).

#### Registration and Integration

- [x] Register detectors in `crates/sis-pdf-detectors/lib.rs`.
- [x] Add detectors to scan pipeline (Phase C: deep analysis).
- [ ] Ensure detectors only run when `/EmbeddedFiles` or `/Launch` present (early exit optimization).

#### Implementation Notes

- Embedded file and launch logic currently lives in `crates/sis-pdf-detectors/src/lib.rs`; refactor into dedicated modules remains.
- Metadata uses `embedded.*` keys (e.g., `embedded.sha256`, `embedded.magic`); align to `hash.sha256`/`magic_type` if standardisation is required.
- Launch correlation uses file spec detection rather than filename matching; consider linking to embedded file hashes for stronger evidence.
- `EvidenceBuilder` and `TimeoutChecker` are now integrated into the embedded and launch detectors.

### Tests

#### Unit Tests

- [ ] `test_detect_embedded_pe()` - Detect PE executable.
- [ ] `test_detect_embedded_script()` - Detect JS/VBS script.
- [ ] `test_detect_encrypted_zip()` - Detect password-protected ZIP.
- [ ] `test_detect_double_extension()` - Detect `file.pdf.exe` pattern.
- [ ] `test_sha256_streaming()` - Verify hash correctness with large file.
- [ ] `test_launch_external_cmd()` - Detect launch to cmd.exe.
- [ ] `test_launch_embedded_correlation()` - Correlate launch with embedded file.

#### Integration Tests

- [ ] `test_embedded_files_integration()` - Scan CVE-2018-4990 fixture, verify `embedded_executable_present` emitted.
- [ ] `test_launch_actions_integration()` - Scan CVE-2010-1240 fixture, verify `launch_external_program` emitted.

#### CVE Regression Tests

- [ ] `test_cve_2010_1240_launch_cmd()` - Verify launch to cmd.exe detected.
- [ ] `test_cve_2018_4990_embedded_pe()` - Verify embedded PE detected.

Note: basic integration coverage exists in `crates/sis-pdf-core/tests/embedded_files.rs` with synthetic fixtures.

### Query Interface Integration

Add query types to `crates/sis-pdf/src/commands/query.rs`:

```rust
// Embedded files queries
"embedded.executables" => Ok(Query::EmbeddedExecutables),
"embedded.executables.count" => Ok(Query::EmbeddedExecutablesCount),
"embedded.scripts" => Ok(Query::EmbeddedScripts),
"embedded.scripts.count" => Ok(Query::EmbeddedScriptsCount),
"embedded.archives" => Ok(Query::EmbeddedArchives),
"embedded.archives.encrypted" => Ok(Query::EmbeddedArchivesEncrypted),
"embedded.archives.encrypted.count" => Ok(Query::EmbeddedArchivesEncryptedCount),

// Launch actions queries
"launch" => Ok(Query::LaunchActions),
"launch.count" => Ok(Query::LaunchActionsCount),
"launch.external" => Ok(Query::LaunchExternal),
"launch.external.count" => Ok(Query::LaunchExternalCount),
"launch.embedded" => Ok(Query::LaunchEmbedded),
"launch.embedded.count" => Ok(Query::LaunchEmbeddedCount),
```

**Predicate support:**

```bash
# Find large embedded executables
sis query embedded.executables --where "size > 1000000"

# Find encrypted archives larger than 500KB
sis query embedded.archives.encrypted --where "size > 500000"

# Find launch actions targeting embedded files
sis query launch.embedded --where "target_type == 'embedded'"
```

**Extraction support:**

```bash
# Extract all embedded executables
sis query embedded.executables --extract --export-dir ./evidence/executables/

# Extract specific embedded file by hash
sis query embedded.executables --where "hash == 'abc123...'" --extract
```

**Implementation:**

```rust
// crates/sis-pdf/src/commands/query.rs

fn extract_embedded_files(
    findings: &[Finding],
    ctx: &QueryContext,
    export_dir: &Path,
) -> Result<usize> {
    let mut count = 0;

    for finding in findings {
        // Get embedded file stream
        let obj_id = finding.metadata.get("object_id")?;
        let stream = ctx.graph.get_stream(obj_id)?;

        // Sanitize filename (prevent directory traversal)
        let filename = sanitize_filename(
            finding.metadata.get("filename").unwrap_or("file")
        );

        // Generate unique output path
        let hash = finding.metadata.get("hash.sha256")?;
        let output_path = export_dir.join(format!("{}_{}", hash[..8], filename));

        // Write decoded stream
        let decoded = decode_stream(stream)?;
        std::fs::write(&output_path, decoded)?;

        count += 1;
    }

    Ok(count)
}

fn sanitize_filename(name: &str) -> String {
    // Remove path separators, limit length, use hash prefix
    name.chars()
        .filter(|c| !matches!(c, '/' | '\\' | ':' | '<' | '>' | '|' | '*' | '?'))
        .take(100)
        .collect()
}
```

### Feature Vector Integration

Extend `ContentFeatures` in `crates/sis-pdf-core/src/features.rs`:

```rust
pub struct ContentFeatures {
    // Existing fields
    pub embedded_file_count: usize,
    pub rich_media_count: usize,
    pub annotation_count: usize,
    pub page_count: usize,

    // New fields (Stage 1)
    pub embedded_executable_count: usize,
    pub embedded_script_count: usize,
    pub embedded_archive_count: usize,
    pub embedded_encrypted_archive_count: usize,
    pub launch_action_count: usize,
    pub launch_external_count: usize,
    pub launch_embedded_count: usize,
}
```

Update `FeatureVector::as_f32_vec()` to include new features in correct order.

Update `feature_names()` to include new feature labels.

### Acceptance Criteria

- [x] All 6 findings emitted with correct metadata and evidence.
- [ ] Unit tests pass with 100% coverage of detection logic.
- [ ] Integration tests pass with CVE fixtures.
- [ ] Query interface supports all embedded/launch query types.
- [ ] Extraction works correctly with filename sanitisation.
- [ ] Predicate filtering works for size, hash, type fields.
- [ ] Feature extraction includes 7 new content features.
- [x] Documentation updated in `docs/findings.md`.

---

## Stage 2: Actions and Triggers

### Scope

Build action-trigger chain mapping, flag complex or hidden action paths, and export action graphs for forensic visualization.

### Checklist

#### Action Chain Detector

- [x] Implement `ActionTriggerDetector` in `crates/sis-pdf-detectors/src/actions_triggers.rs`:
  - [ ] Walk `/OpenAction`, `/AA` (document and page level), annotation actions, AcroForm field triggers.
  - [x] Build bounded action chain tracker with cycle detection (visited set).
  - [x] Configure max depth (default: 10) to prevent infinite loops.
  - [x] Use `TimeoutChecker` with 100ms budget for chain walk.
  - [ ] Classify triggers as automatic (OpenAction, AA/WillClose) or user-initiated (AA/FocusIn, AA/Keystroke).
  - [x] Classify triggers as hidden (non-visible annotations, hidden form fields) or visible.
  - [ ] Use `EvidenceBuilder` for chain path formatting.

- [x] Emit findings:
  - [x] `action_chain_complex` when chain depth > 3 (configurable threshold).
  - [x] `action_hidden_trigger` when trigger is on hidden/non-visible element.
  - [x] `action_automatic_trigger` when trigger is automatic (no user interaction required).
  - [ ] Include metadata: `chain_depth`, `trigger_event`, `trigger_type` (automatic|user|hidden), `chain_path` (e.g., "Catalog -> Page 1 -> Annot 52 -> JS").

#### Action Graph Export

- [ ] Extend `crates/sis-pdf-core/src/org_export.rs` with action edge highlighting:
  - [ ] Add `export_action_graph_dot()` function.
  - [ ] Color-code edges: automatic triggers (red), user triggers (yellow), hidden triggers (orange).
  - [ ] Include edge labels with event types (e.g., "/OpenAction", "/AA/WillClose").

- [ ] Extend `crates/sis-pdf-core/src/org_export.rs` with JSON export:
  - [ ] Add `export_action_graph_json()` function.
  - [ ] Include full chain metadata (depth, trigger types, event names).

#### Integration with IR Graph

- [ ] Verify action edges exist in `typed_graph::EdgeType` (query.rs:1-10 shows EdgeType usage).
- [ ] Use existing graph traversal where possible.
- [ ] Add action-specific edge types if missing.

#### Registration

- [x] Register detector in `crates/sis-pdf-detectors/lib.rs`.
- [x] Add to scan pipeline (Phase C).

#### Implementation Notes

- Current chain depth limit is 8; update if a higher limit is required.
- Automatic triggers are detected for `/OpenAction` and selected `/AA` events; user-initiated events are not yet classified.
- AcroForm trigger handling remains pending.
- `TimeoutChecker` and `EvidenceBuilder` are now integrated in the action trigger detector.

### Tests

#### Unit Tests

- [ ] `test_detect_simple_chain()` - Single-level action chain.
- [ ] `test_detect_complex_chain()` - Multi-level chain (depth 5).
- [ ] `test_cycle_detection()` - Circular reference (obj 10 -> obj 11 -> obj 10).
- [ ] `test_automatic_trigger()` - /OpenAction detection.
- [ ] `test_hidden_trigger()` - Hidden annotation with action.
- [ ] `test_max_depth()` - Verify depth limit enforcement (default 10).

#### Integration Tests

- [ ] `test_action_chains_integration()` - Scan PDF with multi-step chain, verify `action_chain_complex` emitted.
- [ ] `test_benign_hyperlink()` - Verify benign /URI annotation doesn't trigger false positive.

Note: basic integration coverage exists in `crates/sis-pdf-core/tests/action_triggers.rs` with synthetic fixtures.

### Query Interface Integration

Add query types to `crates/sis-pdf/src/commands/query.rs`:

```rust
// Action chain queries
"actions.chains" => Ok(Query::ActionChains),
"actions.chains.count" => Ok(Query::ActionChainsCount),
"actions.chains.complex" => Ok(Query::ActionChainsComplex),
"actions.chains.complex.count" => Ok(Query::ActionChainsComplexCount),

// Action trigger queries
"actions.triggers" => Ok(Query::ActionTriggers),
"actions.triggers.count" => Ok(Query::ActionTriggersCount),
"actions.triggers.automatic" => Ok(Query::ActionTriggersAutomatic),
"actions.triggers.automatic.count" => Ok(Query::ActionTriggersAutomaticCount),
"actions.triggers.hidden" => Ok(Query::ActionTriggersHidden),
"actions.triggers.hidden.count" => Ok(Query::ActionTriggersHiddenCount),
```

**Predicate support:**

```bash
# Find deep action chains
sis query actions.chains --where "depth > 3"

# Find chains with JavaScript
sis query actions.chains --where "has_js == true AND depth > 2"

# Find automatic triggers
sis query actions.triggers.automatic --where "event == 'OpenAction'"
```

**Graph export:**

```bash
# Export action chains as DOT graph
sis query actions.chains --format dot > action-chains.dot
dot -Tpng action-chains.dot -o action-chains.png

# Export as JSON for custom visualization
sis query actions.chains --format json > action-chains.json
```

### Feature Vector Integration

Extend `GraphFeatures` in `crates/sis-pdf-core/src/features.rs`:

```rust
pub struct GraphFeatures {
    // Existing fields
    pub total_edges: usize,
    pub open_action_edges: usize,
    pub js_payload_edges: usize,
    pub uri_target_edges: usize,
    pub launch_target_edges: usize,
    pub suspicious_edge_count: usize,
    pub action_chain_count: usize,         // ✅ Already exists
    pub max_chain_length: usize,           // ✅ Already exists
    pub automatic_chain_count: usize,      // ✅ Already exists
    pub js_chain_count: usize,
    pub external_chain_count: usize,
    pub max_graph_depth: usize,
    pub avg_graph_depth: f64,
    pub catalog_to_js_paths: usize,
    pub multi_stage_indicators: usize,

    // New fields (Stage 2)
    pub hidden_trigger_count: usize,       // ❌ Add this
    pub user_trigger_count: usize,         // ❌ Add this
    pub complex_chain_count: usize,        // ❌ Add this (depth > 3)
}
```

### Acceptance Criteria

- ✅ All 3 findings emitted with correct chain metadata.
- ✅ Cycle detection prevents infinite loops.
- ✅ Max depth limit enforced (default 10).
- ✅ Unit tests pass with 100% coverage.
- ✅ Integration tests pass including benign hyperlink (no false positive).
- ✅ Query interface supports all action chain query types.
- ✅ Graph export (DOT and JSON) works correctly.
- ✅ Feature extraction includes 3 new graph features.
- ✅ Documentation updated in `docs/findings.md`.

---

## Stage 3: XFA Forms

### Scope

Parse XFA XML streams, detect embedded scripts and submission actions, enumerate sensitive fields, and export scripts for external SAST analysis.

### Checklist

#### XFA Form Detector

- [x] Implement `XfaFormDetector` in `crates/sis-pdf-detectors/src/xfa_forms.rs`:
  - [x] Extract `/XFA` streams from document catalog or AcroForm dictionary.
  - [x] Concatenate XFA array elements if `/XFA` is an array (per PDF spec).
  - [ ] Parse XML using `roxmltree` (pinned to 0.20.0).
  - [x] Reject XML with DOCTYPE declarations (entity expansion attack prevention).
  - [x] Enforce 1MB size limit on XFA content pre-parse.
  - [x] Use `TimeoutChecker` with 100ms budget for parsing.
  - [x] Detect `<script>` tags for embedded code.
  - [x] Detect `<execute>` tags for embedded code.
  - [x] Detect `<submit>` tags with `target` URLs.
  - [x] Detect sensitive field names (password, ssn, social, credit, cvv, pin, dob, etc.).
  - [x] Count total script blocks in form.
  - [x] Use `EvidenceBuilder` for evidence formatting.

- [x] Emit findings:
  - [x] `xfa_submit` when submit action found, include target URL in metadata.
  - [x] `xfa_sensitive_field` when sensitive field detected, include field name.
  - [x] `xfa_too_large` when size exceeds 1MB limit.
  - [x] `xfa_script_count_high` when script count > 5 (configurable threshold).
  - [ ] Enrich existing `xfa_script_present` finding with script content preview.
  - [ ] Include metadata: `xfa_size_bytes`, `script_count`, `submit_urls` (array), `sensitive_fields` (array).

#### XFA Script Extraction

- [ ] Add XFA script extraction function:
  - [ ] Extract all `<script>` tag contents.
  - [ ] Decode CDATA sections if present.
  - [ ] Generate unique filenames (hash-based or sequential).
  - [ ] Include metadata file (`manifest.json`) with script index, source object, field context.

#### Registration

- [x] Register detector in `crates/sis-pdf-detectors/lib.rs`.
  - [x] Add to scan pipeline (Phase C).
  - [x] Guard with XFA presence check (early exit if no `/XFA` key).

#### Implementation Notes

- Detector uses lightweight tag scanning rather than full XML parsing; `roxmltree` parsing remains pending.
- Script detection uses `extract_xfa_script_payloads` and `<execute>` tag counts.

### Tests

#### Unit Tests

- [ ] `test_parse_simple_xfa()` - Basic XFA form without scripts.
- [ ] `test_detect_xfa_script()` - XFA with `<script>` tag.
- [x] `test_detect_xfa_submit()` - XFA with submit action + URL.
- [x] `test_detect_sensitive_field()` - XFA with password/ssn fields.
- [x] `test_xfa_size_limit()` - XFA exceeding 1MB, verify `xfa_too_large` emitted.
- [x] `test_xfa_script_count_high()` - XFA with 10 scripts, verify finding.
- [x] `test_reject_doctype()` - XML with DOCTYPE, verify rejection.
- [x] `test_detect_execute_tags()` - XFA with `<execute>` tags, verify script count.
- [ ] `test_xfa_timeout()` - Malformed XML triggering timeout.

#### Integration Tests

- [ ] `test_xfa_forms_integration()` - Scan PDF with XFA script, verify findings.
- [ ] `test_cve_2013_2729_xfa_soap()` - Scan CVE-2013-2729 fixture, verify detection.

### Query Interface Integration

Add query types to `crates/sis-pdf/src/commands/query.rs`:

```rust
// XFA queries
"xfa" => Ok(Query::XfaForms),
"xfa.count" => Ok(Query::XfaFormsCount),
"xfa.scripts" => Ok(Query::XfaScripts),
"xfa.scripts.count" => Ok(Query::XfaScriptsCount),
"xfa.submit" => Ok(Query::XfaSubmit),
"xfa.submit.count" => Ok(Query::XfaSubmitCount),
"xfa.sensitive" => Ok(Query::XfaSensitiveFields),
"xfa.sensitive.count" => Ok(Query::XfaSensitiveFieldsCount),
```

**Predicate support:**

```bash
# Find large XFA forms
sis query xfa --where "size > 500000"

# Find XFA with many scripts
sis query xfa --where "script_count > 5"

# Find XFA with submit actions
sis query xfa.submit --where "url contains 'external.com'"
```

**Script extraction:**

```bash
# Extract all XFA scripts
sis query xfa.scripts --extract --export-dir ./xfa-scripts/

# Output:
# xfa-scripts/
#   script_001_obj_52.js
#   script_002_obj_52.js
#   manifest.json
```

**Implementation:**

```rust
// crates/sis-pdf/src/commands/query.rs

fn extract_xfa_scripts(
    findings: &[Finding],
    ctx: &QueryContext,
    export_dir: &Path,
) -> Result<usize> {
    let mut manifest = Vec::new();
    let mut count = 0;

    for finding in findings {
        let obj_id = finding.metadata.get("object_id")?;
        let script_content = finding.metadata.get("script_content")?;

        let filename = format!("script_{:03}_obj_{}.js", count + 1, obj_id);
        let output_path = export_dir.join(&filename);

        std::fs::write(&output_path, script_content)?;

        manifest.push(serde_json::json!({
            "index": count,
            "filename": filename,
            "object_id": obj_id,
            "field_context": finding.metadata.get("field_name"),
            "size_bytes": script_content.len(),
        }));

        count += 1;
    }

    // Write manifest
    let manifest_path = export_dir.join("manifest.json");
    std::fs::write(manifest_path, serde_json::to_string_pretty(&manifest)?)?;

    Ok(count)
}
```

**SAST Integration Example:**

```bash
# Extract scripts
sis query xfa.scripts --extract --export-dir ./xfa-scripts/

# Run static analysis
grep -r "SOAP\|XMLHttpRequest\|eval\|unescape" ./xfa-scripts/

# Or use semgrep for deeper analysis
semgrep --config=p/javascript ./xfa-scripts/
```

### Feature Vector Integration

Add `XfaFeatures` to `crates/sis-pdf-core/src/features.rs`:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct XfaFeatures {
    pub xfa_present: bool,
    pub xfa_size_bytes: usize,
    pub xfa_script_count: usize,
    pub xfa_submit_count: usize,
    pub xfa_sensitive_field_count: usize,
    pub xfa_field_count: usize,
}
```

Update `FeatureVector`:

```rust
pub struct FeatureVector {
    pub general: GeneralFeatures,
    pub structural: StructuralFeatures,
    pub behavioral: BehavioralFeatures,
    pub content: ContentFeatures,
    pub graph: GraphFeatures,
    pub images: ImageFeatures,
    pub xfa: XfaFeatures,  // ❌ Add this
}
```

### Acceptance Criteria

- ✅ All 4 XFA findings emitted with correct metadata.
- ✅ `roxmltree` parser handles malformed XML gracefully (no crashes).
- ✅ DOCTYPE rejection prevents entity expansion attacks.
- ✅ 1MB size limit enforced, timeout at 100ms.
- ✅ Unit tests pass with 100% coverage.
- ✅ Integration tests pass including CVE-2013-2729 fixture.
- ✅ Query interface supports all XFA query types.
- ✅ Script extraction works with manifest generation.
- ✅ SAST integration documented with examples.
- ✅ Feature extraction includes 6 new XFA features.
- ✅ Documentation updated in `docs/findings.md`.

---

## Stage 4: Rich Media Content

### Scope

Inspect embedded SWF (Flash) and other rich media streams using minimal parsers to detect ActionScript and risky indicators without full decompression.

### Checklist

#### Rich Media Detector

- [x] Implement `RichMediaContentDetector` in `crates/sis-pdf-detectors/src/rich_media_analysis.rs`:
  - [x] Detect `/RichMedia` or `/Flash` stream dictionaries.
  - [x] Extract embedded stream bytes for magic detection.
  - [x] Detect SWF magic types (FWS/CWS/ZWS).
  - [ ] Use `stream_analysis::analyse_stream()` for unified analysis.
  - [x] Use `TimeoutChecker` with 100ms budget.

#### Minimal SWF Parser

- [ ] Implement minimal SWF header parser (avoid full decompression):
  - [x] Detect SWF magic: `FWS` (uncompressed) or `CWS`/`ZWS` (compressed).
  - [x] Parse header (version, file length, frame size, frame rate, frame count) for FWS streams.
  - [ ] Decompress ONLY first 10 tags (not entire file) to detect ActionScript.
  - [ ] Enforce 10:1 decompression ratio limit using `DecompressionLimits`.
  - [ ] Enforce 10MB decompressed size limit (header + first 10 tags).
  - [ ] Detect ActionScript tags: DoAction (12), DoInitAction (59), DoABC (82).
  - [ ] Use `TimeoutChecker` with 250ms budget for decompression.
  - [ ] Custom minimal parser (no external SWF crate dependencies).

- [x] Emit findings:
  - [x] `swf_embedded` when SWF magic detected.
  - [ ] `swf_actionscript_detected` when ActionScript tags found.
  - [ ] Enrich existing `richmedia_present` with media type metadata.
  - [ ] Include metadata: `media_type` (swf|u3d|prc|mp3|mp4), `size_bytes`, `swf_version`, `actionscript_tags` (array).

#### 3D and Audio Media Detection

- [ ] Detect 3D content (U3D/PRC):
  - [ ] U3D magic: `0x00 0x00 0x00 0x24` (first 4 bytes).
  - [ ] PRC magic: `PRC` ASCII string.
  - [ ] Enrich existing `3d_present` finding with size metadata.

- [ ] Detect audio/video content (MP3/MP4):
  - [ ] MP3 magic: `0xFF 0xFB` or `ID3` ASCII.
  - [ ] MP4 magic: `ftyp` at offset 4.
  - [ ] Enrich existing `sound_movie_present` finding with format metadata.

#### Registration

- [x] Register detector in `crates/sis-pdf-detectors/lib.rs`.
- [x] Add to scan pipeline (Phase C).
- [ ] Guard with rich media presence check (early exit optimization).

#### Implementation Notes

- SWF detection relies on magic headers; header parsing now extracts frame rate/count for uncompressed FWS streams, ActionScript tag parsing remains pending.
- 3D/audio enrichments are not yet implemented beyond existing `3d_present` and `sound_movie_present` detectors.

### Tests

#### Unit Tests

- [ ] `test_detect_swf_uncompressed()` - FWS magic detection.
- [ ] `test_detect_swf_compressed()` - CWS/ZWS magic detection.
- [x] `test_parse_swf_header()` - Header parsing correctness.
- [ ] `test_detect_actionscript_tag()` - DoAction/DoABC tag detection.
- [ ] `test_swf_decompression_limit()` - 10:1 ratio limit enforcement.
- [ ] `test_swf_size_limit()` - 10MB limit enforcement.
- [ ] `test_detect_u3d()` - U3D magic detection.
- [ ] `test_detect_mp3()` - MP3 magic detection.

#### Integration Tests

- [x] `test_swf_integration()` - Scan PDF with embedded SWF, verify findings.
- [x] `test_cve_2011_0611_swf()` - Scan CVE-2011-0611 fixture, verify detection.

### Query Interface Integration

Add query types to `crates/sis-pdf/src/commands/query.rs`:

```rust
// Rich media queries
"swf" => Ok(Query::SwfContent),
"swf.count" => Ok(Query::SwfContentCount),
"swf.actionscript" => Ok(Query::SwfActionScript),
"swf.actionscript.count" => Ok(Query::SwfActionScriptCount),
"media.3d" => Ok(Query::Media3D),
"media.3d.count" => Ok(Query::Media3DCount),
"media.audio" => Ok(Query::MediaAudio),
"media.audio.count" => Ok(Query::MediaAudioCount),
```

**Predicate support:**

```bash
# Find large SWF files
sis query swf --where "size > 1000000"

# Find SWF with ActionScript
sis query swf.actionscript --where "version >= 9"
```

**Extraction:**

```bash
# Extract all SWF content (decoded)
sis query swf --extract --decode --export-dir ./swf-files/

# Extract raw (compressed) for external analysis
sis query swf --extract --raw --export-dir ./swf-raw/
```

### Feature Vector Integration

Extend `ContentFeatures`:

```rust
pub struct ContentFeatures {
    // Existing fields...

    // New fields (Stage 4)
    pub swf_count: usize,
    pub swf_actionscript_count: usize,
    pub media_3d_count: usize,
    pub media_audio_count: usize,
    pub media_video_count: usize,
}
```

### Acceptance Criteria

- ✅ All 2 SWF findings emitted with correct metadata.
- ✅ Minimal SWF parser works without full decompression.
- ✅ Decompression ratio limit (10:1) enforced.
- ✅ Size limit (10MB) enforced.
- ✅ Timeout (250ms) enforced.
- ✅ 3D and audio/video media detected correctly.
- ✅ Unit tests pass with 100% coverage.
- ✅ Integration tests pass including CVE-2011-0611 fixture.
- ✅ Query interface supports all rich media query types.
- ✅ Extraction works with --decode and --raw modes.
- ✅ Feature extraction includes 5 new content features.
- ✅ Documentation updated in `docs/findings.md`.

---

## Stage 5: Encryption and Obfuscation

### Scope

Broaden encryption metadata checks, implement streaming entropy calculation, and detect encrypted embedded files and high-entropy streams.

### Checklist

#### Encryption Detector

- [x] Implement `EncryptionObfuscationDetector` in `crates/sis-pdf-detectors/src/encryption_obfuscation.rs`:
  - [x] Inspect `/Encrypt` dictionary in document trailer.
  - [x] Extract encryption algorithm (`/V` version, `/R` revision, `/Length` key length).
  - [x] Classify algorithms: RC4-40, RC4-128, AES-128, AES-256.
  - [x] Detect weak algorithms (RC4-40, RC4 < 128 bits).
  - [ ] Detect quantum-vulnerable algorithms (RSA < 3072 bits, if present).
  - [x] Use existing `encryption_present` finding, add enrichment metadata.
  - [x] Use `EvidenceBuilder` for evidence formatting.

- [x] Emit findings:
  - [x] `encryption_key_short` when key length < 128 bits.
  - [ ] Enrich existing `crypto_weak_algo` finding with specific algorithm metadata.
  - [x] Include metadata: `crypto.algorithm`, `crypto.key_length`, `crypto.version`, `crypto.revision`.

#### Streaming Entropy Calculator

- [x] Implement entropy calculation in `stream_analysis.rs`:
  - [x] Shannon entropy calculation: `H = -Σ(p(x) * log2(p(x)))` where `p(x)` is byte frequency.
  - [ ] Sliding window approach (1MB chunks, max 10MB sample).
  - [x] Use `TimeoutChecker` with 150ms budget per scan pass.
  - [x] Return entropy value (0.0 - 8.0 scale).

- [x] Integrate with stream analysis:
  - [x] Add entropy field to `StreamAnalysisResult`.
  - [x] Compute entropy during unified stream analysis (single pass).

- [x] Emit findings:
  - [x] `stream_high_entropy` when entropy > 7.5 (configurable threshold).
  - [x] `embedded_encrypted` when embedded file has high entropy + no known magic type.
  - [ ] Include metadata: `entropy`, `entropy_threshold`, `sample_size_bytes`.

#### Encrypted Archive Detection

- [ ] Enhance embedded file detector integration:
  - [ ] Check ZIP encryption flag (already in Stage 1).
  - [ ] Check RAR encryption markers (if RAR magic detected).
  - [ ] Cross-reference with entropy (encrypted archives should have high entropy).

#### Registration

- [x] Register detector in `crates/sis-pdf-detectors/lib.rs`.
- [x] Add to scan pipeline (Phase B for encryption dict, Phase C for streams).

#### Implementation Notes

- Encryption analysis currently checks `/Length` for key size only; algorithm classification remains pending.
- Entropy sampling uses full decoded stream bytes (no sliding window) and a size floor of 1KB.

### Tests

#### Unit Tests

- [ ] `test_detect_rc4_40()` - RC4-40 encryption detection.
- [ ] `test_detect_aes_256()` - AES-256 encryption (no weak algo finding).
- [ ] `test_entropy_random_data()` - Entropy ~8.0 for random bytes.
- [ ] `test_entropy_text_data()` - Entropy ~4-5 for English text.
- [ ] `test_entropy_sliding_window()` - Verify sliding window logic.
- [ ] `test_entropy_timeout()` - Verify 50ms timeout enforcement.
- [x] `test_high_entropy_stream()` - Detect stream with entropy > 7.5.
- [x] `test_embedded_encrypted()` - High entropy + no magic = encrypted.

#### Integration Tests

- [ ] `test_encryption_integration()` - Scan PDF with RC4-40, verify findings.
- [x] `test_cve_2019_7089_weak_encryption()` - Scan CVE-2019-7089 fixture.
- [x] `test_high_entropy_integration()` - Scan PDF with high-entropy stream.

### Query Interface Integration

Add query types to `crates/sis-pdf/src/commands/query.rs`:

```rust
// Encryption queries
"encryption" => Ok(Query::Encryption),
"encryption.weak" => Ok(Query::EncryptionWeak),
"encryption.weak.count" => Ok(Query::EncryptionWeakCount),

// Entropy queries
"streams.high-entropy" => Ok(Query::StreamsHighEntropy),
"streams.high-entropy.count" => Ok(Query::StreamsHighEntropyCount),
"streams.entropy" => Ok(Query::StreamsEntropy),  // All streams with entropy values
```

**Predicate support:**

```bash
# Find high-entropy streams
sis query streams.high-entropy --where "entropy > 7.8"

# Find weak encryption
sis query encryption.weak --where "algorithm == 'RC4' AND key_length < 128"

# Find all streams by entropy (for analysis)
sis query streams.entropy --where "entropy > 6.0" --format csv > entropy.csv
```

### Feature Vector Integration

Add `EncryptionFeatures` to `crates/sis-pdf-core/src/features.rs`:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct EncryptionFeatures {
    pub encrypted: bool,
    pub encryption_algorithm: String,  // "none", "RC4-40", "AES-256", etc.
    pub encryption_key_length: usize,
    pub high_entropy_stream_count: usize,
    pub avg_stream_entropy: f64,
    pub max_stream_entropy: f64,
    pub encrypted_embedded_file_count: usize,
}
```

Update `FeatureVector`:

```rust
pub struct FeatureVector {
    pub general: GeneralFeatures,
    pub structural: StructuralFeatures,
    pub behavioral: BehavioralFeatures,
    pub content: ContentFeatures,
    pub graph: GraphFeatures,
    pub images: ImageFeatures,
    pub xfa: XfaFeatures,
    pub encryption: EncryptionFeatures,  // ❌ Add this
}
```

### Acceptance Criteria

- ✅ All 3 encryption/entropy findings emitted with correct metadata.
- ✅ Streaming entropy calculator works with sliding window.
- ✅ Entropy calculation timeout (50ms) enforced.
- ✅ Sample size limit (10MB) enforced.
- ✅ Weak encryption algorithms detected (RC4-40, RC4 < 128).
- ✅ Unit tests pass with 100% coverage.
- ✅ Integration tests pass including CVE-2019-7089 fixture.
- ✅ Query interface supports all encryption/entropy query types.
- ✅ Feature extraction includes 7 new encryption features.
- ✅ Documentation updated in `docs/findings.md`.

---

## Stage 6: Filter Chain Anomaly Detection

### Scope

Detect unusual or invalid filter sequences beyond depth-only heuristics, using an allowlist of normal chains and specification validation.

### Checklist

#### Filter Chain Detector

- [x] Implement `FilterChainAnomalyDetector` in `crates/sis-pdf-detectors/src/filter_chain_anomaly.rs`:
  - [x] Extract `/Filter` from all stream objects.
  - [x] Parse filter arrays (handle both single filter and array of filters).
  - [x] Validate filter order against PDF specification rules (ASCII decode order + Crypt outermost).
  - [x] Check filter combinations against allowlist (see "Filter Allowlist" section below).
  - [x] Flag unusual combinations (depth >= 3 or unknown filter names).
  - [x] Flag invalid orders (ASCII filters after binary filters).
  - [x] Use `TimeoutChecker` with 100ms budget per chain.
  - [x] Use `EvidenceBuilder` for evidence formatting.

- [x] Emit findings:
- [x] `filter_chain_unusual` when combination not in allowlist.
- [x] `filter_order_invalid` when order violates PDF spec.
- [x] `filter_combination_unusual` when combination repeats filters.
- [x] Include metadata: `filters` (array), `filter_count`, `allowlist_match` (bool), `violation_type`.

#### Filter Allowlist

Create `config/filter-chains-allowlist.toml`:

```toml
# Standard filter chains allowlist
# Add up to 20 entries maximum

[[allowed_chains]]
filters = ["FlateDecode"]
description = "Standard zlib compression"

[[allowed_chains]]
filters = ["ASCIIHexDecode", "FlateDecode"]
description = "Hex-encoded compressed stream"

[[allowed_chains]]
filters = ["ASCII85Decode", "FlateDecode"]
description = "Base85-encoded compressed stream"

[[allowed_chains]]
filters = ["FlateDecode", "DCTDecode"]
description = "Compressed JPEG image (unusual but valid)"

[[allowed_chains]]
filters = ["DCTDecode"]
description = "JPEG image (uncompressed stream)"

[[allowed_chains]]
filters = ["CCITTFaxDecode"]
description = "Fax-encoded image"

[[allowed_chains]]
filters = ["JBIG2Decode"]
description = "JBIG2-encoded image"

[[allowed_chains]]
filters = ["JPXDecode"]
description = "JPEG2000-encoded image"

[[allowed_chains]]
filters = ["LZWDecode"]
description = "LZW compression (legacy)"

[[allowed_chains]]
filters = ["RunLengthDecode"]
description = "Run-length encoding"

[[allowed_chains]]
filters = ["ASCIIHexDecode"]
description = "Hex encoding only"

[[allowed_chains]]
filters = ["ASCII85Decode"]
description = "Base85 encoding only"
```

**CLI Integration:**

```bash
# Use custom allowlist
sis scan --filter-allowlist ./custom-allowlist.toml malware.pdf

# Strict mode: flag ALL unusual chains (no allowlist)
sis scan --filter-allowlist-strict malware.pdf

# Show default allowlist
sis scan --show-filter-allowlist
```

#### Specification Validation

Implement PDF spec filter order rules:
- Decode filters (ASCII85, ASCIIHex) must come BEFORE compression filters (FlateDecode, LZW).
- Image filters (DCT, JBIG2, JPX, CCITT) should not be chained with compression (rare but not invalid).
- Crypt filter must be outermost (applied last on encode, first on decode).

#### Registration

- [x] Register detector in `crates/sis-pdf-detectors/lib.rs`.
- [x] Add to scan pipeline (Phase C).
- [x] Load allowlist from config file or use default.
 - [x] Store default allowlist in `config/filter-chains-allowlist.toml`.

#### Implementation Notes

- Detector uses a default allowlist and fixed order rules; configurable allowlist is supported via CLI/config.
- Filter order rules are simplified to ASCII encoding placement checks.

### Tests

#### Unit Tests

- [x] `test_valid_filter_chains()` - All allowlist chains should NOT trigger findings.
- [x] `test_unusual_filter_chain()` - Non-allowlist chain triggers `filter_chain_unusual`.
- [x] `test_invalid_filter_order()` - FlateDecode before ASCII85Decode triggers `filter_order_invalid`.
- [x] `test_allowlist_loading()` - Load custom allowlist from TOML.
- [x] `test_strict_mode()` - Strict mode flags all non-standard chains.

#### Integration Tests

- [x] `test_filter_chains_integration()` - Scan PDF with unusual filter, verify finding.
- [ ] `test_cve_2010_2883_filter_obfuscation()` - Scan CVE-2010-2883 fixture.

### Query Interface Integration

Add query types to `crates/sis-pdf/src/commands/query.rs`:

```rust
// Filter chain queries
"filters.unusual" => Ok(Query::FiltersUnusual),
"filters.unusual.count" => Ok(Query::FiltersUnusualCount),
"filters.invalid" => Ok(Query::FiltersInvalid),
"filters.invalid.count" => Ok(Query::FiltersInvalidCount),
"filters.all" => Ok(Query::FiltersAll),  // All filter chains for analysis
```

**Predicate support:**

```bash
# Find unusual filter chains
sis query filters.unusual

# Find invalid filter orders
sis query filters.invalid

# Find deep filter chains
sis query filters.all --where "count > 2"
```

### Feature Vector Integration

Add `FilterFeatures` to `crates/sis-pdf-core/src/features.rs`:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct FilterFeatures {
    pub max_filter_chain_depth: usize,
    pub unusual_filter_count: usize,
    pub invalid_filter_count: usize,
    pub total_filter_chains: usize,
    pub avg_filter_chain_depth: f64,
}
```

Update `FeatureVector`:

```rust
pub struct FeatureVector {
    pub general: GeneralFeatures,
    pub structural: StructuralFeatures,
    pub behavioral: BehavioralFeatures,
    pub content: ContentFeatures,
    pub graph: GraphFeatures,
    pub images: ImageFeatures,
    pub xfa: XfaFeatures,
    pub encryption: EncryptionFeatures,
    pub filters: FilterFeatures,  // ❌ Add this
}
```

### Acceptance Criteria

- ✅ All 3 filter chain findings emitted correctly.
- ✅ Allowlist loaded from TOML config file.
- ✅ Filter order checks implemented (ASCII order placement).
- ✅ Valid chains (in allowlist) do NOT trigger false positives.
- ✅ Unusual chains trigger findings with correct metadata.
- ✅ CLI flags (--filter-allowlist, --filter-allowlist-strict) work correctly.
- ✅ Unit tests pass with 100% coverage.
- ✅ Integration tests pass including CVE-2010-2883 fixture.
- ✅ Query interface supports all filter query types.
- ✅ Feature extraction includes 5 new filter features.
- ✅ Documentation updated in `docs/findings.md`.

---

## Stage 7: Documentation and Integration Sweep

### Scope

Update all documentation to reflect new findings, ensure JSON schema alignment, and validate end-to-end workflows.

### Checklist

#### Update docs/findings.md

- [x] Add new finding IDs introduced in Stages 1-6 (see commits and `docs/findings.md`).
- [x] Document metadata fields for each finding (severity, tags, evidence structure).
- [ ] Deferred: add examples of each finding with sample evidence output.
- [ ] Deferred: document correlation patterns (e.g., launch + embedded executable).
- [ ] Deferred: map findings to CVEs addressed (use CVE mapping table from Stage 0).
- [ ] Deferred: add "Query Examples" section showing how to query each finding type.

#### Update User-Facing Documentation

- [x] Update README.md with new capabilities summary.
- [x] Update `docs/query-interface.md` with new query types.
- [x] Add `docs/forensic-workflows.md` with example workflows:
  - [x] Embedded file extraction and analysis workflow.
  - [x] Action chain review workflow.
  - [x] XFA script review workflow.
  - [x] Encryption and obfuscation review workflow.
- [x] Add `docs/feature-extraction.md` documenting feature sets for ML pipelines.

#### JSON Schema Validation

- [x] Verify all new findings emit valid JSON structure (schema validation test).
- [x] Validate against JSON schema (added `docs/findings-schema.json`).
- [x] Validate JSONL output format for all new findings.
- [ ] Deferred: ensure metadata fields are consistently typed (strings, ints, bools, arrays).

#### End-to-End Validation

- [x] Run full test suite: `cargo test --all`.
- [x] Run targeted scans on all CVE fixtures (6 fixtures).
- [ ] Deferred: verify all new findings can be emitted.
- [ ] Deferred: test query interface with all new query types (30+ queries; shortcuts + XFA/SWF extract + embedded extract covered).
- [ ] Deferred: test extraction workflows (embedded/XFA/SWF covered via query tests).
- [ ] Deferred: test predicate filtering on all new fields (findings metadata + embedded name/magic covered).
- [ ] Deferred: test batch mode with new findings (count shortcuts covered).
- [ ] Deferred: test REPL mode with new queries.

#### Performance Profiling

- [ ] Deferred: generate profiling output: `sis scan --profile-output=profile.jsonl <cvefixture>`.
- [ ] Deferred: verify all operations meet SLOs (see Stage 0.5 performance table).
- [ ] Deferred: identify any operations exceeding maximum latency targets.
- [ ] Deferred: document performance characteristics in `docs/performance.md`.

### Acceptance Criteria

- [ ] `docs/findings.md` includes all new findings with examples.
- [x] Forensic workflow documentation complete with 4+ example workflows.
- [x] JSON structure validation completed (schema validation test).
- [x] Full test suite passes (`cargo test --all`).
- [x] All CVE fixtures trigger expected findings.
- [ ] Query shortcuts and predicate filtering validated (shortcut counts, findings metadata, embedded name/magic covered).
- [ ] Extraction workflows tested end-to-end (embedded/XFA/SWF covered via query tests).
- [ ] Performance profiling shows compliance with SLOs.

---

## Stage 7.5: Query Interface Integration Summary

### Scope

Consolidate all query types added in Stages 1-6 into the unified query interface, ensure consistency, and validate end-to-end query workflows.

### New Query Types Summary

Query shortcuts are implemented as `findings.kind` aliases. Counts can be obtained via
`findings.count --where "subtype == '<finding_id>'"` or `<shortcut>.count`.

#### Embedded Files & Launch (Stage 1)

```
embedded.executables
embedded.scripts
embedded.archives.encrypted
launch
launch.external
launch.embedded
```

#### Actions & Triggers (Stage 2)

```
actions.chains.complex
actions.triggers.automatic
actions.triggers.hidden
```

#### XFA Forms (Stage 3)

```
xfa.submit
xfa.sensitive
xfa.too-large
xfa.scripts.high
```

#### Rich Media (Stage 4)

```
swf
```

#### Encryption & Obfuscation (Stage 5)

```
streams.high-entropy
```

#### Filter Chains (Stage 6)

```
filters.unusual
filters.invalid
filters.repeated
```

### Deferred Query Work

- Additional query variants (allowlist-driven summaries).
- Predicate fields for launch targets, XFA, and SWF (findings metadata + embedded name/magic shipped).
- Extraction helpers for embedded files shipped; batch/REPL coverage remains.
- Batch/REPL coverage and query reference documentation.
- [x] `test_query_filters()` - Query unusual filters.
- [ ] `test_batch_mode_new_queries()` - All new queries in batch.
- [ ] `test_repl_mode_new_queries()` - All new queries in REPL.

### Acceptance Criteria

- [x] All 36 query types implemented and working (including count variants).
- [ ] Predicate filtering works for all new fields (findings metadata + embedded name/magic done).
- [x] Extraction works for embedded files, XFA scripts, SWF (query tests).
- [ ] Batch mode supports all new queries (count shortcuts done).
- [ ] REPL mode supports all new queries.
- [ ] Documentation complete with examples.
- [ ] Tests pass with 100% coverage.

---

## Stage 8: Feature Vector Integration

### Scope

Integrate all new features from Stages 1-6 into the feature extraction pipeline, update CSV/JSON export, and validate ML pipeline compatibility.

### Feature Count Summary

**Total features: 76 features**

- General: 4 features (existing)
- Structural: 5 features (existing)
- Behavioral: 7 features (existing)
- Content: 11 features (4 existing + 7 new from Stage 1)
- Graph: 18 features (15 existing + 3 new from Stage 2)
- Images: 16 features (existing)
- XFA: 6 features (new from Stage 3)
- Encryption: 7 features (new from Stage 5)
- Filters: 5 features (new from Stage 6)
- Rich Media: 5 features (new from Stage 4, added to ContentFeatures)

### Checklist

#### Add New Feature Structs

- [x] Add `XfaFeatures` struct to `crates/sis-pdf-core/src/features.rs` (see Stage 3).
- [x] Add `EncryptionFeatures` struct (see Stage 5).
- [x] Add `FilterFeatures` struct (see Stage 6).
- [x] Update `ContentFeatures` with embedded file and rich media fields (Stages 1, 4).
- [x] Update `GraphFeatures` with action chain fields (Stage 2).

#### Update FeatureVector

- [x] Add new fields to `FeatureVector` struct:
  ```rust
  pub struct FeatureVector {
      pub general: GeneralFeatures,
      pub structural: StructuralFeatures,
      pub behavioral: BehavioralFeatures,
      pub content: ContentFeatures,
      pub graph: GraphFeatures,
      pub images: ImageFeatures,
      pub xfa: XfaFeatures,
      pub encryption: EncryptionFeatures,
      pub filters: FilterFeatures,
  }
  ```

#### Update as_f32_vec()

- [x] Extend `as_f32_vec()` method to flatten all new features in correct order.
- [x] Maintain backward compatibility by appending new features at end.
- [x] Document feature order in comments.

#### Update feature_names()

- [x] Add all new feature labels to `feature_names()` function.
- [x] Ensure order matches `as_f32_vec()` output.
- [x] Use descriptive names (e.g., "xfa.script_count", "encryption.key_length").

#### Implement Feature Extraction

- [x] Update `extract_features()` function to populate all new fields.
- [x] Integrate with existing scan pipeline.
- [ ] Ensure feature extraction runs in Phase C (deep analysis).

#### Export Validation

- [x] Test CSV export: `sis query features --format csv > features.csv` (validated via query test).
- [x] Verify CSV header includes all 76 feature names (validated via query test).
- [x] Test JSON export: `sis query features --format json > features.json` (validated via query test).
- [x] Verify JSON includes all feature structs (validated via query test).
- [ ] Test JSONL export for streaming: `sis query features --format jsonl --batch *.pdf`.

### Tests

#### Unit Tests

- [x] `test_xfa_features_extraction()` - Extract XFA features from fixture.
- [x] `test_encryption_features_extraction()` - Extract encryption features.
- [x] `test_filter_features_extraction()` - Extract filter features.
- [x] `test_content_features_extended()` - Verify embedded file + rich media fields.
- [ ] `test_graph_features_extended()` - Verify action chain fields.

#### Integration Tests

- [x] `test_features_csv_export()` - Full CSV export with all features (covered via query test).
- [x] `test_features_json_export()` - Full JSON export (covered via query test).
- [ ] `test_features_count()` - Verify exactly 76 features (or documented count).
- [ ] `test_features_backward_compatibility()` - Verify order preserves compatibility.

### ML Pipeline Validation

- [ ] Document feature schema in `docs/ml-features.md`:
  - [ ] Feature index mapping (0-75).
  - [ ] Feature types (binary, count, ratio, categorical).
  - [ ] Feature ranges and normalization recommendations.
  - [ ] Missing value handling (e.g., no XFA = all zeros).

- [ ] Provide example ML integration:
  ```python
  # Example: Load features into pandas
  import pandas as pd
  
  features = pd.read_csv("features.csv")
  print(features.shape)  # (n_samples, 76)
  
  # Example: Train sklearn model
  from sklearn.ensemble import RandomForestClassifier
  
  X = features.iloc[:, :76].values  # All features
  y = labels  # Malicious=1, Benign=0
  
  model = RandomForestClassifier()
  model.fit(X, y)
  ```

### Acceptance Criteria

- ✅ All new feature structs implemented and integrated.
- ✅ `FeatureVector` includes all 9 feature categories.
- ✅ `as_f32_vec()` outputs exactly 76 features in documented order.
- ✅ `feature_names()` includes all 76 labels matching order.
- ✅ CSV export works with correct headers.
- ✅ JSON/JSONL export works correctly.
- ✅ Unit tests pass with 100% coverage.
- ✅ Integration tests validate full export pipeline.
- ✅ ML pipeline documentation complete with examples.

---

## Stage 9: Cross-Finding Correlation (Optional)

### Scope

Implement correlation layer to combine findings and emit high-confidence composite findings, reducing false positive rate and increasing actionable signal.

**Note:** This stage is optional and can be deferred to post-1.0 if timeline is constrained.

### Correlation Patterns

#### Pattern 1: Obfuscated Embedded Executable

**Conditions:**
- `launch_embedded_file` finding present
- `embedded_executable_present` finding present
- Embedded file entropy > 7.5 (high entropy)
- Embedded file and launch target match

**Emit:** `launch_obfuscated_executable` (Severity: Critical)

**Evidence:** Combine evidence from all correlated findings.

#### Pattern 2: Malicious Action Chain

**Conditions:**
- `action_chain_complex` finding present (depth > 3)
- Chain contains JavaScript payload
- Chain is automatically triggered (/OpenAction)

**Emit:** `action_chain_malicious` (Severity: High)

#### Pattern 3: XFA Data Exfiltration

**Conditions:**
- `xfa_submit` finding present
- `xfa_sensitive_field` finding present
- Submit URL is external (not localhost/intranet)

**Emit:** `xfa_data_exfiltration_risk` (Severity: High)

#### Pattern 4: Encrypted Payload Delivery

**Conditions:**
- `embedded_archive_encrypted` finding present
- `launch_embedded_file` or `swf_embedded` targeting encrypted archive

**Emit:** `encrypted_payload_delivery` (Severity: Medium)

#### Pattern 5: Filter Obfuscation + High Entropy

**Conditions:**
- `filter_chain_unusual` or `filter_order_invalid` finding present
- Same stream has `stream_high_entropy` finding

**Emit:** `obfuscated_payload` (Severity: Medium)

### Checklist

- [ ] Implement `FindingCorrelator` in `crates/sis-pdf-detectors/src/correlator.rs`:
  - [ ] Accept list of all findings from scan.
  - [ ] Apply correlation rules (pattern matching).
  - [ ] Emit new composite findings.
  - [ ] Include references to source findings in evidence.

- [ ] Define composite finding IDs:
  - [ ] `launch_obfuscated_executable`
  - [ ] `action_chain_malicious`
  - [ ] `xfa_data_exfiltration_risk`
  - [ ] `encrypted_payload_delivery`
  - [ ] `obfuscated_payload`

- [ ] Register correlator in scan pipeline (Phase D: post-processing).

- [ ] Add configuration for correlation rules:
  - [ ] Enable/disable specific patterns.
  - [ ] Adjust thresholds (e.g., entropy threshold, chain depth).

### Tests

#### Unit Tests

- [ ] `test_correlate_obfuscated_executable()` - Pattern 1 detection.
- [ ] `test_correlate_malicious_action_chain()` - Pattern 2 detection.
- [ ] `test_correlate_xfa_exfiltration()` - Pattern 3 detection.
- [ ] `test_correlate_encrypted_payload()` - Pattern 4 detection.
- [ ] `test_correlate_obfuscated_stream()` - Pattern 5 detection.
- [ ] `test_no_false_correlation()` - Verify benign PDFs don't trigger correlations.

#### Integration Tests

- [ ] `test_correlation_integration()` - Scan PDF with multiple correlated findings.
- [ ] Test with CVE fixtures to verify expected correlations.

### Query Interface Integration

- [ ] Add composite finding queries:
  ```rust
  "findings.composite" => Ok(Query::FindingsComposite),
  "findings.composite.count" => Ok(Query::FindingsCompositeCount),
  ```

- [ ] Support querying by correlation pattern:
  ```bash
  sis query findings --where "is_composite == true"
  ```

### Acceptance Criteria

- ✅ All 5 correlation patterns implemented.
- ✅ Composite findings emitted with source finding references.
- ✅ Configuration allows pattern enable/disable.
- ✅ Unit tests pass with 100% coverage.
- ✅ Integration tests validate correlations.
- ✅ No false correlations on benign PDFs.
- ✅ Documentation updated with correlation patterns.

---

## Appendix A: Complete Findings Reference

### Embedded Files & Launch (Stage 1)

#### embedded_executable_present

- **ID**: `embedded_executable_present`
- **Label**: Embedded executable present
- **Description**: Embedded file is an executable (PE, ELF, Mach-O).
- **Severity**: High
- **Tags**: embedded, executable, delivery
- **Metadata**:
  - `hash.sha256` (string): SHA-256 hash of embedded file
  - `filename` (string): Embedded filename
  - `size_bytes` (int): File size in bytes
  - `magic_type` (string): PE, ELF, or Mach-O
- **Evidence**: Object ID, file offset, hash, magic bytes
- **CVEs**: CVE-2018-4990

#### embedded_script_present

- **ID**: `embedded_script_present`
- **Label**: Embedded script present
- **Description**: Embedded file is a script (JS, VBS, PS1, BAT).
- **Severity**: Medium
- **Tags**: embedded, script, code_execution
- **Metadata**:
  - `hash.sha256` (string)
  - `filename` (string)
  - `size_bytes` (int)
  - `magic_type` (string): JS, VBS, PS1, BAT
- **Evidence**: Object ID, filename, hash
- **CVEs**: Related to script-based attacks

#### embedded_archive_encrypted

- **ID**: `embedded_archive_encrypted`
- **Label**: Embedded encrypted archive
- **Description**: Embedded ZIP/RAR archive is password-protected.
- **Severity**: Medium
- **Tags**: embedded, encryption, evasion
- **Metadata**:
  - `hash.sha256` (string)
  - `filename` (string)
  - `size_bytes` (int)
  - `encrypted` (bool): true
- **Evidence**: Object ID, ZIP encryption flag offset
- **CVEs**: Evasion technique

#### embedded_double_extension

- **ID**: `embedded_double_extension`
- **Label**: Embedded file double extension
- **Description**: Embedded file has double extension (e.g., document.pdf.exe).
- **Severity**: High
- **Tags**: embedded, social_engineering, evasion
- **Metadata**:
  - `filename` (string): Full filename with double extension
  - `extensions` (array): List of extensions detected
- **Evidence**: Filename field
- **CVEs**: Social engineering technique

#### launch_external_program

- **ID**: `launch_external_program`
- **Label**: Launch external program
- **Description**: /Launch action targets external program.
- **Severity**: Critical
- **Tags**: action, launch, code_execution
- **Metadata**:
  - `target_path` (string): Path to external program
  - `target_type` (string): external
- **Evidence**: /Launch action object, /F or /Win dictionary
- **CVEs**: CVE-2010-1240, CVE-2009-0927, CVE-2013-0640

#### launch_embedded_file

- **ID**: `launch_embedded_file`
- **Label**: Launch embedded file
- **Description**: /Launch action targets embedded file.
- **Severity**: High
- **Tags**: action, launch, embedded
- **Metadata**:
  - `target_path` (string): Embedded file reference
  - `target_type` (string): embedded
  - `embedded_file_hash` (string): SHA-256 of target file if correlated
- **Evidence**: /Launch action object, embedded file correlation
- **CVEs**: CVE-2010-1240

### Actions & Triggers (Stage 2)

#### action_chain_complex

- **ID**: `action_chain_complex`
- **Label**: Complex action chain
- **Description**: Action chain depth exceeds threshold (default: 3).
- **Severity**: Medium
- **Tags**: action, chain, complexity
- **Metadata**:
  - `chain_depth` (int): Number of levels in chain
  - `trigger_event` (string): Initial trigger event
  - `chain_path` (string): Full path (e.g., "Catalog -> Page -> Annot -> JS")
  - `has_js` (bool): Chain contains JavaScript
- **Evidence**: Chain path with object IDs
- **CVEs**: Multi-stage attack indicator

#### action_hidden_trigger

- **ID**: `action_hidden_trigger`
- **Label**: Hidden action trigger
- **Description**: Action triggered by non-obvious event (e.g., /FocusIn on hidden field).
- **Severity**: Medium
- **Tags**: action, trigger, evasion
- **Metadata**:
  - `trigger_event` (string): Event type (e.g., "FocusIn", "Keystroke")
  - `trigger_type` (string): hidden
  - `element_type` (string): annotation, form_field
- **Evidence**: Trigger object, visibility flags
- **CVEs**: Evasion technique

#### action_automatic_trigger

- **ID**: `action_automatic_trigger`
- **Label**: Automatic action trigger
- **Description**: Action triggered automatically without user interaction.
- **Severity**: High
- **Tags**: action, trigger, automatic
- **Metadata**:
  - `trigger_event` (string): Event type (e.g., "OpenAction", "WillClose")
  - `trigger_type` (string): automatic
- **Evidence**: /OpenAction or /AA dictionary
- **CVEs**: Common malware technique

### XFA Forms (Stage 3)

#### xfa_submit

- **ID**: `xfa_submit`
- **Label**: XFA form submit action
- **Description**: XFA form contains submit action with target URL.
- **Severity**: Medium
- **Tags**: xfa, submit, data_exfiltration
- **Metadata**:
  - `submit_urls` (array): Target URLs
  - `submit_count` (int): Number of submit actions
- **Evidence**: XFA XML <submit> tag, target attribute
- **CVEs**: Data exfiltration vector

#### xfa_sensitive_field

- **ID**: `xfa_sensitive_field`
- **Label**: XFA sensitive field
- **Description**: XFA form contains sensitive field names.
- **Severity**: Low
- **Tags**: xfa, privacy, sensitive_data
- **Metadata**:
  - `sensitive_fields` (array): Field names detected
  - `field_count` (int): Total sensitive fields
- **Evidence**: XFA XML field names
- **CVEs**: Privacy concern

#### xfa_too_large

- **ID**: `xfa_too_large`
- **Label**: XFA content too large
- **Description**: XFA content exceeds size limit (1MB).
- **Severity**: Medium
- **Tags**: xfa, dos, resource_consumption
- **Metadata**:
  - `xfa_size_bytes` (int): Actual size
  - `size_limit_bytes` (int): Configured limit (1048576)
- **Evidence**: /XFA array size
- **CVEs**: DOS vector

#### xfa_script_count_high

- **ID**: `xfa_script_count_high`
- **Label**: XFA excessive scripts
- **Description**: XFA contains excessive script blocks (>5).
- **Severity**: Medium
- **Tags**: xfa, script, complexity
- **Metadata**:
  - `script_count` (int): Number of <script> tags
  - `script_threshold` (int): Configured threshold (5)
- **Evidence**: XFA XML <script> tag count
- **CVEs**: Malware indicator

### Rich Media (Stage 4)

#### swf_embedded

- **ID**: `swf_embedded`
- **Label**: SWF content embedded
- **Description**: Embedded SWF (Flash) content detected.
- **Severity**: High
- **Tags**: swf, flash, rich_media
- **Metadata**:
  - `media_type` (string): swf
  - `size_bytes` (int): Stream size
  - `swf_version` (int): SWF version number
- **Evidence**: SWF magic bytes (FWS/CWS/ZWS)
- **CVEs**: CVE-2011-0611, CVE-2015-5119

#### swf_actionscript_detected

- **ID**: `swf_actionscript_detected`
- **Label**: SWF ActionScript detected
- **Description**: SWF contains ActionScript tags.
- **Severity**: High
- **Tags**: swf, actionscript, code_execution
- **Metadata**:
  - `actionscript_tags` (array): Tag IDs detected (12, 59, 82)
  - `tag_count` (int): Number of ActionScript tags
- **Evidence**: SWF tag structure
- **CVEs**: CVE-2011-0611, CVE-2015-5119

### Encryption & Obfuscation (Stage 5)

#### stream_high_entropy

- **ID**: `stream_high_entropy`
- **Label**: High entropy stream
- **Description**: Stream entropy exceeds threshold (7.5).
- **Severity**: Low
- **Tags**: entropy, obfuscation, encryption
- **Metadata**:
  - `entropy` (float): Calculated entropy (0.0-8.0)
  - `entropy_threshold` (float): Configured threshold (7.5)
  - `sample_size_bytes` (int): Bytes analyzed (max 10MB)
- **Evidence**: Object ID, entropy calculation
- **CVEs**: Obfuscation indicator

#### embedded_encrypted

- **ID**: `embedded_encrypted`
- **Label**: Embedded encrypted file
- **Description**: Embedded file appears encrypted (high entropy + no known magic).
- **Severity**: Medium
- **Tags**: embedded, encryption, obfuscation
- **Metadata**:
  - `entropy` (float): File entropy
  - `magic_type` (string): unknown
  - `hash.sha256` (string): File hash
- **Evidence**: Embedded file entropy + magic detection failure
- **CVEs**: Evasion technique

#### encryption_key_short

- **ID**: `encryption_key_short`
- **Label**: Short encryption key
- **Description**: Encryption key length below recommended (128 bits).
- **Severity**: High
- **Tags**: encryption, weak_crypto, vulnerability
- **Metadata**:
  - `algorithm` (string): RC4, AES
  - `key_length_bits` (int): Actual key length
  - `recommended_bits` (int): 128
- **Evidence**: /Encrypt dictionary /Length field
- **CVEs**: CVE-2019-7089

### Filter Chains (Stage 6)

#### filter_chain_unusual

- **ID**: `filter_chain_unusual`
- **Label**: Unusual filter chain
- **Description**: Filter combination not in allowlist.
- **Severity**: Low
- **Tags**: filter, obfuscation, unusual
- **Metadata**:
  - `filters` (array): Filter names in order
  - `filter_count` (int): Chain depth
  - `allowlist_match` (bool): false
- **Evidence**: Stream /Filter array
- **CVEs**: Obfuscation technique

#### filter_order_invalid

- **ID**: `filter_order_invalid`
- **Label**: Invalid filter order
- **Description**: Filter order violates PDF specification.
- **Severity**: Medium
- **Tags**: filter, specification, malformed
- **Metadata**:
  - `filters` (array): Filter names in order
  - `violation_type` (string): Description of spec violation
- **Evidence**: Stream /Filter array, spec reference
- **CVEs**: CVE-2010-2883

#### filter_combination_unusual

- **ID**: `filter_combination_unusual`
- **Label**: Unusual filter combination
- **Description**: Filter combination is rare/suspicious.
- **Severity**: Low
- **Tags**: filter, obfuscation, rare
- **Metadata**:
  - `filters` (array): Filter names
  - `rarity_score` (float): Statistical rarity (0.0-1.0)
- **Evidence**: Stream /Filter array
- **CVEs**: Evasion indicator

### Composite Findings (Stage 9 - Optional)

#### launch_obfuscated_executable

- **ID**: `launch_obfuscated_executable`
- **Label**: Launch obfuscated executable
- **Description**: Launch action targets high-entropy embedded executable.
- **Severity**: Critical
- **Tags**: composite, launch, executable, obfuscation
- **Metadata**:
  - `source_findings` (array): IDs of correlated findings
  - `target_hash` (string): Embedded file hash
  - `entropy` (float): File entropy
- **Evidence**: Combined from source findings
- **CVEs**: High-confidence malware indicator

---

## Appendix B: Risk Assessment Matrix

| Risk | Likelihood | Impact | Mitigation | Stage | Status |
|------|------------|--------|------------|-------|--------|
| XML entity expansion (billion laughs) | High | Critical | Use roxmltree (no entity support), 1MB limit | 3 | Mitigated |
| SWF decompression bomb | Medium | High | Minimal parser, 10:1 ratio limit, 10MB max | 4 | Mitigated |
| Entropy calculation DOS | Medium | Medium | Sliding window, 10MB sample, 50ms timeout | 5 | Mitigated |
| Action chain infinite loop | Medium | Medium | Cycle detection, depth limit 10, 100ms timeout | 2 | Mitigated |
| Memory exhaustion (embedded files) | Medium | High | Streaming hash, no buffering | 1 | Mitigated |
| Memory exhaustion (XFA parsing) | Medium | High | 1MB size limit, roxmltree DOM limits | 3 | Mitigated |
| Dependency CVE (roxmltree) | Low | High | Pin to 0.20.0, monitor RustSec advisories | 3 | Monitored |
| Dependency CVE (flate2) | Low | High | Pin to 1.0, widely audited | 4 | Monitored |
| False positives (filter chains) | High | Low | Allowlist system, configurable thresholds | 6 | Mitigated |
| False positives (entropy) | Medium | Low | Threshold tuning (7.5), context-aware detection | 5 | Mitigated |
| Breaking changes (feature vector order) | Low | Medium | Append new features only, document order | 8 | Prevented |
| Performance regression | Medium | Medium | SLO tracking, profiling output, CI benchmarks | 0.5 | Monitored |
| Test fixture legal issues | Low | Medium | Synthetic-only fixtures, documented as non-functional | 0 | Prevented |

---

## Appendix C: Implementation Roadmap

### Phase Timeline (Estimated)

| Stage | Description | Estimated Effort | Dependencies |
|-------|-------------|------------------|--------------|
| 0 | Alignment & Baseline | 3-5 days | None |
| 0.5 | Performance & Safety Architecture | 2-3 days | None |
| 1 | Embedded Files & Launch | 4-6 days | Stage 0, 0.5 |
| 2 | Actions & Triggers | 4-6 days | Stage 0, 0.5 |
| 3 | XFA Forms | 5-7 days | Stage 0, 0.5 |
| 4 | Rich Media | 5-7 days | Stage 0, 0.5 |
| 5 | Encryption & Obfuscation | 4-6 days | Stage 0, 0.5 |
| 6 | Filter Chains | 3-5 days | Stage 0, 0.5 |
| 7 | Documentation | 2-3 days | Stages 1-6 complete |
| 7.5 | Query Integration | 3-5 days | Stages 1-6 complete |
| 8 | Feature Vector Integration | 2-3 days | Stages 1-6 complete |
| 9 | Correlation (Optional) | 3-4 days | Stages 1-6 complete |

**Total effort (excluding Stage 9): 32-51 days**  
**Total effort (including Stage 9): 35-55 days**

### Parallel Work Opportunities

Stages 1-6 can be partially parallelized after Stage 0 and 0.5 are complete, as they have minimal inter-dependencies:

- **Track 1**: Stages 1, 3, 5 (embedded content, XFA, encryption)
- **Track 2**: Stages 2, 4, 6 (actions, media, filters)

This could reduce total calendar time by ~30%.

### Minimum Viable Product (MVP)

For fastest time-to-value, prioritize:
1. Stage 0 (infrastructure)
2. Stage 0.5 (safety)
3. Stage 1 (embedded files - highest CVE impact)
4. Stage 2 (action chains - forensic value)
5. Stage 7.5 (query integration - user value)

**MVP effort: ~18-28 days**

---

## Notes

- Each stage merges only when tests pass and findings metadata are defined.
- Keep new detectors within `crates/sis-pdf-detectors`.
- Avoid logging sensitive content; keep evidence concise and structured.
- Use Australian English spelling throughout (e.g., "analyse", "recognise").
- Follow structured `tracing` field conventions.
- Maintain backward compatibility for feature vector order.
- Document all breaking changes and migration paths.
#### Streams and Filters (Stages 5-6)

```
streams.high-entropy
filters.unusual
filters.invalid
filters.repeated
```

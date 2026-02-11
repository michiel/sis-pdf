# JavaScript Detection Modernisation: Technical Recommendation and Uplift Plan

Date: 2026-02-11
Status: Stage 1 Complete
Scope: `crates/js-analysis/`, `crates/sis-pdf-detectors/`, test infrastructure

---

## 1. Situation Assessment

### 1.1 Current state

The js-analysis crate is a mature static+dynamic JavaScript security analysis engine with:

- **60+ static signals** covering obfuscation, shellcode, exploit kits, anti-analysis, data exfiltration, resource exhaustion, and PDF-specific exploitation.
- **47 behavioural patterns** in the dynamic sandbox covering COM downloader chains, WSH gating, modern browser primitives, WASM staging, prototype hijacking, credential harvesting, and more.
- **Multi-profile execution** across pdf_reader, browser, node, and bun profiles with divergence scoring.
- **Phase-based execution** simulating open, idle, click, and form lifecycle events.
- **Adaptive loop hardening** with profile-specific iteration budgets.
- **Taint-lite source-to-sink** correlation for data exfiltration detection.
- **WASM binary analysis** with bounded parsing.
- **Prototype pollution gadget catalogue** with 15-20 entries.

### 1.2 Corpus coverage

Detection has been validated against a corpus of malicious JavaScript from **2010-2017** (300 samples, 67% execution rate). The corpus represents the WSH/COM-heavy era of PDF malware: `Scripting.FileSystemObject`, `WScript.Shell`, `MSXML2.XMLHTTP`, `ADODB.Stream`, and `ActiveXObject` instantiation chains.

### 1.3 What has changed (2018-2025)

The JavaScript malware landscape has shifted substantially since 2017:

1. **Exploitation primitives have modernised.** Post-2020 Acrobat Reader CVEs (CVE-2020-9715, CVE-2021-39863, CVE-2023-21608, CVE-2023-26369) use ArrayBuffer/TypedArray/DataView-based heap grooming, Low Fragmentation Heap priming, and ROP chain construction from JavaScript. The classic `unescape('%u9090')` NOP sled is largely obsolete.

2. **Obfuscation has diversified.** Esoteric encodings (JSFuck using `[]()!+`, JJEncode using 18 symbols, AAEncode) have moved from curiosities to active campaign tools (269,000+ infected pages using JSFireTruck/JSFuck in March-April 2025 alone). Control flow flattening now uses opaque dispatch tables rather than simple switch/case structures. String splitting with array rotation defeats naive split+fromCharCode detection.

3. **LLM-assisted obfuscation has emerged.** Attackers use LLMs to rewrite malicious JavaScript into natural-looking code that defeats syntactic pattern matching. Multiple layers of LLM-based transformations can fool most malware classifiers.

4. **PDF attack surfaces have expanded.** CVE-2024-4367 (PDF.js) demonstrated arbitrary JavaScript execution via crafted font data. Template injection and form-based injection chains target both Acrobat and browser-based viewers. Attack chains now bridge PDF JavaScript to PowerShell/MSHTA execution.

5. **Anti-analysis has become sophisticated.** Dead code injection adds functional-looking but never-executed paths. Analysis traps trigger only in automated environments. Timing sidechannels detect sandbox execution speed differences.

### 1.4 Outstanding technical debt

The 2026-02-11 review identified 42 findings (5 critical, 11 high) that should be resolved before or alongside modernisation work:

- **C-1**: HashMap non-determinism in telemetry (use BTreeMap)
- **C-2**: Unbounded augmented_source accumulation (cap at 128 KiB)
- **C-3**: Profile divergence over-flagging at 67% threshold
- **C-4**: Five core patterns with zero test coverage
- **C-5**: 3% negative test ratio
- **H-1**: Phase timeout does not break execution
- Concatenation reconstruction not implemented (Phase 2.1 TODO in static_analysis.rs)

---

## 2. Threat Model Update

### 2.1 Priority threat families (2018-2025)

| Family | Prevalence | Current coverage | Gap severity |
|--------|-----------|-----------------|-------------|
| Modern heap exploitation (ArrayBuffer/TypedArray ROP setup) | High (active CVEs) | Partial (basic array manipulation) | High |
| Esoteric encoding (JSFuck, JJEncode, AAEncode) | High (269K+ pages 2025) | None | High |
| Control flow flattening with dispatch tables | High (Remcos campaigns 2025) | Partial (3+ switch heuristic) | Medium |
| LLM-rewritten obfuscation | Emerging | None (inherently hard) | Medium |
| Dead code injection / analysis traps | Medium | None | Medium |
| String splitting with array rotation | Medium | Partial (basic split detection) | Medium |
| PDF.js font/glyph injection | Medium (CVE-2024-4367) | None (outside Acrobat model) | Low-Medium |
| PDF-to-PowerShell/MSHTA bridge | Medium | Partial (WScript stubs exist) | Low |
| Multi-layer successive transformations | High | Partial (decode_layers handles 3 types) | Medium |
| Template/form injection chains | Medium | Partial (form_manipulation signal) | Low |

### 2.2 Updated detection philosophy

The shift from signature-based to behaviour-based detection is well underway in the crate. The next phase should:

1. **Deepen behavioural analysis** rather than adding more signatures. LLM-rewritten malware defeats signatures; behaviour is harder to disguise.
2. **Add structural/statistical detectors** for encoding families that have distinctive entropy and character distribution profiles (JSFuck, JJEncode).
3. **Modernise exploitation primitive detection** to match post-2020 CVE tradecraft.
4. **Expand the decode pipeline** to handle additional encoding layers before static/dynamic analysis.
5. **Strengthen the test corpus** with post-2017 samples and synthetic adversarial fixtures.

---

## 3. Uplift Plan

### Stage 1: Stabilisation (resolve review debt)

**Goal**: Fix the 5 critical and most impactful high findings from the 2026-02-11 review before adding new detection capability. New features built on non-deterministic or unbounded foundations will compound problems.

**Deliverables**:

| Item | Description | Priority | Status |
|------|-------------|----------|--------|
| S1-1 | Replace HashMap with BTreeMap in `SandboxLog.call_counts_by_name` and `approx_string_entropy` (C-1) | Critical | **Done** (prior commit + current branch) |
| S1-2 | Cap `augmented_source` at `MAX_AUGMENTED_SOURCE_BYTES` with truncation (C-2) | Critical | **Done** (prior commit) |
| S1-3 | Widen divergence consistency band: ratio >0.6 = consistent (C-3) | Critical | **Done** (current branch: js_sandbox.rs) |
| S1-4 | Add unit tests for `dynamic_code_generation`, `obfuscated_string_construction`, `environment_fingerprinting`, `error_recovery_patterns`, `variable_promotion_detected` (C-4) | Critical | **Done** (prior commit) |
| S1-5 | Add 15+ negative tests with benign JS fixtures (C-5) | Critical | **Done** (current branch: 16 new benign tests, 22 total negative = 21.4%) |
| S1-6 | Break phase loop on timeout (H-1) | High | **Done** (current branch: dynamic.rs execute_micro_phase returns bool) |
| S1-7 | Report mutex poisoning explicitly (H-2) | High | **Done** (prior commit) |

**Success criteria**: All existing tests pass. Negative test ratio reaches 15%+. Deterministic output under repeated identical runs.

**Achieved**: 141 tests pass (103 dynamic + 13 hostile + 16 profile + 7 unit + 2 static). Negative test ratio 21.4% (22/103 dynamic). All HashMap instances in public API and internal metadata replaced with BTreeMap.

---

### Stage 2: Esoteric Encoding Detection

**Goal**: Detect JSFuck, JJEncode, AAEncode, and JScrew.it encoded payloads. These are high-prevalence, structurally distinctive, and currently invisible to the engine.

**Approach**: Statistical/structural detection rather than signature matching. These encodings have extremely distinctive character distributions.

**Deliverables**:

| Item | Description |
|------|-------------|
| S2-1 | **JSFuck detector** (static signal: `js.jsfuck_encoding`). Detect code composed predominantly of `[]()!+` characters. Heuristic: >80% of non-whitespace characters from the set `[]()!+` AND total length >50 characters. Low false-positive risk due to extreme character restriction. |
| S2-2 | **JJEncode detector** (static signal: `js.jjencode_encoding`). Detect code using the 18-character set `[]()!+,"$.:;_{}~=` with characteristic `$` variable patterns and nested bracket structures. Heuristic: presence of `$=~[];` preamble OR >70% characters from the 18-char set with repetitive bracket nesting. |
| S2-3 | **AAEncode detector** (static signal: `js.aaencode_encoding`). Detect code using Japanese emoticon-style encoding. Heuristic: high density of fullwidth characters (U+FF00-U+FFEF) combined with `(function()` and `constructor` patterns. |
| S2-4 | **Decode pipeline extension**. Add JSFuck/JJEncode/AAEncode decoding as layers in `decode_layers()`, producing decoded output for subsequent static and dynamic analysis. Bounded: max 64 KiB decoded output, max 3 decode iterations per encoding type. |
| S2-5 | **Test fixtures**. Craft 3 benign-looking encoded samples (one per encoding) and 3 malicious encoded samples. Validate both detection and decode-then-analyse pipeline. |

**Success criteria**: Detection rate >95% on synthetic JSFuck/JJEncode/AAEncode samples. Zero false positives on the existing benign test corpus.

---

### Stage 3: Modern Heap Exploitation Primitives

**Goal**: Detect post-2020 JavaScript-assisted heap exploitation patterns used in real Acrobat Reader CVEs.

**Approach**: Static pattern detection combined with dynamic monitoring of ArrayBuffer/TypedArray allocation patterns in the sandbox.

**Deliverables**:

| Item | Description |
|------|-------------|
| S3-1 | **Heap grooming detector** (static signal: `js.heap_grooming`). Detect patterns: (a) multiple ArrayBuffer allocations of identical size in a loop, (b) TypedArray view creation over ArrayBuffer with offset/length manipulation, (c) DataView read/write operations with computed offsets. Require 2+ of these in combination. |
| S3-2 | **LFH priming detector** (static signal: `js.lfh_priming`). Detect Low Fragmentation Heap activation patterns: repeated allocation-then-free cycles of same-sized objects, typically ArrayBuffer or typed arrays, followed by a targeted allocation. |
| S3-3 | **ROP chain construction detector** (static signal: `js.rop_chain_construction`). Detect patterns: (a) reading DLL base addresses via info leak (ArrayBuffer length corruption), (b) computing gadget offsets from a base address, (c) writing address sequences to TypedArray/DataView. Heuristic: hex arithmetic on large constants combined with sequential DataView writes. |
| S3-4 | **Info leak detector** (static signal: `js.info_leak_primitive`). Detect ArrayBuffer/TypedArray patterns where a corrupted length field is used to read out-of-bounds memory. Heuristic: ArrayBuffer creation + TypedArray view + length/byteLength comparison or mutation + out-of-bounds indexed access. |
| S3-5 | **Dynamic sandbox stubs**. Add ArrayBuffer, TypedArray (Uint8Array, Uint32Array, Float64Array), and DataView constructor stubs to the sandbox. Track allocation sizes, view creation patterns, and indexed access patterns in telemetry. Emit `js_runtime_heap_manipulation` finding when allocation-spray or view-corruption patterns are observed. |
| S3-6 | **Test fixtures**. Create fixtures based on sanitised patterns from CVE-2023-26369 and CVE-2023-21608 public write-ups. Include both detection and false-negative tests. |

**Success criteria**: Detection of heap grooming, LFH priming, and ROP setup patterns from post-2020 CVE public analyses. No false positives on benign ArrayBuffer usage (e.g., legitimate binary data processing).

---

### Stage 4: Advanced Obfuscation Resilience

**Goal**: Improve detection of control flow flattening, dead code injection, string splitting with array rotation, and multi-layer obfuscation pipelines.

**Deliverables**:

| Item | Description |
|------|-------------|
| S4-1 | **Enhanced CFF detector** (upgrade `js.control_flow_flattening`). Current heuristic (3+ switch statements) is too coarse. Add detection of: (a) while-loop wrapping a single switch with a state variable, (b) array-based dispatch tables (`arr[state++]()`), (c) computed property dispatch (`obj[keys[i]]()`). Use AST analysis when `js-ast` feature is enabled for higher accuracy. |
| S4-2 | **Dead code injection detector** (static signal: `js.dead_code_injection`). Detect code paths that are statically unreachable: (a) `if(false)` / `if(0)` blocks, (b) code after unconditional `return`/`throw`, (c) functions defined but never called (AST-required). Emit when dead-code-to-live-code ratio exceeds threshold (e.g., >30%). This signal is an evasion indicator, not malicious on its own. |
| S4-3 | **Array rotation decoder** (static signal: `js.array_rotation_decode`). Detect the pattern: array of encoded strings defined, then a rotation function called repeatedly before string access by index. Common in obfuscator.io and similar tools. Pattern: `var _0x = [strings...]; (function(_0x, _0y){ ... _0x.push(_0x.shift()) ... })(_0x, 0x...)`. |
| S4-4 | **Concatenation reconstruction** (implement the Phase 2.1 TODO). Reconstruct string values built from `+` concatenation of string literals. AST-preferred path: walk the AST for BinaryExpression nodes with `+` operator where both sides are string literals or prior concatenation results. Regex fallback: capture `'a' + 'b' + 'c'` patterns. Emit `payload.concatenation_reconstructed`. |
| S4-5 | **Multi-layer decode depth increase**. Extend `decode_layers()` to handle: (a) nested unescape chains, (b) fromCharCode inside eval inside unescape, (c) successive base64 layers. Increase max iterations from current limit to 8, with per-layer size cap of 256 KiB. |
| S4-6 | **Test fixtures**. Create synthetic fixtures for CFF with dispatch tables, dead code injection, array rotation, and multi-layer nesting. Include fixtures from publicly documented obfuscator.io output patterns. |

**Success criteria**: CFF detection rate on obfuscator.io-style output >80%. Concatenation reconstruction implemented and passing. decode_layers handles 5+ layer deep samples.

---

### Stage 5: Behavioural Resilience Against LLM-Rewritten Malware

**Goal**: Reduce dependence on syntactic patterns that LLM rewriting can defeat. Strengthen behavioural and semantic analysis.

**Rationale**: LLM-rewritten malware preserves semantics while altering syntax. Detection must focus on what code does, not how it looks. This is the highest-complexity, highest-impact stage.

**Deliverables**:

| Item | Description |
|------|-------------|
| S5-1 | **API call sequence analysis**. Implement call-sequence pattern matching in the dynamic sandbox. Rather than detecting individual suspicious calls, detect suspicious sequences: e.g., `getAnnots` -> string manipulation -> `eval` is malicious regardless of how the string manipulation is obfuscated. Define 10-15 canonical malicious call sequences from the existing 47 patterns. |
| S5-2 | **Data flow complexity scoring**. Score the complexity of data transformations between source (input/annotation/metadata) and sink (eval/launchURL/submitForm). Simple flows (direct pass) score low; flows involving 3+ transformation steps (decode, split, replace, fromCharCode, etc.) score high. High-complexity flows with sensitive sinks are suspicious regardless of individual transform appearance. |
| S5-3 | **Entropy-at-sink analysis**. Measure Shannon entropy of data arriving at execution sinks (eval, Function constructor). High-entropy data reaching eval is suspicious even if individual code statements look benign. Integrate with existing `approx_string_entropy` (after BTreeMap fix). |
| S5-4 | **Dynamic string materialisation tracking**. Track strings that are constructed at runtime and passed to sinks. Record the "birth" of strings (concatenation, fromCharCode, replace chains, decode operations) and flag strings that: (a) did not exist as literals in the original source, (b) contain executable code patterns, (c) are passed to execution sinks. |
| S5-5 | **Semantic call-graph extraction**. When `js-ast` feature is enabled, extract the call graph and data dependency graph. Identify code that reads from PDF metadata/annotations, transforms the data, and passes it to execution sinks, regardless of variable names or code style. |
| S5-6 | **Adversarial test corpus**. Create 10 fixtures where the same malicious payload is expressed in syntactically different ways (manual rewriting simulating LLM transforms). Validate that behavioural detection catches all variants. |

**Success criteria**: At least 8 of 10 adversarial variants detected. API call sequence analysis catches classic PDF exploit chains regardless of obfuscation style.

---

### Stage 6: Corpus Expansion and Validation

**Goal**: Expand the test corpus beyond 2010-2017 samples. Validate all new detectors against both historical and modern samples.

**Deliverables**:

| Item | Description |
|------|-------------|
| S6-1 | **Acquire 2018-2025 samples**. Source malicious PDF JavaScript from VirusShare, MalwareBazaar, and public CVE proof-of-concept repositories for 2018-2025. Target: 100+ samples spanning modern technique families. Respect licensing and responsible disclosure. |
| S6-2 | **Synthetic adversarial corpus**. Generate 50+ synthetic fixtures covering: JSFuck/JJEncode/AAEncode encoding, control flow flattening, array rotation, heap grooming, ROP construction, dead code injection, multi-layer obfuscation, LLM-style rewrites. |
| S6-3 | **Benign corpus**. Assemble 50+ benign JavaScript samples: legitimate PDF form validation, calculation scripts, annotation handlers, accessibility helpers. Essential for false-positive regression testing. |
| S6-4 | **Validation sweep**. Run the full engine against the expanded corpus. Target metrics: (a) execution rate >75% (up from 67%), (b) true positive rate >85% on known-malicious, (c) false positive rate <5% on benign corpus. |
| S6-5 | **Regression harness**. Automate corpus sweep as a CI-compatible test that can run on each PR. Record per-sample outcomes in a structured format for trend tracking. |

**Success criteria**: Corpus covers 2010-2025 range. Execution rate and detection metrics meet targets. Regression harness runs in CI.

---

## 4. Execution Order and Dependencies

```
Stage 1 (Stabilisation)
    |
    +---> Stage 2 (Esoteric Encoding)
    |         |
    +---> Stage 3 (Heap Exploitation)
    |         |
    +---> Stage 4 (Obfuscation Resilience)
              |
              v
         Stage 5 (Behavioural/LLM Resilience)
              |
              v
         Stage 6 (Corpus Expansion)
```

- Stage 1 is a prerequisite for all other stages (fixes determinism and test infrastructure).
- Stages 2, 3, and 4 can proceed in parallel after Stage 1.
- Stage 5 depends on Stage 4 (needs concatenation reconstruction and enhanced decode pipeline).
- Stage 6 depends on all prior stages (validates the complete detection surface).

---

## 5. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| JSFuck decoder introduces denial-of-service (exponential decode) | Medium | High | Strict size caps and iteration limits on all decode paths |
| Heap grooming detector generates false positives on legitimate ArrayBuffer usage | Medium | Medium | Require 2+ indicators in combination; validate against benign binary-processing JS |
| LLM-rewritten malware evolves faster than behavioural patterns | High | Medium | Focus on semantic invariants (source-to-sink flows) rather than syntactic patterns; plan for periodic pattern refresh |
| Modern corpus acquisition blocked by licensing/availability | Medium | Low | Supplement with synthetic fixtures; public CVE PoCs are freely available |
| Concatenation reconstruction causes performance regression on large files | Low | Medium | Cap reconstructed string count and total byte budget |

---

## 6. Metrics and Success Criteria

### Detection coverage targets (post-Stage 6)

| Technique family | Current detection | Target detection |
|-----------------|-------------------|-----------------|
| Classic COM/WSH chains (2010-2017) | Strong | Maintain |
| Esoteric encoding (JSFuck/JJEncode/AAEncode) | None | >95% |
| Modern heap exploitation (ArrayBuffer/TypedArray) | Partial | >80% |
| Control flow flattening (dispatch table style) | Weak | >80% |
| Dead code injection | None | >70% |
| String array rotation | None | >80% |
| Multi-layer obfuscation (5+ layers) | Partial | >90% |
| LLM-rewritten variants | None | >60% |

### Quality targets

| Metric | Current | Target |
|--------|---------|--------|
| Negative test ratio | 3% | >20% |
| Corpus execution rate | 67% | >75% |
| False positive rate (benign corpus) | Unknown | <5% |
| Untested core patterns | 5 | 0 |
| Deterministic output | No (HashMap) | Yes |

---

## 7. Out of Scope

The following are explicitly excluded from this plan:

- **Global payload limit increase to 50 MiB** - Separate performance/safety discussion needed.
- **Speculative agentic malware attribution** - Research-stage, insufficient basis for implementation.
- **PDF structural evasion** (fake XREF, empty ObjStm) - Handled by `sis-pdf-pdf` crate, not js-analysis.
- **Browser-specific PDF.js vulnerabilities** (CVE-2024-4367) - Outside the Acrobat-focused threat model; PDF.js font injection is a rendering engine bug, not a JavaScript analysis concern.
- **Real network/filesystem side-effects** - Sandbox must remain side-effect-free.
- **Machine learning classifiers** - The engine uses deterministic heuristics and pattern matching; ML-based classification is a separate architectural decision.

---

## 8. References

- [The Power of Obfuscation Techniques in Malicious JavaScript Code (Penn State)](https://www.cse.psu.edu/~sxz16/papers/malware.pdf)
- [JSFireTruck: Malicious JavaScript Using JSFuck (Unit 42, 2025)](https://unit42.paloaltonetworks.com/malicious-javascript-using-jsfiretruck-as-obfuscation/)
- [Using LLMs to Obfuscate Malicious JavaScript (Unit 42, 2024)](https://unit42.paloaltonetworks.com/using-llms-obfuscate-malicious-javascript/)
- [CVE-2023-26369: Adobe Acrobat Reader RCE via TTF fonts (Project Zero)](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2023/CVE-2023-26369.html)
- [CVE-2023-21608: Adobe Acrobat Reader RCE (hacksysteam)](https://github.com/hacksysteam/CVE-2023-21608)
- [CVE-2024-4367: Arbitrary JS execution in PDF.js (Codean Labs)](https://codeanlabs.com/blog/research/cve-2024-4367-arbitrary-js-execution-in-pdf-js/)
- [Increased Evasion Resilience in Modern PDF Malware (Diva Portal, 2022)](http://www.diva-portal.org/smash/get/diva2:1678561/FULLTEXT01.pdf)
- [From Obfuscated to Obvious: JS Deobfuscation (arXiv, 2025)](https://arxiv.org/pdf/2512.14070)
- [Enhancing JavaScript Malware Detection Through Weighted Behavioral DFAs (arXiv, 2025)](https://arxiv.org/pdf/2505.21406)
- [Survey of Malicious PDF Detection Systems (ScienceDirect, 2025)](https://www.sciencedirect.com/science/article/pii/S1877050925008798)
- [SAFE-PDF: Robust Detection with Abstract Interpretation (arXiv, 2018)](https://ar5iv.labs.arxiv.org/html/1810.12490)
- [CVE-T4PDF: CVEs Using PDF as Attack Vector](https://github.com/0xCyberY/CVE-T4PDF)
- Internal: `reviews/20260211-js-uplift-review.md` (42 findings)
- Internal: `plans/20260210-js-uplift-metrics.md` (300-sample validation)
- Internal: `plans/20260209-js-2017-corpus-sweep.md` (2017 corpus assessment)

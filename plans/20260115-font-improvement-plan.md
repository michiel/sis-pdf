Below is a detailed implementation plan to enhance `sis‑pdf` based on the earlier recommendations.  The plan specifies tasks, Rust crate choices, and integration steps to close current detection gaps and future-proof the system.  You can view it here: {{file:file-386eZptZcW1oHLAdkPVbRM}}.

I have structured the plan into thematic sections covering Type 1 font analysis, dynamic parsing improvements, CVE signature handling, correlation with JavaScript and remote actions, support for new font formats, instrumentation, risk scoring, user‑configurable thresholds, and CI/automation.  Each section lists concrete tasks, outlines how to use Rust-native crates (such as `postscript`, `ttf-parser`, `allsorts`, `libafl`, `serde`, `reqwest`, etc.), and explains how these components will work together.

# Implementation Plan for Enhancing `sis‑pdf` Font Detection and Scanning

This plan translates the recommendations from the security assessment into actionable tasks using **Rust‑native crates**. All modules should reside within the existing `sis-pdf` workspace (e.g., `crates/font-analysis` and `crates/sis-pdf-detectors`). The plan assumes familiarity with Rust’s async ecosystem (Tokio), error handling (thiserror), and serialization (serde).

---

## 1 Type‑1 Font Recognition and Analysis

### 1.1 Detect Type 1 fonts in PDF streams

-   **Task:** Add a detector for PostScript Type 1 fonts in the `FontExploitDetector` module.
    
-   **Approach:**
    
    -   Identify PDF objects whose `/Subtype` is `/Type1` or whose stream data begins with `%!PS‑AdobeFont`. The existing PDF parser should provide the raw byte stream; implement heuristics to check for `FontType 1`, `currentdict`, or `.notdef` names in the first kilobyte.
        
    -   If the font is encoded via `eexec`, decrypt it using the Type 1 eexec decoding algorithm (simple XOR and rolling seed). Use or implement a small utility; if a crate exists, prefer `postscript` (see below).
        
-   **Crates:**
    
    -   [`postscript`](https://crates.io/crates/postscript) – provides parsing of Type 1, Type 2, and CFF charstrings. Use its `type1` module to decode and iterate through charstrings.
        

### 1.2 Parse and analyse Type 1 charstrings

-   **Task:** Implement a new module `type1_analysis` in `crates/font-analysis`.
    
-   **Approach:**
    
    1.  Use `postscript::type1` to parse the decrypted eexec portion into font dictionaries and charstring programs.
        
    2.  For each charstring:
        
        -   Walk through the sequence of operators and operands.
            
        -   Track stack depth; record the maximum depth and detect unusual stack growth (e.g., > 100 entries).
            
        -   Flag use of dangerous or rarely used operators (`callothersubr`, `pop`, `return`, `put`, `store`).
            
        -   Search for the `blend` operator (if the font uses CFF2) or multiple `callothersubr`/`return` sequences typical of the 2015 BLEND exploit.
            
        -   Compute the total number of instructions; flag extremely large programs (e.g., > 10,000 ops).
            
    3.  Emit new findings:
        
        -   `font.type1_dangerous_operator` (severity HIGH) when dangerous operators or unusual stack manipulations are present.
            
        -   `font.type1_excessive_stack` for high stack usage.
            
        -   `font.type1_large_charstring` for large programs.
            
-   **Crates:**
    
    -   `postscript` for Type 1 charstrings.
        
    -   `log` or `tracing` for structured logging.
        
-   **Testing:** Create unit tests with benign Type 1 fonts and a synthetic BLEND exploit sample to ensure heuristics trigger correctly.
    

### 1.3 Integration

-   Modify `font_analysis::analyse_font` to dispatch to the new `type1_analysis` when a Type 1 font is detected. Combine its findings with existing static and dynamic analyses.
    
-   Update `docs/findings.md` with new finding definitions.
    

---

## 2 Integrate a Type 1 Interpreter/Sanitizer

### 2.1 Interpreter integration

-   **Task:** Evaluate embedding a PostScript interpreter for dynamic execution of Type 1 charstrings.
    
-   **Approach:**
    
    -   Use the `postscript` crate’s Type 1 and Type 2 charstring interpreters for sandboxed execution. They expose data structures rather than executing code; implement a mini interpreter that emulates the charstring stack machine with strict limits on instruction count and stack depth.
        
    -   Maintain an execution budget (e.g., 50,000 instructions) to prevent infinite loops. Terminate and flag if the budget is exceeded.
        
    -   During execution, track memory access operations (e.g., `put`, `get`) and flag unexpected modifications. The interpreter should not allow arbitrary file access; restrict operations to charstring context only.
        
-   **Crates:**
    
    -   `postscript` – contains definitions for charstring operators; this crate does not provide a full interpreter, but we can build one on top.
        
    -   `rayon` – optional for parallel analysis if scanning multiple fonts concurrently.
        

### 2.2 Sanitizer integration

-   **Task:** Where dynamic execution is not required, implement a sanitizer based on the OpenType Sanitizer (OTS) logic.
    
-   **Approach:**
    
    -   For TrueType/CFF fonts, use the `allsorts` or `ttf-parser` crate to parse tables and apply OTS‑like validity rules (e.g., proper ordering, correct checksums, and non‑overlapping tables). Many of these checks already exist in the static scan module; extend them to cover variable fonts and color tables.
        
    -   Expose a `sanitize_font(data: &[u8]) -> Result<(), SanitizerError>` function that is called before deeper analysis.
        
-   **Crates:**
    
    -   [`ttf-parser`](https://docs.rs/ttf-parser) – safe, zero‑allocation parser for TrueType/OpenType fonts; supports variable font tables.
        
    -   [`allsorts`](https://docs.rs/allsorts) – advanced parser including WOFF/WOFF2 and shaping; can validate more complex features.
        

---

## 3 Extend Dynamic Analysis for TrueType/CFF

### 3.1 Enhanced dynamic parser

-   **Task:** Replace the current no‑op dynamic analysis with an instrumented parser.
    
-   **Approach:**
    
    1.  **Parsing with Skrifa / ttf-parser:** Use `skriva` or `ttf-parser` to load fonts. On parse errors, capture the error message and record a `font.dynamic_parse_failure` finding. On success, proceed to heuristics.
        
    2.  **Hinting program execution:** For TTF fonts, iterate through glyph instructions (`glyf` and `prep` programs) using `ttf-parser` or `fonttools-rs`. Simulate execution using a simple TrueType virtual machine limited to arithmetic and stack operations. Apply instruction budget and stack depth limits; flag unusual loops or calls.
        
    3.  **Variable fonts and gvar/avar:** For fonts containing `gvar` or `avar` tables, verify that data sizes and indices are consistent. The Cisco Talos vulnerabilities (CVE‑2025‑27163/27164) highlight mismatches between `hmtx`/`hhea` and `CFF2`/`maxp` table counts. Implement checks for:
        
        -   `hmtx` length ≥ `4 * numberOfHMetrics` (from `hhea`).
            
        -   `maxp.num_glyphs` ≤ the number of `CharStrings` entries in the `CFF2` table.
            
        -   `gvar`/`GlyphVariationData_size` ≥ `4 + total_tvh_size`.
            
        -   Existence of `EBSC` table offsets and ensure they do not point outside the table (prevents CVE‑2023‑26369 type OOB writes).
            
    4.  **Automate rule registration:** Define a `DynamicRule` trait with `check(&FontContext) -> Option<Finding>`; implement rules for each CVE pattern. Register rules in a static list so new CVEs can be added easily.
        
-   **Crates:**
    
    -   `ttf-parser` or `fontations/read-fonts` for safe parsing.
        
    -   `skriva` for memory‑safe parsing and to reuse the engine adopted by Chrome.
        
    -   `lazy_static` or `once_cell` for rule registration.
        

### 3.2 Fuzz testing integration

-   **Task:** Incorporate fuzzing to discover unknown vulnerabilities.
    
-   **Approach:**
    
    -   Use the `libafl` or `cargo-afl` crate to build a fuzzing harness around the dynamic parser and interpreter. Provide mutated fonts as input and run under sanitizers (ASan, UBSan) to detect memory issues. Fuzzing should be optional and run offline as part of continuous security testing rather than during end‑user scanning.
        
    -   Create a `fuzz/fuzz_targets/dynamic_font_parser.rs` target that loads fonts through the new dynamic analysis code. Use `arbitrary` crate to generate random font data.
        
-   **Crates:**
    
    -   `libafl` for fuzzing infrastructure.
        
    -   `arbitrary` for generating test inputs.
        
    -   `anyhow` or `eyre` for error reporting.
        

---

## 4 Signature‑Based Detection

### 4.1 Signature repository

-   **Task:** Maintain a repository of CVE signatures describing known font vulnerabilities.
    
-   **Approach:**
    
    -   Create a new crate `font-signatures` containing YAML/JSON files for each vulnerability. Each signature includes metadata (CVE ID, description, severity) and a `Pattern` struct describing conditions on table lengths, offsets, or instruction sequences.
        
    -   Provide a procedural macro or builder to compile signatures into Rust code at build time. For example, `build.rs` can read YAML files and generate a `const SIGNATURES: &[Signature]` array.
        
    -   Expose a function `match_signatures(context: &FontContext) -> Vec<Finding>` that evaluates each signature against the parsed font.
        
-   **Crates:**
    
    -   `serde` and `serde_yaml`/`serde_json` for reading signatures.
        
    -   `proc_macro2` and `quote` if using procedural macros.
        

### 4.2 Automatic CVE feed integration

-   **Task:** Automate updates from NVD or GitHub Security Advisories.
    
-   **Approach:**
    
    -   Write a small `cve-update` binary using `reqwest` and `serde` to fetch JSON feeds from the National Vulnerability Database (NVD) or GitHub’s advisory API. Filter for font‑related vulnerabilities (e.g., keywords: *font*, *TrueType*, *CFF*, *Adobe*, *FreeType*).
        
    -   Generate new signature files or update existing ones based on the CVE description. Use heuristics to convert common vulnerability patterns into signature expressions (e.g., `tableLength < expected`). This may require manual curation for complex cases.
        
    -   Run this binary as part of CI or a scheduled GitHub Action, committing updates to the repository.
        
-   **Crates:**
    
    -   `reqwest` for HTTP requests.
        
    -   `serde` and `serde_json` for parsing CVE feeds.
        
    -   `regex` for searching keywords.
        

---

## 5 Correlation with JavaScript and Remote Actions

### 5.1 JavaScript correlation

-   **Task:** Combine font findings with JavaScript analysis results to increase confidence.
    
-   **Approach:**
    
    -   Use an internal `analysis_context` object that aggregates findings from multiple detectors (fonts, JavaScript, encryption). When the font analyser emits a high‑risk finding and the JavaScript analyser flags suspicious code (e.g., heap spray, obfuscated shellcode), produce a composite finding `pdf.font_js_correlation` with severity escalated.
        
    -   Implement a simple rule engine that triggers correlation findings based on combinations of conditions.
        
-   **Crates:**
    
    -   existing `sis-pdf` code; may not require new crates.
        
    -   `indexmap` or `dashmap` for efficient context storage.
        

### 5.2 Remote font linking and external references

-   **Task:** Detect fonts referenced via remote URIs or external actions.
    
-   **Approach:**
    
    -   Enhance the PDF parser to inspect dictionary entries for keys like `/GoToR`, `/URI`, `/Launch`, and `/F` in `FileSpecification`. When a font reference uses an external file (e.g., `/FS /URL`), flag it as `font.external_reference`.
        
    -   Examine `FontDescriptor` and `CIDFont` dictionaries; if `/FontFile` is missing but `/FontFile2` or `/FontFile3` points to a remote object, flag it.
        
    -   Provide an option to fetch the remote resource (if network access is enabled) and scan it as well, but by default mark the PDF as high risk.
        
-   **Crates:**
    
    -   The existing PDF parser (likely `pdf-parser` crate) or `lopdf`/`pdf` crate to parse dictionaries.
        
    -   `url` to validate URIs.
        
    -   `serde` to handle PDF objects if using a custom parser.
        

---

## 6 Support Emerging Font Formats

### 6.1 Variable fonts and color fonts

-   **Task:** Extend the static and dynamic analysis to handle variable and color font tables.
    
-   **Approach:**
    
    -   Use `ttf-parser` or `allsorts` to parse `avar`, `gvar`, `HVAR`, `MVAR`, `COLR`, and `CPAL` tables. For each table:
        
        -   Validate header lengths and offsets.
            
        -   Ensure that indices are within range of glyph counts.
            
        -   Check that color palettes and layers are consistent.
            
    -   Implement heuristics to detect anomalous sizes (e.g., excessively large `gvar` data) and invalid variation axes values.
        
    -   Add new findings such as `font.anomalous_variation_table` or `font.color_table_inconsistent`.
        
-   **Crates:**
    
    -   `ttf-parser` version ≥ 0.15 (variable font support).
        
    -   `allsorts` for color font tables.
        

### 6.2 WOFF/WOFF2 support

-   **Task:** Add detection for Web Open Font Format.
    
-   **Approach:**
    
    -   Use `allsorts` to parse WOFF and WOFF2; decompress and convert them to SFNT representation before analysis.
        
    -   Check for known vulnerabilities in decompressors (e.g., integer overflows in bounding calculations).
        

---

## 7 Instrumented Dynamic Analysis

### 7.1 Integrate instrumentation hooks

-   **Task:** Instrument memory accesses and control flow during dynamic analysis.
    
-   **Approach:**
    
    -   For custom interpreters (Type 1 or TrueType VM), implement hooks that log each operation, memory read/write and control transfer. Provide optional per‑instruction callbacks allowing external monitoring.
        
    -   Use `tracing` crate to emit events; integrate with `tokio-tracing-console` for debugging.
        
    -   If integrating with memory‑unsafe parsers (e.g., `FreeType` via FFI for extended coverage), wrap them in `mprotect`/`guarded_alloc` to detect buffer overflows. However, to satisfy “Rust‑native only”, prefer using safe crates and instrumenting them.
        
-   **Crates:**
    
    -   `tracing` and `tracing-subscriber` for instrumentation.
        
    -   `mimallo` or `jemallocator` if customizing allocators for instrumentation.
        

### 7.2 Timeouts and budgets

-   **Task:** Prevent denial‑of‑service by bounding analysis time.
    
-   **Approach:**
    
    -   Pass a `deadline: Instant` or `instruction_budget: u64` to analysis functions. Use `tokio::time::timeout` or periodic checks to abort analysis when limits are reached.
        
    -   Emit `font.dynamic_timeout` finding when aborting due to time/budget.
        
-   **Crates:**
    
    -   `tokio` for async timeouts.
        

---

## 8 Memory‑Safe Parser Selection

### 8.1 Default to Skrifa when possible

-   **Task:** Use `skriva` (Rust port of Skia’s font parsing) as the default parser.
    
-   **Approach:**
    
    -   Replace any dependency on C libraries with `skriva` or `ttf-parser`/`allsorts`. Provide fallbacks if a font feature is unsupported by these crates.
        
    -   Expose a configuration option allowing users to choose between parsers.
        
-   **Crates:**
    
    -   `skriva` (if published on crates.io) or `fontations/read-fonts`.
        
    -   `thiserror` for unified error types.
        

### 8.2 Sandboxing and optional FFI

-   **Task:** Provide optional FFI to FreeType for extended coverage while isolating it via sandboxing.
    
-   **Approach:**
    
    -   Use `rustix` and `seccomp` crates to create a restricted process or thread for FFI calls. This can be conditionally compiled behind a `freetype` feature flag. Capture any segmentation faults or illegal memory accesses and translate them into findings.
        

---

## 9 Correlation and Machine‑Learning‑Based Risk Scoring

### 9.1 Scoring model

-   **Task:** Develop a scoring algorithm that weights findings from various detectors.
    
-   **Approach:**
    
    -   Define a `RiskScore` struct containing factors such as number of high‑severity findings, presence of remote links, dynamic failures, etc. Use a simple weighted sum for initial implementation.
        
    -   Consider training a model (e.g., logistic regression or gradient boosting) using `linfa` or `lightgbm-rs` on labelled benign/malicious samples. Extract features from font metadata (entropy, table counts, instruction counts) and PDF context (JavaScript presence, encryption). The model could produce a probability of maliciousness.
        
-   **Crates:**
    
    -   `linfa` or `smartcore` for basic ML algorithms.
        
    -   `ndarray` for feature matrices.
        

### 9.2 Feature extraction

-   **Task:** Collect features during analysis.
    
-   **Approach:**
    
    -   Add a feature collector that records metrics such as average glyph instruction count, maximum stack depth, table entropy, number of tables, existence of external references, etc.
        
    -   Serialize features into a vector and feed into the model.
        

---

## 10 User‑Configurable Thresholds and Context Awareness

### 10.1 Configuration system

-   **Task:** Allow tuning of detection thresholds based on deployment context.
    
-   **Approach:**
    
    -   Define a `FontAnalysisConfig` struct with fields like `max_charstring_ops`, `max_stack_depth`, `max_tables`, `enable_dynamic_analysis`, and `network_access`. Provide `Default` implementation with conservative values.
        
    -   Load configuration from a TOML or JSON file using `serde` or allow overriding via command‑line flags.
        
    -   Pass `FontAnalysisConfig` through the detection pipeline so each module can adjust behaviour accordingly.
        
-   **Crates:**
    
    -   `config` or `serde` + `serde_derive` for configuration parsing.
        

### 10.2 Context awareness

-   **Task:** Adjust severity based on environment (e.g., server vs desktop).
    
-   **Approach:**
    
    -   Add a `Context` enum (e.g., `Server`, `Desktop`, `CI`) to the config. Implement logic that reduces severity for fonts loaded from trusted sources or signed PDFs, and increases severity for untrusted inputs.
        

---

## 11 Regular Updates and Community Sharing

### 11.1 CI integration

-   **Task:** Integrate update and fuzz testing into continuous integration.
    
-   **Approach:**
    
    -   Add GitHub Actions workflows to run unit tests, fuzzers (with `cargo afl` time‑limited runs), and the CVE update script.
        
    -   When new signatures are generated, open automated pull requests for review.
        

### 11.2 Documentation and examples

-   **Task:** Document new modules and provide usage examples.
    
-   **Approach:**
    
    -   Update `docs/findings.md` with new finding IDs and descriptions.
        
    -   Provide example binaries under `examples/` demonstrating how to call the font analysis functions and interpret results.
        
    -   Write blog posts or internal guides describing how to contribute signatures.
        

---

## Summary

This plan outlines a comprehensive implementation strategy for enhancing `sis‑pdf`’s font detection and scanning capabilities using **Rust‑native crates**. The work includes adding Type 1 font analysis, integrating sanitizers and dynamic parsers, building signature‑based detection, supporting emerging formats, detecting remote font linking, implementing fuzzing and instrumentation, and creating configurable, context‑aware scoring. These improvements will equip the system to detect known and emerging vulnerabilities, including those like the BLEND exploit and recent variable‑font bugs, while remaining maintainable and secure.

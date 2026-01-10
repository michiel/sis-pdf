# Robustness Review and Validation Plan

**Date**: 2026-01-09  
**Status**: Draft  
**Scope**: Detection coverage, finding completeness, data provenance, feature prevalence, parser robustness

## Open Questions (Expanded)

### 1) Are detections robust?
- Do detectors consistently trigger on known malicious constructs across a diverse corpus?
- Are the results stable across parser modes (`--deep`, `--strict`, `--diff-parser`)?
- Are there detectors that frequently misfire on benign PDFs?
- Are any detectors overly sensitive to metadata variability or parsing quirks?

### 2) Are possible findings complete?
- Do we cover all relevant PDF attack surfaces (actions, JS, forms, embedded files, streams/filters, crypto, content, structure)?
- Do findings map to current threat patterns documented in `docs/js-detection-*.md`?
- Are there missing findings for emerging or evasion techniques?

### 3) Do we have enough detections and possible findings?
- Is the detection surface broad enough for operational triage?
- Do we have sufficient granularity to distinguish high‑risk from low‑risk cases?
- Are there blind spots where we have only a single heuristic?

### 4) Are there gaps?
- Are there systematic false negatives (e.g., obfuscated JS, encrypted content, encoded streams)?
- Are there gaps in cross‑surface correlation (e.g., action chains with JS/URI pivot)?
- Are there gaps in evidence capture (offsets, decoded spans)?

### 5) Sample data provenance and correctness
- Are “benign” samples actually benign?
- Are “malicious” samples actually malicious?
- Is the corpus class‑balanced, or skewed toward a specific family or campaign?
- Do we have temporal drift in the sample set (old malware vs modern files)?

### 6) Feature prevalence
- Do key ML signals appear sufficiently across the corpus?
- Are large feature groups mostly zero?
- Are there features that never appear (dead signals)?

### 7) Parser and detector robustness against sample data
- Do any samples crash the parser or exhaust budgets?
- Do detectors behave predictably under strict parsing or deep decoding?
- Are findings consistent across parser modes?

## Plan to Answer Using `sis`

### Phase 1: Corpus Baseline and Provenance
**Goal**: Establish data quality and provenance indicators.

Steps:
1. **Scan all samples with JSONL output**:
   ```
   sis scan --path /corpus --glob "*.pdf" --jsonl-findings > corpus.findings.jsonl
   ```
2. **Collect structural summaries** (size, object counts, trailers, incremental updates):
   ```
   sis scan --path /corpus --glob "*.pdf" --jsonl-findings --strict > corpus.strict.jsonl
   ```
3. **Extract intent and action chains** for suspicious behaviour:
   ```
   sis scan --path /corpus --glob "*.pdf" --export-intents --export-intents-out intents.jsonl
   ```

Outputs:
- `corpus.findings.jsonl`: detector‑level events
- `corpus.strict.jsonl`: strict parser deviations for robustness
- `intents.jsonl`: network intents for provenance hints
- If the corpus files do not use `.pdf` extensions, replace `--glob "*.pdf"` with `--glob "*"` to match hashed filenames.

### Phase 2: Detection Robustness and Mode Sensitivity
**Goal**: Compare findings across scan modes to quantify stability.

Steps:
1. **Standard scan**:
   ```
   sis scan --path /corpus --glob "*.pdf" --jsonl-findings > findings.standard.jsonl
   ```
2. **Deep scan**:
   ```
   sis scan --path /corpus --glob "*.pdf" --deep --jsonl-findings > findings.deep.jsonl
   ```
3. **Strict + diff parser**:
   ```
   sis scan --path /corpus --glob "*.pdf" --strict --diff-parser --jsonl-findings > findings.strict.jsonl
   ```

Analysis:
- Compare per‑file findings between modes.
- Flag detectors that are highly unstable or overly sensitive.

### Phase 3: Feature Prevalence and Gaps
**Goal**: Determine whether ML features are informative or mostly zero.

Steps:
1. **Extract extended features**:
   ```
   sis export-features --path /corpus --glob "*.pdf" --format jsonl --feature-names -o features.jsonl
   ```
2. **Compute feature prevalence** (counts of non‑zero per feature).
3. **Identify dead or near‑zero features** and correlate with detector metadata.

Outputs:
- Feature coverage report (non‑zero counts per feature)
- List of underutilised signals and missing metadata inputs

### Phase 4: Robustness Against Sample Data
**Goal**: Identify parser failures and detector brittleness.

Steps:
1. **Record errors**:
   - Extract any `ml_model_error`, `strict_parse_deviation`, or parser errors.
2. **Correlate failures to file sizes and structures**:
   - Large file thresholds, objstm density, deep stream decoding.
3. **Surface high‑risk anomalies**:
   - `xref_conflict`, `incremental_update_chain`, `stream_length_mismatch`, etc.

Outputs:
- Parser error rate per mode
- Detector error rate per surface

### Phase 5: Corpus Classification Sanity
**Goal**: Validate labels when provenance is unknown.

Steps:
1. **Manual spot checks**:
   - Sample top “benign” files with high‑severity findings.
   - Sample “malicious” files with few findings.
2. **Heuristic consistency checks**:
   - Presence of JS, embedded files, or suspicious URI patterns in “benign” files.
3. **External analysis** (if allowed):
   - Hash comparison against known malware feeds (if policy allows).

Outputs:
- Mislabel suspect list
- Provenance confidence score per file (optional)

## Recommendations (Initial)

### Detection Coverage
- Add or refine detectors for:
  - Obfuscated action chains that pivot across object streams
  - Cross‑surface correlation (Action + JS + URI in same chain)
  - Incremental update abuse patterns (changes introduced late in file)

### Feature Instrumentation
- Ensure metadata keys used in feature extraction are emitted consistently.
- Add counters for detector usage frequency to detect dead signals.

### Parser Robustness
- Track parser failure rate and add explicit findings for decode budget exhaustion.
- Add “fallback path” markers when recovery parsing is used.

### Reporting Improvements
- Add summary tables for “mode differences” (standard vs deep vs strict).
- Add a top‑N list of detectors with highest false positives (benign corpus).

## Deliverables

- Robustness report (CSV or Markdown) with:
  - Detector stability metrics
  - Feature prevalence distribution
  - Parser failure rates
  - Suspect mislabels
- Recommendations list for new detectors or refinements
- Update `docs/` or `plans/` with findings

# sis-pdf Usage

This guide shows end-to-end workflows with concrete commands and suggested analysis steps. All commands assume you run the `sis` binary in your executable path.

## 1) Triage scan (fast, default)

Use this for first-pass analysis when you need a quick answer.

```
sis scan suspicious.pdf
```

For a stricter fast path:

```
sis scan suspicious.pdf --fast
```

Suggested steps:
- Review grouped findings by attack surface (Actions, JavaScript, EmbeddedFiles, StreamsAndFilters).
- Note high-severity findings first (JavaScript, embedded files, decoder-risk filters).
- If you see only structural issues (xref conflicts, object shadowing), plan a deep scan.

## 2) JSON report for automation

```
sis scan suspicious.pdf --json > report.json
```

JSONL (stream-friendly):

```
sis scan suspicious.pdf --jsonl > report.jsonl
```

Notes:
- JSONL output emits one record per finding plus an optional `ml_inference` record if ML inference is requested.
- Use `--jsonl-findings` to emit findings with the input path attached (useful for batch scans).

Export network intents for correlation:

```
sis scan suspicious.pdf --export-intents --export-intents-out intents.jsonl
```

Include derived intents (domains and obfuscated URLs):

```
sis scan suspicious.pdf --export-intents --intents-derived --export-intents-out intents.jsonl
```

SARIF (CI integration):

```
sis scan suspicious.pdf --sarif > report.sarif
```

SARIF to file:

```
sis scan suspicious.pdf --sarif-out report.sarif
```

Analysis steps:
- Parse `summary` for high/medium counts.
- Use `grouped` to drive dashboards or alerting.
- Use `findings[*].evidence` to link to raw offsets or decoded offsets.

## 3) Deep scan for decoding risk

```
sis scan suspicious.pdf --deep
```

Focused scan for a specific trigger:

```
sis scan suspicious.pdf --focus-trigger openaction
```

Limit reachability to a smaller graph radius:

```
sis scan suspicious.pdf --focus-trigger openaction --focus-depth 3
```

Strict parsing (record lexer-level deviations):

```
sis scan suspicious.pdf --strict
```

Strict parsing with deviation summary (reduces per‑deviation output in batch runs):

```
sis scan suspicious.pdf --strict --strict-summary
```

When to use deep scan:
- You have `StreamsAndFilters` findings and need to measure decode ratios.
- You suspect embedded JavaScript or embedded files hidden behind filters.
- You see `/ObjStm` density warnings or incremental updates.

## 3b) Logging and tracing

`sis` emits structured tracing logs to STDERR so report output on STDOUT stays clean.

Enable verbose logging for loop investigations:

```
RUST_LOG=trace sis scan suspicious.pdf
```

Scope logging to specific crates:

```
RUST_LOG=sis_pdf=debug,sis_pdf_core=trace,sis_pdf_pdf=trace sis scan suspicious.pdf
```

## 3c) Configuration (TOML)

By default, `sis` looks for a config file at:
- Linux: `~/.config/sis/config.toml`
- macOS: `~/.config/sis/config.toml`
- Windows: `%APPDATA%\\sis\\config.toml`

Override the config path:

```
sis scan suspicious.pdf --config /path/to/config.toml
```

See `docs/config.toml` for a starter configuration.

Create a default config:

```
sis config init
```

Verify a config:

```
sis config verify
```

## 4) Explain a specific finding

First, run a scan to get an ID, then:

```
sis explain suspicious.pdf sis-<finding-id>
```

## 4b) Generate a full Markdown report

```
sis report suspicious.pdf
```

Write to a file:

```
sis report suspicious.pdf -o report.md
```

Analysis steps:
- Use evidence source to decide if you need to inspect raw bytes or decoded output.
- For file-backed evidence, offsets are absolute in the original PDF.
- For decoded evidence, consult `origin` spans to map back to raw stream bytes.

## 4c) ML inference and explanations

Run ML inference with a trained model:

```
sis scan suspicious.pdf --ml-model-dir models/ --ml-extended-features
```

Run ML inference with explanations (requires a benign baseline):

```
sis scan suspicious.pdf --ml-model-dir models/ --ml-extended-features --ml-explain --ml-baseline models/benign_baseline.json
```

Include advanced explainability (counterfactuals and interactions):

```
sis scan suspicious.pdf --ml-model-dir models/ --ml-extended-features --ml-explain --ml-advanced --ml-baseline models/benign_baseline.json
```

Include calibration if available:

```
sis scan suspicious.pdf --ml-model-dir models/ --ml-extended-features --ml-explain --ml-baseline models/benign_baseline.json --ml-calibration models/calibration.json
```

Generate a Markdown report with ML inference:

```
sis report suspicious.pdf --ml-model-dir models/ --ml-extended-features --ml-explain --ml-baseline models/benign_baseline.json
```

ML runtime health check (execution providers and model load):

```
sis ml health --ml-model-dir models/
```

Detect ML runtime capabilities and provider recommendations:

```
sis ml detect
sis ml detect --format json
```

Download the ONNX Runtime dynamic library for this host:

```
sis ml ort download --write-config
```

Checksum verification is automatic:
- Embedded checksums for known versions are used when available
- If no checksum is available, the tool will compute the SHA256, display it, and prompt for confirmation
- You can override with manual checksum verification:

```
sis ml ort download --checksum-url https://mirror.example/onnxruntime-linux-x64-rocm-1.17.3.tgz.sha256
sis ml ort download --checksum-file /path/to/onnxruntime.sha256
sis ml ort download --checksum-sha256 <sha256>
```

Auto-configure ML runtime settings:

```
sis ml autoconfig
sis ml autoconfig --dry-run
```

Print selected execution provider:

```
sis scan suspicious.pdf --ml-model-dir models/ --ml-extended-features --ml-provider-info
```

Point to a custom ONNX Runtime dynamic library:

```
sis scan suspicious.pdf --ml-model-dir models/ --ml-extended-features --ml-ort-dylib /path/to/onnxruntime.dll
```

## 5) Extract JavaScript payloads

```
mkdir -p out/js
sis extract js suspicious.pdf -o out/js
```

Analysis steps:
- Review extracted JS files for obfuscation patterns and network calls.
- Correlate JS filenames to object IDs from findings.
- If JS extraction yields nothing but JS findings exist, the payload may be a ref or in a filtered stream. Use deep scan and inspect the referenced objects.

## 6) Extract embedded files

```
mkdir -p out/embedded
sis extract embedded suspicious.pdf -o out/embedded
```

Analysis steps:
- Hash extracted files and submit to internal malware pipeline.
- Inspect file headers for PE/ELF/Mach-O signatures.
- Map embedded file object IDs back to findings for provenance.

## 7) Detect files with specific findings

Use `detect` to find files that contain all specified findings. This is useful for filtering large corpora:

```
sis detect --path /path/to/pdfs --findings js_present,open_action_present
```

With custom glob pattern:

```
sis detect --path /path/to/pdfs --glob "*.pdf" --findings js_present
```

Multiple findings (ALL required):

```
sis detect --path samples/ --findings js_present,uri_present,embedded_file_present
```

Sequential processing (no parallelism):

```
sis detect --path samples/ --findings js_present --sequential
```

Analysis workflow:
- Use comma-separated finding IDs (no spaces): `--findings id1,id2,id3`
- Output is one filename per line (easy to pipe to other tools)
- Only files with ALL specified findings are returned
- Files that fail to scan are silently skipped
- Parallel processing is enabled by default for performance

Example pipeline:

```bash
# Find PDFs with JavaScript and OpenAction
sis detect --path samples/ --findings js_present,open_action_present > matches.txt

# Scan each match in detail
while read pdf; do
  sis scan "$pdf" --deep --json >> detailed_results.jsonl
done < matches.txt
```

Use cases:
- Filter malware corpus to specific threat patterns
- Find files requiring manual review
- Automated triage in CI/CD pipelines
- Rapid corpus classification

## 8) Structural evasions (incremental updates)

If you see `xref_conflict` or `incremental_update_chain`:

1) Run `--deep` to gather additional decoder findings.
2) Use `explain` on shadowed object findings to locate offsets.
3) Compare object spans across revisions (same object ID, different spans).

If you want a parser-differential view:

```
sis scan suspicious.pdf --diff-parser
```

Notes:
- Differential parsing uses `lopdf` as a secondary parser.
- Use this when you suspect parser differentials or malformed structures.

## 9) Decoder-risk triage

If you see `decoder_risk_present` or `decompression_ratio_suspicious`:

1) Identify filters (JBIG2/JPX are high risk).
2) Inspect stream span offsets to verify size and filter chain.
3) If needed, extract embedded content to a quarantine directory.

## 10) Phishing-content heuristic workflow

If you see `content_phishing`:

1) Inspect URIs for non-corporate or recently-registered domains.
2) Review page content for full-page images and overlay links.
3) Cross-reference with JS and Actions findings for behaviour.

## 11) Building a minimal synthetic fixture

This is useful for smoke tests or training.

```
cat > tmp/synthetic.pdf <<'PDF'
%PDF-1.4
1 0 obj
<< /Type /Catalog /OpenAction 2 0 R >>
endobj
2 0 obj
<< /S /JavaScript /JS (app.alert('hi')) >>
endobj
3 0 obj
<< /Type /Pages /Count 1 /Kids [4 0 R] >>
endobj
4 0 obj
<< /Type /Page /Parent 3 0 R /MediaBox [0 0 300 200] >>
endobj
xref
0 5
0000000000 65535 f 
0000000010 00000 n 
0000000062 00000 n 
0000000125 00000 n 
0000000178 00000 n 
trailer
<< /Root 1 0 R /Size 5 >>
startxref
240
%%EOF
PDF
```

Then run:

```
sis scan tmp/synthetic.pdf
```

Expected result:
- `open_action_present`
- `js_present`

## 11) Operational guidance

- Keep `--deep` scans for targeted cases; triage scans should be fast.
- Never execute extracted payloads; treat everything as untrusted.
- For long-running analyses, prefer JSON output and post-process in separate tools.

Batch scans across a directory:

```
sis scan --path samples --glob \"*.pdf\"
```

Batch scan JSON summary:

```
sis scan --path samples --glob \"*.pdf\" --json
```

Configuration-based scans:

```
sis scan suspicious.pdf --config config.yml --profile interactive
```

Example config for focus depth and strict mode:

```
cat > config.yml <<'YAML'
scan:
  strict: true
  focus_depth: 3
profiles:
  interactive:
    scan:
      deep: true
      diff_parser: true
YAML
```

Then run:

```
sis scan suspicious.pdf --config config.yml --profile interactive
```

YARA export (stdout or file):

```
sis scan suspicious.pdf --yara
sis scan suspicious.pdf --yara-out rules.yar
```

YARA scope (all/medium/high):

```
sis scan suspicious.pdf --yara --yara-scope all
```

JavaScript AST summaries (feature build):

```
cargo run -p sis-pdf --features js-ast --bin sis -- scan suspicious.pdf
```

Optional JavaScript sandbox execution (feature build):

```
cargo run -p sis-pdf --features js-sandbox --bin sis -- scan suspicious.pdf --deep
```

Report example with strict parsing and differential parsing:

```
sis report suspicious.pdf --strict --diff-parser -o report.md
```

## 12) ML classification

Enable the stacking classifier (requires a model JSON file or directory).

```
sis scan suspicious.pdf --ml --ml-model-dir models --ml-threshold 0.9
```

Notes:
- `--ml-model-dir` can point to a directory containing `stacking.json`, `model.json`, or `ml.json`.
- The ML score adds a `ml_malware_score_high` finding when it exceeds the threshold.
- Adversarial checks add `ml_adversarial_suspected` when feature profiles look manipulated.

Graph ML mode (PDFObj IR + ORG + GNN, feature build):

```
cargo run -p sis-pdf --features ml-graph --bin sis -- scan suspicious.pdf --ml --ml-mode graph --ml-model-dir models
```

Notes:
- Graph ML expects `graph_model.json` in the model directory.
- Graph ML emits `ml_graph_score_high` when it exceeds the threshold.
- Graph ML schema reference: `docs/graph-model-schema.md`.

## 12b) IR/ORG static analysis (no ML)

Enable IR extraction and static IR/ORG detectors:

```
sis scan suspicious.pdf --ir
```

Include IR/ORG summary in a report:

```
sis report suspicious.pdf --ir -o report.md
```

Static IR/ORG finding kinds:
- `action_payload_path`
- `orphan_payload_object`
- `shadow_payload_chain`
- `objstm_action_chain`

## 12c) Export object reference graph (ORG)

**By default, ORG exports include suspicious paths and classifications (enhanced mode).**

DOT export with paths:

```
sis export-org suspicious.pdf --format dot -o org.dot
```

JSON export with paths and risk analysis:

```
sis export-org suspicious.pdf --format json -o org.json
```

Basic graph only (no enhancements):

```
sis export-org suspicious.pdf --basic --format json -o org_basic.json
```

## 12d) Export PDFObj IR

**By default, IR exports include findings and risk scores (enhanced mode).**

Text export with findings:

```
sis export-ir suspicious.pdf --format text -o ir.txt
```

JSON export with findings and risk analysis:

```
sis export-ir suspicious.pdf --format json -o ir.json
```

Basic IR only (no findings):

```
sis export-ir suspicious.pdf --basic --format text -o ir_basic.txt
```

## 13) Export features for datasets

**By default, feature export generates the extended 333-feature vector.**

JSONL feature export (333 features):

```
sis export-features --path samples --glob "*.pdf" --format jsonl -o features.jsonl
```

Include feature names in each JSONL record:

```
sis export-features --path samples --glob "*.pdf" --format jsonl --feature-names -o features.jsonl
```

CSV feature export (333 features):

```
sis export-features --path samples --glob "*.pdf" --format csv -o features.csv
```

Basic features only (35 features, legacy mode):

```
sis export-features --path samples --glob "*.pdf" --basic --format jsonl -o features_basic.jsonl
```

### Extended Feature Vector (333 Features)

The extended feature extractor generates **333 features** for ML training pipelines:

**Legacy features (35):** General, Structural, Behavioral, Content, Graph
**Attack surface distribution (12):** Counts per surface (JavaScript, Actions, etc.)
**Severity distribution (15):** Critical/High/Medium/Low counts with confidence weights
**Confidence distribution (9):** Strong/Probable/Heuristic per severity level
**Finding presence/counts (142):** Binary flags + count for each finding type (71 × 2)
**JS signals (30):** Obfuscation, eval, string operations, API usage
**URI signals (20):** IP addresses, obfuscation, automatic triggers, JS-triggered
**Content signals (15):** Overlays, full-page images, forms, phishing indicators
**Supply chain signals (10):** Staged payloads, update vectors, persistence
**Structural anomaly signals (20):** Xref conflicts, shadowing, objstm depth
**Crypto signals (10):** Weak algorithms, certificate anomalies, mining patterns
**Embedded content signals (15):** Executable embedding, nested archives, auto-launch

See `docs/training-pipeline.md` for ML training workflow.

## 13b) ML Training Pipeline

### Compute Benign Baseline

After extracting features from benign samples, compute a statistical baseline:

```
sis compute-baseline --input benign_features.jsonl --out baseline.json
```

The baseline includes feature means, standard deviations, and percentiles for:
- Feature normalization
- Anomaly detection (values beyond p99 are suspicious)
- Explainability (show deviation from benign baseline)

### Complete Training Pipeline

Use the automated pipeline script to extract features, compute baseline, train model, and fit calibration:

```bash
python scripts/training_pipeline.py \
    --benign-dir /path/to/benign/pdfs \
    --malicious-dir /path/to/malicious/pdfs \
    --output-dir models \
    --sis-binary ./target/release/sis \
    --calibration-method platt
```

**Pipeline outputs:**
- `models/model.json`: Trained logistic regression model
- `models/baseline.json`: Benign feature baseline
- `models/calibration.json`: Platt scaling or isotonic regression calibration
- `models/metrics.json`: Test set evaluation metrics

### Model Calibration

Calibrate raw model scores to well-calibrated probabilities:

```bash
# Fit calibration from validation predictions
python scripts/calibrate.py \
    --predictions validation_predictions.jsonl \
    --method platt \
    --output calibration.json \
    --evaluate

# Apply calibration to new predictions
python scripts/apply_calibration.py \
    --calibration calibration.json \
    --predictions raw_predictions.jsonl \
    --output calibrated_predictions.jsonl
```

**Calibration methods:**
- `platt`: Logistic regression on predictions (recommended, works with 100-1000 samples)
- `isotonic`: Non-parametric monotonic mapping (requires 1000+ samples)

See `docs/training-pipeline.md` for comprehensive ML training documentation.

## 14) Advanced detectors (supply chain, crypto, multi-stage, quantum)

These detectors run automatically during `sis scan` and surface the following finding kinds:
- `supply_chain_staged_payload`, `supply_chain_update_vector`, `supply_chain_persistence`
- `crypto_weak_algo`, `crypto_cert_anomaly`, `crypto_mining_js`
- `multi_stage_attack_chain`
- `quantum_vulnerable_crypto`

Example triage:

```
sis scan suspicious.pdf --json
```

## 15) Stream analysis (CLI)

```
sis stream-analyze suspicious.pdf --chunk-size 65536 --max-buffer 262144
```

## 16) Campaign correlation (CLI)

Generate intent JSONL from scans:

```
sis scan --path samples --glob "*.pdf" --export-intents --export-intents-out intents.jsonl
```

Provide JSONL with fields `path` and `url`:

```
cat > intents.jsonl <<'JSONL'
{"path":"sample_a.pdf","url":"http://example.com/c2"}
{"path":"sample_b.pdf","url":"http://example.com/c2"}
JSONL

sis campaign-correlate --input intents.jsonl -o campaigns.json
```

## 17) Response generation (CLI)

```
sis response-generate --kind js_present -o response_rules.yar
```

From an existing JSON report:

```
sis scan suspicious.pdf --json > report.json
sis response-generate --from-report report.json -o response_rules.yar
```

## 18) Mutation testing (CLI)

```
sis mutate suspicious.pdf -o tmp/mutants
```

Scan mutants and summarize detection deltas:

```
sis mutate suspicious.pdf -o tmp/mutants --scan
```

## 19) Red-team simulation (CLI)

```
sis red-team --target js_present -o tmp/redteam.pdf
```

## 20) Stream analysis (library API)

The stream analyzer is a library helper for gateway-style streaming inspection.

```rust
use sis_pdf_core::stream_analyzer::StreamAnalyzer;

let mut analyzer = StreamAnalyzer::new(64 * 1024);
for chunk in pdf_chunks {
    let state = analyzer.analyze_chunk(chunk);
    if let Some(threat) = analyzer.early_terminate(&state) {
        println!("early terminate: {} {}", threat.kind, threat.reason);
        break;
    }
}
```

## 21) Campaign correlation (library API)

```rust
use sis_pdf_core::campaign::{extract_domain, MultiStageCorrelator, NetworkIntent, PDFAnalysis};

let analyses = vec![
    PDFAnalysis {
        id: "a".into(),
        path: Some("sample_a.pdf".into()),
        network_intents: vec![NetworkIntent {
            url: "http://example.com/c2".into(),
            domain: extract_domain("http://example.com/c2"),
        }],
    },
];
let correlator = MultiStageCorrelator;
let campaigns = correlator.correlate_campaign(&analyses);
```

## 22) Automated response generation (library API)

```rust
use sis_pdf_core::behavior::ThreatPattern;
use sis_pdf_core::response::ResponseGenerator;

let pattern = ThreatPattern {
    id: "kind:js_present".into(),
    kinds: vec!["js_present".into()],
    objects: vec!["2 0 obj".into()],
    severity: sis_pdf_core::model::Severity::Medium,
    summary: "JS present".into(),
};
let generator = ResponseGenerator;
let yara_rules = generator.generate_yara_variants(&pattern);
```

## 23) Mutation testing and red-team simulation (library API)

```rust
use sis_pdf_core::mutation::MutationTester;
use sis_pdf_core::redteam::{DetectorProfile, RedTeamSimulator};

let tester = MutationTester;
let mutants = tester.mutate_malware(pdf_bytes);

let simulator = RedTeamSimulator;
let evasive = simulator.generate_evasive_pdf(&DetectorProfile { target: "js_present".into() });
```

## 24) Troubleshooting

- If `scan` misses objects, try `--deep` and check for `/ObjStm` usage.
- If findings have no evidence spans, the detector may not yet attach spans for that rule.
- If decoding fails, the stream may be malformed or use unsupported filters.

## 25) Notes on evidence spans

- `source=File` offsets are absolute in the original PDF.
- `source=Decoded` offsets refer to decoded buffers and should include `origin` spans when available.
- Use `origin` spans to map decoded evidence back to raw stream data for forensic traceability.

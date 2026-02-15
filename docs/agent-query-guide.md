# Agent Query Guide

This guide is for analysts using `sis query` to investigate suspicious PDFs with reproducible, command-first workflows.

## Objectives
1. Confirm whether a PDF is malicious by tracing triggers, payloads, and outcomes.
2. Prioritise by severity/impact and correlate related findings.
3. Capture reproducible evidence (finding IDs, object refs, offsets, stream artefacts).

## Core workflow
1. Baseline triage: `sis scan sample.pdf`
2. Deep scan for evasive/encoded content: `sis scan sample.pdf --deep`
3. Interactive investigation: `sis query sample.pdf`
4. One-shot automation and export: `sis query sample.pdf <query> --format json`

## Command shape (important)
Use this order:

```bash
sis query <file.pdf> <query> [options]
```

Examples:

```bash
sis query sample.pdf findings
sis query sample.pdf actions
sis query sample.pdf xref.sections
```

## High-value one-shot queries

```bash
# Findings triage
sis query sample.pdf findings
sis query sample.pdf findings --where "severity == 'High'" --format json

# Action and JS surfaces
sis query sample.pdf actions.chains --where "depth >= 2"
sis query sample.pdf js.count

# URL and embedded payload surfaces
sis query sample.pdf urls --where "suspicious == true"
sis query sample.pdf embedded.executables

# Structural state
sis query sample.pdf xref
sis query sample.pdf xref.startxrefs
sis query sample.pdf xref.sections
sis query sample.pdf xref.deviations
sis query sample.pdf revisions
sis query sample.pdf revisions.detail
```

## Stream and artefact extraction

```bash
# Preview stream details
sis query sample.pdf stream 8 0

# Write raw stream bytes
sis query sample.pdf stream 8 0 --raw --extract-to /tmp/streams

# Write decoded stream bytes
sis query sample.pdf stream 8 0 --decode --extract-to /tmp/streams

# Hexdump view
sis query sample.pdf stream 8 0 --hexdump
```

Use only one of `--raw`, `--decode`, or `--hexdump` per invocation.

## REPL workflow

Start REPL:

```bash
sis query sample.pdf
```

Useful REPL commands:

```text
sis> findings
sis> cache.info
sis> :where severity == 'High'
sis> findings
sis> cache.info
sis> :where kind contains 'xref'
sis> xref.sections
sis> :json
sis> correlations | jq .
sis> :readable
sis> org > graph.dot
```

`cache.info` reports REPL findings-cache state for the current session. The cache is populated after the first findings-family query and reused for subsequent findings-family queries in that same REPL session.

## Recent query extensions and refinements (last two weeks)

### 1) First-class xref and revision queries
Use these when investigating trailer/xref anomalies:

```bash
sis query sample.pdf xref
sis query sample.pdf xref.startxrefs
sis query sample.pdf xref.sections --where "kind == 'stream'"
sis query sample.pdf xref.trailers
sis query sample.pdf xref.deviations
sis query sample.pdf revisions
sis query sample.pdf revisions.detail --where "anomaly_score >= 4"
```

Typical use: validate whether a warning is benign incremental history or suspicious chain inconsistency.

### 2) Composite finding shortcuts
Stage-9 correlated findings are available directly:

```bash
sis query sample.pdf findings.composite
sis query sample.pdf findings.composite.count
sis query sample.pdf findings.composite --where "kind == 'launch_obfuscated_executable'"
```

### 3) Correlation exports for dashboards

```bash
sis query sample.pdf correlations
sis query sample.pdf correlations.count
sis query sample.pdf correlations --format json
sis query sample.pdf correlations --format jsonl
```

### 4) Action-chain summaries and filtering

```bash
sis query sample.pdf actions.chains
sis query sample.pdf actions.chains --where "has_js == true"
sis query sample.pdf actions.chains --where "depth >= 3"
sis query sample.pdf actions.chains --chain-summary minimal
sis query sample.pdf actions.chains --chain-summary events
sis query sample.pdf actions.chains --chain-summary full
```

### 5) Findings output summary block (JSON/YAML/JSONL)
`findings` output now includes a top-level summary (`findings_by_severity`, `findings_by_surface`, `findings_by_kind`) for quick reporting.

For JavaScript runtime triage, the summary also includes:

- `js_emulation_breakpoints_by_bucket` (for example `missing_callable`, `recursion_limit`, `parser_dialect_mismatch`)
- `js_runtime_budget` with:
  - `script_timeout_findings`
  - `loop_iteration_limit_hits`

```bash
sis query sample.pdf findings --format json
sis query sample.pdf findings --where "kind == 'js_runtime_downloader_pattern'" --format json
sis query sample.pdf findings --where "kind == 'js_runtime_wasm_loader_staging'" --format json
sis query sample.pdf findings --where "kind == 'js_runtime_dependency_loader_abuse'" --format json
sis query sample.pdf findings --where "kind == 'js_runtime_credential_harvest'" --format json
```

### 6) URI aggregation triage (`uri_listing` + `uri_content_analysis`)
`uri_present` is retired. Use:

- `uri_listing` for document-level URI inventory and roll-up risk.
- `uri_content_analysis` for per-URI suspicious detail.

```bash
# URI roll-up row
sis query sample.pdf findings --where "kind == 'uri_listing'" --format json

# Pull URI roll-up metadata (top-level risk and counts)
sis query sample.pdf findings --where "kind == 'uri_listing'" --format json \
  | jq '.results[0].meta | {total: ."uri.count_total", suspicious: ."uri.suspicious_count", max_severity: ."uri.max_severity", max_confidence: ."uri.max_confidence", risk_bands: ."uri.risk_band_counts"}'

# List suspicious URIs only
sis query sample.pdf findings --where "kind == 'uri_content_analysis'" --format json
```

### 7) Query predicate parity in one-shot and REPL
Use `--where` in one-shot mode and `:where` in REPL mode for the same query families (including `findings.composite` and xref namespaces).

### 8) Runtime telemetry in `explain` (phase/profile-aware)
When a finding is produced from JavaScript sandbox execution, `explain` now includes:

- phase telemetry: `js.runtime.phase_order`, `js.runtime.phase_count`, `js.runtime.phase_summaries`
- profile fusion telemetry: `js.runtime.profile_count`, `js.runtime.profile_status`, `js.runtime.profile_divergence`
- scoring adjustments: `js.runtime.profile_consistency_signal`, `js.runtime.profile_consistency_ratio`, `js.runtime.profile_severity_adjusted`, `js.runtime.profile_confidence_adjusted`
- timeout-aware scoring/coverage telemetry: `js.runtime.script_timeout_profiles`, `js.runtime.script_timeout_ratio`, `js.runtime.timeout_confidence_adjusted`, `js.runtime.loop_iteration_limit_hits`
- timeout root-cause context (when present): `js.runtime.timeout_profile`, `js.runtime.timeout_phase`, `js.runtime.timeout_elapsed_ms`, `js.runtime.timeout_budget_ratio`
- integrity metadata: `js.runtime.replay_id`, `js.runtime.ordering`, and `js.runtime.truncation.*`
- behaviour-derived metadata (when applicable): `js.runtime.behavior.name`, `js.runtime.behavior.confidence_score`, `js.runtime.behavior.severity`, `js.runtime.behavior.evidence`, `js.runtime.behavior.meta.*`
- service worker lifecycle telemetry (when applicable): `js.runtime.service_worker.*`
- realtime channel telemetry (when applicable): `js.runtime.realtime.*`
- lifecycle hook telemetry (when applicable): `js.runtime.lifecycle.phase`, `js.runtime.lifecycle.hook_calls`, `js.runtime.lifecycle.background_attempts`

Example:

```bash
sis query sample.pdf findings
sis query sample.pdf explain <finding-id>
```

Use these fields to determine whether behaviour is consistent across emulated environments (`pdf_reader`, `browser`, `node`, `bun`) and whether final severity/confidence was promoted or demoted by profile consistency scoring.

## Practical investigation playbook

```bash
# 1. Pull high-risk findings
sis query sample.pdf findings --where "severity == 'High' || severity == 'Critical'" --format json

# 2. Inspect chain context
sis query sample.pdf actions.chains --where "depth >= 2" --format json

# 3. Inspect structural anomalies
sis query sample.pdf xref.sections
sis query sample.pdf xref.deviations

# 4. Validate payload-bearing objects
sis query sample.pdf objects --where "stream.filter_count > 0" --format json

# 5. Extract suspicious stream for offline analysis
sis query sample.pdf stream 45 0 --decode --extract-to /tmp/streams
```

## Batch and corpus exercises

```bash
sis query --path ./samples --glob "*.pdf" findings.composite --format jsonl
sis query --path ./samples --glob "*.pdf" correlations --format jsonl
sis query --path ./samples --glob "*.pdf" xref.deviations --format jsonl
```

## Reporting checklist
- Include `finding.id` values and relevant `objects`.
- Include exact query commands used.
- Include extracted artefact paths and offsets where relevant.
- Distinguish direct findings from correlation/composite findings.

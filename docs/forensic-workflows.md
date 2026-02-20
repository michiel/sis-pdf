# Forensic Workflows

This guide outlines repeatable workflows for triage and analysis using `sis`.
All workflows assume hostile PDFs and use safe defaults.

## 1) Triage and Deep Scan

```bash
sis scan suspicious.pdf
sis scan suspicious.pdf --deep
```

Review high-severity findings and follow evidence spans to the object ids reported
in the scan output.

## 2) Embedded File Extraction

```bash
sis query suspicious.pdf embedded
sis query suspicious.pdf embedded --extract-to ./evidence/embedded
```

Follow-up:
- Hash and scan extracted files with your internal tooling.
- Compare `embedded.sha256` metadata against allowlists or threat intel.

## 3) Action and Trigger Review

```bash
sis scan suspicious.pdf --deep --json
```

Focus on findings such as `open_action_present`, `launch_action_present`,
`action_chain_complex`, and `action_hidden_trigger` to understand automatic or
hidden execution paths.

## 4) XFA Form Review

```bash
sis scan suspicious.pdf --deep --json
```

Look for `xfa_submit`, `xfa_sensitive_field`, and `xfa_script_count_high`. Use
evidence spans to locate the XFA payload for external SAST review.

## 5) Filter and Entropy Analysis

```bash
sis scan suspicious.pdf --deep --json
```

Inspect `filter_chain_unusual`, `filter_order_invalid`, and
`stream_high_entropy` findings to identify obfuscation patterns and potential
encrypted payloads.

## 6) Cross-run Finding Diff

```bash
sis scan baseline.pdf --deep --jsonl-findings > baseline.jsonl
sis scan comparison.pdf --deep --jsonl-findings > comparison.jsonl
sis diff baseline.jsonl comparison.jsonl
sis diff baseline.jsonl comparison.jsonl --format json
```

`sis diff` matches findings by a stable fingerprint (kind, canonical objects,
selected context fields, and optional evidence offset), not by finding id.
For `action_target`, the matcher normalises URI query strings and fragments
before fingerprinting so volatile tokens do not break matching across runs.

Exit codes:
- `0`: no new High/Critical findings
- `1`: one or more new High/Critical findings

## 7) Report Schema Version Check

When consuming `sis scan --json` output programmatically, check
`report.chain_schema_version` before reading chain enrichment fields.

- `chain_schema_version = 2`: chain metadata fields (for example
  `confirmed_stages`, `reader_risk`, `narrative`, `finding_criticality`) are
  available.
- missing `chain_schema_version` (legacy v1 payloads) defaults to `0`, and
  additive chain fields fall back to empty/default values.

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

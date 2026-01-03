# sis-pdf Usage

This guide shows end-to-end workflows with concrete commands and suggested analysis steps. All commands assume you run from the repository root.

## 1) Triage scan (fast, default)

Use this for first-pass analysis when you need a quick answer.

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf
```

For a stricter fast path:

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --fast
```

Suggested steps:
- Review grouped findings by attack surface (Actions, JavaScript, EmbeddedFiles, StreamsAndFilters).
- Note high-severity findings first (JavaScript, embedded files, decoder-risk filters).
- If you see only structural issues (xref conflicts, object shadowing), plan a deep scan.

## 2) JSON report for automation

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --json > report.json
```

JSONL (stream-friendly):

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --jsonl > report.jsonl
```

SARIF (CI integration):

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --sarif > report.sarif
```

SARIF to file:

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --sarif-out report.sarif
```

Analysis steps:
- Parse `summary` for high/medium counts.
- Use `grouped` to drive dashboards or alerting.
- Use `findings[*].evidence` to link to raw offsets or decoded offsets.

## 3) Deep scan for decoding risk

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --deep
```

Focused scan for a specific trigger:

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --focus-trigger openaction
```

Limit reachability to a smaller graph radius:

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --focus-trigger openaction --focus-depth 3
```

Strict parsing (record lexer-level deviations):

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --strict
```

When to use deep scan:
- You have `StreamsAndFilters` findings and need to measure decode ratios.
- You suspect embedded JavaScript or embedded files hidden behind filters.
- You see `/ObjStm` density warnings or incremental updates.

## 4) Explain a specific finding

First, run a scan to get an ID, then:

```
cargo run -p sis-pdf --bin sis -- explain suspicious.pdf sis-<finding-id>
```

## 4b) Generate a full Markdown report

```
cargo run -p sis-pdf --bin sis -- report suspicious.pdf
```

Write to a file:

```
cargo run -p sis-pdf --bin sis -- report suspicious.pdf -o report.md
```

Analysis steps:
- Use evidence source to decide if you need to inspect raw bytes or decoded output.
- For file-backed evidence, offsets are absolute in the original PDF.
- For decoded evidence, consult `origin` spans to map back to raw stream bytes.

## 5) Extract JavaScript payloads

```
mkdir -p out/js
cargo run -p sis-pdf --bin sis -- extract js suspicious.pdf -o out/js
```

Analysis steps:
- Review extracted JS files for obfuscation patterns and network calls.
- Correlate JS filenames to object IDs from findings.
- If JS extraction yields nothing but JS findings exist, the payload may be a ref or in a filtered stream. Use deep scan and inspect the referenced objects.

## 6) Extract embedded files

```
mkdir -p out/embedded
cargo run -p sis-pdf --bin sis -- extract embedded suspicious.pdf -o out/embedded
```

Analysis steps:
- Hash extracted files and submit to internal malware pipeline.
- Inspect file headers for PE/ELF/Mach-O signatures.
- Map embedded file object IDs back to findings for provenance.

## 7) Structural evasions (incremental updates)

If you see `xref_conflict` or `incremental_update_chain`:

1) Run `--deep` to gather additional decoder findings.
2) Use `explain` on shadowed object findings to locate offsets.
3) Compare object spans across revisions (same object ID, different spans).

If you want a parser-differential view:

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --diff-parser
```

Notes:
- Differential parsing uses `lopdf` as a secondary parser.
- Use this when you suspect parser differentials or malformed structures.

## 8) Decoder-risk triage

If you see `decoder_risk_present` or `decompression_ratio_suspicious`:

1) Identify filters (JBIG2/JPX are high risk).
2) Inspect stream span offsets to verify size and filter chain.
3) If needed, extract embedded content to a quarantine directory.

## 9) Phishing-content heuristic workflow

If you see `content_phishing`:

1) Inspect URIs for non-corporate or recently-registered domains.
2) Review page content for full-page images and overlay links.
3) Cross-reference with JS and Actions findings for behaviour.

## 10) Building a minimal synthetic fixture

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
cargo run -p sis-pdf --bin sis -- scan tmp/synthetic.pdf
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
cargo run -p sis-pdf --bin sis -- scan --path samples --glob \"*.pdf\"
```

Batch scan JSON summary:

```
cargo run -p sis-pdf --bin sis -- scan --path samples --glob \"*.pdf\" --json
```

Configuration-based scans:

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --config config.yml --profile interactive
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
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --config config.yml --profile interactive
```

YARA export (stdout or file):

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --yara
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --yara-out rules.yar
```

YARA scope (all/medium/high):

```
cargo run -p sis-pdf --bin sis -- scan suspicious.pdf --yara --yara-scope all
```

JavaScript AST summaries (feature build):

```
cargo run -p sis-pdf --features js-ast --bin sis -- scan suspicious.pdf
```

Report example with strict parsing and differential parsing:

```
cargo run -p sis-pdf --bin sis -- report suspicious.pdf --strict --diff-parser -o report.md
```

## 12) Troubleshooting

- If `scan` misses objects, try `--deep` and check for `/ObjStm` usage.
- If findings have no evidence spans, the detector may not yet attach spans for that rule.
- If decoding fails, the stream may be malformed or use unsupported filters.

## 13) Notes on evidence spans

- `source=File` offsets are absolute in the original PDF.
- `source=Decoded` offsets refer to decoded buffers and should include `origin` spans when available.
- Use `origin` spans to map decoded evidence back to raw stream data for forensic traceability.

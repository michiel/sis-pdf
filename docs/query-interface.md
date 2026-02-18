# Query Interface Guide

This guide describes the `sis query` interface for exploring PDF structure, content, and findings.

## Basics

Run a one-shot query:

```bash
sis query sample.pdf images
```

Adjust the report verbosity with `--report-verbosity [compact|standard|verbose]` (default `standard`). `compact` drops info/low findings from the default tables while the JSON output still contains every finding.

Control the amount of detail that action chains expose with `--chain-summary [minimal|events|full]` (default `events`). Minimal hides all edges, events keeps only suspicious or well-weighted edges, and full always emits the complete chain regardless of the format. JSON, JSONL, and YAML outputs always show the full data for reproducibility.

Start an interactive REPL:

```bash
sis query sample.pdf
```

Inside the REPL you can now emit the ORG, Event, and IR graphs with `org`, `graph.event`, and `ir` commands; they default to dot/text output but respond to `:json`, `:yaml`, or `:readable` just like other queries (for example `org | jq '.'` or `graph.event | jq .`).

By default the REPL uses the new `:readable` formatter so lists render as ASCII tables and objects show simple trees. Use `:json`, `:yaml`, `:readable`, etc., to switch formats, and append `| <shell command>` or `> <path>` to any query (for example `findings | jq .` or `org > graph.dot`) to pipe or redirect the formatter output.

## Common Queries

```bash
sis query sample.pdf pages
sis query sample.pdf js.count
sis query sample.pdf embedded
sis query sample.pdf images
sis query sample.pdf images.risky
sis query sample.pdf launch
sis query sample.pdf embedded.executables
sis query sample.pdf embedded.executables.count
sis query sample.pdf xfa.submit
sis query sample.pdf filters.unusual
sis query sample.pdf streams.high-entropy
sis query sample.pdf streams.entropy
sis query sample.pdf xfa.scripts.count
sis query sample.pdf swf.count
sis query sample.pdf swf.actionscript
sis query sample.pdf media.3d
sis query sample.pdf media.audio
sis query sample.pdf encryption
sis query sample.pdf encryption.weak
sis query sample.pdf encryption.weak.count
sis query sample.pdf xref
sis query sample.pdf xref.startxrefs
sis query sample.pdf xref.sections
sis query sample.pdf xref.trailers
sis query sample.pdf xref.deviations
sis query sample.pdf revisions
```

## Xref and revision queries

Use the xref namespace when you need to trace structural findings (`xref_conflict`, trailer anomalies, startxref out-of-bounds) back to concrete parser state:

```bash
sis query sample.pdf xref
sis query sample.pdf xref.startxrefs
sis query sample.pdf xref.sections
sis query sample.pdf xref.trailers
sis query sample.pdf xref.deviations
sis query sample.pdf revisions
```

- `xref` returns a combined summary with counts plus `startxrefs`, `sections`, `trailers`, and `deviations` arrays.
- `xref.startxrefs` exposes marker offsets and bounds checks.
- `xref.sections` exposes parsed chain section kind (`table`, `stream`, `unknown`) and trailer linkage.
- `xref.trailers` summarises `/Size`, `/Root`, `/Info`, `/Encrypt`, `/Prev`, and `/ID` presence.
- `xref.deviations` exposes xref parser deviations (for example trailer-search issues).
- `revisions` provides revision-oriented records derived from startxref/trailer state.

## Canonical diff

```bash
sis query sample.pdf canonical-diff
```

This command reports the canonical object view that detectors consume: how many incremental updates were stripped, which names were normalised, and a sampled list of the removed objects and renamed entries. The default text output formats the entire JSON blob, so use `--format json` or `--format yaml` for automated pipelines; `--where` predicates are not supported for this query.

## Image Queries

Image queries report image XObjects and XFA images:

```bash
sis query sample.pdf images
sis query sample.pdf images.jbig2
sis query sample.pdf images.jpx
sis query sample.pdf images.ccitt
sis query sample.pdf images.risky
sis query sample.pdf images.malformed --deep
```

Run `images --deep` when you need decode metadata (timeouts, malformed streams, buckets of filters) and combine with `--where` to hunt for specific decode outcomes. The JSON output includes fields such as `image.decode` (`success`, `failed`, `skipped`), `image.decode_error`, `image.decode_too_large_reason`, `image.filters`, `image.width`, and `image.height`, so you can chain predicates like:

```bash
sis query sample.pdf images --deep --where "image.decode == 'failed'"
sis query sample.pdf images --where "format == 'JPEG' AND pixels > 1000000"
sis query sample.pdf images --where "image.decode_skipped == 'budget_exceeded'"
```

`images.malformed` already forces a deep scan and highlights any decode failures (JBIG2, JPX, JPEG, CCITT) or skipped streams; use it along with `--where` or `--extract-to` to flush out the offending bytes before exporting to another tool. Our new fixtures (`images/valid_jpeg.pdf`, `images/malformed_jbig2.pdf`, `images/malformed_jpx.pdf`) live under `crates/sis-pdf-core/tests/fixtures/images/` and demonstrate how the pipeline responds to success, malformed JBIG2, and malformed JPX streams.

## Rich media queries

Use `swf` and `swf.actionscript` to list all SWF streams or just the ones that carry ActionScript tags; `media.3d` and `media.audio` summarise 3D, visual and audio/rendition objects, and all four commands grow richer metadata with each scan. They support `--where` filters on SWF version, action-tag count, declared size, media type and payload size.

```bash
sis query sample.pdf swf --where "size > 1024"
sis query sample.pdf swf.actionscript --format json
sis query sample.pdf media.3d --where "media_type == 'prc'"
sis query sample.pdf media.audio --where "media_type == 'mp3'"
```

## Predicate Filters

Use `--where` to filter results:

```bash
sis query sample.pdf images --where "pixels > 1000000 AND risky == true"
sis query sample.pdf images --where "format == 'PNG' AND entropy > 7.5"
sis query sample.pdf findings.count --where "subtype == 'embedded_executable_present'"
```

In interactive mode, predicates are set with `:where` and then applied to subsequent queries:

```text
sis> :where kind == 'table'
sis> xref.sections
```

See `docs/query-predicates.md` for all fields.

## Extraction

Extract payloads to disk:

```bash
sis query sample.pdf images --extract-to /tmp/images
sis query sample.pdf images --extract-to /tmp/images --raw
sis query sample.pdf xfa.scripts --extract-to /tmp/xfa-scripts
sis query sample.pdf swf --extract-to /tmp/swf --decode
sis query sample.pdf swf.extract --extract-to /tmp/swf
sis query sample.pdf stream 1487 0 --extract-to /tmp/streams --decode
```

When `stream` is used without `--extract-to`, it returns a short preview string instead of writing a file.

## Output Formats

```bash
sis query sample.pdf images --format json
sis query sample.pdf images --format jsonl
sis query sample.pdf images --format yaml
sis query sample.pdf images --format json --colour
```

`findings` queries now add a top-level `summary` object in JSON/YAML/JSONL outputs when the result is an array of findings. The summary includes `findings_by_severity` and `findings_by_surface` counts so dashboards can chart the digest without parsing every entry.

## Finding Shortcuts

The following query shortcuts return `findings.kind` for common analysis paths.
Add `.count` to return a numeric count.

```bash
sis query sample.pdf embedded.executables
sis query sample.pdf embedded.scripts
sis query sample.pdf embedded.archives.encrypted
sis query sample.pdf embedded.encrypted
sis query sample.pdf launch
sis query sample.pdf launch.external
sis query sample.pdf launch.embedded
sis query sample.pdf actions.chains.complex
sis query sample.pdf actions.triggers.automatic
sis query sample.pdf actions.triggers.hidden
sis query sample.pdf xfa.submit
sis query sample.pdf xfa.sensitive
sis query sample.pdf xfa.too-large
sis query sample.pdf xfa.scripts.high
sis query sample.pdf findings.swf
sis query sample.pdf streams.high-entropy
sis query sample.pdf streams.entropy
sis query sample.pdf encryption
sis query sample.pdf encryption.weak
sis query sample.pdf encryption.weak.count
sis query sample.pdf filters.unusual
sis query sample.pdf filters.invalid
sis query sample.pdf filters.repeated
sis query sample.pdf findings.composite
sis query sample.pdf findings.composite.count
```

### Composite findings queries

`findings.composite` and `findings.composite.count` expose the Stage 9 correlated findings (for example `launch_obfuscated_executable`, `action_chain_malicious`, `xfa_data_exfiltration_risk`, `encrypted_payload_delivery`, `obfuscated_payload`). Because the predicate guard list now includes these queries, you can still pipe `--where` expressions such as `--where "kind == 'launch_obfuscated_executable'"` or `:where kind == \"launch_obfuscated_executable\"` in the REPL without hitting `QUERY_ERROR`. The regression coverage for both batch and REPL modes lives in `crates/sis-pdf/src/commands/query.rs:7238-7327`, so you can reference those tests when evaluating future grazing.

### Correlation exports

`correlations` and `correlations.count` provide dashboard-ready summaries of the composite patterns emitted by Stage 9:

```bash
sis query sample.pdf correlations
sis query sample.pdf correlations --format json
sis query sample.pdf correlations --format jsonl
sis query sample.pdf correlations.count
```

The default response is a JSON object keyed by the correlation pattern name (for example `xfa_data_exfiltration_risk`), with each entry describing the `count` of matching findings and the `severity` level for that pattern. Use the `.count` shortcut when you only care about whether any composite findings fired during a batch run, and pipe the JSON/JSONL output into dashboards or analytics pipelines to track per-pattern activity.

## Action Chain Queries

Use `actions.chains` to inspect the catalog of action chains and `actions.chains.count` to tally them (predicate filtering applies to both). The JSON output includes chain metadata such as trigger, length (depth), automatic flag, `has_js`, and `has_external` flags, so you can run queries like:

When using text/readable output, the `--chain-summary` flag (and the REPL prompt indicator) control whether edges are trimmed — `minimal` hides edges entirely, `events` retains only suspicious or high-weight edges, and `full` keeps every link for comparison. JSON/YAML/JSONL always include the complete chain data for consistency.

```bash
sis query sample.pdf actions.chains
sis query sample.pdf actions.chains.count
sis query sample.pdf actions.chains --where "depth >= 3"
sis query sample.pdf actions.chains --where "has_js == true"
sis query sample.pdf actions.chains --format json
```

`actions.chains` also supports the `--format dot` export that can be rendered with Graphviz.

## Event Graph Queries

Use `graph.event` to export the connected event/outcome graph used by the GUI event mode.  
`graph.action` is an alias of `graph.event`.

```bash
sis query sample.pdf graph.event
sis query sample.pdf graph.event --format json
sis query sample.pdf graph.event --where "event_type == 'DocumentOpen'"
sis query sample.pdf graph.event --where "outcome_type == 'NetworkEgress'"
sis query sample.pdf graph.event.hops 2 --where "outcome_type == 'ExternalLaunch'"
sis query sample.pdf graph.action --format dot
```

Useful predicate keys for `graph.event` are exposed via `meta` fields:
- `event_type`
- `outcome_type`
- `node_kind` (`event`, `outcome`, `object`, `collapse`)
- `trigger_class` (`automatic`, `hidden`, `user`)
- `target`

## Structure vs Event Graph Playbook

Use this sequence when triaging suspicious PDFs:

1. Start with structure to confirm parser-level relationships:
```bash
sis query sample.pdf graph.org --format dot
```
2. Switch to event graph to identify execution-relevant paths:
```bash
sis query sample.pdf graph.event --format json
```
3. Focus on automatic entry points:
```bash
sis query sample.pdf graph.event --where "trigger_class == 'automatic'"
```
4. Focus on concrete outcomes:
```bash
sis query sample.pdf graph.event --where "outcome_type == 'NetworkEgress'"
```
5. Reduce noise with local induced subgraph export:
```bash
sis query sample.pdf graph.event.hops 2 --where "outcome_type == 'NetworkEgress'"
```

## XFA form queries

`xfa`/`xfa.count` lists decoded XFA payloads with script counts, submit targets, and hidden-field indicators. Use `--where` to filter by payload size or script volume, and predicate filtering extends to `xfa.submit`/`xfa.sensitive` via the `url` and `field` fields.

```bash
sis query sample.pdf xfa
sis query sample.pdf xfa.count
sis query sample.pdf xfa --where "size > 500000"
sis query sample.pdf xfa --where "script_count > 5"
sis query sample.pdf xfa.submit --where "url contains 'external.com'"
```

## Encryption & Stream Entropy Queries

`encryption` reports findings related to `/Encrypt` dictionaries, including detected algorithms and key lengths. Use `encryption.weak` to focus on detected weak cryptography and `.count` to tally them.

```bash
sis query sample.pdf encryption
sis query sample.pdf encryption.weak --where "crypto.algorithm == 'RC4-40'"
sis query sample.pdf encryption.weak.count
```

`streams.entropy` lists every decoded stream along with entropy, sample size, magic type, and timing metadata. Combine with `--where` to hunt for highly entropic, unknown, or timed-out streams.

```bash
sis query sample.pdf streams.entropy --where "entropy > 7.5 AND magic == 'unknown'"
sis query sample.pdf streams.entropy --format jsonl
```

## Filter Chain Queries

Inspect filter-chain findings with optional predicates:

```bash
sis query sample.pdf filters.unusual
sis query sample.pdf filters.invalid
sis query sample.pdf filters.repeated
sis query sample.pdf filters.unusual --where "filter_count > 1"
sis query sample.pdf filters.invalid --where "violation_type == 'crypt_not_outermost'"
```

## Feature vector exports

Use `sis query features` (or `sis export-features`) to emit the fixed-length ML feature vector. The vector includes the new XFA, encryption and filter-chain inputs that Stage 8 feeds into downstream models; the order is stable and matches `sis_pdf_core::features::feature_names()`, so CSV, JSON and JSONL outputs line up with the documented index mapping.

```bash
sis query sample.pdf features --format csv
sis query sample.pdf features --format json | jq -r '.features'
sis query --path corpus --glob "*.pdf" features --format jsonl
```

CSV output includes a header row (`feature,value`) while JSON/JSONL include feature-name→value objects, which makes the encryption (`encryption.*`), filter (`filters.*`) and XFA (`xfa.*`) contributions easy to consume. See `docs/ml-features.md` for the full breakdown and instructions on ingesting the vector in ML pipelines.

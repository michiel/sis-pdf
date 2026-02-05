# Agent Query Guide

This guide is for a security analyst using `sis query` to investigate PDF samples with the `sis` toolkit. Treat each step as part of a structured analysis: gather context, explore suspicious artefacts, follow attack paths, and validate results before acting. Always run queries locally on a copy of the PDF sample and keep extracted data confined to the analysis workspace.

## Objectives for an analyst agent
1. Confirm whether a PDF is malicious by reconstructing its attack surface (actions, URIs, embedded payloads, filters, JS).  
2. Prioritise findings by severity/impact and trace their correlations (chains, shared objects).  
3. Document observable artefacts (preview snippets, triggers, outcomes) and suggest containment/remediation steps.  
4. Provide clear, reproducible query commands so teammates or automation can rerun the same investigation.

## General workflow
1. **Triage scan**: `sis scan sample.pdf` to produce baseline findings.  
2. **Deep dive**: re-run `sis scan sample.pdf --deep` if structural issues were flagged (polyglot, ObjStm anomalies, irregular filters).  
3. **Report generation**: `sis report sample.pdf -o sample.md` (or `--format json`/`jsonl`) to summarise findings, chains, evidence, and metadata.  
4. **Interactive querying**: Use `sis query` to inspect specific surfaces (JavaScript, URLs, actions, objects) when something looks suspicious.

## `sis query` patterns for PDF analysts
### Basic commands
- `sis query findings sample.pdf` — dump all findings with metadata; pipe to `jq` or `grep` to filter.  
- `sis query findings sample.pdf --where "severity == 'High'" --format json` — focus on high-severity signals for quick triage.  
- `sis query actions sample.pdf --format table` — view action dictionaries (trigger/action/payload).  
- `sis query urls sample.pdf --where "length > 32"` — show long, potentially obfuscated URIs along with canonicalised details.

### Structured surfaces
- **Objects**: `sis query objects sample.pdf --where "stream.filter_count > 0"` to inspect decoded streams.  
- **Action chains**: `sis query actions sample.pdf --where "chain.depth >= 3" --format json` (use `--chain-summary minimal` to drop verbose edges).  
- **JavaScript**: `sis query js sample.pdf --where "length > 1024" --format jsonl` and examine `js.payload_preview`/`js.ast_urls`.  
- **URIs**: `sis query urls sample.pdf --where "suspicious == true" --format table` identifies flagged URIs with chain context (action label, chain depth).  
- **Embedded files**: `sis query embedded sample.pdf --where "mime.contains('pe')"` surfaces executables hidden inside objects.

### Advanced queries & filtering tips
- Use `--where` to combine predicates: `sis query findings sample.pdf --where "kind == 'annotation_action_chain' && severity == 'Medium'"`.  
- Combine `--format json` with `jq`/Python to produce custom dashboards (e.g., summarise `uri.count_*`, `action.chain_depth`).  
- `sis query graph sample.pdf --format dot` exports the ORG/IR graph to visualise relationships (use Graphviz to render).  
- Add `--extract-to /tmp/out` for object streams or JS when you need to analyse payload bytes offline.

### Chain/correlation observation
The new `Chain analysis` section in `sis report` summarises grouped attack paths. Use `sis query findings sample.pdf --where "chain_id == 'chain-abc'"` when you need an individual chain definition, or run `sis query actions sample.pdf --where "chain_id != null" --format table` to inspect triggers, actions, and payloads per chain. Correlate `correlation` metadata (e.g., `correlation.object`) between findings to understand which objects host multiple suspicious artefacts.

## Recommended agent behaviour
1. Start with high-severity findings (`sis query findings --where "severity == 'High'"`). Document the path from trigger to payload/result using `node_preview`/`payload.summary`.  
2. Look for polyglot/policy violations (`polyglot_signature_conflict`, `invalid_pdf_header`). These often accompany hidden payloads or tampering.  
3. Use `sis query uris` and follow the `chain_depth` metadata to see how many steps away a URI is from a trigger.  
4. Capture evidence spans (offsets/lengths) from findings or `sis query objects` output, so incident responders can reproduce the exact byte ranges.  
5. When raising alerts, cite the `finding.id`, `meta.action.target`, and `node preview` information from the query to make investigations reproducible.

## Sample session notes
```
# Step 1: Review high severity findings
sis query findings sample.pdf --where "severity == 'High'" --format table
# Step 2: See where URIs live
sis query urls sample.pdf --where "suspicious == true" --format table
# Step 3: Check event chains for automatic execution
sis query actions sample.pdf --where "chain.depth > 2" --chain-summary events --format table
# Step 4: Inspect potential payload objects for encoded binaries
sis query objects sample.pdf --where "stream.filter_count >= 2" --format jsonl
```

## Reporting back
Summarise the attack in terms of outcome: describe triggers/actions/payloads, the evidence (object references, offsets, previews), and recommended mitigations (e.g., block the suspicious URI, restrict automatic actions). Link to the generated Markdown/JSON report for completeness.

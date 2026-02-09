# Questions

## Q: Why does sis-pdf implement a custom parser? Why not use an existing PDF library or a parser generator?

sis-pdf is built for hostile-PDF forensics, not document rendering. It needs parser behaviour that is both viewer-tolerant and security-explicit.

The custom parser enables this combination:

- Tolerant recovery paths for malformed files while still recording structural deviations for triage.
- Deterministic evidence spans (byte offsets and decoded origins) for every finding.
- Security budgets baked into parsing and decoding paths (for example parse depth, dictionary/array sizes, object and decode budgets).
- PDF-specific anti-evasion behaviour such as always expanding `/ObjStm` and using the latest object revision for shadowed object IDs.
- Direct alignment with `sis query` forensic workflows (`xref.*`, `revisions`, stream decode modes, predicate filters).

Historically, plan work in `plans/old/20260206-pdfjs-reference.md` and `plans/20260208-xref-conflict-refinement.md` shows why this matters: resilience fixes and xref integrity scoring required tight control over parse internals and metadata output, not just generic parsing.

## Q: How do malicious PDFs hide and later access content? How does sis-pdf identify hidden content? Is sis-pdf comprehensive in this?

Common hiding tactics include:

- Object streams (`/ObjStm`) containing payload objects.
- Incremental updates that shadow older object IDs.
- Multi-hop indirect references to payload strings/streams.
- Fragmented payloads across arrays.
- Filter declaration mismatches and decode tricks.
- Hidden annotations and automatic action triggers.

sis-pdf addresses these by default and in deep mode:

- `/ObjStm` expansion runs during parse with limits, even without `--deep`.
- Object lookup resolves to the latest object version, which reduces shadowing evasion.
- Payload resolution follows references with cycle detection, max hop depth, and array-size guards.
- Stream decoding tracks mismatches and recovery paths (`decode_recovery_used`) with metadata.
- Action/trigger detectors flag hidden and automatic execution paths (`action_hidden_trigger`, `action_automatic_trigger`, `action_chain_complex`).

Comprehensiveness status: broad but not absolute. The project intentionally treats findings as probabilistic signals plus structural evidence, not a formal proof of benignness. Historical plans still track ongoing hardening and coverage uplift in areas like corpus trend automation and specialised parser-stress telemetry.

## Q: What assurance exists that sis-pdf is safe to run on hostile PDFs?

Assurance is layered:

- Code-level guardrails: parse/decode limits, recursion bounds, object budgets, timeouts, and non-fatal recovery for many malformed structures.
- Memory-safety posture: core crates declare `#![forbid(unsafe_code)]`.
- Operational hardening from real corpus incidents: page-tree recursion, xref trailer-search crashes, and object-stream stress paths were addressed and documented in historical plans.
- Regression coverage: integration tests include malicious and malformed fixtures across actions, XFA, image codecs, object streams, encryption, and parser deviations.

Recent verification examples in this repo include passing targeted tests such as runtime profiling, findings schema, regression payloads, URI classification, JS sandbox integration, and structural anomalies suites.

## Q: What are the most important built-in limits and budgets?

Representative defaults include:

- Parser: max depth 64, max array elements 100,000, max dictionary entries 10,000.
- Stream decode service: max decoded bytes 8 MiB (default service limit), max filter chain depth 8.
- ObjStm expansion: capped object-stream count and total decode budgets.
- Payload reference resolution: max depth 10, max array elements 1,000.
- Detector-level watchdogs: multiple cheap/moderate detectors use short timeout guards to avoid runaway scans.

These limits are there to keep batch analysis stable while preserving evidentiary output.

## Q: How should analysts interpret `severity`, `impact`, and `confidence`?

Use them together:

- `severity`: priority/risk level for response.
- `impact`: likely consequence class if the behaviour is exploited.
- `confidence`: certainty of detection correctness.

The model is documented in AGENTS guidance and reflected in findings output. Recent refinements (for example xref integrity scoring) intentionally reduce noisy escalations by tying severity to concrete coherence checks.

## Q: What changed recently in query and xref assurance?

The query workflow now has first-class xref and revision inspection (`xref`, `xref.startxrefs`, `xref.sections`, `xref.trailers`, `xref.deviations`, `revisions`) and better explain/query traceability.

`xref_conflict` was also refined so coherent incremental-update chains are downgraded appropriately, while broken chains and deviation-heavy structures remain higher severity. This significantly improves triage trustworthiness.

## Q: Does `--deep` change detection quality?

Yes. Base scan is designed for fast triage. `--deep` enables heavier decode and content analysis paths (for example richer stream, image, and embedded payload inspection).

That said, some high-value anti-evasion logic is intentionally active even without `--deep` (notably ObjStm expansion and several structural/action detectors), so triage mode still catches many hostile patterns quickly.

## Q: What does `--diff-parser` do, and when should I use it?

`--diff-parser` runs an additional parser comparison path and emits differential findings when the structural view diverges (for example object count/trailer mismatches or shadow-related structural differences).

Use it when:

1. You suspect parser-targeted evasion.
2. You see xref/incremental-update anomalies.
3. You need higher assurance before escalating a sample.

It increases analysis cost, so it is best used for suspicious files rather than first-pass bulk triage. A practical high-assurance invocation is:

`sis scan sample.pdf --deep --diff-parser`

Then follow with targeted queries such as `xref.*`, `revisions`, `findings`, and `stream` to validate where the parser views disagree.

## Q: What is the ORG graph, and how is it used across sis-pdf?

The ORG (Object Reference Graph) is sis-pdf’s graph model of object-to-object relationships in a PDF (for example references between catalog, pages, actions, payload containers, and streams). It provides a structural backbone for higher-confidence analysis.

In broader sis-pdf workflows, ORG is used to:

1. Support path-based detection (for example action-to-payload reachability and shadowed payload chains).
2. Improve correlation and chain synthesis by linking findings that share graph context.
3. Power forensic drill-down via query and export surfaces (including ORG/IR views).
4. Feed optional graph-centric ML and feature export paths when enabled.

Practically, ORG complements signature/heuristic findings: it helps answer not just “what suspicious artefacts exist” but also “how those artefacts are connected into an execution or delivery path”.

## Q: What is the IR, and how is it used across sis-pdf?

IR (Intermediate Representation) is sis-pdf’s normalised per-object representation of parsed PDF content. It captures object semantics in a consistent form that is easier to analyse than raw token streams.

In broader sis-pdf workflows, IR is used to:

1. Provide stable analysis inputs for static graph/path detectors.
2. Reduce parser-noise differences by normalising object structure before correlation.
3. Power IR/ORG exports for forensic workflows and reproducible investigation.
4. Feed feature extraction and optional graph ML pipelines.

IR and ORG are complementary: IR describes what each object contains, while ORG describes how objects connect. Together they support higher-assurance reasoning about attack paths, hidden payload staging, and chain-level findings.

## Q: Is sis-pdf a replacement for sandbox detonation or multiple parser comparison?

No. It is a defensive analysis engine and forensic query tool. For high-risk samples, best practice is to combine:

1. `sis scan sample.pdf --deep --diff-parser`
2. Focused `sis query` drill-down on findings/streams/actions/xref
3. Controlled external tooling or sandbox workflows as needed

This layered approach matches the project’s documented intent and historical hardening strategy.

## Q: What are the current known trade-offs?

- No scanner can guarantee complete malware detection for every novel or viewer-specific exploit path.
- Some advanced JS dynamic analysis paths rely on sandbox feature availability at build/runtime.
- The project favours safe defaults and bounded analysis over unbounded extraction; this may intentionally skip some expensive artefacts and emit “skipped/limited” style findings instead.

For assurance-sensitive workflows, run deep scans, review structural findings in context, and preserve JSON/JSONL outputs for reproducible triage.

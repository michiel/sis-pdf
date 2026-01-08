# Glossary

This glossary explains acronyms and core concepts used in the SIS-PDF project, grouped by the analysis stages they appear in.

## Parsing and Structure Recovery

### PDF (Portable Document Format)
What it is: A structured document format made of indirect objects and a cross-reference index.
What it captures: The full file structure, object graph, and embedded content containers.
Why it exists: It defines the attack surface and parsing rules that SIS-PDF analyzes.
Relevance to SIS-PDF: All analysis starts from parsing the PDF into objects and trailers.
Where it is used: `sis_pdf_pdf::parse_pdf`, `ObjectGraph`, `ScanContext`.

### Object Graph
What it is: The in-memory graph of parsed PDF objects, spans, and metadata.
What it captures: Object IDs, parsed atoms, trailer entries, and byte spans.
Why it exists: It is the canonical representation used by detectors and exports.
Relevance to SIS-PDF: All detectors traverse the object graph for evidence.
Where it is used: `sis-pdf-pdf/src/graph.rs`, `sis-pdf-core/src/runner.rs`.

### Xref (Cross-Reference Table)
What it is: A PDF index that maps object IDs to byte offsets.
What it captures: Object positions and revision structure.
Why it exists: It defines how parsers locate objects and detect conflicts.
Relevance to SIS-PDF: Xref anomalies often indicate evasions or shadowing.
Where it is used: `ObjectGraph.startxrefs`, structural detectors.

### Trailer
What it is: The metadata section that points to the catalog and object count.
What it captures: `/Root`, `/Size`, and other top-level document metadata.
Why it exists: It anchors the object graph and document entry point.
Relevance to SIS-PDF: Catalog reachability and root analysis depend on it.
Where it is used: `ObjectGraph.trailers`, IR/ORG reachability checks.

### ObjStm (Object Stream)
What it is: A stream that packs multiple objects into compressed data.
What it captures: Compressed objects that are not visible as top-level objects.
Why it exists: It reduces file size but complicates analysis.
Relevance to SIS-PDF: Hidden payloads and shadowed objects often appear here.
Where it is used: Deep scan decoding and `objstm_*` detectors.

### Strict Parsing / Deviations
What it is: A parsing mode that records syntax errors and recovery actions.
What it captures: Nonconformant tokens and repaired structures.
Why it exists: It surfaces parser ambiguity and malformed input indicators.
Relevance to SIS-PDF: Deviations indicate evasion attempts and parser gaps.
Where it is used: `--strict`, `strict_parse_deviation` findings.

### Polyglot
What it is: A file valid as multiple formats (e.g., PDF + PNG).
What it captures: Conflicting signatures and multiple magic headers.
Why it exists: It bypasses scanners that rely on a single magic header.
Relevance to SIS-PDF: It is a key evasion technique in structural analysis.
Where it is used: Polyglot detection in `structural_summary`.

## Fast Triage and Structural Detectors

### /OpenAction
What it is: A catalog-level trigger that runs on document open.
What it captures: Automatic execution entry points for actions.
Why it exists: It enables interactive behaviors without user input.
Relevance to SIS-PDF: It is a high-signal trigger for malicious content.
Where it is used: Action detectors and chain synthesis.

### /AA (Additional Actions)
What it is: A dictionary of event-driven triggers (page open, close, etc.).
What it captures: Implicit actions tied to document or page events.
Why it exists: It enables richer interactivity and automation.
Relevance to SIS-PDF: It is often used to hide triggers across pages.
Where it is used: Action detectors, correlation, chain synthesis.

### Shadowed Object
What it is: Multiple definitions of the same object ID across revisions.
What it captures: Conflicting object content in incremental updates.
Why it exists: Incremental updates allow changes without rewrites.
Relevance to SIS-PDF: Shadowed payloads are common evasion tactics.
Where it is used: `object_id_shadowing`, diff parser checks.

### Incremental Update
What it is: Appended updates that modify existing PDFs.
What it captures: New xref sections and replacement objects.
Why it exists: It supports edits while preserving prior content.
Relevance to SIS-PDF: It enables hiding malicious objects behind newer ones.
Where it is used: Structural detectors and diff parser summary.

## Deep Decoding and Stream Analysis

### Stream
What it is: A PDF object containing raw or encoded bytes.
What it captures: Payloads, images, scripts, and embedded files.
Why it exists: It stores binary content outside the object dictionary.
Relevance to SIS-PDF: Stream decoding reveals hidden content and risk.
Where it is used: Stream decoders and payload extraction.

### Filter Chain
What it is: A sequence of decoders applied to stream data.
What it captures: The transforms required to recover original bytes.
Why it exists: It supports compression and encoding.
Relevance to SIS-PDF: Deep scan inspects chain depth and risky filters.
Where it is used: Decoder-risk detectors and stream analysis.

### JBIG2
What it is: A complex image compression format used in PDFs.
What it captures: Bitmaps with symbol dictionaries.
Why it exists: It compresses monochrome images efficiently.
Relevance to SIS-PDF: It is historically exploited in PDF readers.
Where it is used: Decoder-risk scoring and filter analysis.

### JPX (JPEG 2000)
What it is: A high-complexity image compression format.
What it captures: Image data with advanced codecs.
Why it exists: It allows high compression and progressive rendering.
Relevance to SIS-PDF: It is a high-risk decoder surface.
Where it is used: Decoder-risk scoring and filter analysis.

### Decompression Ratio
What it is: The expansion factor when decoding a stream.
What it captures: The size mismatch between encoded and decoded bytes.
Why it exists: High ratios indicate bombs or excessive obfuscation.
Relevance to SIS-PDF: It drives `decompression_ratio_suspicious` findings.
Where it is used: Stream analysis in deep scan mode.

## Intent, Behavior, and Correlation

### Finding
What it is: A single detection result with metadata and evidence.
What it captures: Kind, severity, confidence, evidence spans, and context.
Why it exists: It is the primary unit of analysis output.
Relevance to SIS-PDF: All reporting and correlation flows through findings.
Where it is used: `Report`, JSON output, SARIF output.

### Evidence Span
What it is: Byte offsets that support a finding.
What it captures: File-backed spans and decoded spans with origins.
Why it exists: It allows analysts to verify detections.
Relevance to SIS-PDF: Evidence spans ground findings in raw bytes.
Where it is used: `Finding.evidence`, report rendering.

### Behavior Summary
What it is: A grouping of related findings into behavior clusters.
What it captures: Repeated patterns such as multiple JS findings.
Why it exists: It reduces alert noise and highlights repeated tactics.
Relevance to SIS-PDF: It supports operator triage and correlation.
Where it is used: `behavior_summary` in reports.

### Intent Bucket
What it is: A high-level goal classification (exfiltration, phishing, etc.).
What it captures: Aggregated signals across findings and chains.
Why it exists: It translates low-level findings into operator intent.
Relevance to SIS-PDF: It surfaces likely attacker goals.
Where it is used: `intent_summary` in JSON and report output.

### Correlation
What it is: Logic that links findings across objects and actions.
What it captures: Shared objects, shared actions, or shared payload paths.
Why it exists: It reconstructs attack paths from distributed signals.
Relevance to SIS-PDF: It powers chain synthesis and intent scoring.
Where it is used: Chain synthesis and behavior correlation.

## IR/ORG Static Graph Analysis

### IR (PDFObj Intermediate Representation)
What it is: An assembly-like textual representation of each PDF object.
What it captures: Flattened key paths, value types, and references.
Why it exists: It normalizes objects for static analysis and embeddings.
Relevance to SIS-PDF: It enables graph detectors and ML features.
Where it is used: `sis_pdf_pdf::ir`, `--ir`, IR export.

### ORG (Object Reference Graph)
What it is: A directed graph of object references.
What it captures: Edges from one object to another via indirect refs.
Why it exists: It models execution and data flow relationships.
Relevance to SIS-PDF: It enables reachability and path analysis.
Where it is used: `sis-pdf-core/src/org.rs`, ORG export.

### Action-to-Payload Path
What it is: A graph path from trigger/action nodes to payload nodes.
What it captures: Reachable payloads from actions within a bounded depth.
Why it exists: It finds likely execution chains.
Relevance to SIS-PDF: It is a key static risk signal without ML.
Where it is used: `ir_graph_static` detector, `action_payload_path` finding.

### Orphaned Payload
What it is: A payload-like object not reachable from the catalog root.
What it captures: Hidden payloads outside normal document flow.
Why it exists: Attackers hide content in unreachable object graphs.
Relevance to SIS-PDF: It flags stealth or revision hiding.
Where it is used: `orphan_payload_object` finding.

## ML Classification

### ML (Machine Learning)
What it is: A model-driven classifier for maliciousness.
What it captures: Signals from features or graph embeddings.
Why it exists: It complements static detectors with learned patterns.
Relevance to SIS-PDF: Optional scoring layer for automation.
Where it is used: `--ml`, `ml_summary`, `ml_*` findings.

### GNN (Graph Neural Network)
What it is: A neural model that operates on graphs.
What it captures: Node features and structural relationships.
Why it exists: It can model complex PDF object graphs.
Relevance to SIS-PDF: It powers graph ML mode.
Where it is used: `--ml-mode graph`, `sis-pdf-ml-graph`.

### GIN (Graph Isomorphism Network)
What it is: A GNN architecture for graph classification.
What it captures: Aggregated neighborhood information per node.
Why it exists: It is strong for classification of structured graphs.
Relevance to SIS-PDF: It is the planned graph model target.
Where it is used: GNN model packaging and inference.

### Embedding
What it is: A numeric vector representation of IR text.
What it captures: Semantic tokens and structure of objects.
Why it exists: It provides node features for graph models.
Relevance to SIS-PDF: It is required for graph ML inference.
Where it is used: Embedding backend in `sis-pdf-ml-graph`.

### ONNX (Open Neural Network Exchange)
What it is: A portable model format for inference.
What it captures: Transformer or GNN model weights and graphs.
Why it exists: It allows running models without Python.
Relevance to SIS-PDF: Planned backend for embeddings and GNN.
Where it is used: `graph_model.json` configuration and inference.

## Reporting and Outputs

### JSON
What it is: Structured output format for reports.
What it captures: All findings, summaries, and metadata.
Why it exists: It is easy to parse and automate.
Relevance to SIS-PDF: Primary machine-readable output.
Where it is used: `--json` output mode.

### JSONL (JSON Lines)
What it is: One JSON object per line for streaming.
What it captures: Individual report items for batch workflows.
Why it exists: It scales to large scans and pipelines.
Relevance to SIS-PDF: Used for datasets and correlations.
Where it is used: `--jsonl`, dataset export.

### SARIF
What it is: A standard static analysis report format.
What it captures: Findings as SARIF results with locations.
Why it exists: It integrates with CI and code scanning platforms.
Relevance to SIS-PDF: Enables enterprise pipelines.
Where it is used: `--sarif` output mode.

### YARA
What it is: A rule format for file content matching.
What it captures: Signatures and metadata for detections.
Why it exists: It supports operational detection in scanners.
Relevance to SIS-PDF: SIS-PDF can emit response rules.
Where it is used: `--yara` and response generation.

### DOT
What it is: Graphviz text format for graph visualization.
What it captures: Nodes and edges in ORG or action graphs.
Why it exists: It enables quick graph rendering.
Relevance to SIS-PDF: Used for graph exports.
Where it is used: `sis export-org` and `sis export-graph`.

### GML
What it is: Graph Modeling Language used by graph tools.
What it captures: Graph nodes and edges with attributes.
Why it exists: It interoperates with Gephi and yEd.
Relevance to SIS-PDF: Alternative graph export format.
Where it is used: Graph exports for offline analysis.

### CLI (Command-Line Interface)
What it is: The `sis` binary and its subcommands.
What it captures: User actions to run scans and exports.
Why it exists: It is the primary operator interface.
Relevance to SIS-PDF: All workflows are CLI-driven by default.
Where it is used: `crates/sis-pdf/src/main.rs`.

### AST (Abstract Syntax Tree)
What it is: A structured representation of JavaScript code.
What it captures: Syntax nodes and code structure.
Why it exists: It enables static JS analysis beyond string matching.
Relevance to SIS-PDF: Optional JS analysis feature.
Where it is used: enabled by default (can be disabled with `--no-default-features`).

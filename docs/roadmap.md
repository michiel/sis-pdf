## Roadmap: next upgrades & steps for **sis-pdf** (PDF security analyzer)

This is a practical “what next” list, ordered by **highest impact first** (accuracy + triage value), with explicit feature buckets. Treat each bullet as a shippable milestone.

---

# Phase 1 — Detection quality and coverage

### 1) Decode filtered `/JS` streams (major coverage win)

* Add filter decoding for stream-based `/JS` (Flate/LZW/ASCII85/RunLength + predictor handling if present)
* Apply size/budget caps (decoded bytes max, time max)
* Record meta:

  * `js.stream.filters`, `js.stream.decoded=true/false`, `js.stream.decode_error`
  * `js.decoded_len`, `js.decode_ratio`
* Feed decoded bytes into `js_signals`

### 2) Resolve *all* action payload ref targets (not just `/JS`)

* For `/URI`, `/F`, `/Launch`, `/GoToR`, `/SubmitForm`:

  * resolve string/stream/ref targets
  * extract safe previews + metadata
* Meta:

  * `payload.decoded_len`, `payload.type`, `payload.ref_chain` (bounded)

### 3) Expand action surface coverage (PDF action zoo)

Add detectors / graph modeling for:

* `/RichMedia`, `/3D`, `/U3D`, `/PRC` (embedded interactive)
* `/Sound`, `/Movie`, `/Rendition`
* `/EmbeddedFile` + `/Filespec` + `/AF` (Associated Files)
* `/XFA` (dynamic forms), `/AcroForm` calculation scripts
* `/AA` on more objects (page, form fields, document catalog variants)
* `/OCG` optional content triggers (viewer-dependent)

### 4) Annotation + form event completeness

* Enumerate events beyond the usual (E/X/U/D/Bl/Fo/PO/PC/PV/PI) across:

  * page annotations
  * form fields
  * document-level AA
* Graph: create standardized trigger nodes for each event path

---

# Phase 2 — Exploit chain synthesis maturity

### 5) Chain clustering & dedup

* Merge chains that share:

  * same trigger + same action object ref
  * or same payload ref + same container ref(s)
* Output both:

  * “unique chain templates”
  * “instances per template”

### 6) Scoring improvements (triage that matches reality)

Add scoring factors (all explainable):

* **Auto-trigger** confidence: OpenAction, doc AA, page open/close, timer-like events (viewer dependent)
* **Action class severity**: Launch > JS > EmbeddedFile/AF > SubmitForm > URI
* **Payload obfuscation**: use existing JS signals + add:

  * `js.string_concat_density`
  * `js.escape_density`
  * `js.regex_packing`
  * `js.suspicious_apis` (e.g., app.launchURL, util.printf abuse indicators—without executing)
* **Structural suspiciousness**:

  * unusual xref patterns, missing xref, incremental update abuse, object number jumps
  * multiple xref sections with conflicting offsets
  * ObjStm containing action dictionaries
* **Exploitability likelihood** (still heuristic):

  * presence of viewer-specific features (Acrobat JS APIs, RichMedia)
  * presence of malformed constructs (parser differentials)

### 7) “Path to payload” reconstruction upgrade

* Prefer exact structural paths:

  * Trigger → Action(ref) → Payload(ref) → (resolved bytes)
* Emit canonical chain path text:

  * stable for diffing between file versions
* Export chain subgraphs (DOT/JSON/GML) per chain

---

# Phase 3 — Malformation and parser differential analysis

### 8) Strict PDF grammar validation + deviation catalog

* Implement a “strict parse” mode that records:

  * tokenization anomalies (unbalanced delimiters, odd escapes)
  * invalid xref entries
  * illegal object constructs
  * stream length mismatches
* Findings include:

  * exact byte spans + decode context
  * classification: “likely exploit primitive vs benign corruption”

### 9) Cross-parser differential mode (very high signal)

* Parse the same PDF with:

  * your parser
  * a second independent Rust lib (or call out to a known tool in test harness only)
* Compare:

  * object counts
  * resolved refs
  * stream decode results
  * action extraction results
* Emit findings where parsers disagree (common exploit indicator)

---

# Phase 4 — Payload intelligence without execution

### 10) Static JS “feature extraction” (no deobfuscation)

* Token-level statistics:

  * identifier entropy, string literal ratios
  * suspicious API usage signatures (pattern-based)
  * iframe/url patterns, file path patterns
* Optional: AST parse in a *non-executing* JS parser mode (Boa parse-only)

  * collect imports/strings/calls
  * never run code

### 11) Embedded file triage

* Identify embedded file types by magic bytes (PDF embedded files, ZIP, EXE, scripts)
* Hash (SHA256), size, compression ratios
* Flag:

  * double extensions
  * executable MIME
  * encrypted containers

---

# Phase 5 — Performance, UX, and interactive workflows

### 12) Interactive mode performance work

* Add multi-stage pipeline:

  * **fast pre-scan** (xref/objstm/trigger enumeration)
  * **targeted deep scan** (only objects reachable from triggers)
  * **full scan** (optional)
* Caching:

  * stream decode cache keyed by (obj ref + filters + revision)
  * name tree cache
* Parallelism:

  * safe parallel traversal by object groups, with deterministic output ordering

### 13) Output formats and integrations

* Report formats:

  * JSONL streaming output (for interactive UI)
  * SARIF (for CI)
  * minimal “triage summary” + full detail
* Graph export:

  * chain-only graphs
  * global graph with chain overlays
* CLI ergonomics:

  * `sis scan file.pdf --fast`
  * `sis scan --focus trigger=openaction`
  * `sis export-graph --chains-only`

### 14) Rule system / configuration

* YAML rule tuning:

  * weights for scoring
  * allow/deny lists (domains, actions)
  * size/time budgets
* “profiles”:

  * `interactive`, `ci`, `forensics`

---

# Phase 6 — Hardening & test strategy (must-have for security tooling)

### 15) Corpus + regression harness

* Unit tests: xref/objstm parsing edge cases
* Golden tests: expected findings for known PDFs
* Fuzzing:

  * focus on tokenizer, xref parser, stream decoding
  * structured fuzzing around object boundaries
* Performance benchmarks:

  * per-stage timings
  * memory ceilings

### 16) Safety rails

* Hard resource budgets everywhere:

  * max recursion depth
  * max objects visited
  * max decoded bytes per stream
  * max total decoded bytes
* “taint” tracking:

  * mark data derived from suspicious constructs
  * propagate to chain scoring

---

# Suggested next 5 milestones (most bang-for-buck)

1. **Decode filtered `/JS` streams** + meta + scoring integration
2. **Resolve payload refs for `/URI`, `/F`, `/Launch`** (bytes/strings)
3. **Extend action/event coverage** (AcroForm/XFA/AF/EmbeddedFile)
4. **Chain dedup + chain subgraph export**
5. **Strict parse deviation findings** (malformations + byte spans)



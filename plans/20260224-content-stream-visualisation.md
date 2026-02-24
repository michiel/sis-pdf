# Content Stream Unpacking and Visualisation

**Date**: 2026-02-24
**Status**: Complete (Stages 1–3)

## Motivation

PDF content streams are the primary rendering instruction sets for pages. They encode text placement,
graphics state transformations, image inclusion, XObject invocations, and marked-content sections in
a compact postfix operator language. Currently `sis` can:

- decode and hexdump raw stream bytes (`sis query "stream N G --decode"`)
- detect high-entropy and suspicious patterns in stream bodies
- graph `ContentStreamExec` events in the event graph (which page executes which stream)

What is missing is a structured breakdown of *what the content stream does*: which operators fire in
which order, what text strings are placed, which XObjects and fonts are referenced and resolved to
actual PDF objects, and how the graphics state evolves. This is the forensic primitive needed to:

- identify obfuscated text rendering (e.g. character-by-character `Tj` with large kern offsets)
- trace XObject chains (Form XObjects that themselves execute further streams)
- visualise page construction order for triage explanation
- surface stream-embedded payloads that piggyback on normal rendering

The feature adds:
1. **CLI**: structured content stream query commands
2. **Core library**: operator grouping, resource resolution, and graph export
3. **GUI**: a Content Stream panel and a new graph mode wired into the existing graph viewer

---

## Architecture Overview

```
PDF bytes
  │
  ▼
sis-pdf-pdf::content::parse_content_ops()        [already exists]
  │
  ▼
Caller (sis-pdf or sis-pdf-core) resolves:       [NOT in sis-pdf-pdf]
  - decode_stream() → DecodedStream
  - build_page_tree() → page resources dict (with inheritance chain)
  │
  ▼
sis-pdf-pdf::content_summary::summarise_stream() [NEW — Stage 1]
  Resolves resources against caller-supplied /Resources dict
  Groups operators into ContentBlock hierarchy
  Annotates with object references
  │
  ├──▶ CLI: "page.content N" / "stream.content N G"  [NEW — Stage 2]
  │       text / JSON / JSONL output
  │
  ├──▶ CLI: "graph.content N G" / "graph.page.content N"  [NEW — Stage 2]
  │       DOT / JSON graph of operator sequence (built lazily from summary)
  │
  └──▶ GUI: ContentStreamPanel + GraphViewMode::ContentStream  [NEW — Stage 3]
              Structured operator list
              Graph viewer with operator nodes and resource edges
```

### Crate dependency constraint

`summarise_stream` lives in `sis-pdf-pdf` and **must not** depend on `sis-pdf-core`.
`build_page_tree` (and resource inheritance resolution) lives in `sis-pdf-core`. The caller
(CLI handler in `sis-pdf`, or detector in `sis-pdf-core`) is responsible for:

1. Calling `decode_stream` to obtain `DecodedStream.data` and `DecodedStream.truncated`.
2. Calling `build_page_tree` to locate the page dict.
3. Walking the page's `/Resources` dict including inherited resources from parent `/Pages` nodes.
4. Passing the fully resolved `resources: Option<&PdfDict>` and `truncated: bool` into
   `summarise_stream`.

---

## Data Model

### `ContentBlock` (new, in `sis-pdf-pdf`)

Groups raw `ContentOp` values into semantic blocks that model the nesting structure of a content
stream. Stored in document order; blocks are non-overlapping.

All `span_start`/`span_end` values are byte offsets within the **decoded** stream body, not within
the raw PDF file. See `raw_stream_offset` in `ContentStreamSummary` for navigation to the file
position.

```rust
pub enum ContentBlock {
    /// BT … ET — text object containing text positioning and string operators
    TextObject {
        ops: Vec<AnnotatedOp>,
        /// All Tf invocations inside this BT/ET block, in order.
        /// Each entry is (resource_key, resolved_ref). A block may use multiple fonts.
        fonts: Vec<(String, Option<(u32, u16)>)>,
        /// Best-effort text strings from Tj/TJ/' operators, in order.
        /// NOTE: these are raw PDF string bytes converted lossily to UTF-8.
        /// Proper decoding requires font ToUnicode CMaps and Encoding arrays,
        /// which are not resolved at this stage. Do not treat as unicode text.
        strings: Vec<String>,
        span_start: u64,
        span_end: u64,
    },
    /// q … Q — graphics state save/restore (may nest)
    GraphicsState {
        children: Vec<ContentBlock>,
        ctm_ops: Vec<AnnotatedOp>,       // cm operators inside
        span_start: u64,
        span_end: u64,
    },
    /// Do — XObject invocation
    XObjectInvoke {
        resource_name: String,           // e.g. "/Im0"
        target_ref: Option<(u32, u16)>, // resolved object reference
        subtype: Option<String>,         // "Image" or "Form"
        span_start: u64,
        span_end: u64,
    },
    /// BI … ID … EI — inline image
    InlineImage {
        width: Option<i32>,
        height: Option<i32>,
        color_space: Option<String>,
        span_start: u64,
        span_end: u64,
    },
    /// BMC/BDC … EMC — marked-content section
    MarkedContent {
        tag: String,
        properties: Option<String>,     // MCID property dict if BDC
        children: Vec<ContentBlock>,
        span_start: u64,
        span_end: u64,
    },
    /// Remaining ungrouped operators (path construction, colour, etc.)
    /// Runs of 3+ consecutive non-anomalous path/colour ops are collapsed
    /// into this variant to keep graph output manageable.
    Ops(Vec<AnnotatedOp>),
}

pub struct AnnotatedOp {
    pub op: ContentOp,
    /// Resolved PDF object reference for operator arguments that are resource names
    pub resolved_ref: Option<(u32, u16)>,
}
```

### `ContentStreamSummary` (new, in `sis-pdf-pdf`)

Top-level summary for one decoded content stream.

```rust
pub struct ContentStreamSummary {
    pub stream_ref: (u32, u16),
    pub page_ref: Option<(u32, u16)>,   // backlink to owning page (None for Form XObjects)
    /// Byte offset of the raw stream's data_span.start within the PDF file.
    /// Used by the GUI "Go to" button to navigate the hex viewer to the stream object.
    /// Distinct from span_start/span_end in ContentBlock, which are decoded-body offsets.
    pub raw_stream_offset: u64,
    pub blocks: Vec<ContentBlock>,
    pub stats: ContentStreamStats,
    pub anomalies: Vec<ContentStreamAnomaly>,
}

pub struct ContentStreamStats {
    pub total_op_count: usize,
    pub text_op_count: usize,   // Tj, TJ, ', " operators
    pub path_op_count: usize,   // m, l, c, v, y, h, re, S, s, f, F, B, B*, b, b*, n
    pub image_invoke_count: usize,
    pub form_xobject_invoke_count: usize,
    pub graphics_state_depth_max: usize,
    pub marked_content_depth_max: usize,
    pub unique_fonts: Vec<String>,     // resource keys e.g. ["/F1", "/F2"]
    pub unique_xobjects: Vec<String>,  // resource keys e.g. ["/Im0", "/Fm0"]
}

pub enum ContentStreamAnomaly {
    GraphicsStateUnderflow { op: String, position: u64 },
    TextObjectUnterminatedAtEof,
    /// Operator not in the known PDF operator set (see parser_divergence.rs allowlist).
    /// Only emitted outside BX/EX compatibility sections.
    UnknownOperator { op: String, position: u64 },
    ExcessiveKernOffset { value: f32, position: u64 }, // TJ kern > 200 units
    ZeroScaleText { position: u64 },                   // Tz 0 or Ts reducing size to zero
    /// Tr 3 sets text rendering mode to invisible. Correlates with content_invisible_text finding.
    InvisibleRenderingMode { position: u64 },
    HighOpCount { count: usize },
    /// decode_stream reported truncated output (truncated: true from DecodedStream).
    StreamTruncated,
}
```

### `ContentStreamGraph` (new, in `sis-pdf-pdf`)

Directed graph representation suitable for DOT/JSON export and GUI rendering. Built lazily from
`ContentStreamSummary` only when graph output is actually requested — do not build on every
`summarise_stream` call.

```rust
pub struct ContentStreamGraph {
    pub nodes: Vec<CsgNode>,
    pub edges: Vec<CsgEdge>,
}

pub enum CsgNodeKind {
    TextBlock { strings: Vec<String>, fonts: Vec<String> },
    XObjectRef { name: String, subtype: Option<String> },
    InlineImage { width: Option<i32>, height: Option<i32> },
    MarkedContent { tag: String },
    GraphicsState { depth: usize },
    OpGroup { label: String, count: usize }, // collapsed path/colour ops
    PdfObject { obj: u32, gen: u16, obj_type: String }, // resolved resource
}

pub struct CsgNode {
    pub id: String,         // stable, e.g. "blk_0", "obj_15_0"
    pub kind: CsgNodeKind,
    pub sequence: usize,    // document order index
    pub span_start: u64,
    pub span_end: u64,
    pub anomaly: bool,
}

pub struct CsgEdge {
    pub from: String,
    pub to: String,
    pub kind: CsgEdgeKind,
}

pub enum CsgEdgeKind {
    Sequence,          // A then B in document order
    ResourceRef,       // operator → resolved PDF object
    XObjectContains,   // Form XObject stream that itself contains blocks (recursive)
    Nesting,           // parent block → child block (q/Q, BT/ET, BMC/EMC)
}
```

---

## Stage 1 — Core Library: `content_summary` Module

**Goal**: New public module `sis_pdf_pdf::content_summary` that takes a decoded stream body and
page resources dict, and returns `ContentStreamSummary`.

**File**: `crates/sis-pdf-pdf/src/content_summary.rs`

### Functions

```rust
/// Summarise a single decoded content stream body.
///
/// `bytes` is the decoded (filter-decompressed) stream body from DecodedStream.data.
/// `truncated` should be set from DecodedStream.truncated — emits StreamTruncated anomaly.
/// `resources` is the fully resolved /Resources dict from the owning page or Form XObject,
///   including inherited resources from parent /Pages nodes. The caller (in sis-pdf or
///   sis-pdf-core, which has access to build_page_tree) is responsible for this resolution.
/// `raw_stream_offset` is PdfStream.data_span.start — used for hex viewer navigation in GUI.
pub fn summarise_stream(
    bytes: &[u8],
    truncated: bool,
    stream_ref: (u32, u16),
    page_ref: Option<(u32, u16)>,
    raw_stream_offset: u64,
    resources: Option<&PdfDict<'_>>,
    graph: &ObjectGraph<'_>,
) -> ContentStreamSummary

/// Resolve a resource name (e.g. b"/F1") against a /Resources dict.
/// Returns the target indirect reference if found.
/// Supports categories: "Font", "XObject", "ExtGState", "ColorSpace", "Pattern", "Shading".
fn resolve_resource(
    name: &[u8],
    category: &str,
    resources: &PdfDict<'_>,
    graph: &ObjectGraph<'_>,
) -> Option<(u32, u16)>

/// Build a ContentStreamGraph from a ContentStreamSummary.
/// Call lazily — only when DOT/JSON graph output or the GUI graph panel is requested.
pub fn build_content_graph(summary: &ContentStreamSummary) -> ContentStreamGraph

/// Render a ContentStreamGraph to Graphviz DOT.
pub fn content_graph_to_dot(graph: &ContentStreamGraph, title: &str) -> String

/// Render a ContentStreamGraph to JSON (serde_json::Value).
pub fn content_graph_to_json(graph: &ContentStreamGraph) -> serde_json::Value
```

### Resource resolution

Resources live in the page dict under `/Resources` as a dict with sub-categories:

```
/Resources <<
  /Font << /F1 15 0 R /F2 20 0 R >>
  /XObject << /Im0 30 0 R /Fm0 31 0 R >>
  /ExtGState << /GS1 40 0 R >>
>>
```

Resolution: parse the resource name from operator operands (e.g. `/F1` for `Tf`, `/Im0` for `Do`,
`/GS1` for `gs`), look up the corresponding category sub-dict in `/Resources`, find the matching
key, and follow the indirect reference. The `ObjectGraph::index` map provides O(1) lookup by
`(obj, gen)`.

**Resource inheritance**: PDF allows page dicts to omit `/Resources` and inherit from parent
`/Pages` nodes. The caller must walk the page tree upward and merge inherited resource dicts before
passing `resources` to `summarise_stream`. `build_page_tree` in `sis-pdf-core` traverses the
tree — the CLI/core handler that calls `summarise_stream` handles this. If `resources` is `None`,
all resolution returns `resolved_ref: None` without error.

**Operators that require resource resolution**:

| Operator | Resource category | Example operand |
|---|---|---|
| `Tf` | `Font` | `/F1` |
| `Do` | `XObject` | `/Im0` |
| `gs` | `ExtGState` | `/GS1` |
| `CS` / `cs` | `ColorSpace` | `/Cs1` |
| `SCN` / `scn` | `Pattern` | `/P1` |
| `sh` | `Shading` | `/Sh1` |

For this stage, `Font`, `XObject`, and `ExtGState` are the priority categories. Others are
resolved if present but not surfaced in anomaly detection.

### TJ kern extraction

`ContentOperand::Array` in the existing parser stores array tokens as raw strings (e.g.
`"[(abc) 120 (def) -300 (ghi)]"`). To detect excessive kern offsets, `summarise_stream` must
re-parse `TJ` array operands: scan the raw string for numeric tokens between string tokens and
extract `f32` values. This is a second-pass parse within the summariser, not a change to
`content.rs`. The threshold for `ExcessiveKernOffset` is ±200 units.

### BX/EX compatibility sections

`BX`/`EX` delimit compatibility sections (PDF spec §8.9.6) where unknown operators are explicitly
valid. The summariser must track a `compatibility_depth: usize` counter: increment on `BX`,
decrement on `EX`. `UnknownOperator` anomalies are suppressed when `compatibility_depth > 0`.
The operator allowlist for "unknown" detection should mirror the set in
`sis-pdf-detectors::parser_divergence` to avoid divergence between the two.

### Text string representation

`strings` in `TextObject` holds best-effort UTF-8 from `Tj`/`TJ`/`'`/`"` operands. Raw PDF
string bytes are lossily converted via `String::from_utf8_lossy`. This is **not** glyph-decoded
text — proper decoding requires font `ToUnicode` CMaps and `Encoding` arrays, which are complex
and deferred to a future stage. Callers and display code must not treat these values as human-readable
text for all fonts. Prefix hex strings with `<` to distinguish from literal strings in display.

### Anomaly detection during summarisation

- Graphics state underflow: `Q` without preceding `q` at same nesting level
- Unterminated `BT` at EOF
- `TJ` kern offsets > ±200 units (text hiding / obfuscation) — requires re-parsing Array operand
- `Tz` (horizontal scale) = 0 → `ZeroScaleText`
- `Tr 3` (invisible rendering mode) → `InvisibleRenderingMode`; correlates with the existing
  `content_invisible_text` finding produced by `content_phishing.rs` / `content_index.rs`
- Op count > 50,000 → `HighOpCount`
- Unknown operators outside BX/EX sections
- `DecodedStream.truncated == true` → `StreamTruncated`

### Relation to existing `content_index.rs`

`content_index.rs` already walks page content streams to build `PageContent` (text/image points,
invisible text flag via `Tr 3`, media box). `summarise_stream` will duplicate this traversal.
This duplication is acceptable because the two serve different purposes (ML feature extraction vs.
forensic structured output) and operate independently. Do not refactor `content_index.rs` as part
of this plan. Ensure that anomaly detection logic for `Tr 3` matches the existing condition
(`(v - 3.0).abs() < f32::EPSILON`) for consistency.

### Type 3 CharProc streams

Type 3 font character procedures (`/CharProc` streams) are valid content streams that accept the
same operator set as page streams. `summarise_stream` handles them with the same code path.
The `structural-type3-charproc-abuse-f942b416.pdf` fixture exercises this. The "View content
operators" button (Stage 3a) should trigger on objects classified as `ObjectRole::PageContent`
**or** on objects that are Type 3 CharProc streams (identified by the parent font dict's
`/Subtype /Type3` and `/CharProcs` keys).

### OpGroup collapsing

Runs of **3 or more consecutive non-anomalous** path/colour operators outside BT/ET blocks are
collapsed into `ContentBlock::Ops` for graph output. Anomalous operators (e.g. those within a
block that triggered an anomaly) are never collapsed. The threshold of 3 prevents single path
commands from creating excessive graph nodes while keeping short sequences visible.

### Tests

**Primary fixture**: `crates/sis-pdf-core/tests/fixtures/content_first_phase1.pdf` for all Stage 1
real-world tests. `launch_cve_2010_1240.pdf` for a hostile-document smoke test.

Unit tests in `crates/sis-pdf-pdf/tests/`:

- `parse_and_summarise_simple_page`: synthetic stream with BT/ET, q/Q, Do
- `resolve_font_reference`: mock `ObjectGraph` with `/Resources /Font` dict
- `resolve_xobject_reference`: Image and Form XObject
- `resolve_extgstate_reference`: `gs` operator → `/ExtGState`
- `detect_graphics_state_underflow`: Q without q
- `detect_excessive_kern`: TJ with large kern value (re-parses Array operand)
- `detect_zero_scale_text`: Tz 0 operator
- `detect_invisible_rendering_mode`: Tr 3 operator
- `detect_truncated_stream`: truncated=true propagates to StreamTruncated anomaly
- `suppress_unknown_op_in_bx_ex`: unknown op between BX/EX emits no anomaly
- `unknown_op_outside_bx_ex_emits_anomaly`: unknown op outside BX/EX emits UnknownOperator
- `multiple_fonts_in_single_text_object`: two Tf calls inside one BT/ET → two entries in fonts vec
- `content_graph_to_dot_is_valid_syntax`: smoke test DOT output
- `type3_charproc_stream`: synthetic CharProc stream summarises without panic

**Success criteria**: `summarise_stream` returns correct `ContentStreamSummary` for a real-world
page content stream decoded from `content_first_phase1.pdf`, with correct font and XObject
resolution.

**Status**: Complete

---

## Stage 2 — CLI: New Query Commands

**Goal**: Expose `content_summary` through `sis query` with text, JSON, and DOT output.

### New `Query` variants (in `sis-pdf/src/commands/query.rs`)

```rust
// Structured operator breakdown for a stream object
StreamContentOps { obj: u32, gen: u16 },
StreamContentOpsJson { obj: u32, gen: u16 },

// Same but looked up by page index (0-based)
// Returns summaries for all content streams on the page (Contents may be an array).
PageContentOps { page_idx: usize },
PageContentOpsJson { page_idx: usize },

// Graph export — content stream as operator/resource graph
GraphContentStreamDot { obj: u32, gen: u16 },
GraphContentStreamJson { obj: u32, gen: u16 },
GraphPageContentDot { page_idx: usize },
GraphPageContentJson { page_idx: usize },
```

### Query string surface

```
stream.content N G           - text operator breakdown for stream object N G
stream.content.json N G      - JSON breakdown
page.content N               - text operator breakdown for page N (0-based)
page.content.json N          - JSON breakdown
graph.content N G            - DOT graph for stream object N G
graph.content.json N G       - JSON graph for stream object N G
graph.page.content N         - DOT graph for page N
graph.page.content.json N    - JSON graph for page N
```

These slot into the existing `parse_query()` dispatch in `query.rs` following the same pattern as
the existing `stream N G` and `graph.event.stream` variants.

### Multiple content streams per page

A page's `/Contents` may be a single stream ref or an array of stream refs that are concatenated
during rendering. `page.content N` and related variants produce **one summary per stream** in the
array, presented sequentially in text output and as a JSON array at the top level. For DOT output,
each stream is a separate graph — they are rendered as separate digraph blocks in the same file if
there are multiple. This matches the existing `content_index.rs` behaviour in `page_contents_streams`.

### Page lookup and resource resolution in CLI handlers

The CLI handler for `PageContentOps` / `GraphPageContentDot` etc. must:

1. Call `sis_pdf_core::page_tree::build_page_tree(&graph)` to get the page list.
2. Index by `page_idx` to get the page's `(obj, gen)`.
3. Look up the page dict via `graph.get_object(obj, gen)`.
4. Resolve `/Resources` with inheritance: walk parent `/Pages` nodes and merge resource dicts,
   with the page's own dict taking precedence. This traversal uses `build_page_tree` internals or
   a new `resolve_page_resources(graph, page_obj, page_gen) -> Option<PdfDict>` helper in
   `sis-pdf-core::page_tree`.
5. Pass the decoded bytes, resolved resources, and `data_span.start` to `summarise_stream`.

For `StreamContentOps`, the handler must verify the object is a stream object (reject with
`QueryResult::Error { error_code: "NOT_A_STREAM" }` if not) and identify its owning page by
scanning for a `PageContents` edge in the typed graph.

### Text output format for `stream.content` / `page.content`

Human-readable, triage-oriented. Example for a simple page:

```
Content stream 15 0  (page 3)
  Stats: 42 ops · 2 text objects · 1 image · 0 form XObjects · max q-depth 2
  Anomalies: none

  [0] GraphicsState (q…Q)
    [0.0] cm  1 0 0 1 72 720
    [0.1] TextObject (BT…ET)  fonts: /F1 → 8 0 R  strings: ["Hello, world"]
            Td 0 -12 · Tf /F1 12 · Tj "Hello, world"
    [0.2] XObjectInvoke /Im0 → 30 0 R  [Image 200×150]
  [1] Ops (path/colour)  3 ops
```

### JSON output format for `page.content.json`

```json
{
  "stream_ref": [15, 0],
  "page_ref": [7, 0],
  "raw_stream_offset": 4096,
  "stats": {
    "total_op_count": 42,
    "text_op_count": 12,
    "path_op_count": 8,
    "image_invoke_count": 1,
    "form_xobject_invoke_count": 0,
    "graphics_state_depth_max": 2,
    "unique_fonts": ["/F1"],
    "unique_xobjects": ["/Im0"]
  },
  "anomalies": [],
  "blocks": [
    {
      "type": "GraphicsState",
      "span": [120, 850],
      "children": [
        { "type": "TextObject", "fonts": [["/F1", [8, 0]]], "strings": ["Hello, world"],
          "span": [200, 350], "ops": [...] },
        { "type": "XObjectInvoke", "name": "/Im0", "target_ref": [30, 0],
          "subtype": "Image", "span": [351, 420] }
      ]
    },
    { "type": "Ops", "count": 3, "span": [421, 500] }
  ]
}
```

### Tests (integration, `crates/sis-pdf/tests/`)

- `stream_content_query_returns_blocks`: against `content_first_phase1.pdf`
- `stream_content_hostile_fixture`: against `launch_cve_2010_1240.pdf`
- `page_content_query_resolves_page_zero`: benign fixture, verifies resource inheritance
- `page_content_multiple_streams`: page with array `/Contents` returns multiple summaries
- `graph_content_dot_is_renderable`: emits valid DOT; gated behind `#[cfg_attr(not(feature = "ci_dot"), ignore)]` or `SKIP_DOT_TEST` env var — do not use runtime skip without marking `#[ignore]`
- `page_content_out_of_range_returns_error`: `QueryResult::Error`
- `stream_content_non_stream_object_returns_error`: `QueryResult::Error { error_code: "NOT_A_STREAM" }`
- `page_content_json_is_valid`: JSON output parses and `stream_ref` field is present

**Success criteria**: All four output modes work against `content_first_phase1.pdf` and
`launch_cve_2010_1240.pdf`. DOT output renders without error via Graphviz.

**Status**: Complete

---

## Stage 3 — GUI: Content Stream Panel and Graph Mode

**Goal**: Surface content stream information in the GUI with (a) a structured list panel and (b) an
extended graph viewer mode.

### 3a — Content Stream Panel

**File**: `crates/sis-pdf-gui/src/panels/content_stream.rs` (new)

#### Panel state

```rust
pub struct ContentStreamPanelState {
    /// Currently displayed stream (object reference)
    pub active_stream: Option<(u32, u16)>,
    /// Cached summary for active stream
    pub summary: Option<ContentStreamSummaryView>,
    /// Expanded state for each top-level block (by index)
    pub expanded: HashMap<usize, bool>,
    /// Selected block index (drives graph highlight)
    pub selected_block: Option<usize>,
    /// Show anomalies only toggle
    pub anomalies_only: bool,
    /// Scroll position
    pub scroll_offset: f32,
}
```

`ContentStreamSummaryView` is a GUI-side mirror of `ContentStreamSummary` with pre-formatted
strings (to avoid re-formatting on every frame in the immediate-mode loop).

#### How it is triggered

Three entry points navigate to the content stream panel:

1. **From the Objects panel**: when viewing a stream object that is a content stream, identified by
   `ObjectRole::PageContent` from the classification map **or** by membership in a Type 3 font's
   `/CharProcs` dict. Use `graph.classify_objects()` for this check — do not scan event records.
   A "View content operators" button appears in the object header.

2. **From the Events panel**: clicking a `ContentStreamExec` event row opens the stream panel for
   that stream (using the `execute_target` field from the event record).

3. **From the command bar**: `page.content N` or `stream.content N G` — the GUI query parser (in
   `sis-pdf-gui/src/query.rs`) maps them to `Query::ContentStream { ... }` and opens the panel.

#### Panel layout (egui)

```
┌─ Content Stream: 15 0 (Page 3) ───────────────────────── [Show in graph] [x] ─┐
│  42 ops · 2 text · 1 image · max q-depth 2  [Anomalies only ☐]               │
├───────────────────────────────────────────────────────────────────────────────┤
│ ▼ [0] GraphicsState  q…Q                                        [Go to obj] │
│   ▼ [0.0] cm  1 0 0 1 72 720                                                 │
│   ▼ [0.1] TextObject  BT…ET  /F1 → obj 8 0                       [Ref 8 0] │
│       Tf /F1 12 · Td 0 -12 · Tj "Hello, world"                              │
│   ► [0.2] XObjectInvoke /Im0 → obj 30 0  [Image 200×150]         [Ref 30 0]│
│ ► [1] Ops (path/colour)  3 ops                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

- Tree-view collapsible blocks with `▼`/`►` disclosure
- Anomalous blocks highlighted in amber (matching the severity colour scheme)
- `[Ref N G]` buttons navigate the Object Inspector to the resolved resource
- `[Show in graph]` switches the graph viewer to ContentStream mode for this stream
- `[Go to obj]` scrolls the hex viewer to `raw_stream_offset` (start of the raw stream data in
  the PDF file). Note: this navigates to the stream object's position in the file, not to a decoded
  byte offset. Decoded `span_start`/`span_end` are shown as informational offsets only.

#### Integration into `SisApp`

Add to `SisApp`:
```rust
pub show_content_stream: bool,
pub content_stream_state: ContentStreamPanelState,
```

The panel is a floating window (following the same pattern as `show_events`, `show_objects`, etc.)
toggled from the View menu and from the trigger points listed above.

Analysis: the `ContentStreamSummaryView` is computed on demand when `active_stream` changes.
Computation calls `sis_pdf_pdf::content_summary::summarise_stream` directly — synchronous on
already-decoded bytes, adequate for typical streams (< 1 MB decoded). For very large streams
(> 500 KB), computation is deferred via the existing native analysis channel or a `OnceLock` guard.
The caller in the GUI layer must supply the resolved resources dict (via its own page tree
traversal) and `raw_stream_offset` from the object graph.

---

### 3b — Graph Viewer: `ContentStream` Mode

**File**: `crates/sis-pdf-gui/src/panels/graph.rs` (extend), `graph_data.rs` (extend)

#### New `GraphViewMode`

```rust
pub enum GraphViewMode {
    Structure,
    Event,
    StagedDag,
    ContentStream { stream_ref: (u32, u16) },   // NEW
}
```

#### Graph population

When `ContentStream { stream_ref }` is the active mode, the graph viewer calls a new function:

```rust
// in graph_data.rs
pub fn from_content_graph(csg: &ContentStreamGraph) -> GraphData
```

This converts `CsgNode`/`CsgEdge` to `GraphNode`/`GraphEdge`. Mappings:

| `CsgNodeKind` | `GraphNode.obj_type` | Colour |
|---|---|---|
| `TextBlock` | `"content_text"` | Blue |
| `XObjectRef` (Image) | `"content_image"` | Green |
| `XObjectRef` (Form) | `"content_form_xobj"` | Teal |
| `InlineImage` | `"content_inline_image"` | Green |
| `MarkedContent` | `"content_marked"` | Grey |
| `GraphicsState` | `"content_gstate"` | Light grey |
| `OpGroup` | `"content_ops"` | Light grey |
| `PdfObject` | `"object"` | (existing colour for obj_type) |

Edge kinds map to:
- `Sequence` → thin grey arrow (document order)
- `ResourceRef` → dashed blue arrow (resolves to)
- `XObjectContains` → dashed teal arrow (contains)
- `Nesting` → solid light grey (parent–child nesting)

#### Layout

Sequence edges form a left-to-right chain (or top-to-bottom for tall graphs). Resource and nesting
edges are lateral. The existing DAG layout engine in `graph_layout.rs` handles this natively; the
`sequence` field on `CsgNode` provides the topological sort key.

#### Highlighting

When the user selects a block in the Content Stream panel, the corresponding node in the graph
viewer is highlighted (gold border, same as the existing finding-selection highlight). The link is
by `CsgNode.id` ↔ block index. Conversely, clicking a graph node focuses the content stream panel
on that block.

#### Navigation from graph node

Right-click / double-click on:
- A `PdfObject` node → navigates Object Inspector to that reference (existing behaviour)
- A `TextBlock` node → scrolls content stream panel to that block
- An `XObjectRef` node with subtype Form → (future) opens a nested content stream panel for
  the Form XObject's own content stream (recursive visualisation, Stage 4)

#### Mode switching

The graph viewer mode selector (existing radio buttons or dropdown) gains a "Content" option. It is
only enabled when a content stream is active (i.e., `content_stream_state.active_stream` is
`Some`). Switching to Content mode automatically loads the graph for the active stream.

**Status**: Complete

---

## Stage 4 — Recursive Form XObject Visualisation

**Goal**: Follow Form XObject references transitively — collecting a `ContentStreamSummary` for
each reachable Form stream and integrating them into the graph with `XObjectContains` edges. Expose
this through a `--recursive` CLI flag and an "Expand Form XObjects" toggle in the GUI panel.

**Status**: Not Started

### 4.1 — Background and constraints

Form XObjects (`/Subtype /Form`) are reusable content streams referenced via `Do` operators.
The `ContentBlock::XObjectInvoke` block already captures `resource_name`, `target_ref: Option<(u32, u16)>`,
and `subtype: Some("Form")` for resolved Form XObjects. The `CsgEdgeKind::XObjectContains` edge type
is defined in `content_summary.rs` but currently never emitted — `build_content_graph` treats Form
XObjects as opaque leaf nodes.

Key constraints:

- `summarise_stream` takes borrowed references (`bytes: &[u8]`, `resources: Option<&PdfDict<'_>>`,
  `graph: &ObjectGraph<'_>`). Form XObject streams live in the same `ObjectGraph`, so child summaries
  can be computed within the same borrow scope.
- Form XObjects carry their own `/Resources` dict (PDF spec §8.10.3). The child summary must use
  the Form's own resource dict, not the parent page's. If the Form dict has no `/Resources`, pass
  `None`.
- Circular references (`Fm0 → Fm1 → Fm0`) must be detected via a `visited: HashSet<(u32, u16)>`.
  Default depth limit: 5. Both limits apply independently — stop whichever is reached first.
- Stage 4 is additive: the non-recursive path (current Stage 1–3 behaviour) must remain unchanged.

### 4.2 — New data model: `RecursiveContentSummary`

**File**: `crates/sis-pdf-pdf/src/content_summary.rs`

```rust
/// Top-level summary for a content stream and all reachable Form XObject sub-streams.
///
/// Produced by `summarise_xobject_tree`. The `root` field is identical to what
/// `summarise_stream` would return for the same stream. `xobject_children` is empty
/// when called without recursion (equivalent to the non-recursive API).
#[derive(Debug, Clone)]
pub struct RecursiveContentSummary {
    /// Summary for the directly-requested stream.
    pub root: ContentStreamSummary,
    /// Summaries for all Form XObject streams reachable from `root`, keyed by stream ref.
    /// Populated in breadth-first order up to `depth_limit` hops from root.
    pub xobject_children: HashMap<(u32, u16), ContentStreamSummary>,
}
```

### 4.3 — New function: `summarise_xobject_tree`

**File**: `crates/sis-pdf-pdf/src/content_summary.rs`

```rust
/// Summarise a content stream and, recursively, all Form XObjects it invokes.
///
/// `depth_limit` caps transitive Form XObject depth (default: 5). Set to 0 for
/// non-recursive behaviour (equivalent to calling `summarise_stream` directly).
/// `visited` tracks stream refs already processed to break cycles; callers should
/// pass an empty set.
///
/// For each Form XObject in `root.blocks` with `subtype == Some("Form")` and a resolved
/// `target_ref`, this function:
/// 1. Looks up the Form stream via `graph.get_object(target_ref.0, target_ref.1)`.
/// 2. Decodes it via `decode_stream(bytes, stream, MAX_DECODE_BYTES)`.
/// 3. Reads the Form's own `/Resources` from its stream dict; falls back to `None`.
/// 4. Calls `summarise_stream` on the decoded bytes with `page_ref: None`.
/// 5. Recurses into the child summary's blocks.
///
/// The function does not mutate `bytes` and makes no heap allocation beyond the
/// returned `RecursiveContentSummary`.
pub fn summarise_xobject_tree(
    bytes: &[u8],
    truncated: bool,
    stream_ref: (u32, u16),
    page_ref: Option<(u32, u16)>,
    raw_stream_offset: u64,
    resources: Option<&PdfDict<'_>>,
    graph: &ObjectGraph<'_>,
    depth_limit: usize,
    visited: &mut HashSet<(u32, u16)>,
) -> RecursiveContentSummary
```

Internal helper called by `summarise_xobject_tree` (private):

```rust
fn collect_form_xobject_children(
    bytes: &[u8],
    summary: &ContentStreamSummary,
    graph: &ObjectGraph<'_>,
    depth: usize,
    depth_limit: usize,
    visited: &mut HashSet<(u32, u16)>,
    out: &mut HashMap<(u32, u16), ContentStreamSummary>,
)
```

`collect_form_xobject_children` scans `summary.blocks` recursively (handling `GraphicsState` and
`MarkedContent` children) for `ContentBlock::XObjectInvoke { subtype: Some("Form"), target_ref: Some(r), .. }`,
then for each unvisited `r` decodes and summarises the child stream and recurses.

### 4.4 — Updated graph builder: `build_content_graph_recursive`

**File**: `crates/sis-pdf-pdf/src/content_summary.rs`

The existing `build_content_graph(summary)` remains unchanged (non-recursive). Add:

```rust
/// Build a ContentStreamGraph including XObjectContains edges to child Form XObject summaries.
///
/// For each `XObjectInvoke` node with `subtype == Some("Form")` whose `target_ref` appears in
/// `child_summaries`, this function:
/// 1. Adds all nodes/edges from the child's graph inline, with ids prefixed `"child_{obj}_{gen}_"`.
/// 2. Creates a `CsgEdge { from: xobj_node_id, to: child_first_node_id, kind: XObjectContains }`.
///
/// `child_summaries` is typically `RecursiveContentSummary.xobject_children`.
pub fn build_content_graph_recursive(
    summary: &ContentStreamSummary,
    child_summaries: &HashMap<(u32, u16), ContentStreamSummary>,
) -> ContentStreamGraph
```

The DOT renderer already assigns colour `"#44aa88"` and label `"contains"` to `XObjectContains`
edges (`content_graph_to_dot`); no change needed there.

### 4.5 — CLI changes

**File**: `crates/sis-pdf/src/commands/query.rs`

Add `--recursive` / `-r` bool flag to the `stream.content`, `page.content`, `graph.content`, and
`graph.page.content` query variants. This maps to a new `recursive: bool` field on the relevant
`Query` enum variants:

```rust
StreamContentOps     { obj: u32, gen: u16, recursive: bool },
StreamContentOpsJson { obj: u32, gen: u16, recursive: bool },
GraphContentStreamDot  { obj: u32, gen: u16, recursive: bool },
GraphContentStreamJson { obj: u32, gen: u16, recursive: bool },
GraphPageContentDot    { page_idx: usize,    recursive: bool },
GraphPageContentJson   { page_idx: usize,    recursive: bool },
```

Query string surface (new variants alongside existing ones):

```
stream.content.recursive N G         — text breakdown, follows Form XObjects
stream.content.json.recursive N G    — JSON breakdown
graph.content.recursive N G          — DOT graph with XObjectContains edges
graph.content.json.recursive N G     — JSON graph with XObjectContains edges
graph.page.content.recursive N       — DOT graph for page (all streams + Form children)
graph.page.content.json.recursive N
```

When `recursive: true`, `decode_and_summarise_stream` calls `summarise_xobject_tree` instead of
`summarise_stream`, and the graph builder calls `build_content_graph_recursive` instead of
`build_content_graph`.

**Text output for recursive mode**: each Form XObject child is printed as an indented sub-section
prefixed with `  [Form XObject N G]\n` before its own `summary_to_text` output.

**JSON output for recursive mode**: the top-level JSON object gains an `"xobject_children"` key:

```json
{
  "stream_ref": [15, 0],
  "blocks": [...],
  "stats": {...},
  "anomalies": [...],
  "xobject_children": {
    "31 0": { "stream_ref": [31, 0], "blocks": [...], ... },
    "32 0": { "stream_ref": [32, 0], "blocks": [...], ... }
  }
}
```

### 4.6 — GUI changes

**File**: `crates/sis-pdf-gui/src/panels/content_stream.rs`

Extend `ContentStreamPanelState`:

```rust
pub struct ContentStreamPanelState {
    pub active_stream: Option<(u32, u16)>,
    pub summary: Option<ContentStreamSummary>,
    pub expanded: HashMap<usize, bool>,
    pub selected_block: Option<usize>,
    pub anomalies_only: bool,
    /// Lazy-loaded Form XObject child summaries. Populated on demand when the user
    /// clicks "Expand Form XObjects". Keyed by stream ref.
    pub xobject_children: HashMap<(u32, u16), ContentStreamSummary>,
    /// Whether Form XObject children are currently expanded in the tree view.
    pub show_xobject_children: bool,
}
```

UI additions in `show_inner`:

- "Expand Form XObjects" toggle button in the header bar, visible only when the summary contains
  at least one `XObjectInvoke` block with `subtype == Some("Form")` and a resolved `target_ref`.
- When toggled on, `open_stream` is called for each unloaded Form XObject ref (depth 1 only; the
  user must click through for deeper nesting). Results are stored in `xobject_children`.
- Each `XObjectInvoke` row with an expanded child renders the child's block tree inline, indented,
  under a collapsible `"Form XObject N G"` header with the child's anomaly badge.

**Graph viewer** (`graph.rs` / `graph_data.rs`):

When the active mode is `ContentStream` and `show_xobject_children` is true,
`build_content_stream_graph_for_gui` calls `build_content_graph_recursive` passing
`app.content_stream_state.xobject_children`. The resulting graph will contain `XObjectContains`
edges rendered as dashed teal arrows.

### 4.7 — Tests

**Unit tests** (`crates/sis-pdf-pdf/tests/`):

- `summarise_xobject_tree_form_xobject_depth_1`: synthetic PDF bytes with a page stream invoking
  a Form XObject; assert `xobject_children` has one entry with correct `stream_ref`.
- `summarise_xobject_tree_cycle_detection`: stream A invokes Form B, Form B invokes Form A;
  assert no panic and only one entry in `xobject_children` (cycle broken at depth 2).
- `summarise_xobject_tree_depth_limit`: chain of 6 nested Forms; assert `xobject_children.len() == 5`
  (depth limit 5 honoured).
- `build_content_graph_recursive_emits_xobject_contains_edge`: `child_summaries` with one entry;
  assert graph contains at least one edge with `kind == XObjectContains`.
- `summarise_xobject_tree_form_resources`: Form XObject with its own `/Resources /Font` dict;
  assert child summary resolves font refs correctly.

**Integration tests** (`crates/sis-pdf/tests/`):

- `stream_content_recursive_follows_form_xobject`: fixture with page → Form chain; assert
  `xobject_children` key count > 0 in JSON output.
- `graph_content_recursive_emits_contains_edge_dot`: DOT output contains the string `"contains"`.

**Success criteria**: `summarise_xobject_tree` on `content_first_phase1.pdf` returns a
`RecursiveContentSummary` where `xobject_children` is non-empty if the page uses Form XObjects,
and empty otherwise. No panic on a 6-deep Form XObject chain or a circular reference.

---

## Stage 5 — Findings Integration

**Goal**: Correlate `ContentStreamAnomaly` values with existing detector findings, surface matched
findings in the content stream panel (with severity highlighting), and annotate graph nodes that
correspond to active findings.

**Status**: Not Started

### 5.1 — Anomaly-to-finding correlation table

The following anomalies produced by `summarise_stream` correspond to findings from existing detectors:

| Anomaly variant | Finding kind | Detector | Correlation key |
|---|---|---|---|
| `InvisibleRenderingMode` | `content_invisible_text` | `ContentDeceptionDetector` | page ref matches finding's `objects[]` |
| `ExcessiveKernOffset` | `content_invisible_text` | `ContentDeceptionDetector` | page ref matches finding's `objects[]` |
| `ZeroScaleText` | `content_invisible_text` | `ContentDeceptionDetector` | page ref matches finding's `objects[]` |
| — (stream-level) | `stream_high_entropy` | `EncryptionObfuscationDetector` | stream ref matches finding's `objects[]` |
| — (stream-level) | `stream_zlib_bomb` | `EncryptionObfuscationDetector` | stream ref matches finding's `objects[]` |

The `content_invisible_text` finding's `objects` field contains the page object ref string
(`"P 0 obj"` format, produced by `content_phishing.rs:419`). Stream-level findings use the stream
object ref string directly.

### 5.2 — New type: `CorrelatedFinding`

**File**: `crates/sis-pdf-gui/src/panels/content_stream.rs`

```rust
/// A finding from the scan report correlated to the active content stream.
#[derive(Debug, Clone)]
pub struct CorrelatedFinding {
    /// Finding ID (for navigating to the findings panel).
    pub finding_id: String,
    /// Finding kind string (e.g. `"content_invisible_text"`).
    pub kind: String,
    pub severity: sis_pdf_core::model::Severity,
    pub confidence: sis_pdf_core::model::Confidence,
    pub title: String,
    /// Which anomaly in the stream summary this finding correlates to, if any.
    /// Matches on anomaly variant name, e.g. `"InvisibleRenderingMode"`.
    pub anomaly_hint: Option<String>,
    /// Decoded stream byte offset of the matching evidence span, if the finding
    /// carries an `EvidenceSource::Decoded` span that falls within this stream.
    pub decoded_offset: Option<u64>,
}
```

### 5.3 — Correlation function

**File**: `crates/sis-pdf-gui/src/panels/content_stream.rs`

```rust
/// Collect findings from `report` that are correlated to stream `stream_ref` / page `page_ref`.
///
/// Correlation rules (applied in order, all matching findings are included):
/// 1. Finding's `objects` list contains `"N G obj"` for stream_ref or page_ref.
/// 2. Finding has at least one `EvidenceSource::Decoded` evidence span whose `offset` falls
///    within `[raw_stream_offset, raw_stream_offset + decoded_stream_len]`.
/// 3. Finding kind is in STREAM_FINDING_KINDS and finding's `objects` contains stream_ref.
///
/// Deduplicates by `finding.id`. Returns findings sorted by severity (highest first).
fn correlate_findings(
    report: &sis_pdf_core::model::Report,
    stream_ref: (u32, u16),
    page_ref: Option<(u32, u16)>,
    raw_stream_offset: u64,
    decoded_stream_len: u64,
) -> Vec<CorrelatedFinding>
```

The set `STREAM_FINDING_KINDS` is a `const` slice:

```rust
const STREAM_FINDING_KINDS: &[&str] = &[
    "stream_high_entropy",
    "stream_zlib_bomb",
    "content_invisible_text",
    "content_image_only_page",
    "content_overlay_link",
];
```

The function parses `finding.objects` strings via a simple pattern `"N G obj"` → `(N, G): (u32, u16)`.
It does not depend on the `ObjectContextIndex` to avoid a second pass over all findings.

### 5.4 — Panel state extension

**File**: `crates/sis-pdf-gui/src/panels/content_stream.rs`

Extend `ContentStreamPanelState` (in addition to the Stage 4 fields):

```rust
pub struct ContentStreamPanelState {
    // ... existing fields ...
    // NEW for Stage 5:
    /// Findings correlated to the active stream. Populated when `active_stream` changes.
    pub correlated_findings: Vec<CorrelatedFinding>,
    /// Show only blocks/anomalies that match a correlated finding.
    pub findings_only: bool,
}
```

Populate in `open_stream` after computing `summary`:

```rust
if let (Some(ref summary), Some(ref result)) =
    (&app.content_stream_state.summary, &app.result)
{
    let decoded_len = /* estimate from summary.stats.total_op_count or store in summary */;
    app.content_stream_state.correlated_findings = correlate_findings(
        &result.report,
        stream_ref,
        summary.page_ref,
        summary.raw_stream_offset,
        decoded_len,
    );
}
```

To support `decoded_len`, add `decoded_len: u64` to `ContentStreamSummary` (set from
`decoded.data.len()` in `summarise_stream`'s caller — in `decode_and_summarise_stream` for CLI and
`compute_stream_summary` for GUI).

### 5.5 — Panel UI changes

**File**: `crates/sis-pdf-gui/src/panels/content_stream.rs`

In `show_inner`:

**Findings bar** (new section between stats and anomalies):

```
┌─ Content Stream: 15 0 ──────────────────────────────────────────────────────┐
│  42 ops · 2 text · 1 image · max q-depth 2                                  │
│  Findings:  ● content_invisible_text [Low/Heuristic]  [Go to finding]       │
│  Anomalies: 1  [Show anomalies only ☐]  [Show findings only ☐]              │
├─────────────────────────────────────────────────────────────────────────────┤
```

- Each `CorrelatedFinding` is shown as a coloured badge (`●`) with severity colour (matching the
  existing `severity_colour()` helper from `panels/findings.rs`).
- `[Go to finding]` sets `app.selected_finding` to the index of that finding in `result.report.findings`
  and opens `app.show_findings = true`.
- The `findings_only` toggle collapses all blocks except those whose anomaly variant appears in
  `correlated_findings[].anomaly_hint`.

**Block-level finding highlight**: In `show_block`, when rendering a `TextObject` or
`XObjectInvoke` block, check whether any `CorrelatedFinding` has a `decoded_offset` whose value
falls within `[span_start, span_end]`. If so, render the block label with amber background colour
(`egui::Color32::from_rgb(255, 220, 120)`) and append `[Finding: content_invisible_text]`.

### 5.6 — Graph node annotation

**File**: `crates/sis-pdf-gui/src/graph_data.rs`

In `from_content_graph`, pass `correlated_findings: &[CorrelatedFinding]` as an additional
parameter. For each `CsgNode`, if a finding's `decoded_offset` falls within
`[node.span_start, node.span_end]`, set `node.anomaly = true` (already exists on `CsgNode`) and
append `\n[finding_kind]` to the node label.

Update `from_content_graph` signature:

```rust
pub fn from_content_graph(
    csg: &sis_pdf_pdf::content_summary::ContentStreamGraph,
    correlated_findings: &[crate::panels::content_stream::CorrelatedFinding],
) -> Result<GraphData, GraphError>
```

Update the call site in `build_content_stream_graph_for_gui` (graph.rs):

```rust
fn build_content_stream_graph_for_gui(app: &mut SisApp) -> Result<GraphData, GraphError> {
    let summary = app.content_stream_state.summary.as_ref().ok_or_else(|| {
        GraphError::ParseFailed("No content stream summary available.".to_string())
    })?;
    let findings = &app.content_stream_state.correlated_findings;
    let csg = sis_pdf_pdf::content_summary::build_content_graph(summary);
    graph_data::from_content_graph(&csg, findings)
}
```

Graph nodes that correspond to a finding have their colour overridden to amber (severity High/Critical)
or yellow (Medium/Low) in `node_colour` by checking `node.anomaly`. This reuses the existing
`anomaly: bool` field on `CsgNode` — no new fields needed.

### 5.7 — CLI: `--with-findings` flag

**File**: `crates/sis-pdf/src/commands/query.rs`

Add `with_findings: bool` to `StreamContentOps`, `StreamContentOpsJson`, `PageContentOps`,
`PageContentOpsJson` variants. When true, `execute_stream_content_ops` runs `correlate_findings`
(reusing the same logic as the GUI) and appends a `"correlated_findings"` section to both text and
JSON output.

Text output addition (appended after stats):

```
  Correlated findings:
    ● content_invisible_text [Low/Heuristic]  id: abc123
```

JSON output addition (new top-level key):

```json
"correlated_findings": [
  { "id": "abc123", "kind": "content_invisible_text", "severity": "Low",
    "confidence": "Heuristic", "title": "Invisible text rendering",
    "anomaly_hint": "InvisibleRenderingMode", "decoded_offset": 1234 }
]
```

To avoid duplicating the correlation logic across CLI and GUI crates, extract `correlate_findings`
into `sis-pdf-core` as:

```rust
// crates/sis-pdf-core/src/content_correlation.rs (new file)
pub fn correlate_content_stream_findings(
    findings: &[Finding],
    stream_ref: (u32, u16),
    page_ref: Option<(u32, u16)>,
    raw_stream_offset: u64,
    decoded_stream_len: u64,
) -> Vec<CorrelatedStreamFinding>

pub struct CorrelatedStreamFinding {
    pub finding_id: String,
    pub kind: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub anomaly_hint: Option<String>,
    pub decoded_offset: Option<u64>,
}
```

The GUI's `CorrelatedFinding` type becomes a thin wrapper or type alias over
`CorrelatedStreamFinding` to avoid re-implementing the same struct.

### 5.8 — Tests

**Unit tests** (`crates/sis-pdf-core/tests/`):

- `correlate_finds_content_invisible_text_by_page_ref`: synthetic `Report` with one
  `content_invisible_text` finding; assert correlation returns it when page_ref matches.
- `correlate_finds_stream_high_entropy_by_stream_ref`: synthetic `Report` with one
  `stream_high_entropy` finding; assert correlation returns it when stream_ref matches.
- `correlate_deduplicates_same_finding`: finding matching both stream_ref and page_ref appears once.
- `correlate_returns_empty_for_unrelated_findings`: unrelated finding not included.

**Integration tests** (`crates/sis-pdf/tests/`):

- `stream_content_with_findings_includes_correlated`: use `launch_cve_2010_1240.pdf` with
  `--with-findings`; assert no panic and valid JSON output.
- `page_content_with_findings_round_trips_json`: JSON output has `"correlated_findings"` key.

**Success criteria**: On a real PDF that produces a `content_invisible_text` finding, the content
stream panel shows that finding in the findings bar and highlights the relevant block(s). The
`stream.content N G --with-findings` CLI command emits the finding in its JSON output.

---

## Implementation Order

```
Stage 1  →  Stage 2  →  Stage 3a  →  Stage 3b  →  Stage 4  →  Stage 5
(core lib)  (CLI)        (GUI panel)  (graph mode)  (XObj rec)  (findings)
```

Each stage is independently testable and delivers user value on its own. Stage 1 is the prerequisite
for all others.

---

## File Change Summary

### New files

| File | Purpose | Stage |
|---|---|---|
| `crates/sis-pdf-pdf/src/content_summary.rs` | `summarise_stream`, `build_content_graph`, DOT/JSON export | 1 |
| `crates/sis-pdf-gui/src/panels/content_stream.rs` | Content Stream floating panel | 3a |
| `fuzz/fuzz_targets/content_summary.rs` | Fuzz target for `summarise_stream` over untrusted decoded bytes | 1 |
| `crates/sis-pdf-core/src/content_correlation.rs` | `correlate_content_stream_findings`, `CorrelatedStreamFinding` | 5 |

### Modified files

| File | Change | Stage |
|---|---|---|
| `crates/sis-pdf-pdf/src/lib.rs` | Export `content_summary` module | 1 |
| `crates/sis-pdf-core/src/page_tree.rs` | Add `resolve_page_resources(graph, obj, gen) -> Option<PdfDict>` helper | 1 |
| `crates/sis-pdf/src/commands/query.rs` | New query variants + handlers; `--recursive` and `--with-findings` flags | 2, 4, 5 |
| `crates/sis-pdf/src/main.rs` | Register new query string aliases in `parse_query()` | 2, 4 |
| `crates/sis-pdf-gui/src/query.rs` | New `Query::ContentStream` variant | 3a |
| `crates/sis-pdf-gui/src/app.rs` | Add `show_content_stream`, `content_stream_state` fields | 3a |
| `crates/sis-pdf-gui/src/panels/mod.rs` | Register new panel | 3a |
| `crates/sis-pdf-gui/src/panels/graph.rs` | `ContentStream` mode; recursive graph builder call | 3b, 4, 5 |
| `crates/sis-pdf-gui/src/graph_data.rs` | `from_content_graph()` with `correlated_findings` parameter | 3b, 5 |
| `crates/sis-pdf-gui/src/panels/events.rs` | "View content operators" button on `ContentStreamExec` rows | 3a |
| `crates/sis-pdf-gui/src/panels/objects.rs` | "View content operators" button on `ObjectRole::PageContent` objects | 3a |
| `crates/sis-pdf-pdf/src/content_summary.rs` | Add `summarise_xobject_tree`, `build_content_graph_recursive`, `RecursiveContentSummary` | 4 |
| `crates/sis-pdf-core/src/lib.rs` | Export `content_correlation` module | 5 |

---

## Test Coverage Requirements

### Stage 1 (unit tests in `crates/sis-pdf-pdf/tests/`)

- `parse_and_summarise_simple_page`: synthetic stream with BT/ET, q/Q, Do
- `resolve_font_reference`: mock ObjectGraph with /Resources /Font dict
- `resolve_xobject_reference`: Image and Form XObject
- `resolve_extgstate_reference`: gs operator → /ExtGState entry
- `detect_graphics_state_underflow`: Q without q
- `detect_excessive_kern`: TJ with large kern value (re-parses raw Array operand string)
- `detect_zero_scale_text`: Tz 0 operator
- `detect_invisible_rendering_mode`: Tr 3 operator → InvisibleRenderingMode anomaly
- `detect_truncated_stream`: truncated=true → StreamTruncated anomaly
- `suppress_unknown_op_in_bx_ex`: unknown op between BX/EX emits no UnknownOperator anomaly
- `unknown_op_outside_bx_ex_emits_anomaly`: unknown op outside sections emits anomaly
- `multiple_fonts_in_single_text_object`: two Tf calls inside BT/ET → two entries in fonts vec
- `type3_charproc_stream_summarises`: synthetic CharProc stream with d0 and path ops
- `content_first_phase1_real_world`: summarise page 0 from `content_first_phase1.pdf`, assert non-empty blocks
- `launch_cve_fixture_hostile`: summarise from `launch_cve_2010_1240.pdf`, no panic, returns summary
- `content_graph_to_dot_is_valid_syntax`: smoke test DOT string contains "digraph"

### Stage 2 (integration tests in `crates/sis-pdf/tests/`)

- `stream_content_query_returns_blocks`: against `content_first_phase1.pdf`
- `stream_content_hostile_fixture`: against `launch_cve_2010_1240.pdf`
- `page_content_query_resolves_page_zero`: benign fixture with resource inheritance
- `page_content_multiple_streams`: fixture with array /Contents → multiple summaries returned
- `graph_content_dot_is_renderable`: `#[cfg_attr(not(feature = "ci_dot"), ignore)]` or `SKIP_DOT_TEST` env var; pipes to `dot -Tnull`
- `page_content_out_of_range_returns_error`: `QueryResult::Error`
- `stream_content_non_stream_object_returns_error`: `QueryResult::Error { error_code: "NOT_A_STREAM" }`
- `page_content_json_schema_valid`: top-level `stream_ref` and `blocks` keys present

### Stage 3 (GUI — compile + smoke in existing GUI test harness)

- Panel opens and closes without panic
- `from_content_graph` converts a `ContentStreamGraph` with all node kinds without panic
- Mode switch to `ContentStream` populates graph data
- "View content operators" button appears for `ObjectRole::PageContent` classified object

### Stage 4 (unit tests in `crates/sis-pdf-pdf/tests/`)

- `summarise_xobject_tree_form_xobject_depth_1`: synthetic PDF bytes with page stream invoking one
  Form XObject; assert `xobject_children.len() == 1` and child `stream_ref` matches.
- `summarise_xobject_tree_cycle_detection`: stream A invokes Form B, Form B invokes Form A; assert
  no panic and `xobject_children.len() == 1` (cycle detected at second hop).
- `summarise_xobject_tree_depth_limit`: chain of 6 nested Forms with `depth_limit: 5`; assert
  `xobject_children.len() == 5`.
- `summarise_xobject_tree_image_xobject_not_followed`: `Do /Im0` with subtype Image; assert not
  added to `xobject_children`.
- `summarise_xobject_tree_form_resources`: Form XObject with `/Resources /Font` dict; assert child
  summary resolves font refs using Form's own resources, not page resources.
- `build_content_graph_recursive_emits_xobject_contains_edge`: `child_summaries` with one entry;
  assert graph contains at least one edge with `kind == XObjectContains`.
- `build_content_graph_recursive_empty_children_equivalent_to_non_recursive`: `child_summaries`
  empty → graph identical to `build_content_graph` output.

**Integration tests** (`crates/sis-pdf/tests/`):

- `stream_content_recursive_follows_form_xobject`: fixture with Form XObject chain; assert JSON
  `xobject_children` key is present and non-empty.
- `graph_content_recursive_emits_contains_edge_dot`: DOT output contains `"contains"`.
- `stream_content_recursive_hostile_no_panic`: `launch_cve_2010_1240.pdf` with `--recursive`; no panic.

### Stage 5 (unit tests in `crates/sis-pdf-core/tests/`)

- `correlate_finds_content_invisible_text_by_page_ref`: synthetic `Report` with one
  `content_invisible_text` finding whose `objects` contains `"P 0 obj"` matching `page_ref`;
  assert `correlate_content_stream_findings` returns it.
- `correlate_finds_stream_high_entropy_by_stream_ref`: `stream_high_entropy` finding with
  `objects` containing stream ref; assert returned.
- `correlate_deduplicates_same_finding`: finding matching both stream_ref and page_ref; assert
  appears exactly once.
- `correlate_returns_empty_for_unrelated_findings`: finding with different object refs; assert
  empty result.
- `correlate_matches_decoded_evidence_offset`: finding with `EvidenceSource::Decoded` span
  falling within `[raw_stream_offset, raw_stream_offset + decoded_len]`; assert returned with
  `decoded_offset` populated.

**Integration tests** (`crates/sis-pdf/tests/`):

- `stream_content_with_findings_includes_correlated`: `launch_cve_2010_1240.pdf` with
  `--with-findings`; assert no panic and JSON output is valid.
- `page_content_with_findings_round_trips_json`: JSON output has `"correlated_findings"` key.

### Fuzz target (`fuzz/fuzz_targets/content_summary.rs`)

Fuzz `summarise_stream` with arbitrary bytes as the decoded stream body, a minimal mock
`ObjectGraph`, and `resources: None`. Asserts no panic and no `unwrap` paths. Run against the
existing content stream corpus in `fuzz/corpus/` if one exists; seed with bytes from
`content_first_phase1.pdf`'s decoded content stream.

---

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Hostile streams with extremely large op count | `ContentStreamStats.total_op_count` guard; cap block list at 10,000 ops, emit `HighOpCount` anomaly above threshold |
| Recursive Form XObjects causing infinite loop | Depth limit (default 5) in `summarise_xobject_tree`; `visited: HashSet<(u32, u16)>` breaks cycles |
| Form XObject with missing stream body | `graph.get_object` and `decode_stream` both return `Option`/`Result`; skip silently |
| Resource dict absent or malformed | All resolution is `Option`-returning; missing resource → `resolved_ref: None`, no panic |
| Resource inheritance traversal is expensive | `resolve_page_resources` is called once per query, result passed through — not called inside the summariser loop |
| Very long decoded strings in TJ/Tj | Truncate preview strings to 200 chars in GUI display and DOT labels |
| DOT output too large for Graphviz for large streams | Op groups collapse runs of 3+ non-anomalous path/colour ops into a single `OpGroup` node |
| WASM binary size increase | `content_summary` module is pure computation over existing types; no new dependencies |
| TJ kern re-parsing complexity | Array operand re-parsing is a single linear scan; bounded by the raw string length already parsed |
| Fuzz-discovered panics in summariser | Fuzz target catches these before landing; all branches must use `Option`-returning paths, no `unwrap` |
| `strings` misinterpreted as readable text | Doc comments, JSON output, and GUI label all note the best-effort / raw-bytes limitation explicitly |
| Finding correlation false positives | Correlation is opt-in (`--with-findings` / toggle); conservative match on object ref string exact match |
| `decoded_stream_len` unavailable at correlation call site | Store `decoded_len: u64` in `ContentStreamSummary` (added in Stage 5); populated from `decoded.data.len()` in callers |

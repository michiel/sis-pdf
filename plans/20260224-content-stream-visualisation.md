# Content Stream Unpacking and Visualisation

**Date**: 2026-02-24
**Status**: Proposed

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

**Status**: Not Started

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

**Status**: Not Started

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

---

## Stage 4 — Recursive Form XObject Visualisation (Future)

Not in scope for the initial implementation, but the data model supports it:

- `XObjectContains` edges in `ContentStreamGraph` can point to a nested `ContentStreamGraph` for
  Form XObjects.
- The GUI could render this as a sub-panel or an expandable sub-graph.
- The CLI could expose `graph.content N G --recursive` to include transitive Form XObject streams.
- Depth limit (default 5) and visited-set tracking are required to prevent infinite recursion on
  circular Form XObject references.

---

## Stage 5 — Findings Integration (Future)

Not in scope initially:

- `InvisibleRenderingMode` and `ExcessiveKernOffset` anomalies can backlink to the existing
  `content_invisible_text` finding (from `content_phishing.rs`). Even before a full Stage 5
  implementation, anomaly metadata can include `finding_kind: "content_invisible_text"` as a
  correlation hint.
- If a finding has evidence spanning a content stream (e.g. `EvidenceSpan` pointing at stream bytes),
  the content stream panel could highlight the relevant block in red.
- `stream_high_entropy` findings could surface directly in the graph as a node annotation.

---

## Implementation Order

```
Stage 1  →  Stage 2  →  Stage 3a  →  Stage 3b
(core lib)  (CLI)        (GUI panel)  (graph mode)
```

Each stage is independently testable and delivers user value on its own. Stage 1 is the prerequisite
for all others.

---

## File Change Summary

### New files

| File | Purpose |
|---|---|
| `crates/sis-pdf-pdf/src/content_summary.rs` | `summarise_stream`, `build_content_graph`, DOT/JSON export |
| `crates/sis-pdf-gui/src/panels/content_stream.rs` | Content Stream floating panel |
| `fuzz/fuzz_targets/content_summary.rs` | Fuzz target for `summarise_stream` over untrusted decoded bytes |

### Modified files

| File | Change |
|---|---|
| `crates/sis-pdf-pdf/src/lib.rs` | Export `content_summary` module |
| `crates/sis-pdf-core/src/page_tree.rs` | Add `resolve_page_resources(graph, obj, gen) -> Option<PdfDict>` helper with inheritance traversal |
| `crates/sis-pdf/src/commands/query.rs` | New `Query` variants + handlers for `stream.content`, `page.content`, `graph.content`, `graph.page.content` |
| `crates/sis-pdf/src/main.rs` | Register new query string aliases in `parse_query()` |
| `crates/sis-pdf-gui/src/query.rs` | New `Query::ContentStream` variant, parse `page.content N` / `stream.content N G` |
| `crates/sis-pdf-gui/src/app.rs` | Add `show_content_stream`, `content_stream_state` fields |
| `crates/sis-pdf-gui/src/panels/mod.rs` | Register new panel |
| `crates/sis-pdf-gui/src/panels/graph.rs` | Add `ContentStream` mode, `from_content_graph` call, highlight bridge |
| `crates/sis-pdf-gui/src/graph_data.rs` | `from_content_graph()` conversion function |
| `crates/sis-pdf-gui/src/panels/events.rs` | "View content operators" button on `ContentStreamExec` rows |
| `crates/sis-pdf-gui/src/panels/objects.rs` | "View content operators" button on `ObjectRole::PageContent` and Type 3 CharProc stream objects |

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
| Recursive Form XObjects causing infinite loop | Depth limit (default 5) on recursive summarisation; track visited stream refs |
| Resource dict absent or malformed | All resolution is `Option`-returning; missing resource → `resolved_ref: None`, no panic |
| Resource inheritance traversal is expensive | `resolve_page_resources` is called once per query, result passed through — not called inside the summariser loop |
| Very long decoded strings in TJ/Tj | Truncate preview strings to 200 chars in GUI display and DOT labels |
| DOT output too large for Graphviz for large streams | Op groups collapse runs of 3+ non-anomalous path/colour ops into a single `OpGroup` node |
| WASM binary size increase | `content_summary` module is pure computation over existing types; no new dependencies |
| TJ kern re-parsing complexity | Array operand re-parsing is a single linear scan; bounded by the raw string length already parsed |
| Fuzz-discovered panics in summariser | Fuzz target catches these before landing; all branches must use `Option`-returning paths, no `unwrap` |
| `strings` misinterpreted as readable text | Doc comments, JSON output, and GUI label all note the best-effort / raw-bytes limitation explicitly |

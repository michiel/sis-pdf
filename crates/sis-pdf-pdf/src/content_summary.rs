/// Content stream unpacking and structured analysis.
///
/// Takes decoded content stream bytes (from `decode_stream`) and page resources
/// (caller-resolved, including inheritance), and returns a structured `ContentStreamSummary`
/// that groups operators into semantic `ContentBlock` values and flags anomalies.
///
/// Crate-boundary note: this module lives in `sis-pdf-pdf` and must not depend on
/// `sis-pdf-core`. The caller (in `sis-pdf` or `sis-pdf-core`) is responsible for:
///   - decoding the stream via `decode_stream`
///   - resolving the page's `/Resources` dict (including inherited resources)
///   - passing `raw_stream_offset` from `PdfStream.data_span.start`
use crate::content::{parse_content_ops, ContentOp, ContentOperand};
use crate::graph::ObjectGraph;
use crate::object::{PdfAtom, PdfDict};

// ---------------------------------------------------------------------------
// Public data model
// ---------------------------------------------------------------------------

/// A semantic block extracted from a content stream.
///
/// All `span_start`/`span_end` values are byte offsets within the **decoded** stream body,
/// not within the raw PDF file. Use `ContentStreamSummary.raw_stream_offset` for file navigation.
#[derive(Debug, Clone)]
pub enum ContentBlock {
    /// BT … ET text object.
    TextObject {
        ops: Vec<AnnotatedOp>,
        /// All `Tf` invocations inside this BT/ET block, in order.
        /// Each entry is `(resource_key, resolved_indirect_ref)`.
        fonts: Vec<(String, Option<(u32, u16)>)>,
        /// Best-effort text strings from `Tj`/`TJ`/`'`/`"` operators, in order.
        ///
        /// These are raw PDF string bytes converted lossily to UTF-8 via
        /// `String::from_utf8_lossy`. They are **not** glyph-decoded — proper
        /// decoding requires font ToUnicode CMaps and Encoding arrays, which are
        /// not resolved here. Do not treat these as human-readable text for
        /// encoded fonts. Hex strings are prefixed with `<`.
        strings: Vec<String>,
        span_start: u64,
        span_end: u64,
    },
    /// q … Q graphics-state save/restore (may nest).
    GraphicsState {
        children: Vec<ContentBlock>,
        /// `cm` operators found directly inside this graphics state.
        ctm_ops: Vec<AnnotatedOp>,
        span_start: u64,
        span_end: u64,
    },
    /// `Do` XObject invocation.
    XObjectInvoke {
        resource_name: String,
        target_ref: Option<(u32, u16)>,
        /// `"Image"` or `"Form"` if resolved; `None` otherwise.
        subtype: Option<String>,
        span_start: u64,
        span_end: u64,
    },
    /// BI … ID … EI inline image.
    InlineImage {
        width: Option<i32>,
        height: Option<i32>,
        color_space: Option<String>,
        span_start: u64,
        span_end: u64,
    },
    /// BMC/BDC … EMC marked-content section.
    MarkedContent {
        tag: String,
        /// Raw `MCID` property dict string when operator is `BDC`.
        properties: Option<String>,
        children: Vec<ContentBlock>,
        span_start: u64,
        span_end: u64,
    },
    /// Ungrouped operators (path construction, colour, etc.).
    ///
    /// Runs of 3+ consecutive non-anomalous path/colour ops outside BT/ET blocks
    /// are collapsed into this variant to keep graph output manageable.
    Ops(Vec<AnnotatedOp>),
}

/// A single content stream operator with its resolved resource reference (if any).
#[derive(Debug, Clone)]
pub struct AnnotatedOp {
    pub op: ContentOp,
    /// Resolved PDF indirect reference for operator arguments that name resources.
    pub resolved_ref: Option<(u32, u16)>,
}

/// Top-level summary for one decoded content stream.
#[derive(Debug, Clone)]
pub struct ContentStreamSummary {
    pub stream_ref: (u32, u16),
    /// Owning page, if known. `None` for Form XObjects and Type 3 CharProc streams.
    pub page_ref: Option<(u32, u16)>,
    /// `PdfStream.data_span.start` — byte offset of the stream's raw data within the
    /// PDF file. Used by GUI hex-viewer navigation. Distinct from the decoded-body
    /// offsets in `ContentBlock.span_start`/`span_end`.
    pub raw_stream_offset: u64,
    pub blocks: Vec<ContentBlock>,
    pub stats: ContentStreamStats,
    pub anomalies: Vec<ContentStreamAnomaly>,
}

/// Aggregate statistics for a content stream.
#[derive(Debug, Clone, Default)]
pub struct ContentStreamStats {
    pub total_op_count: usize,
    /// Count of `Tj`, `TJ`, `'`, `"` operators.
    pub text_op_count: usize,
    /// Count of path construction/painting operators: `m`, `l`, `c`, `v`, `y`, `h`,
    /// `re`, `S`, `s`, `f`, `F`, `B`, `B*`, `b`, `b*`, `n`.
    pub path_op_count: usize,
    pub image_invoke_count: usize,
    pub form_xobject_invoke_count: usize,
    pub graphics_state_depth_max: usize,
    pub marked_content_depth_max: usize,
    /// Resource keys of all fonts referenced (e.g. `["/F1", "/F2"]`).
    pub unique_fonts: Vec<String>,
    /// Resource keys of all XObjects referenced (e.g. `["/Im0", "/Fm0"]`).
    pub unique_xobjects: Vec<String>,
}

/// Anomaly detected during content stream summarisation.
#[derive(Debug, Clone)]
pub enum ContentStreamAnomaly {
    /// `Q` operator with no preceding `q` at the same nesting level.
    GraphicsStateUnderflow { op: String, position: u64 },
    /// `BT` without closing `ET` at end of stream.
    TextObjectUnterminatedAtEof,
    /// Operator not in the known PDF operator set, found outside BX/EX sections.
    UnknownOperator { op: String, position: u64 },
    /// `TJ` array contains a kern offset with absolute value > 200 units.
    ExcessiveKernOffset { value: f32, position: u64 },
    /// `Tz 0` (zero horizontal scale), making text invisible.
    ZeroScaleText { position: u64 },
    /// `Tr 3` (invisible rendering mode). Correlates with the `content_invisible_text` finding.
    InvisibleRenderingMode { position: u64 },
    /// Total operator count exceeded the safety cap (50 000).
    HighOpCount { count: usize },
    /// Caller reported that `DecodedStream.truncated == true`.
    StreamTruncated,
}

// ---------------------------------------------------------------------------
// Graph types (built lazily from ContentStreamSummary)
// ---------------------------------------------------------------------------

/// Directed graph of content stream blocks and resource references.
///
/// Build with `build_content_graph`; only call when DOT/JSON graph output or the
/// GUI graph panel is actually requested — not on every `summarise_stream` call.
#[derive(Debug, Clone)]
pub struct ContentStreamGraph {
    pub nodes: Vec<CsgNode>,
    pub edges: Vec<CsgEdge>,
}

/// Node in a `ContentStreamGraph`.
#[derive(Debug, Clone)]
pub struct CsgNode {
    /// Stable identifier (e.g. `"blk_0"`, `"obj_15_0"`).
    pub id: String,
    pub kind: CsgNodeKind,
    /// Document-order sequence index; used as topological sort key for layout.
    pub sequence: usize,
    pub span_start: u64,
    pub span_end: u64,
    /// True if this node corresponds to at least one anomaly.
    pub anomaly: bool,
}

/// Semantics of a graph node.
#[derive(Debug, Clone)]
pub enum CsgNodeKind {
    TextBlock { strings: Vec<String>, fonts: Vec<String> },
    XObjectRef { name: String, subtype: Option<String> },
    InlineImage { width: Option<i32>, height: Option<i32> },
    MarkedContent { tag: String },
    GraphicsState { depth: usize },
    /// Collapsed run of path/colour operators.
    OpGroup { label: String, count: usize },
    /// Resolved PDF object (font, XObject, ExtGState, …).
    PdfObject { obj: u32, gen: u16, obj_type: String },
}

/// Directed edge in a `ContentStreamGraph`.
#[derive(Debug, Clone)]
pub struct CsgEdge {
    pub from: String,
    pub to: String,
    pub kind: CsgEdgeKind,
}

/// Semantics of a graph edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsgEdgeKind {
    /// Document order: A then B.
    Sequence,
    /// Operator references a resolved PDF object.
    ResourceRef,
    /// Form XObject stream that itself contains further blocks.
    XObjectContains,
    /// Parent block contains a child block (q/Q, BT/ET, BMC/EMC).
    Nesting,
}

// ---------------------------------------------------------------------------
// Internal summariser state
// ---------------------------------------------------------------------------

const MAX_OP_COUNT: usize = 50_000;
const EXCESSIVE_KERN_THRESHOLD: f32 = 200.0;
const OPGROUP_COLLAPSE_RUN: usize = 3;

struct Summariser<'a> {
    resources: Option<&'a PdfDict<'a>>,
    graph: &'a ObjectGraph<'a>,
    stats: ContentStreamStats,
    anomalies: Vec<ContentStreamAnomaly>,
    /// Graphics state nesting depth (for anomaly and stats tracking).
    gs_depth: usize,
    /// Marked-content nesting depth.
    mc_depth: usize,
    /// BX/EX compatibility section nesting depth; unknown operators are suppressed when > 0.
    compat_depth: usize,
}

impl<'a> Summariser<'a> {
    fn new(resources: Option<&'a PdfDict<'a>>, graph: &'a ObjectGraph<'a>) -> Self {
        Self {
            resources,
            graph,
            stats: ContentStreamStats::default(),
            anomalies: Vec::new(),
            gs_depth: 0,
            mc_depth: 0,
            compat_depth: 0,
        }
    }

    /// Resolve a resource name (e.g. `b"/F1"`) against a `/Resources` sub-category.
    fn resolve_resource(&self, name: &[u8], category: &[u8]) -> Option<(u32, u16)> {
        let resources = self.resources?;
        let (_, cat_obj) = resources.get_first(category)?;
        let cat_dict = match &cat_obj.atom {
            PdfAtom::Dict(d) => d,
            PdfAtom::Ref { .. } => {
                return self.graph.resolve_ref(cat_obj).and_then(|e| match &e.atom {
                    PdfAtom::Dict(d) => find_ref_in_dict(d, name, self.graph),
                    _ => None,
                });
            }
            _ => return None,
        };
        find_ref_in_dict(cat_dict, name, self.graph)
    }

    /// Extract the XObject subtype string for a resolved ref.
    fn xobject_subtype(&self, target_ref: (u32, u16)) -> Option<String> {
        let entry = self.graph.get_object(target_ref.0, target_ref.1)?;
        let dict = match &entry.atom {
            PdfAtom::Stream(st) => &st.dict,
            PdfAtom::Dict(d) => d,
            _ => return None,
        };
        let (_, subtype_obj) = dict.get_first(b"/Subtype")?;
        match &subtype_obj.atom {
            PdfAtom::Name(n) => {
                let s = String::from_utf8_lossy(&n.decoded).into_owned();
                // Strip leading slash if present
                Some(s.trim_start_matches('/').to_string())
            }
            _ => None,
        }
    }

    /// Process all operators and return the top-level block list.
    fn process(&mut self, ops: &[ContentOp]) -> Vec<ContentBlock> {
        if ops.len() > MAX_OP_COUNT {
            self.anomalies.push(ContentStreamAnomaly::HighOpCount { count: ops.len() });
        }
        self.stats.total_op_count = ops.len().min(MAX_OP_COUNT);
        self.process_slice(&ops[..ops.len().min(MAX_OP_COUNT)], 0)
    }

    fn process_slice(&mut self, ops: &[ContentOp], depth: usize) -> Vec<ContentBlock> {
        let mut blocks: Vec<ContentBlock> = Vec::new();
        let mut i = 0usize;

        while i < ops.len() {
            let op = &ops[i];
            match op.op.as_str() {
                // ---- BX / EX compatibility sections ----
                "BX" => {
                    self.compat_depth += 1;
                    i += 1;
                }
                "EX" => {
                    if self.compat_depth > 0 {
                        self.compat_depth -= 1;
                    }
                    i += 1;
                }

                // ---- Graphics state save/restore ----
                "q" => {
                    self.gs_depth += 1;
                    self.stats.graphics_state_depth_max =
                        self.stats.graphics_state_depth_max.max(self.gs_depth);
                    let span_start = op.span.start;
                    // Collect all ops until the matching Q (or end of slice).
                    let (children_ops, end_idx) = collect_until_q(ops, i + 1, 0);
                    let children = self.process_slice(children_ops, depth + 1);
                    let ctm_ops = collect_cm_ops(children_ops, self.resources, self.graph);
                    let span_end = ops.get(end_idx).map(|o| o.span.end).unwrap_or(span_start);
                    self.gs_depth -= 1;
                    blocks.push(ContentBlock::GraphicsState {
                        children,
                        ctm_ops,
                        span_start,
                        span_end,
                    });
                    i = end_idx + 1;
                }
                "Q" => {
                    if depth == 0 {
                        self.anomalies.push(ContentStreamAnomaly::GraphicsStateUnderflow {
                            op: "Q".into(),
                            position: op.span.start,
                        });
                    }
                    // At depth > 0 Q is consumed by the parent collect_until_q.
                    i += 1;
                }

                // ---- Text objects ----
                "BT" => {
                    let span_start = op.span.start;
                    let (text_ops, end_idx) = collect_until_et(ops, i + 1);
                    let (annotated, fonts, strings) =
                        self.process_text_ops(text_ops);
                    let span_end =
                        ops.get(end_idx).map(|o| o.span.end).unwrap_or(span_start);
                    blocks.push(ContentBlock::TextObject {
                        ops: annotated,
                        fonts,
                        strings,
                        span_start,
                        span_end,
                    });
                    i = end_idx + 1;
                    // ET was consumed; check if we went past end (unterminated BT at EOF).
                    if end_idx >= ops.len() {
                        self.anomalies.push(ContentStreamAnomaly::TextObjectUnterminatedAtEof);
                    }
                }

                // ---- XObject invocation ----
                "Do" => {
                    self.stats.total_op_count = self.stats.total_op_count.saturating_add(1);
                    let resource_name = operand_name(&op.operands).unwrap_or_default();
                    if !resource_name.is_empty() {
                        let key_bytes = resource_name.as_bytes();
                        let target_ref =
                            self.resolve_resource(key_bytes, b"/XObject");
                        let subtype = target_ref.and_then(|r| self.xobject_subtype(r));
                        match subtype.as_deref() {
                            Some("Image") => self.stats.image_invoke_count += 1,
                            Some("Form") => self.stats.form_xobject_invoke_count += 1,
                            _ => {}
                        }
                        if !self.stats.unique_xobjects.contains(&resource_name) {
                            self.stats.unique_xobjects.push(resource_name.clone());
                        }
                        blocks.push(ContentBlock::XObjectInvoke {
                            resource_name,
                            target_ref,
                            subtype,
                            span_start: op.span.start,
                            span_end: op.span.end,
                        });
                    }
                    i += 1;
                }

                // ---- Inline image ----
                "BI" => {
                    let span_start = op.span.start;
                    let (width, height, color_space, end_idx) =
                        extract_inline_image_attrs(ops, i + 1);
                    let span_end =
                        ops.get(end_idx).map(|o| o.span.end).unwrap_or(span_start);
                    blocks.push(ContentBlock::InlineImage {
                        width,
                        height,
                        color_space,
                        span_start,
                        span_end,
                    });
                    i = end_idx + 1;
                }
                "ID" | "EI" => {
                    // Consumed by extract_inline_image_attrs; skip stray tokens.
                    i += 1;
                }

                // ---- Marked content ----
                "BMC" | "BDC" => {
                    self.mc_depth += 1;
                    self.stats.marked_content_depth_max =
                        self.stats.marked_content_depth_max.max(self.mc_depth);
                    let span_start = op.span.start;
                    let tag = operand_name(&op.operands)
                        .unwrap_or_else(|| "/Unknown".to_string());
                    let properties = if op.op == "BDC" {
                        op.operands.get(1).map(|o| format!("{:?}", o))
                    } else {
                        None
                    };
                    let (mc_ops, end_idx) = collect_until_emc(ops, i + 1, 0);
                    let children = self.process_slice(mc_ops, depth + 1);
                    let span_end =
                        ops.get(end_idx).map(|o| o.span.end).unwrap_or(span_start);
                    self.mc_depth -= 1;
                    blocks.push(ContentBlock::MarkedContent {
                        tag,
                        properties,
                        children,
                        span_start,
                        span_end,
                    });
                    i = end_idx + 1;
                }
                "EMC" => {
                    // Consumed by parent collect_until_emc; stray EMC is skipped.
                    i += 1;
                }

                // ---- Anomaly: unknown operator ----
                other if !is_known_operator(other) => {
                    if self.compat_depth == 0 {
                        self.anomalies.push(ContentStreamAnomaly::UnknownOperator {
                            op: other.to_string(),
                            position: op.span.start,
                        });
                    }
                    i += 1;
                }

                // ---- Path and colour ops — may collapse into OpGroup ----
                _ => {
                    self.count_path_colour_op(op);
                    // Try to accumulate a run and collapse if long enough.
                    let run_start = i;
                    let mut run_end = i + 1;
                    while run_end < ops.len()
                        && is_collapsible_op(&ops[run_end].op)
                        && !is_structural_op(&ops[run_end].op)
                    {
                        self.count_path_colour_op(&ops[run_end]);
                        run_end += 1;
                    }
                    let run_len = run_end - run_start;
                    let run_ops: Vec<AnnotatedOp> = ops[run_start..run_end]
                        .iter()
                        .map(|o| AnnotatedOp {
                            op: o.clone(),
                            resolved_ref: None,
                        })
                        .collect();
                    if run_len >= OPGROUP_COLLAPSE_RUN {
                        blocks.push(ContentBlock::Ops(run_ops));
                    } else {
                        for aop in run_ops {
                            blocks.push(ContentBlock::Ops(vec![aop]));
                        }
                    }
                    i = run_end;
                }
            }
        }
        blocks
    }

    fn count_path_colour_op(&mut self, op: &ContentOp) {
        match op.op.as_str() {
            "m" | "l" | "c" | "v" | "y" | "h" | "re" | "S" | "s" | "f" | "F" | "B" | "B*"
            | "b" | "b*" | "n" => {
                self.stats.path_op_count += 1;
            }
            _ => {}
        }
    }

    /// Process the ops inside a BT/ET block.
    /// Returns (annotated_ops, fonts_vec, strings_vec).
    fn process_text_ops(
        &mut self,
        ops: &[ContentOp],
    ) -> (Vec<AnnotatedOp>, Vec<(String, Option<(u32, u16)>)>, Vec<String>) {
        let mut annotated = Vec::new();
        let mut fonts: Vec<(String, Option<(u32, u16)>)> = Vec::new();
        let mut strings: Vec<String> = Vec::new();

        for op in ops {
            self.stats.total_op_count = self.stats.total_op_count.saturating_add(1);
            let mut resolved_ref: Option<(u32, u16)> = None;

            match op.op.as_str() {
                // Font selection
                "Tf" => {
                    let font_name = operand_name(&op.operands).unwrap_or_default();
                    if !font_name.is_empty() {
                        let r = self.resolve_resource(font_name.as_bytes(), b"/Font");
                        resolved_ref = r;
                        fonts.push((font_name.clone(), r));
                        if !self.stats.unique_fonts.contains(&font_name) {
                            self.stats.unique_fonts.push(font_name);
                        }
                    }
                }
                // Text painting
                "Tj" | "'" | "\"" => {
                    self.stats.text_op_count += 1;
                    if let Some(s) = extract_string_operand(&op.operands) {
                        strings.push(s);
                    }
                }
                "TJ" => {
                    self.stats.text_op_count += 1;
                    let (strs, max_kern) = extract_tj_array(&op.operands);
                    strings.extend(strs);
                    if let Some(kern) = max_kern {
                        if kern.abs() > EXCESSIVE_KERN_THRESHOLD {
                            self.anomalies.push(ContentStreamAnomaly::ExcessiveKernOffset {
                                value: kern,
                                position: op.span.start,
                            });
                        }
                    }
                }
                // Invisible text tricks
                "Tz" => {
                    if let Some(v) = first_number(&op.operands) {
                        if v.abs() < f32::EPSILON {
                            self.anomalies
                                .push(ContentStreamAnomaly::ZeroScaleText { position: op.span.start });
                        }
                    }
                }
                "Tr" => {
                    if let Some(v) = first_number(&op.operands) {
                        if (v - 3.0).abs() < f32::EPSILON {
                            self.anomalies.push(ContentStreamAnomaly::InvisibleRenderingMode {
                                position: op.span.start,
                            });
                        }
                    }
                }
                // gs — ExtGState resource reference
                "gs" => {
                    let name = operand_name(&op.operands).unwrap_or_default();
                    if !name.is_empty() {
                        resolved_ref = self.resolve_resource(name.as_bytes(), b"/ExtGState");
                    }
                }
                // Extended state ops in text context — no resource resolution needed
                _ => {}
            }

            annotated.push(AnnotatedOp { op: op.clone(), resolved_ref });
        }
        (annotated, fonts, strings)
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Summarise a single decoded content stream body.
///
/// `bytes` is the decoded (filter-decompressed) stream body from `DecodedStream.data`.
/// `truncated` should reflect `DecodedStream.truncated` — emits a `StreamTruncated` anomaly.
/// `resources` is the fully resolved `/Resources` dict including inherited entries.
/// `raw_stream_offset` is `PdfStream.data_span.start` for GUI hex-viewer navigation.
pub fn summarise_stream(
    bytes: &[u8],
    truncated: bool,
    stream_ref: (u32, u16),
    page_ref: Option<(u32, u16)>,
    raw_stream_offset: u64,
    resources: Option<&PdfDict<'_>>,
    graph: &ObjectGraph<'_>,
) -> ContentStreamSummary {
    let ops = parse_content_ops(bytes);
    let mut summariser = Summariser::new(resources, graph);
    let blocks = summariser.process(&ops);
    if truncated {
        summariser.anomalies.push(ContentStreamAnomaly::StreamTruncated);
    }
    ContentStreamSummary {
        stream_ref,
        page_ref,
        raw_stream_offset,
        blocks,
        stats: summariser.stats,
        anomalies: summariser.anomalies,
    }
}

/// Build a `ContentStreamGraph` from a `ContentStreamSummary`.
///
/// Call lazily — only when DOT/JSON graph output or the GUI graph panel is requested.
pub fn build_content_graph(summary: &ContentStreamSummary) -> ContentStreamGraph {
    let mut nodes: Vec<CsgNode> = Vec::new();
    let mut edges: Vec<CsgEdge> = Vec::new();
    let mut seq = 0usize;

    // Collect anomaly-flagged byte ranges for quick lookup.
    let anomaly_positions: Vec<u64> = summary
        .anomalies
        .iter()
        .filter_map(|a| match a {
            ContentStreamAnomaly::ExcessiveKernOffset { position, .. } => Some(*position),
            ContentStreamAnomaly::ZeroScaleText { position } => Some(*position),
            ContentStreamAnomaly::InvisibleRenderingMode { position } => Some(*position),
            ContentStreamAnomaly::UnknownOperator { position, .. } => Some(*position),
            ContentStreamAnomaly::GraphicsStateUnderflow { position, .. } => Some(*position),
            _ => None,
        })
        .collect();

    add_blocks_to_graph(
        &summary.blocks,
        None,
        &mut nodes,
        &mut edges,
        &mut seq,
        &anomaly_positions,
        0,
    );

    ContentStreamGraph { nodes, edges }
}

fn add_blocks_to_graph(
    blocks: &[ContentBlock],
    parent_id: Option<&str>,
    nodes: &mut Vec<CsgNode>,
    edges: &mut Vec<CsgEdge>,
    seq: &mut usize,
    anomaly_positions: &[u64],
    depth: usize,
) {
    let mut prev_id: Option<String> = None;

    for block in blocks {
        let id = format!("blk_{}", *seq);
        *seq += 1;

        let (kind, span_start, span_end, children, resource_edges) =
            block_to_graph_parts(block, &id, nodes, edges, seq, anomaly_positions, depth);

        let anomaly = anomaly_positions.iter().any(|&p| p >= span_start && p <= span_end);
        nodes.push(CsgNode { id: id.clone(), kind, sequence: *seq, span_start, span_end, anomaly });

        // Sequence edge from previous sibling.
        if let Some(ref prev) = prev_id {
            edges.push(CsgEdge { from: prev.clone(), to: id.clone(), kind: CsgEdgeKind::Sequence });
        }
        // Nesting edge from parent.
        if let Some(p) = parent_id {
            edges.push(CsgEdge {
                from: p.to_string(),
                to: id.clone(),
                kind: CsgEdgeKind::Nesting,
            });
        }
        // Resource reference edges.
        for (target_ref, obj_type) in resource_edges {
            let obj_id = format!("obj_{}_{}", target_ref.0, target_ref.1);
            // Add PdfObject node if not already present.
            if !nodes.iter().any(|n| n.id == obj_id) {
                nodes.push(CsgNode {
                    id: obj_id.clone(),
                    kind: CsgNodeKind::PdfObject {
                        obj: target_ref.0,
                        gen: target_ref.1,
                        obj_type,
                    },
                    sequence: *seq,
                    span_start: 0,
                    span_end: 0,
                    anomaly: false,
                });
                *seq += 1;
            }
            edges.push(CsgEdge {
                from: id.clone(),
                to: obj_id,
                kind: CsgEdgeKind::ResourceRef,
            });
        }

        // Add children blocks with nesting edges.
        if !children.is_empty() {
            add_blocks_to_graph(children, Some(&id), nodes, edges, seq, anomaly_positions, depth + 1);
        }

        prev_id = Some(id);
    }
}

/// Returns `(kind, span_start, span_end, children_ref, resource_edges)`.
/// `resource_edges` is a list of `(ref, obj_type_string)` for `ResourceRef` edges.
fn block_to_graph_parts<'a>(
    block: &'a ContentBlock,
    _id: &str,
    _nodes: &mut Vec<CsgNode>,
    _edges: &mut Vec<CsgEdge>,
    _seq: &mut usize,
    _anomaly_positions: &[u64],
    _depth: usize,
) -> (CsgNodeKind, u64, u64, &'a [ContentBlock], Vec<((u32, u16), String)>) {
    match block {
        ContentBlock::TextObject { ops: _, fonts, strings, span_start, span_end } => {
            let font_names: Vec<String> = fonts.iter().map(|(n, _)| n.clone()).collect();
            let resource_edges: Vec<((u32, u16), String)> = fonts
                .iter()
                .filter_map(|(_, r)| r.map(|rf| (rf, "font".to_string())))
                .collect();
            (
                CsgNodeKind::TextBlock {
                    strings: strings.iter().take(5).cloned().collect(),
                    fonts: font_names,
                },
                *span_start,
                *span_end,
                &[],
                resource_edges,
            )
        }
        ContentBlock::GraphicsState { children, span_start, span_end, .. } => (
            CsgNodeKind::GraphicsState { depth: 0 },
            *span_start,
            *span_end,
            children.as_slice(),
            vec![],
        ),
        ContentBlock::XObjectInvoke {
            resource_name,
            target_ref,
            subtype,
            span_start,
            span_end,
        } => {
            let res: Vec<((u32, u16), String)> = target_ref
                .map(|r| vec![(r, subtype.as_deref().unwrap_or("xobject").to_string())])
                .unwrap_or_default();
            (
                CsgNodeKind::XObjectRef {
                    name: resource_name.clone(),
                    subtype: subtype.clone(),
                },
                *span_start,
                *span_end,
                &[],
                res,
            )
        }
        ContentBlock::InlineImage { width, height, span_start, span_end, .. } => (
            CsgNodeKind::InlineImage { width: *width, height: *height },
            *span_start,
            *span_end,
            &[],
            vec![],
        ),
        ContentBlock::MarkedContent { tag, children, span_start, span_end, .. } => (
            CsgNodeKind::MarkedContent { tag: tag.clone() },
            *span_start,
            *span_end,
            children.as_slice(),
            vec![],
        ),
        ContentBlock::Ops(ops) => {
            let count = ops.len();
            let span_start = ops.first().map(|o| o.op.span.start).unwrap_or(0);
            let span_end = ops.last().map(|o| o.op.span.end).unwrap_or(0);
            let label = if count == 1 {
                ops[0].op.op.clone()
            } else {
                format!("{} ops", count)
            };
            (
                CsgNodeKind::OpGroup { label, count },
                span_start,
                span_end,
                &[],
                vec![],
            )
        }
    }
}

// ---------------------------------------------------------------------------
// DOT export
// ---------------------------------------------------------------------------

/// Render a `ContentStreamGraph` to Graphviz DOT format.
pub fn content_graph_to_dot(graph: &ContentStreamGraph, title: &str) -> String {
    let mut out = String::new();
    let safe_title = title.replace('"', "'");
    out.push_str(&format!("digraph \"{}\" {{\n", safe_title));
    out.push_str("  rankdir=LR;\n");
    out.push_str("  node [fontname=\"Helvetica\", fontsize=10];\n");
    out.push_str("  edge [fontsize=9];\n\n");

    for node in &graph.nodes {
        let label = node_dot_label(node);
        let color = node_dot_color(node);
        let border = if node.anomaly { "color=orange, penwidth=2" } else { "" };
        let style = if node.anomaly {
            format!("style=filled, fillcolor={}, {}", color, border)
        } else {
            format!("style=filled, fillcolor={}", color)
        };
        out.push_str(&format!(
            "  \"{}\" [label=\"{}\", {}];\n",
            dot_escape(&node.id),
            dot_escape(&label),
            style
        ));
    }

    out.push('\n');

    for edge in &graph.edges {
        let (style, color, label) = edge_dot_attrs(edge.kind);
        out.push_str(&format!(
            "  \"{}\" -> \"{}\" [style={}, color={}, label=\"{}\"];\n",
            dot_escape(&edge.from),
            dot_escape(&edge.to),
            style,
            color,
            label
        ));
    }

    out.push_str("}\n");
    out
}

fn node_dot_label(node: &CsgNode) -> String {
    match &node.kind {
        CsgNodeKind::TextBlock { strings, fonts } => {
            let font_str = fonts.first().cloned().unwrap_or_default();
            let text_preview: String = strings
                .iter()
                .flat_map(|s| s.chars())
                .take(30)
                .collect();
            format!("Text\\n{}\\n\"{}\"", font_str, text_preview)
        }
        CsgNodeKind::XObjectRef { name, subtype } => {
            format!("XObject\\n{}\\n{}", name, subtype.as_deref().unwrap_or("?"))
        }
        CsgNodeKind::InlineImage { width, height } => {
            format!(
                "InlineImage\\n{}x{}",
                width.map(|w| w.to_string()).unwrap_or_else(|| "?".into()),
                height.map(|h| h.to_string()).unwrap_or_else(|| "?".into())
            )
        }
        CsgNodeKind::MarkedContent { tag } => format!("MarkedContent\\n{}", tag),
        CsgNodeKind::GraphicsState { depth } => format!("q…Q (depth {})", depth),
        CsgNodeKind::OpGroup { label, count } => format!("{}\\n({} ops)", label, count),
        CsgNodeKind::PdfObject { obj, gen, obj_type } => {
            format!("{} {} R\\n({})", obj, gen, obj_type)
        }
    }
}

fn node_dot_color(node: &CsgNode) -> &'static str {
    match &node.kind {
        CsgNodeKind::TextBlock { .. } => "\"#b3d9ff\"",
        CsgNodeKind::XObjectRef { subtype, .. } => match subtype.as_deref() {
            Some("Form") => "\"#b3ffe0\"",
            _ => "\"#c8ffc8\"",
        },
        CsgNodeKind::InlineImage { .. } => "\"#c8ffc8\"",
        CsgNodeKind::MarkedContent { .. } => "\"#dddddd\"",
        CsgNodeKind::GraphicsState { .. } => "\"#eeeeee\"",
        CsgNodeKind::OpGroup { .. } => "\"#f5f5f5\"",
        CsgNodeKind::PdfObject { .. } => "\"#fff8b3\"",
    }
}

fn edge_dot_attrs(kind: CsgEdgeKind) -> (&'static str, &'static str, &'static str) {
    match kind {
        CsgEdgeKind::Sequence => ("solid", "\"#aaaaaa\"", ""),
        CsgEdgeKind::ResourceRef => ("dashed", "\"#4488cc\"", "ref"),
        CsgEdgeKind::XObjectContains => ("dashed", "\"#44aa88\"", "contains"),
        CsgEdgeKind::Nesting => ("solid", "\"#cccccc\"", ""),
    }
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

// ---------------------------------------------------------------------------
// JSON export
// ---------------------------------------------------------------------------

/// Render a `ContentStreamGraph` to JSON.
pub fn content_graph_to_json(graph: &ContentStreamGraph) -> serde_json::Value {
    use serde_json::json;

    let nodes: Vec<serde_json::Value> = graph
        .nodes
        .iter()
        .map(|n| {
            json!({
                "id": n.id,
                "kind": node_kind_json(&n.kind),
                "sequence": n.sequence,
                "span": [n.span_start, n.span_end],
                "anomaly": n.anomaly,
            })
        })
        .collect();

    let edges: Vec<serde_json::Value> = graph
        .edges
        .iter()
        .map(|e| {
            json!({
                "from": e.from,
                "to": e.to,
                "kind": edge_kind_str(e.kind),
            })
        })
        .collect();

    json!({ "nodes": nodes, "edges": edges })
}

fn node_kind_json(kind: &CsgNodeKind) -> serde_json::Value {
    use serde_json::json;
    match kind {
        CsgNodeKind::TextBlock { strings, fonts } => {
            json!({ "type": "TextBlock", "strings": strings, "fonts": fonts })
        }
        CsgNodeKind::XObjectRef { name, subtype } => {
            json!({ "type": "XObjectRef", "name": name, "subtype": subtype })
        }
        CsgNodeKind::InlineImage { width, height } => {
            json!({ "type": "InlineImage", "width": width, "height": height })
        }
        CsgNodeKind::MarkedContent { tag } => {
            json!({ "type": "MarkedContent", "tag": tag })
        }
        CsgNodeKind::GraphicsState { depth } => {
            json!({ "type": "GraphicsState", "depth": depth })
        }
        CsgNodeKind::OpGroup { label, count } => {
            json!({ "type": "OpGroup", "label": label, "count": count })
        }
        CsgNodeKind::PdfObject { obj, gen, obj_type } => {
            json!({ "type": "PdfObject", "ref": [obj, gen], "obj_type": obj_type })
        }
    }
}

fn edge_kind_str(kind: CsgEdgeKind) -> &'static str {
    match kind {
        CsgEdgeKind::Sequence => "sequence",
        CsgEdgeKind::ResourceRef => "resource_ref",
        CsgEdgeKind::XObjectContains => "xobject_contains",
        CsgEdgeKind::Nesting => "nesting",
    }
}

/// Serialise a `ContentStreamSummary` to a JSON `Value`.
pub fn summary_to_json(summary: &ContentStreamSummary) -> serde_json::Value {
    use serde_json::json;

    let blocks_json: Vec<serde_json::Value> =
        summary.blocks.iter().map(block_to_json).collect();

    let anomalies_json: Vec<serde_json::Value> =
        summary.anomalies.iter().map(anomaly_to_json).collect();

    json!({
        "stream_ref": [summary.stream_ref.0, summary.stream_ref.1],
        "page_ref": summary.page_ref.map(|(o, g)| json!([o, g])),
        "raw_stream_offset": summary.raw_stream_offset,
        "stats": {
            "total_op_count": summary.stats.total_op_count,
            "text_op_count": summary.stats.text_op_count,
            "path_op_count": summary.stats.path_op_count,
            "image_invoke_count": summary.stats.image_invoke_count,
            "form_xobject_invoke_count": summary.stats.form_xobject_invoke_count,
            "graphics_state_depth_max": summary.stats.graphics_state_depth_max,
            "marked_content_depth_max": summary.stats.marked_content_depth_max,
            "unique_fonts": summary.stats.unique_fonts,
            "unique_xobjects": summary.stats.unique_xobjects,
        },
        "anomalies": anomalies_json,
        "blocks": blocks_json,
    })
}

fn block_to_json(block: &ContentBlock) -> serde_json::Value {
    use serde_json::json;
    match block {
        ContentBlock::TextObject { fonts, strings, span_start, span_end, ops } => {
            let fonts_json: Vec<serde_json::Value> = fonts
                .iter()
                .map(|(n, r)| json!({ "name": n, "ref": r.map(|(o, g)| json!([o, g])) }))
                .collect();
            json!({
                "type": "TextObject",
                "fonts": fonts_json,
                "strings": strings,
                "span": [span_start, span_end],
                "op_count": ops.len(),
            })
        }
        ContentBlock::GraphicsState { children, span_start, span_end, ctm_ops } => {
            let children_json: Vec<serde_json::Value> =
                children.iter().map(block_to_json).collect();
            json!({
                "type": "GraphicsState",
                "span": [span_start, span_end],
                "ctm_op_count": ctm_ops.len(),
                "children": children_json,
            })
        }
        ContentBlock::XObjectInvoke { resource_name, target_ref, subtype, span_start, span_end } => {
            json!({
                "type": "XObjectInvoke",
                "name": resource_name,
                "target_ref": target_ref.map(|(o, g)| json!([o, g])),
                "subtype": subtype,
                "span": [span_start, span_end],
            })
        }
        ContentBlock::InlineImage { width, height, color_space, span_start, span_end } => {
            json!({
                "type": "InlineImage",
                "width": width,
                "height": height,
                "color_space": color_space,
                "span": [span_start, span_end],
            })
        }
        ContentBlock::MarkedContent { tag, properties, children, span_start, span_end } => {
            let children_json: Vec<serde_json::Value> =
                children.iter().map(block_to_json).collect();
            json!({
                "type": "MarkedContent",
                "tag": tag,
                "properties": properties,
                "span": [span_start, span_end],
                "children": children_json,
            })
        }
        ContentBlock::Ops(ops) => {
            json!({
                "type": "Ops",
                "count": ops.len(),
                "span": [
                    ops.first().map(|o| o.op.span.start).unwrap_or(0),
                    ops.last().map(|o| o.op.span.end).unwrap_or(0),
                ],
            })
        }
    }
}

fn anomaly_to_json(a: &ContentStreamAnomaly) -> serde_json::Value {
    use serde_json::json;
    match a {
        ContentStreamAnomaly::GraphicsStateUnderflow { op, position } => {
            json!({ "kind": "GraphicsStateUnderflow", "op": op, "position": position })
        }
        ContentStreamAnomaly::TextObjectUnterminatedAtEof => {
            json!({ "kind": "TextObjectUnterminatedAtEof" })
        }
        ContentStreamAnomaly::UnknownOperator { op, position } => {
            json!({ "kind": "UnknownOperator", "op": op, "position": position })
        }
        ContentStreamAnomaly::ExcessiveKernOffset { value, position } => {
            json!({ "kind": "ExcessiveKernOffset", "value": value, "position": position })
        }
        ContentStreamAnomaly::ZeroScaleText { position } => {
            json!({ "kind": "ZeroScaleText", "position": position })
        }
        ContentStreamAnomaly::InvisibleRenderingMode { position } => {
            json!({ "kind": "InvisibleRenderingMode", "position": position })
        }
        ContentStreamAnomaly::HighOpCount { count } => {
            json!({ "kind": "HighOpCount", "count": count })
        }
        ContentStreamAnomaly::StreamTruncated => {
            json!({ "kind": "StreamTruncated" })
        }
    }
}

/// Text-format summary for CLI output.
pub fn summary_to_text(summary: &ContentStreamSummary) -> String {
    let mut out = String::new();
    let (sr_obj, sr_gen) = summary.stream_ref;
    let page_str = summary
        .page_ref
        .map(|(o, g)| format!("  (page obj {} {})", o, g))
        .unwrap_or_default();
    out.push_str(&format!("Content stream {} {}{}\n", sr_obj, sr_gen, page_str));
    let s = &summary.stats;
    out.push_str(&format!(
        "  Stats: {} ops · {} text · {} images · {} form XObjects · max q-depth {}\n",
        s.total_op_count,
        s.text_op_count,
        s.image_invoke_count,
        s.form_xobject_invoke_count,
        s.graphics_state_depth_max
    ));
    if summary.anomalies.is_empty() {
        out.push_str("  Anomalies: none\n");
    } else {
        out.push_str(&format!("  Anomalies: {} detected\n", summary.anomalies.len()));
        for a in &summary.anomalies {
            out.push_str(&format!("    - {}\n", anomaly_text(a)));
        }
    }
    out.push('\n');
    for (i, block) in summary.blocks.iter().enumerate() {
        render_block_text(&mut out, block, i, 0);
    }
    out
}

fn anomaly_text(a: &ContentStreamAnomaly) -> String {
    match a {
        ContentStreamAnomaly::GraphicsStateUnderflow { op, position } => {
            format!("GraphicsStateUnderflow: {} at offset {}", op, position)
        }
        ContentStreamAnomaly::TextObjectUnterminatedAtEof => {
            "TextObjectUnterminatedAtEof".into()
        }
        ContentStreamAnomaly::UnknownOperator { op, position } => {
            format!("UnknownOperator: {} at offset {}", op, position)
        }
        ContentStreamAnomaly::ExcessiveKernOffset { value, position } => {
            format!("ExcessiveKernOffset: {} at offset {}", value, position)
        }
        ContentStreamAnomaly::ZeroScaleText { position } => {
            format!("ZeroScaleText at offset {}", position)
        }
        ContentStreamAnomaly::InvisibleRenderingMode { position } => {
            format!("InvisibleRenderingMode (Tr 3) at offset {}", position)
        }
        ContentStreamAnomaly::HighOpCount { count } => {
            format!("HighOpCount: {} operators", count)
        }
        ContentStreamAnomaly::StreamTruncated => "StreamTruncated".into(),
    }
}

fn render_block_text(out: &mut String, block: &ContentBlock, idx: usize, depth: usize) {
    let indent = "  ".repeat(depth + 1);
    match block {
        ContentBlock::TextObject { fonts, strings, span_start, span_end, ops } => {
            let font_str = fonts
                .iter()
                .map(|(n, r)| match r {
                    Some((o, g)) => format!("{} -> {} {} R", n, o, g),
                    None => n.clone(),
                })
                .collect::<Vec<_>>()
                .join(", ");
            let strings_preview: Vec<String> =
                strings.iter().take(3).map(|s| format!("\"{}\"", s)).collect();
            out.push_str(&format!(
                "{}[{}] TextObject (BT…ET)  fonts: {}  strings: [{}]  ({} ops, span {}–{})\n",
                indent,
                idx,
                if font_str.is_empty() { "-" } else { &font_str },
                strings_preview.join(", "),
                ops.len(),
                span_start,
                span_end,
            ));
        }
        ContentBlock::GraphicsState { children, span_start, span_end, .. } => {
            out.push_str(&format!(
                "{}[{}] GraphicsState (q…Q)  span {}–{}\n",
                indent, idx, span_start, span_end
            ));
            for (ci, child) in children.iter().enumerate() {
                render_block_text(out, child, ci, depth + 1);
            }
        }
        ContentBlock::XObjectInvoke { resource_name, target_ref, subtype, span_start, span_end } => {
            let ref_str = match target_ref {
                Some((o, g)) => format!("-> {} {} R", o, g),
                None => "(unresolved)".into(),
            };
            let sub_str = subtype.as_deref().unwrap_or("?");
            out.push_str(&format!(
                "{}[{}] XObjectInvoke {} {} [{}]  span {}–{}\n",
                indent, idx, resource_name, ref_str, sub_str, span_start, span_end
            ));
        }
        ContentBlock::InlineImage { width, height, span_start, span_end, .. } => {
            let dim = format!(
                "{}x{}",
                width.map(|w| w.to_string()).unwrap_or_else(|| "?".into()),
                height.map(|h| h.to_string()).unwrap_or_else(|| "?".into())
            );
            out.push_str(&format!(
                "{}[{}] InlineImage {}  span {}–{}\n",
                indent, idx, dim, span_start, span_end
            ));
        }
        ContentBlock::MarkedContent { tag, children, span_start, span_end, .. } => {
            out.push_str(&format!(
                "{}[{}] MarkedContent {}  span {}–{}\n",
                indent, idx, tag, span_start, span_end
            ));
            for (ci, child) in children.iter().enumerate() {
                render_block_text(out, child, ci, depth + 1);
            }
        }
        ContentBlock::Ops(ops) => {
            out.push_str(&format!("{}[{}] Ops ({} operators)\n", indent, idx, ops.len()));
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers: operator collection
// ---------------------------------------------------------------------------

/// Collect ops from `start` until the balancing `Q` or end-of-slice.
/// Returns `(ops_slice, index_of_Q_or_past_end)`.
fn collect_until_q<'a>(ops: &'a [ContentOp], start: usize, depth: usize) -> (&'a [ContentOp], usize) {
    let mut i = start;
    let mut d = depth;
    while i < ops.len() {
        match ops[i].op.as_str() {
            "q" => d += 1,
            "Q" if d == 0 => return (&ops[start..i], i),
            "Q" => d -= 1,
            _ => {}
        }
        i += 1;
    }
    (&ops[start..i], i)
}

/// Collect ops until the matching `ET` or end-of-slice.
/// Returns `(ops_slice, index_of_ET_or_past_end)`.
fn collect_until_et(ops: &[ContentOp], start: usize) -> (&[ContentOp], usize) {
    for (offset, op) in ops[start..].iter().enumerate() {
        if op.op == "ET" {
            return (&ops[start..start + offset], start + offset);
        }
    }
    (&ops[start..], ops.len())
}

/// Collect ops until the matching `EMC` or end-of-slice.
fn collect_until_emc(ops: &[ContentOp], start: usize, depth: usize) -> (&[ContentOp], usize) {
    let mut i = start;
    let mut d = depth;
    while i < ops.len() {
        match ops[i].op.as_str() {
            "BMC" | "BDC" => d += 1,
            "EMC" if d == 0 => return (&ops[start..i], i),
            "EMC" => d -= 1,
            _ => {}
        }
        i += 1;
    }
    (&ops[start..i], i)
}

/// Collect all `cm` operators from a slice and annotate them.
fn collect_cm_ops(
    ops: &[ContentOp],
    _resources: Option<&PdfDict<'_>>,
    _graph: &ObjectGraph<'_>,
) -> Vec<AnnotatedOp> {
    ops.iter()
        .filter(|o| o.op == "cm")
        .map(|o| AnnotatedOp { op: o.clone(), resolved_ref: None })
        .collect()
}

/// Extract inline image dimension attributes from the operator slice starting after `BI`.
/// Returns `(width, height, color_space, index_of_EI_or_past_end)`.
fn extract_inline_image_attrs(
    ops: &[ContentOp],
    start: usize,
) -> (Option<i32>, Option<i32>, Option<String>, usize) {
    let mut width: Option<i32> = None;
    let mut height: Option<i32> = None;
    let mut color_space: Option<String> = None;
    let mut i = start;
    while i < ops.len() {
        let op = &ops[i];
        match op.op.as_str() {
            "ID" => { i += 1; continue; }
            "EI" => return (width, height, color_space, i),
            "/W" | "/Width" => {
                if let Some(ContentOperand::Number(n)) = op.operands.first() {
                    width = Some(*n as i32);
                }
            }
            "/H" | "/Height" => {
                if let Some(ContentOperand::Number(n)) = op.operands.first() {
                    height = Some(*n as i32);
                }
            }
            "/CS" | "/ColorSpace" => {
                if let Some(ContentOperand::Name(n)) = op.operands.first() {
                    color_space = Some(n.clone());
                }
            }
            _ => {}
        }
        i += 1;
    }
    (width, height, color_space, i)
}

// ---------------------------------------------------------------------------
// Helpers: operand extraction
// ---------------------------------------------------------------------------

fn operand_name(operands: &[ContentOperand]) -> Option<String> {
    operands.iter().find_map(|o| match o {
        ContentOperand::Name(n) => Some(n.clone()),
        _ => None,
    })
}

fn first_number(operands: &[ContentOperand]) -> Option<f32> {
    operands.iter().find_map(|o| match o {
        ContentOperand::Number(n) => Some(*n),
        _ => None,
    })
}

/// Extract text strings from Tj / ' / " operands (single string operand).
fn extract_string_operand(operands: &[ContentOperand]) -> Option<String> {
    operands.iter().find_map(|o| match o {
        ContentOperand::Str(s) => {
            // Prefix hex strings with '<' for display; literal strings are '(...)'.
            if s.starts_with('<') && !s.starts_with("<<") {
                Some(format!("<{}>", s.trim_matches(|c| c == '<' || c == '>')))
            } else {
                let inner: String = s
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .to_string();
                let truncated: String = inner.chars().take(200).collect();
                Some(truncated)
            }
        }
        _ => None,
    })
}

/// Parse a `TJ` array operand string and return `(strings, max_abs_kern)`.
///
/// The `ContentOperand::Array` stores the raw bracket-enclosed token (e.g.
/// `"[(abc) 120 (def) -300 (ghi)]"`). This function performs a second-pass scan
/// to extract text fragments and numeric kern offsets.
fn extract_tj_array(operands: &[ContentOperand]) -> (Vec<String>, Option<f32>) {
    let raw = operands.iter().find_map(|o| match o {
        ContentOperand::Array(s) => Some(s.as_str()),
        _ => None,
    });
    let Some(raw) = raw else { return (vec![], None) };

    // Strip outer brackets.
    let inner = raw.trim_start_matches('[').trim_end_matches(']');
    let mut strings: Vec<String> = Vec::new();
    let mut max_kern: Option<f32> = None;
    let bytes = inner.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        // Skip whitespace.
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'(' {
            // Literal string — scan to matching ')'.
            let start = i + 1;
            i += 1;
            let mut depth = 1i32;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'(' {
                    depth += 1;
                } else if bytes[i] == b')' {
                    depth -= 1;
                }
                i += 1;
            }
            let end = i - 1;
            if end > start {
                let s: String = bytes[start..end.min(start + 200)]
                    .iter()
                    .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                    .collect();
                strings.push(s);
            }
        } else if bytes[i] == b'<' {
            // Hex string.
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'>' {
                i += 1;
            }
            let hex_part: String = String::from_utf8_lossy(&bytes[start..i]).into_owned();
            strings.push(format!("<{}>", &hex_part[..hex_part.len().min(200)]));
            if i < bytes.len() {
                i += 1; // skip '>'
            }
        } else {
            // Numeric kern offset — scan until whitespace or '['.
            let start = i;
            while i < bytes.len()
                && bytes[i] != b' '
                && bytes[i] != b'\t'
                && bytes[i] != b'\n'
                && bytes[i] != b'('
                && bytes[i] != b'<'
            {
                i += 1;
            }
            if let Ok(s) = std::str::from_utf8(&bytes[start..i]) {
                if let Ok(v) = s.parse::<f32>() {
                    let current_max = max_kern.unwrap_or(0.0_f32);
                    if v.abs() > current_max.abs() {
                        max_kern = Some(v);
                    }
                }
            }
        }
    }

    (strings, max_kern)
}

// ---------------------------------------------------------------------------
// Helpers: operator classification
// ---------------------------------------------------------------------------

/// True if this operator is in the known PDF operator set.
/// Mirrors the allowlist in `sis-pdf-detectors::parser_divergence`.
fn is_known_operator(op: &str) -> bool {
    matches!(
        op,
        "q" | "Q"
            | "cm"
            | "w"
            | "J"
            | "j"
            | "M"
            | "d"
            | "ri"
            | "i"
            | "gs"
            | "m"
            | "l"
            | "c"
            | "v"
            | "y"
            | "h"
            | "re"
            | "S"
            | "s"
            | "f"
            | "F"
            | "B"
            | "B*"
            | "b"
            | "b*"
            | "n"
            | "W"
            | "W*"
            | "BT"
            | "ET"
            | "Tc"
            | "Tw"
            | "Tz"
            | "TL"
            | "Tf"
            | "Tr"
            | "Ts"
            | "Td"
            | "TD"
            | "Tm"
            | "T*"
            | "Tj"
            | "TJ"
            | "'"
            | "\""
            | "CS"
            | "cs"
            | "SC"
            | "SCN"
            | "sc"
            | "scn"
            | "G"
            | "g"
            | "RG"
            | "rg"
            | "K"
            | "k"
            | "sh"
            | "Do"
            | "d0"
            | "d1"
            | "MP"
            | "DP"
            | "BMC"
            | "BDC"
            | "EMC"
            | "BX"
            | "EX"
            | "BI"
            | "ID"
            | "EI"
    )
}

/// True if this operator is a path/colour op that can be collapsed.
fn is_collapsible_op(op: &str) -> bool {
    matches!(
        op,
        "m" | "l"
            | "c"
            | "v"
            | "y"
            | "h"
            | "re"
            | "S"
            | "s"
            | "f"
            | "F"
            | "B"
            | "B*"
            | "b"
            | "b*"
            | "n"
            | "W"
            | "W*"
            | "CS"
            | "cs"
            | "SC"
            | "SCN"
            | "sc"
            | "scn"
            | "G"
            | "g"
            | "RG"
            | "rg"
            | "K"
            | "k"
            | "sh"
            | "w"
            | "J"
            | "j"
            | "M"
            | "d"
            | "ri"
            | "i"
    )
}

/// True if this operator starts a structural block (and should not be collapsed).
fn is_structural_op(op: &str) -> bool {
    matches!(op, "q" | "Q" | "BT" | "ET" | "BMC" | "BDC" | "EMC" | "BI" | "Do" | "BX" | "EX")
}

// ---------------------------------------------------------------------------
// Helpers: resource dict lookup
// ---------------------------------------------------------------------------

fn find_ref_in_dict(
    dict: &PdfDict<'_>,
    name: &[u8],
    graph: &ObjectGraph<'_>,
) -> Option<(u32, u16)> {
    // The resource name from operands has a leading '/' (e.g. b"/F1").
    // Dict keys also have leading '/' in their decoded bytes.
    let (_, value) = dict.get_first(name)?;
    match &value.atom {
        PdfAtom::Ref { obj, gen } => Some((*obj, *gen)),
        PdfAtom::Dict(_) | PdfAtom::Stream(_) => {
            // Inline (direct) resource — find its object id in the graph.
            let span_start = value.span.start;
            graph.objects.iter().find(|e| e.body_span.start == span_start).map(|e| (e.obj, e.gen))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::ObjectGraph;

    fn empty_graph() -> ObjectGraph<'static> {
        ObjectGraph {
            bytes: b"",
            objects: vec![],
            index: std::collections::HashMap::new(),
            trailers: vec![],
            startxrefs: vec![],
            xref_sections: vec![],
            deviations: vec![],
            telemetry_events: vec![],
        }
    }

    fn summarise(bytes: &[u8]) -> ContentStreamSummary {
        let graph = empty_graph();
        summarise_stream(bytes, false, (1, 0), None, 0, None, &graph)
    }

    #[test]
    fn parse_and_summarise_simple_page() {
        let stream = b"q\ncm 1 0 0 1 72 720\nBT\n/F1 12 Tf\n(Hello) Tj\nET\nQ\n";
        let s = summarise(stream);
        assert_eq!(s.anomalies.len(), 0, "expected no anomalies");
        assert_eq!(s.stats.graphics_state_depth_max, 1);
        assert_eq!(s.stats.text_op_count, 1);
        // One GraphicsState block at top level
        assert!(s.blocks.iter().any(|b| matches!(b, ContentBlock::GraphicsState { .. })));
    }

    #[test]
    fn detect_graphics_state_underflow() {
        let stream = b"Q";
        let s = summarise(stream);
        assert!(s.anomalies.iter().any(|a| matches!(a, ContentStreamAnomaly::GraphicsStateUnderflow { .. })));
    }

    #[test]
    fn detect_excessive_kern() {
        // TJ with a kern offset well beyond 200 units
        let stream = b"BT /F1 12 Tf [(abc) -500 (def)] TJ ET";
        let s = summarise(stream);
        assert!(
            s.anomalies.iter().any(|a| matches!(
                a,
                ContentStreamAnomaly::ExcessiveKernOffset { value, .. } if value.abs() > 200.0
            )),
            "expected ExcessiveKernOffset anomaly"
        );
    }

    #[test]
    fn detect_zero_scale_text() {
        let stream = b"BT /F1 12 Tf 0 Tz (invisible) Tj ET";
        let s = summarise(stream);
        assert!(
            s.anomalies.iter().any(|a| matches!(a, ContentStreamAnomaly::ZeroScaleText { .. })),
            "expected ZeroScaleText anomaly"
        );
    }

    #[test]
    fn detect_invisible_rendering_mode() {
        // Tr 3 = invisible rendering mode
        let stream = b"BT /F1 12 Tf 3 Tr (hidden) Tj ET";
        let s = summarise(stream);
        assert!(
            s.anomalies.iter().any(|a| matches!(a, ContentStreamAnomaly::InvisibleRenderingMode { .. })),
            "expected InvisibleRenderingMode anomaly"
        );
    }

    #[test]
    fn detect_truncated_stream() {
        let graph = empty_graph();
        let s = summarise_stream(b"BT (hello) Tj ET", true, (1, 0), None, 0, None, &graph);
        assert!(
            s.anomalies.iter().any(|a| matches!(a, ContentStreamAnomaly::StreamTruncated)),
            "expected StreamTruncated anomaly"
        );
    }

    #[test]
    fn suppress_unknown_op_in_bx_ex() {
        let stream = b"BX BADOP EX";
        let s = summarise(stream);
        assert!(
            !s.anomalies.iter().any(|a| matches!(a, ContentStreamAnomaly::UnknownOperator { .. })),
            "unknown op inside BX/EX should not be flagged"
        );
    }

    #[test]
    fn unknown_op_outside_bx_ex_emits_anomaly() {
        let stream = b"BADOP";
        let s = summarise(stream);
        assert!(
            s.anomalies.iter().any(|a| matches!(a, ContentStreamAnomaly::UnknownOperator { op, .. } if op == "BADOP")),
            "unknown op outside BX/EX should be flagged"
        );
    }

    #[test]
    fn multiple_fonts_in_single_text_object() {
        let stream = b"BT /F1 12 Tf (hello) Tj /F2 10 Tf (world) Tj ET";
        let s = summarise(stream);
        let text_blocks: Vec<_> = s.blocks.iter().filter_map(|b| match b {
            ContentBlock::TextObject { fonts, .. } => Some(fonts.clone()),
            _ => None,
        }).collect();
        assert_eq!(text_blocks.len(), 1);
        assert_eq!(text_blocks[0].len(), 2, "should have two font entries");
        assert_eq!(text_blocks[0][0].0, "/F1");
        assert_eq!(text_blocks[0][1].0, "/F2");
    }

    #[test]
    fn text_object_unterminated_at_eof() {
        let stream = b"BT /F1 12 Tf (text) Tj";
        let s = summarise(stream);
        assert!(
            s.anomalies.iter().any(|a| matches!(a, ContentStreamAnomaly::TextObjectUnterminatedAtEof)),
            "expected TextObjectUnterminatedAtEof anomaly"
        );
    }

    #[test]
    fn content_graph_to_dot_is_valid_syntax() {
        let stream = b"q BT /F1 12 Tf (Hello) Tj ET Q";
        let s = summarise(stream);
        let graph = build_content_graph(&s);
        let dot = content_graph_to_dot(&graph, "test");
        assert!(dot.starts_with("digraph"), "DOT output should start with 'digraph'");
        assert!(dot.contains("->"), "DOT output should contain edges");
    }

    #[test]
    fn type3_charproc_stream_summarises() {
        // d0 and d1 are the CharProc width-setting operators
        let stream = b"10 0 d0 0.5 g 0 0 10 10 re f";
        let s = summarise(stream);
        assert!(s.anomalies.iter().all(|a| !matches!(a, ContentStreamAnomaly::UnknownOperator { .. })),
            "d0 should not be flagged as unknown");
        assert!(!s.blocks.is_empty());
    }

    #[test]
    fn stats_path_op_count() {
        let stream = b"0 0 m 100 0 l 100 100 l 0 100 l h f";
        let s = summarise(stream);
        assert!(s.stats.path_op_count > 0, "path ops should be counted");
    }

    #[test]
    fn summary_to_json_has_required_fields() {
        let stream = b"BT /F1 12 Tf (Test) Tj ET";
        let s = summarise(stream);
        let j = summary_to_json(&s);
        assert!(j["stream_ref"].is_array());
        assert!(j["stats"]["total_op_count"].is_number());
        assert!(j["blocks"].is_array());
    }

    #[test]
    fn do_xobject_invoke_creates_block() {
        let stream = b"/Im0 Do";
        let s = summarise(stream);
        assert!(s.blocks.iter().any(|b| matches!(b, ContentBlock::XObjectInvoke { resource_name, .. } if resource_name == "/Im0")));
    }
}

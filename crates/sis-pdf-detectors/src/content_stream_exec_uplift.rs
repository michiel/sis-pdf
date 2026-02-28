use anyhow::Result;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::page_tree::build_page_tree;
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::content::{parse_content_ops, ContentOp, ContentOperand};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStream};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::entry_dict;

const MAX_CONTENT_STREAM_BYTES: usize = 2 * 1024 * 1024; // 2 MB — skip larger streams
const MAX_CONTENT_OPS_SCAN: usize = 5_000; // hard cap on ops fed to cluster detection
const MIN_OPS_FOR_CLUSTER: usize = 8;
const CLUSTER_FRACTION_THRESHOLD: f64 = 0.80;
const CLUSTER_BUCKET_SIZE: usize = 50;

pub struct ContentStreamExecUpliftDetector;

impl Detector for ContentStreamExecUpliftDetector {
    fn id(&self) -> &'static str {
        "content_stream_exec_uplift"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::FileStructure
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH | Needs::STREAM_DECODE | Needs::PAGE_CONTENT
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let page_tree = build_page_tree(&ctx.graph);
        let mut findings = Vec::new();
        let mut names_by_page = BTreeMap::<usize, BTreeSet<String>>::new();

        for page in &page_tree.pages {
            let Some(page_entry) = ctx.graph.get_object(page.obj, page.gen) else {
                continue;
            };
            let Some(page_dict) = entry_dict(page_entry) else {
                continue;
            };
            let form_xobjects = resolve_form_xobjects(&ctx.graph, page_dict);
            let stream_refs = page_content_stream_refs(ctx, page_dict);
            for stream_ref in stream_refs {
                let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, &stream_ref.stream) else {
                    continue;
                };
                // Skip very large streams to avoid O(n²) worst case
                if decoded.data.len() > MAX_CONTENT_STREAM_BYTES {
                    continue;
                }
                let ops = parse_content_ops(&decoded.data);
                if ops.is_empty() {
                    continue;
                }
                let analysis = analyse_ops(&ops, &form_xobjects);

                for name in &analysis.resource_names {
                    names_by_page.entry(page.number).or_default().insert(name.clone());
                }

                if analysis.gstate_max_depth > 28
                    || analysis.gstate_underflow_count > 0
                    || analysis.do_sandwich_count > 0
                {
                    findings.push(gstate_finding(
                        page.obj,
                        page.gen,
                        stream_ref.obj_ref,
                        stream_ref.stream.data_span,
                        &analysis,
                    ));
                }

                if let Some(marked_candidate) = analysis
                    .marked_candidates
                    .iter()
                    .max_by(|a, b| a.resource_fraction.total_cmp(&b.resource_fraction))
                {
                    findings.push(marked_evasion_finding(
                        page.obj,
                        page.gen,
                        stream_ref.obj_ref,
                        stream_ref.stream.data_span,
                        marked_candidate,
                    ));
                }

                if analysis.do_form_invoke_count > MAX_DO_DEPTH {
                    findings.push(do_depth_finding(
                        page.obj,
                        page.gen,
                        stream_ref.obj_ref,
                        stream_ref.stream.data_span,
                        analysis.do_form_invoke_count,
                    ));
                }

                if let Some(anomaly_meta) = detect_inline_image_anomaly(&ops) {
                    findings.push(inline_image_anomaly_finding(
                        page.obj,
                        page.gen,
                        stream_ref.obj_ref,
                        page.number,
                        &anomaly_meta,
                    ));
                }

                let js_text_hits = scan_text_ops_for_js(&ops);
                if !js_text_hits.is_empty() {
                    let mut meta = HashMap::new();
                    meta.insert("stream.js_patterns".into(), js_text_hits.join(", "));
                    meta.insert(
                        "stream.obj".into(),
                        stream_ref
                            .obj_ref
                            .map(|(o, g)| format!("{o} {g}"))
                            .unwrap_or_else(|| format!("{} {}", page.obj, page.gen)),
                    );
                    meta.insert("page.number".into(), page.number.to_string());
                    findings.push(Finding {
                        id: String::new(),
                        surface: AttackSurface::FileStructure,
                        kind: "content_stream_js_literal".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Tentative,
                        impact: Impact::Unknown,
                        title: "JavaScript-like literal in content stream".into(),
                        description: "Text rendering operators (Tj/TJ) contain strings \
                            resembling JavaScript. Some advanced payloads embed JS as \
                            text literals in appearance streams for later harvesting."
                            .into(),
                        objects: vec![format!("{} {} obj", page.obj, page.gen)],
                        evidence: vec![span_to_evidence(
                            stream_ref.stream.data_span,
                            "Content stream text operators",
                        )],
                        remediation: Some(
                            "Inspect content stream text; determine whether JS fragments \
                             are incidental or harvested by a Do/action chain."
                                .into(),
                        ),
                        meta,
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }
            }
        }

        if let Some(finding) = resource_name_obfuscation_finding(&names_by_page, &page_tree.pages) {
            findings.push(finding);
        }

        cap_findings_by_kind(&mut findings, "content_stream_js_literal", 10);
        Ok(findings)
    }
}

/// JS-like patterns that would be suspicious as rendered text content.
const JS_TEXT_PATTERNS: &[&[u8]] =
    &[b"function", b"eval(", b"Function(", b"window.", b"document.", b"<script", b"javascript:"];

/// Scan Tj / TJ / ' / " text operator string operands for JS-like patterns.
/// Returns deduplicated list of matched pattern strings.
fn scan_text_ops_for_js(ops: &[ContentOp]) -> Vec<String> {
    let mut hits = Vec::new();
    for op in ops {
        if !matches!(op.op.as_str(), "Tj" | "TJ" | "'" | "\"") {
            continue;
        }
        for operand in &op.operands {
            let raw: &[u8] = match operand {
                ContentOperand::Str(s) => s.as_bytes(),
                ContentOperand::Array(s) => s.as_bytes(),
                _ => continue,
            };
            let lower = raw.to_ascii_lowercase();
            for pat in JS_TEXT_PATTERNS {
                if lower.windows(pat.len()).any(|w| w == *pat) {
                    if let Ok(s) = std::str::from_utf8(pat) {
                        hits.push(s.to_string());
                    }
                }
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

/// Cap the number of findings of a given kind, aggregating suppressed ones.
fn cap_findings_by_kind(findings: &mut Vec<Finding>, kind: &str, cap: usize) {
    let total = findings.iter().filter(|f| f.kind == kind).count();
    if total <= cap {
        return;
    }
    let suppressed = total - cap;
    let mut retained = 0usize;
    findings.retain_mut(|f| {
        if f.kind != kind {
            return true;
        }
        retained += 1;
        if retained == 1 {
            f.meta.insert("aggregate.suppressed_count".into(), suppressed.to_string());
            f.meta.insert("aggregate.total_count".into(), total.to_string());
        }
        retained <= cap
    });
}

#[derive(Clone)]
struct PageContentStreamRef<'a> {
    obj_ref: Option<(u32, u16)>,
    stream: PdfStream<'a>,
}

/// Maximum number of `Do` invocations targeting Form XObjects per content stream before
/// a `content_stream_do_depth_excessive` finding is emitted.
const MAX_DO_DEPTH: usize = 16;

#[derive(Default)]
struct OpsAnalysis {
    gstate_max_depth: usize,
    gstate_underflow_count: usize,
    do_sandwich_count: usize,
    /// Count of `Do` operator invocations that target a Form XObject in this stream.
    do_form_invoke_count: usize,
    resource_names: Vec<String>,
    marked_candidates: Vec<MarkedCandidate>,
}

#[derive(Default)]
struct MarkedCandidate {
    tag: String,
    resource_fraction: f64,
    visible_op_count: usize,
}

#[derive(Default)]
struct MarkedFrame {
    tag: String,
    start_idx: usize,
    resource_ops: usize,
    visible_ops: usize,
}

fn analyse_ops(ops: &[ContentOp], form_xobjects: &HashMap<String, (u32, u16)>) -> OpsAnalysis {
    let mut out = OpsAnalysis::default();
    let mut gdepth = 0usize;
    let mut marked_stack = Vec::<MarkedFrame>::new();

    for (idx, op) in ops.iter().enumerate() {
        match op.op.as_str() {
            "q" => {
                gdepth += 1;
                out.gstate_max_depth = out.gstate_max_depth.max(gdepth);
            }
            "Q" => {
                if gdepth == 0 {
                    out.gstate_underflow_count += 1;
                } else {
                    gdepth -= 1;
                }
            }
            "BMC" | "BDC" => {
                marked_stack.push(MarkedFrame {
                    tag: marked_tag(op),
                    start_idx: idx,
                    resource_ops: 0,
                    visible_ops: 0,
                });
            }
            "EMC" => {
                if let Some(frame) = marked_stack.pop() {
                    let boundary_len = idx.saturating_sub(frame.start_idx).saturating_add(1);
                    let inner_len = boundary_len.saturating_sub(2);
                    let resource_fraction = if inner_len == 0 {
                        0.0
                    } else {
                        frame.resource_ops as f64 / inner_len as f64
                    };
                    let within_tight_boundary = boundary_len.saturating_mul(10) <= ops.len().max(1);
                    if frame.resource_ops > 0
                        && frame.visible_ops == 0
                        && resource_fraction > 0.80
                        && within_tight_boundary
                    {
                        out.marked_candidates.push(MarkedCandidate {
                            tag: frame.tag,
                            resource_fraction,
                            visible_op_count: frame.visible_ops,
                        });
                    }
                }
            }
            _ => {}
        }

        if matches!(op.op.as_str(), "Do" | "Tf") {
            if let Some(name) = first_name(&op.operands) {
                out.resource_names.push(name.clone());
                if op.op == "Do" && form_xobjects.contains_key(&name) {
                    out.do_form_invoke_count += 1;
                    let prev_q =
                        idx.checked_sub(1).and_then(|p| ops.get(p)).is_some_and(|p| p.op == "q");
                    let next_q = ops.get(idx + 1).is_some_and(|n| n.op == "Q");
                    if prev_q && next_q {
                        out.do_sandwich_count += 1;
                    }
                }
            }
        }

        let is_resource = matches!(op.op.as_str(), "Do" | "Tf");
        let is_visible = is_visible_render_op(op.op.as_str());
        for frame in &mut marked_stack {
            if is_resource {
                frame.resource_ops += 1;
            }
            if is_visible {
                frame.visible_ops += 1;
            }
        }
    }

    if out.marked_candidates.is_empty() {
        if let Some(cluster) = detect_resource_cluster_without_markers(ops) {
            out.marked_candidates.push(cluster);
        }
    }

    out
}

fn marked_tag(op: &ContentOp) -> String {
    op.operands
        .iter()
        .find_map(|operand| match operand {
            ContentOperand::Name(name) => Some(name.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "/Unknown".into())
}

fn is_visible_render_op(op: &str) -> bool {
    matches!(op, "Tj" | "TJ" | "'" | "\"" | "S" | "s" | "f" | "F" | "f*" | "B" | "B*" | "b" | "b*")
}

fn detect_resource_cluster_without_markers(ops: &[ContentOp]) -> Option<MarkedCandidate> {
    // Hard cap: only examine the first MAX_CONTENT_OPS_SCAN ops to bound worst case
    let ops = if ops.len() > MAX_CONTENT_OPS_SCAN { &ops[..MAX_CONTENT_OPS_SCAN] } else { ops };
    if ops.len() < MIN_OPS_FOR_CLUSTER {
        return None;
    }

    // Single-pass: walk ops in fixed-size non-overlapping buckets and compute
    // resource/visible ratio per bucket. O(N) total — no sliding window.
    let bucket = CLUSTER_BUCKET_SIZE.min(ops.len());
    let mut max_resource_fraction = 0.0f64;
    let mut best_visible = usize::MAX;

    for chunk in ops.chunks(bucket) {
        if chunk.len() < MIN_OPS_FOR_CLUSTER {
            break;
        }
        let resource_ops = chunk.iter().filter(|op| matches!(op.op.as_str(), "Do" | "Tf")).count();
        let visible_ops = chunk.iter().filter(|op| is_visible_render_op(op.op.as_str())).count();
        let fraction = resource_ops as f64 / chunk.len() as f64;
        if fraction > max_resource_fraction {
            max_resource_fraction = fraction;
            best_visible = visible_ops;
        }
    }

    if max_resource_fraction > CLUSTER_FRACTION_THRESHOLD && best_visible == 0 {
        Some(MarkedCandidate {
            tag: "/Cluster".into(),
            resource_fraction: max_resource_fraction,
            visible_op_count: best_visible,
        })
    } else {
        None
    }
}

fn gstate_finding(
    page_obj: u32,
    page_gen: u16,
    stream_ref: Option<(u32, u16)>,
    span: sis_pdf_pdf::span::Span,
    analysis: &OpsAnalysis,
) -> Finding {
    let stream_label = stream_ref
        .map(|(obj, gen)| format!("{obj} {gen}"))
        .unwrap_or_else(|| format!("{page_obj} {page_gen}"));
    let mut meta = HashMap::new();
    meta.insert("gstate.max_depth".into(), analysis.gstate_max_depth.to_string());
    meta.insert("gstate.underflow_count".into(), analysis.gstate_underflow_count.to_string());
    meta.insert("gstate.do_sandwich_count".into(), analysis.do_sandwich_count.to_string());
    meta.insert("stream.obj".into(), stream_label.clone());

    Finding {
        id: String::new(),
        surface: AttackSurface::FileStructure,
        kind: "content_stream_gstate_abuse".into(),
        severity: Severity::Medium,
        confidence: Confidence::Probable,
        impact: Impact::Medium,
        title: "Content stream graphics-state abuse".into(),
        description: "Content stream exhibits graphics-state depth/underflow anomalies or q-Do-Q form invocation sandwich patterns.".into(),
        objects: vec![format!("{page_obj} {page_gen} obj")],
        evidence: vec![span_to_evidence(span, "Content stream graphics-state sequence")],
        remediation: Some(
            "Review graphics-state stack usage and form XObject invocation patterns for obfuscation.".into(),
        ),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    }
}

fn do_depth_finding(
    page_obj: u32,
    page_gen: u16,
    stream_ref: Option<(u32, u16)>,
    span: sis_pdf_pdf::span::Span,
    depth: usize,
) -> Finding {
    let stream_label = stream_ref
        .map(|(obj, gen)| format!("{obj} {gen}"))
        .unwrap_or_else(|| format!("{page_obj} {page_gen}"));
    let mut meta = HashMap::new();
    meta.insert("do.max_depth".into(), depth.to_string());
    meta.insert("stream.obj".into(), stream_label);

    Finding {
        id: String::new(),
        surface: AttackSurface::StreamsAndFilters,
        kind: "content_stream_do_depth_excessive".into(),
        severity: Severity::Medium,
        confidence: Confidence::Strong,
        impact: Impact::Medium,
        title: "Excessive Form XObject Do invocation depth".into(),
        description: format!(
            "Content stream invokes `Do` on Form XObjects {depth} times, \
             exceeding the safe threshold ({MAX_DO_DEPTH}). \
             Deep Do chains can be used to exhaust renderer resources or \
             conceal payloads across many indirection layers."
        ),
        objects: vec![format!("{page_obj} {page_gen} obj")],
        evidence: vec![span_to_evidence(span, "Content stream Do invocation sequence")],
        remediation: Some(
            "Inspect Form XObject chain depth; legitimate documents rarely \
             exceed a handful of Do levels per page."
                .into(),
        ),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    }
}

fn marked_evasion_finding(
    page_obj: u32,
    page_gen: u16,
    stream_ref: Option<(u32, u16)>,
    span: sis_pdf_pdf::span::Span,
    candidate: &MarkedCandidate,
) -> Finding {
    let stream_label = stream_ref
        .map(|(obj, gen)| format!("{obj} {gen}"))
        .unwrap_or_else(|| format!("{page_obj} {page_gen}"));
    let mut meta = HashMap::new();
    meta.insert("mc.tag".into(), candidate.tag.clone());
    meta.insert("mc.resource_op_fraction".into(), format!("{:.3}", candidate.resource_fraction));
    meta.insert("mc.visible_op_count".into(), candidate.visible_op_count.to_string());
    meta.insert("stream.obj".into(), stream_label);

    Finding {
        id: String::new(),
        surface: AttackSurface::FileStructure,
        kind: "content_stream_marked_evasion".into(),
        severity: Severity::Medium,
        confidence: Confidence::Tentative,
        impact: Impact::Medium,
        title: "Marked-content evasion pattern".into(),
        description: "Marked-content block concentrates resource invocation operators without visible render operators in a tight boundary.".into(),
        objects: vec![format!("{page_obj} {page_gen} obj")],
        evidence: vec![span_to_evidence(span, "Marked-content operator concentration")],
        remediation: Some(
            "Inspect marked-content boundaries for concealed invocation staging and renderer differential risk.".into(),
        ),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    }
}

fn resource_name_obfuscation_finding(
    names_by_page: &BTreeMap<usize, BTreeSet<String>>,
    pages: &[sis_pdf_core::page_tree::PageInfo],
) -> Option<Finding> {
    let mut all_names = Vec::<String>::new();
    let mut appearances = HashMap::<String, usize>::new();
    for names in names_by_page.values() {
        for name in names {
            all_names.push(name.clone());
            *appearances.entry(name.clone()).or_insert(0) += 1;
        }
    }
    if all_names.is_empty() {
        return None;
    }

    let mut max_entropy = 0.0f64;
    let mut max_len = 0usize;
    for name in &all_names {
        let ent = shannon_entropy(name.as_bytes());
        if ent > max_entropy {
            max_entropy = ent;
        }
        if name.len() > max_len {
            max_len = name.len();
        }
    }

    let page_count = pages.len().max(1);
    let mut distinct = all_names;
    distinct.sort();
    distinct.dedup();
    let churn_rate = distinct.len() as f64 / page_count as f64;

    let mut changing_every_page = false;
    if names_by_page.len() >= 2 && names_by_page.len() == page_count {
        let single_page_names = appearances.values().all(|count| *count == 1);
        let all_pages_nonempty = names_by_page.values().all(|set| !set.is_empty());
        changing_every_page = single_page_names && all_pages_nonempty;
    }

    let suspicious = max_entropy > 4.5 || max_len > 32 || changing_every_page;
    if !suspicious {
        return None;
    }

    let mut meta = HashMap::new();
    meta.insert("resource.name_max_entropy".into(), format!("{:.3}", max_entropy));
    meta.insert("resource.churn_rate".into(), format!("{:.3}", churn_rate));
    meta.insert("resource.max_name_length".into(), max_len.to_string());
    meta.insert(
        "resource.change_every_page".into(),
        if changing_every_page { "true" } else { "false" }.into(),
    );

    Some(Finding {
        id: String::new(),
        surface: AttackSurface::FileStructure,
        kind: "content_stream_resource_name_obfuscation".into(),
        severity: Severity::Low,
        confidence: Confidence::Tentative,
        impact: Impact::Low,
        title: "Resource-name obfuscation in content streams".into(),
        description: "Content stream Do/Tf resource identifiers show high entropy, excessive length, or page-to-page churn patterns.".into(),
        objects: Vec::new(),
        evidence: Vec::new(),
        remediation: Some(
            "Review resource naming strategy for obfuscation patterns and resolve names to concrete resource objects.".into(),
        ),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    })
}

fn resolve_form_xobjects(
    graph: &sis_pdf_pdf::ObjectGraph<'_>,
    page_dict: &PdfDict<'_>,
) -> HashMap<String, (u32, u16)> {
    let mut out = HashMap::new();
    let Some((_, resources_obj)) = page_dict.get_first(b"/Resources") else {
        return out;
    };
    let Some(resources_dict) = resolve_dict(graph, resources_obj) else {
        return out;
    };
    let Some((_, xobj_obj)) = resources_dict.get_first(b"/XObject") else {
        return out;
    };
    let Some(xobj_dict) = resolve_dict(graph, xobj_obj) else {
        return out;
    };
    for (name, obj) in &xobj_dict.entries {
        let Some((obj_num, gen_num)) = resolve_ref_tuple(graph, obj) else {
            continue;
        };
        let is_form = graph
            .get_object(obj_num, gen_num)
            .and_then(entry_dict)
            .map(|dict| dict.has_name(b"/Subtype", b"/Form"))
            .unwrap_or(false);
        if is_form {
            out.insert(String::from_utf8_lossy(&name.decoded).to_string(), (obj_num, gen_num));
        }
    }
    out
}

fn page_content_stream_refs<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext<'a>,
    dict: &PdfDict<'a>,
) -> Vec<PageContentStreamRef<'a>> {
    let mut out = Vec::new();
    let Some((_, contents)) = dict.get_first(b"/Contents") else {
        return out;
    };
    match &contents.atom {
        PdfAtom::Array(items) => {
            for item in items {
                if let Some(stream_ref) = resolve_stream_ref(ctx, item) {
                    out.push(stream_ref);
                }
            }
        }
        _ => {
            if let Some(stream_ref) = resolve_stream_ref(ctx, contents) {
                out.push(stream_ref);
            }
        }
    }
    out
}

fn resolve_stream_ref<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext<'a>,
    obj: &PdfObj<'a>,
) -> Option<PageContentStreamRef<'a>> {
    match &obj.atom {
        PdfAtom::Stream(stream) => {
            Some(PageContentStreamRef { obj_ref: None, stream: stream.clone() })
        }
        PdfAtom::Ref { obj: obj_num, gen: gen_num } => {
            ctx.graph.get_object(*obj_num, *gen_num).and_then(|entry| match &entry.atom {
                PdfAtom::Stream(stream) => Some(PageContentStreamRef {
                    obj_ref: Some((*obj_num, *gen_num)),
                    stream: stream.clone(),
                }),
                _ => None,
            })
        }
        _ => ctx.graph.resolve_ref(obj).and_then(|entry| match &entry.atom {
            PdfAtom::Stream(stream) => Some(PageContentStreamRef {
                obj_ref: Some((entry.obj, entry.gen)),
                stream: stream.clone(),
            }),
            _ => None,
        }),
    }
}

fn resolve_dict<'a>(
    graph: &'a sis_pdf_pdf::ObjectGraph<'a>,
    obj: &'a PdfObj<'a>,
) -> Option<&'a PdfDict<'a>> {
    match &obj.atom {
        PdfAtom::Dict(dict) => Some(dict),
        PdfAtom::Stream(stream) => Some(&stream.dict),
        PdfAtom::Ref { obj, gen } => graph.get_object(*obj, *gen).and_then(entry_dict),
        _ => None,
    }
}

fn resolve_ref_tuple(graph: &sis_pdf_pdf::ObjectGraph<'_>, obj: &PdfObj<'_>) -> Option<(u32, u16)> {
    match obj.atom {
        PdfAtom::Ref { obj, gen } => Some((obj, gen)),
        _ => graph.resolve_ref(obj).map(|entry| (entry.obj, entry.gen)),
    }
}

fn first_name(operands: &[ContentOperand]) -> Option<String> {
    operands.iter().find_map(|operand| match operand {
        ContentOperand::Name(name) => Some(name.clone()),
        _ => None,
    })
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum::<f64>()
}

// --- Inline image anomaly detector ---

struct InlineImageInfo {
    data_bytes: u64,
    filters: Vec<String>,
}

struct InlineImageAnomalyMeta {
    inline_count: usize,
    max_data_bytes: u64,
    filter_chains_csv: String,
    oversized: bool,
    suspicious_filter_chain: bool,
    sparse_render_ops: bool,
}

fn extract_filter_names_from_operands(operands: &[ContentOperand]) -> Vec<String> {
    let mut filters = Vec::new();
    let mut j = 0;
    while j < operands.len() {
        if let ContentOperand::Name(name) = &operands[j] {
            let lower = name.to_ascii_lowercase();
            if lower == "/f" || lower == "/filter" {
                if let Some(ContentOperand::Name(filter_name)) = operands.get(j + 1) {
                    filters.push(filter_name.trim_start_matches('/').to_string());
                    j += 2;
                    continue;
                }
            }
        }
        j += 1;
    }
    filters
}

fn extract_inline_image_infos(ops: &[ContentOp]) -> Vec<InlineImageInfo> {
    let mut images = Vec::new();
    let mut i = 0;
    while i < ops.len() {
        if ops[i].op == "BI" {
            let id_idx = (i + 1..ops.len()).find(|&j| ops[j].op == "ID");
            if let Some(id_idx) = id_idx {
                let ei_idx = (id_idx + 1..ops.len()).find(|&j| ops[j].op == "EI");
                if let Some(ei_idx) = ei_idx {
                    let id_op = &ops[id_idx];
                    let ei_op = &ops[ei_idx];
                    let data_bytes = ei_op.span.start.saturating_sub(id_op.span.end);
                    let filters = extract_filter_names_from_operands(&id_op.operands);
                    images.push(InlineImageInfo { data_bytes, filters });
                    i = ei_idx + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    images
}

fn detect_inline_image_anomaly(ops: &[ContentOp]) -> Option<InlineImageAnomalyMeta> {
    let images = extract_inline_image_infos(ops);
    if images.is_empty() {
        return None;
    }

    let total_ops = ops.len();
    let render_ops = ops.iter().filter(|op| is_visible_render_op(op.op.as_str())).count();
    let render_fraction = if total_ops == 0 { 1.0 } else { render_ops as f64 / total_ops as f64 };

    let max_data_bytes = images.iter().map(|img| img.data_bytes).max().unwrap_or(0);
    let oversized = max_data_bytes > 64 * 1024;

    let suspicious_filter_chain = images.iter().any(|img| {
        let has_ascii85 = img.filters.iter().any(|f| {
            let fl = f.to_ascii_lowercase();
            fl == "ascii85decode" || fl == "a85"
        });
        let has_flate = img.filters.iter().any(|f| {
            let fl = f.to_ascii_lowercase();
            fl == "flatedecode" || fl == "fl"
        });
        has_ascii85 && has_flate
    });

    let sparse_render_ops = render_fraction < 0.10;

    let filter_chains_csv = images
        .iter()
        .filter_map(|img| if img.filters.is_empty() { None } else { Some(img.filters.join("+")) })
        .collect::<Vec<_>>()
        .join(",");

    if oversized || suspicious_filter_chain || sparse_render_ops {
        Some(InlineImageAnomalyMeta {
            inline_count: images.len(),
            max_data_bytes,
            filter_chains_csv,
            oversized,
            suspicious_filter_chain,
            sparse_render_ops,
        })
    } else {
        None
    }
}

fn inline_image_anomaly_finding(
    page_obj: u32,
    page_gen: u16,
    stream_ref: Option<(u32, u16)>,
    page_number: usize,
    meta_info: &InlineImageAnomalyMeta,
) -> Finding {
    let stream_label = stream_ref
        .map(|(obj, gen)| format!("{obj} {gen}"))
        .unwrap_or_else(|| format!("{page_obj} {page_gen}"));
    let mut meta = HashMap::new();
    let mut trigger_flags = Vec::new();
    if meta_info.oversized {
        trigger_flags.push("oversized");
    }
    if meta_info.suspicious_filter_chain {
        trigger_flags.push("suspicious_filter_chain");
    }
    if meta_info.sparse_render_ops {
        trigger_flags.push("sparse_render_ops");
    }
    meta.insert("inline.count".into(), meta_info.inline_count.to_string());
    meta.insert("inline.max_bytes".into(), meta_info.max_data_bytes.to_string());
    meta.insert("inline.filter_chains".into(), meta_info.filter_chains_csv.clone());
    meta.insert("inline.trigger_flags".into(), trigger_flags.join(","));
    meta.insert("stream.obj".into(), stream_label);
    meta.insert("page.number".into(), page_number.to_string());

    Finding {
        id: String::new(),
        surface: AttackSurface::FileStructure,
        kind: "content_stream_inline_image_anomaly".into(),
        severity: Severity::Medium,
        confidence: Confidence::Tentative,
        impact: Impact::Medium,
        title: "Inline image anomaly in content stream".into(),
        description: "Content stream contains inline image data with anomalous size, filter chain, or near-absence of visible render operators.".into(),
        objects: vec![format!("{page_obj} {page_gen} obj")],
        evidence: Vec::new(),
        remediation: Some(
            "Inspect inline image data for embedded payload carriers or decoder-chain obfuscation.".into(),
        ),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    }
}

#[cfg(test)]
mod tests {
    use super::detect_inline_image_anomaly;
    use sis_pdf_pdf::content::{ContentOp, ContentOperand};
    use sis_pdf_pdf::span::Span;

    fn make_op(op: &str, operands: Vec<ContentOperand>, start: u64, end: u64) -> ContentOp {
        ContentOp { op: op.to_string(), operands, span: Span { start, end } }
    }

    #[test]
    fn inline_image_anomaly_triggers_on_oversized_data() {
        // ID.span.end = 2, EI.span.start = 128*1024 + 2 → data_bytes = 131072 > 65536
        let data_end: u64 = 2 + 128 * 1024;
        let ops = vec![
            make_op("BT", vec![], 0, 1),
            make_op("Tj", vec![], 1, 2),
            make_op("ET", vec![], 2, 3),
            make_op("BI", vec![], 3, 4),
            make_op("ID", vec![], 4, 6),
            make_op("EI", vec![], data_end, data_end + 2),
        ];
        let result = detect_inline_image_anomaly(&ops);
        assert!(result.is_some(), "expected anomaly on oversized inline image");
        let meta = result.unwrap();
        assert!(meta.oversized);
        assert!(meta.max_data_bytes > 64 * 1024);
    }

    #[test]
    fn inline_image_anomaly_triggers_on_suspicious_filter_chain() {
        // ID operands contain both /ASCII85Decode and /FlateDecode
        let operands = vec![
            ContentOperand::Name("/F".to_string()),
            ContentOperand::Name("/ASCII85Decode".to_string()),
            ContentOperand::Name("/Filter".to_string()),
            ContentOperand::Name("/FlateDecode".to_string()),
            ContentOperand::Name("/W".to_string()),
            ContentOperand::Number(8.0),
            ContentOperand::Name("/H".to_string()),
            ContentOperand::Number(8.0),
        ];
        let ops = vec![
            make_op("BI", vec![], 0, 2),
            make_op("ID", operands, 2, 4),
            // small image data (only 100 bytes)
            make_op("EI", vec![], 104, 106),
        ];
        let result = detect_inline_image_anomaly(&ops);
        assert!(result.is_some(), "expected anomaly on suspicious filter chain");
        let meta = result.unwrap();
        assert!(meta.suspicious_filter_chain);
    }

    #[test]
    fn inline_image_anomaly_triggers_on_near_absence_of_render_ops() {
        // One BI/ID/EI with no text or path rendering ops at all → sparse_render_ops
        let ops = vec![
            make_op("BI", vec![], 0, 2),
            make_op("ID", vec![], 2, 4),
            make_op("EI", vec![], 104, 106),
        ];
        let result = detect_inline_image_anomaly(&ops);
        assert!(result.is_some(), "expected anomaly on near-absence of render ops");
        let meta = result.unwrap();
        assert!(meta.sparse_render_ops);
    }

    #[test]
    fn inline_image_anomaly_no_trigger_on_benign_small_image() {
        // Small image (100 bytes), no suspicious filters, plenty of text ops → no anomaly
        let mut ops = vec![
            make_op("BT", vec![], 0, 2),
            make_op(
                "Tf",
                vec![ContentOperand::Name("/F1".to_string()), ContentOperand::Number(12.0)],
                2,
                10,
            ),
        ];
        // Add many Tj ops to ensure render_fraction > 10%
        for k in 0..20u64 {
            let base = 10 + k * 10;
            ops.push(make_op("Tj", vec![ContentOperand::Str("(x)".to_string())], base, base + 8));
        }
        ops.push(make_op("ET", vec![], 210, 212));
        ops.push(make_op("BI", vec![], 212, 214));
        let id_operands = vec![
            ContentOperand::Name("/W".to_string()),
            ContentOperand::Number(8.0),
            ContentOperand::Name("/H".to_string()),
            ContentOperand::Number(8.0),
        ];
        ops.push(make_op("ID", id_operands, 214, 216));
        // EI starts 100 bytes after ID end → 316
        ops.push(make_op("EI", vec![], 316, 318));

        let result = detect_inline_image_anomaly(&ops);
        assert!(result.is_none(), "expected no anomaly on benign small inline image");
    }
}

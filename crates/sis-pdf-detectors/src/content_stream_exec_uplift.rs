use anyhow::Result;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::page_tree::build_page_tree;
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::content::{parse_content_ops, ContentOp, ContentOperand};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStream};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::entry_dict;

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
            }
        }

        if let Some(finding) = resource_name_obfuscation_finding(&names_by_page, &page_tree.pages) {
            findings.push(finding);
        }

        Ok(findings)
    }
}

#[derive(Clone)]
struct PageContentStreamRef<'a> {
    obj_ref: Option<(u32, u16)>,
    stream: PdfStream<'a>,
}

#[derive(Default)]
struct OpsAnalysis {
    gstate_max_depth: usize,
    gstate_underflow_count: usize,
    do_sandwich_count: usize,
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
    if ops.len() < 8 {
        return None;
    }
    let mut window = (ops.len() / 10).max(8);
    if window > ops.len() {
        window = ops.len();
    }
    for start in 0..=ops.len().saturating_sub(window) {
        let slice = &ops[start..start + window];
        let resource_ops = slice.iter().filter(|op| matches!(op.op.as_str(), "Do" | "Tf")).count();
        let visible_ops = slice.iter().filter(|op| is_visible_render_op(op.op.as_str())).count();
        if resource_ops < 6 || visible_ops > 0 {
            continue;
        }
        let fraction = resource_ops as f64 / window as f64;
        if fraction > 0.80 {
            return Some(MarkedCandidate {
                tag: "/Cluster".into(),
                resource_fraction: fraction,
                visible_op_count: visible_ops,
            });
        }
    }
    None
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
        impact: Some(Impact::Medium),
        title: "Content stream graphics-state abuse".into(),
        description: "Content stream exhibits graphics-state depth/underflow anomalies or q-Do-Q form invocation sandwich patterns.".into(),
        objects: vec![format!("{page_obj} {page_gen} obj")],
        evidence: vec![span_to_evidence(span, "Content stream graphics-state sequence")],
        remediation: Some(
            "Review graphics-state stack usage and form XObject invocation patterns for obfuscation.".into(),
        ),
        meta,
        yara: None,
        position: None,
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
        impact: Some(Impact::Medium),
        title: "Marked-content evasion pattern".into(),
        description: "Marked-content block concentrates resource invocation operators without visible render operators in a tight boundary.".into(),
        objects: vec![format!("{page_obj} {page_gen} obj")],
        evidence: vec![span_to_evidence(span, "Marked-content operator concentration")],
        remediation: Some(
            "Inspect marked-content boundaries for concealed invocation staging and renderer differential risk.".into(),
        ),
        meta,
        yara: None,
        position: None,
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
        impact: Some(Impact::Low),
        title: "Resource-name obfuscation in content streams".into(),
        description: "Content stream Do/Tf resource identifiers show high entropy, excessive length, or page-to-page churn patterns.".into(),
        objects: Vec::new(),
        evidence: Vec::new(),
        remediation: Some(
            "Review resource naming strategy for obfuscation patterns and resolve names to concrete resource objects.".into(),
        ),
        meta,
        yara: None,
        position: None,
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

use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::graph_walk::{build_adjacency, reachable_from, ObjRef};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfDict};

pub struct IrGraphStaticDetector;

const ACTION_PATH_DEPTH: usize = 4;

impl Detector for IrGraphStaticDetector {
    fn id(&self) -> &'static str {
        "ir_graph_static"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::FileStructure
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Moderate
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        if !ctx.options.ir {
            return Ok(Vec::new());
        }
        let ir_opts = sis_pdf_pdf::ir::IrOptions::default();
        let ir_graph = sis_pdf_core::ir_pipeline::build_ir_graph(&ctx.graph, &ir_opts);
        let flags = classify_nodes(&ir_graph.ir_objects);
        let adjacency = build_adjacency(&ctx.graph.objects);
        let mut findings = Vec::new();

        findings.extend(find_action_payload_paths(
            ctx,
            &ir_graph.org.nodes,
            &adjacency,
            &flags,
        ));
        findings.extend(find_orphan_payloads(ctx, &adjacency, &flags));
        findings.extend(find_shadow_payloads(ctx, &flags));
        findings.extend(find_objstm_payloads(ctx, &flags));

        Ok(findings)
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct NodeFlags {
    has_action: bool,
    has_js: bool,
    has_external: bool,
    has_payload: bool,
}

fn classify_nodes(
    ir_objects: &[sis_pdf_pdf::ir::PdfIrObject],
) -> std::collections::HashMap<ObjRef, NodeFlags> {
    let mut map = std::collections::HashMap::new();
    for obj in ir_objects {
        let mut flags = NodeFlags::default();
        for line in &obj.lines {
            let path = line.path.as_str();
            let value = line.value.as_str();
            if path.ends_with("/OpenAction") || path.ends_with("/AA") || path.ends_with("/Action") {
                flags.has_action = true;
            }
            if line.value_type == "name" && value == "/JavaScript" {
                flags.has_js = true;
            }
            if value == "/URI" || value == "/GoToR" || value == "/Launch" || value == "/SubmitForm" {
                flags.has_external = true;
            }
            if line.value_type == "stream" || line.value_type == "str" {
                flags.has_payload = true;
            }
            if path.ends_with("/JS") || path.ends_with("/JavaScript") {
                flags.has_js = true;
            }
        }
        flags.has_payload = flags.has_payload || flags.has_js || flags.has_external;
        let key = ObjRef {
            obj: obj.obj_ref.0,
            gen: obj.obj_ref.1,
        };
        map.insert(key, flags);
    }
    map
}

fn find_action_payload_paths(
    ctx: &sis_pdf_core::scan::ScanContext,
    nodes: &[ObjRef],
    adjacency: &std::collections::HashMap<ObjRef, Vec<ObjRef>>,
    flags: &std::collections::HashMap<ObjRef, NodeFlags>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut action_nodes = Vec::new();
    for n in nodes {
        if flags.get(n).map(|f| f.has_action).unwrap_or(false) {
            action_nodes.push(*n);
        }
    }
    if action_nodes.is_empty() {
        return findings;
    }
    let reachable = reachable_from(adjacency, &action_nodes, ACTION_PATH_DEPTH);
    for target in reachable {
        if flags.get(&target).map(|f| f.has_payload).unwrap_or(false) {
            if action_nodes.contains(&target) {
                continue;
            }
            let mut evidence = Vec::new();
            if let Some(entry) = ctx.graph.get_object(target.obj, target.gen) {
                evidence.push(span_to_evidence(entry.full_span, "Payload object"));
            }
            let mut meta = std::collections::HashMap::new();
            meta.insert("ir.path_depth".into(), ACTION_PATH_DEPTH.to_string());
            meta.insert(
                "ir.action_objects".into(),
                action_nodes
                    .iter()
                    .map(|n| format!("{} {}", n.obj, n.gen))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Actions,
                kind: "action_payload_path".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Action path reaches payload".into(),
                description: format!(
                    "Action object reaches payload-like object {} {}.",
                    target.obj, target.gen
                ),
                objects: vec![format!("{} {} obj", target.obj, target.gen)],
                evidence,
                remediation: Some("Inspect referenced payload chain for malicious intent.".into()),
                meta,
                yara: None,
        position: None,
        positions: Vec::new(),
            });
        }
    }
    findings
}

fn find_orphan_payloads(
    ctx: &sis_pdf_core::scan::ScanContext,
    adjacency: &std::collections::HashMap<ObjRef, Vec<ObjRef>>,
    flags: &std::collections::HashMap<ObjRef, NodeFlags>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let roots = catalog_roots(&ctx.graph.trailers);
    if roots.is_empty() {
        return findings;
    }
    let reachable = reachable_from(adjacency, &roots, 6);
    for (obj, f) in flags {
        if f.has_payload && !reachable.contains(obj) {
            let mut evidence = Vec::new();
            if let Some(entry) = ctx.graph.get_object(obj.obj, obj.gen) {
                evidence.push(span_to_evidence(entry.full_span, "Orphan payload"));
            }
            let mut meta = std::collections::HashMap::new();
            meta.insert("ir.orphan_root_count".into(), roots.len().to_string());
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::FileStructure,
                kind: "orphan_payload_object".into(),
                severity: Severity::Low,
                confidence: Confidence::Probable,
                title: "Orphaned payload object".into(),
                description: format!(
                    "Payload-like object {} {} is not reachable from catalog root.",
                    obj.obj, obj.gen
                ),
                objects: vec![format!("{} {} obj", obj.obj, obj.gen)],
                evidence,
                remediation: Some("Inspect for hidden or shadowed revisions.".into()),
                meta,
                yara: None,
        position: None,
        positions: Vec::new(),
            });
        }
    }
    findings
}

fn find_shadow_payloads(
    ctx: &sis_pdf_core::scan::ScanContext,
    flags: &std::collections::HashMap<ObjRef, NodeFlags>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for ((obj, gen), idxs) in &ctx.graph.index {
        if idxs.len() <= 1 {
            continue;
        }
        let key = ObjRef { obj: *obj, gen: *gen };
        if flags.get(&key).map(|f| f.has_payload).unwrap_or(false) {
            let mut evidence = Vec::new();
            for idx in idxs {
                if let Some(entry) = ctx.graph.objects.get(*idx) {
                    evidence.push(span_to_evidence(entry.full_span, "Shadowed object span"));
                }
            }
            let mut meta = std::collections::HashMap::new();
            meta.insert("ir.shadow_count".into(), idxs.len().to_string());
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::FileStructure,
                kind: "shadow_payload_chain".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Shadowed payload object".into(),
                description: format!(
                    "Shadowed object {} {} contains payload-like content.",
                    obj, gen
                ),
                objects: vec![format!("{} {} obj", obj, gen)],
                evidence,
                remediation: Some("Review incremental updates for hidden payloads.".into()),
                meta,
                yara: None,
        position: None,
        positions: Vec::new(),
            });
        }
    }
    findings
}

fn find_objstm_payloads(
    ctx: &sis_pdf_core::scan::ScanContext,
    flags: &std::collections::HashMap<ObjRef, NodeFlags>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut objstm_spans = Vec::new();
    for entry in &ctx.graph.objects {
        if let PdfAtom::Stream(st) = &entry.atom {
            if st.dict.has_name(b"/Type", b"/ObjStm") {
                objstm_spans.push((st.data_span.start, st.data_span.end));
            }
        }
    }
    if objstm_spans.is_empty() {
        return findings;
    }
    for (obj, f) in flags {
        if !f.has_payload {
            continue;
        }
        if let Some(entry) = ctx.graph.get_object(obj.obj, obj.gen) {
            let span = (entry.full_span.start, entry.full_span.end);
            if objstm_spans.iter().any(|s| *s == span) {
                let mut meta = std::collections::HashMap::new();
                meta.insert("ir.objstm_count".into(), objstm_spans.len().to_string());
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::ObjectStreams,
                    kind: "objstm_action_chain".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Probable,
                    title: "Payload in ObjStm".into(),
                    description: format!(
                        "Payload-like object {} {} appears within ObjStm stream span.",
                        obj.obj, obj.gen
                    ),
                    objects: vec![format!("{} {} obj", obj.obj, obj.gen)],
                    evidence: vec![span_to_evidence(entry.full_span, "ObjStm span")],
                    remediation: Some("Use deep scan to inspect embedded objects.".into()),
                    meta,
                    yara: None,
        position: None,
        positions: Vec::new(),
                });
            }
        }
    }
    findings
}

fn catalog_roots(trailers: &[PdfDict<'_>]) -> Vec<ObjRef> {
    let mut roots = Vec::new();
    for t in trailers {
        if let Some((_, obj)) = t.get_first(b"/Root") {
            if let PdfAtom::Ref { obj, gen } = obj.atom {
                roots.push(ObjRef { obj, gen });
            }
        }
    }
    roots
}

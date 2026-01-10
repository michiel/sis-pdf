use anyhow::Result;
use std::collections::HashSet;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::graph_walk::ObjRef;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::page_tree::build_page_tree;
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};

use crate::entry_dict;

pub struct PageTreeManipulationDetector;

impl Detector for PageTreeManipulationDetector {
    fn id(&self) -> &'static str {
        "page_tree_anomalies"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::FileStructure
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Cheap
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = Vec::new();

        let root = root_pages_obj(ctx).or_else(|| fallback_pages_root(ctx, &mut findings));
        if let Some(root) = root {
            detect_cycles(ctx, &root, &mut visited, &mut stack, &mut findings);
            let actual = count_pages(ctx, &root, &mut HashSet::new());
            let declared = declared_page_count(ctx, &root);
            if let Some(declared) = declared {
                if declared != actual as i64 {
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("page_tree.declared".into(), declared.to_string());
                    meta.insert("page_tree.actual".into(), actual.to_string());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "page_tree_mismatch".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Probable,
                        title: "Page tree count mismatch".into(),
                        description: "Page tree /Count does not match actual leaf pages.".into(),
                        objects: vec!["page_tree".into()],
                        evidence: vec![],
                        remediation: Some("Inspect page tree structure for missing or hidden pages.".into()),
                        meta,
                        yara: None,
        position: None,
        positions: Vec::new(),
                    });
                }
            }
            let page_tree = build_page_tree(&ctx.graph);
            let tree_pages: HashSet<ObjRef> = page_tree
                .pages
                .iter()
                .map(|p| ObjRef { obj: p.obj, gen: p.gen })
                .collect();
            let all_pages: HashSet<ObjRef> = ctx
                .graph
                .objects
                .iter()
                .filter_map(|e| {
                    let dict = entry_dict(e)?;
                    if dict.has_name(b"/Type", b"/Page") {
                        Some(ObjRef { obj: e.obj, gen: e.gen })
                    } else {
                        None
                    }
                })
                .collect();
            let orphaned_pages: Vec<ObjRef> = all_pages
                .difference(&tree_pages)
                .copied()
                .collect();
            if !orphaned_pages.is_empty() {
                let mut meta = std::collections::HashMap::new();
                meta.insert(
                    "page_tree.orphaned".into(),
                    orphaned_pages.len().to_string(),
                );
                let mut objects = Vec::with_capacity(orphaned_pages.len() + 1);
                objects.push("page_tree".into());
                for orphaned in &orphaned_pages {
                    objects.push(format!("{} {} obj", orphaned.obj, orphaned.gen));
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "page_tree_mismatch".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Probable,
                    title: "Orphaned page objects".into(),
                    description: "Some /Page objects are not reachable from the page tree.".into(),
                    objects,
                    evidence: vec![],
                    remediation: Some("Inspect page tree references and catalog root.".into()),
                    meta,
                    yara: None,
        position: None,
        positions: Vec::new(),
                });
            }
        }
        Ok(findings)
    }
}

fn fallback_pages_root<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext<'a>,
    findings: &mut Vec<Finding>,
) -> Option<PdfObj<'a>> {
    let entry = ctx.graph.objects.iter().find(|entry| {
        entry_dict(entry)
            .map(|d| d.has_name(b"/Type", b"/Pages"))
            .unwrap_or(false)
    })?;
    findings.push(Finding {
        id: String::new(),
        surface: AttackSurface::FileStructure,
        kind: "page_tree_fallback".into(),
        severity: Severity::Low,
        confidence: Confidence::Heuristic,
        title: "Fallback /Pages root".into(),
        description: "Page tree root resolved by scanning the object graph, not by the catalog /Root.".into(),
        objects: vec!["page_tree".into()],
        evidence: vec![span_to_evidence(entry.body_span, "Fallback /Pages root")],
        remediation: Some("Inspect catalog /Root and /Pages references for consistency.".into()),
        meta: Default::default(),
        yara: None,
        position: None,
        positions: Vec::new(),
    });
    Some(PdfObj {
        span: entry.body_span,
        atom: entry.atom.clone(),
    })
}

fn root_pages_obj<'a>(ctx: &'a sis_pdf_core::scan::ScanContext<'a>) -> Option<PdfObj<'a>> {
    let root = ctx
        .graph
        .trailers
        .last()
        .and_then(|t| t.get_first(b"/Root"))
        .map(|(_, v)| v.clone())?;
    let catalog = resolve_dict(&ctx.graph, &root)?;
    catalog.get_first(b"/Pages").map(|(_, v)| v.clone())
}

fn detect_cycles(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &PdfObj<'_>,
    visited: &mut HashSet<ObjRef>,
    stack: &mut Vec<ObjRef>,
    findings: &mut Vec<Finding>,
) {
    let Some(dict) = resolve_dict(&ctx.graph, obj) else { return };
    if !dict.has_name(b"/Type", b"/Pages") {
        return;
    }
    let node_ref = object_ref(&ctx.graph, obj);
    if let Some(node_ref) = node_ref {
        if stack.contains(&node_ref) {
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::FileStructure,
                kind: "page_tree_cycle".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Page tree cycle detected".into(),
                description: "Page tree contains a cycle, which can confuse traversal.".into(),
                objects: vec![format!("{} {} obj", node_ref.obj, node_ref.gen)],
                evidence: vec![span_to_evidence(dict.span, "Pages node")],
                remediation: Some("Inspect /Kids references for cycles.".into()),
                meta: Default::default(),
                yara: None,
        position: None,
        positions: Vec::new(),
            });
            return;
        }
        if visited.contains(&node_ref) {
            return;
        }
        visited.insert(node_ref);
        stack.push(node_ref);
    }
    if let Some((_, kids)) = dict.get_first(b"/Kids") {
        if let PdfAtom::Array(arr) = &kids.atom {
            for kid in arr {
                detect_cycles(ctx, kid, visited, stack, findings);
            }
        }
    }
    if let Some(node_ref) = node_ref {
        if stack.last() == Some(&node_ref) {
            stack.pop();
        }
    }
}

fn count_pages(ctx: &sis_pdf_core::scan::ScanContext, obj: &PdfObj<'_>, seen: &mut HashSet<ObjRef>) -> usize {
    let Some(dict) = resolve_dict(&ctx.graph, obj) else { return 0 };
    if dict.has_name(b"/Type", b"/Page") {
        return 1;
    }
    if !dict.has_name(b"/Type", b"/Pages") {
        return 0;
    }
    let node_ref = object_ref(&ctx.graph, obj);
    if let Some(node_ref) = node_ref {
        if !seen.insert(node_ref) {
            return 0;
        }
    }
    if let Some((_, kids)) = dict.get_first(b"/Kids") {
        if let PdfAtom::Array(arr) = &kids.atom {
            return arr.iter().map(|k| count_pages(ctx, k, seen)).sum();
        }
    }
    0
}

fn declared_page_count(ctx: &sis_pdf_core::scan::ScanContext, obj: &PdfObj<'_>) -> Option<i64> {
    let dict = resolve_dict(&ctx.graph, obj)?;
    let (_, count_obj) = dict.get_first(b"/Count")?;
    match &count_obj.atom {
        PdfAtom::Int(i) => Some(*i),
        _ => None,
    }
}

fn resolve_dict<'a>(graph: &'a sis_pdf_pdf::ObjectGraph<'a>, obj: &PdfObj<'a>) -> Option<PdfDict<'a>> {
    match &obj.atom {
        PdfAtom::Dict(d) => Some(d.clone()),
        PdfAtom::Stream(st) => Some(st.dict.clone()),
        PdfAtom::Ref { .. } => graph.resolve_ref(obj).and_then(|e| match &e.atom {
            PdfAtom::Dict(d) => Some(d.clone()),
            PdfAtom::Stream(st) => Some(st.dict.clone()),
            _ => None,
        }),
        _ => None,
    }
}

fn object_ref(graph: &sis_pdf_pdf::ObjectGraph<'_>, obj: &PdfObj<'_>) -> Option<ObjRef> {
    match obj.atom {
        PdfAtom::Ref { obj, gen } => Some(ObjRef { obj, gen }),
        PdfAtom::Dict(_) | PdfAtom::Stream(_) => {
            let span_start = obj.span.start;
            graph
                .objects
                .iter()
                .find(|e| e.body_span.start == span_start)
                .map(|e| ObjRef { obj: e.obj, gen: e.gen })
        }
        _ => None,
    }
}

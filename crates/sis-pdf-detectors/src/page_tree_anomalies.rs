use anyhow::Result;
use std::collections::HashSet;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::graph_walk::ObjRef;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::page_tree::build_page_tree;
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};

use crate::entry_dict;

/// Maximum recursion depth for page tree traversal to prevent stack overflow
const MAX_PAGE_TREE_DEPTH: usize = 128;

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
            detect_cycles(ctx, &root, &mut visited, &mut stack, &mut findings, 0);
            let actual = count_pages(ctx, &root, &mut HashSet::new(), 0);
            let declared = declared_page_count(ctx, &root);
            if let Some(declared) = declared {
                if declared != actual as i64 {
                    let tolerance = (declared - actual as i64).abs();
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("page_tree.declared".into(), declared.to_string());
                    meta.insert("page_tree.actual".into(), actual.to_string());
                    meta.insert("page_tree.tolerance".into(), tolerance.to_string());

                    // Off-by-one is common in benign PDFs, reduce severity
                    let (severity, description) = if tolerance == 1 {
                        (
                            Severity::Info,
                            format!(
                                "Page tree /Count off by one (declared {}, actual {}). Common in benign PDFs.",
                                declared, actual
                            )
                        )
                    } else {
                        (
                            Severity::Low,
                            format!(
                                "Page tree /Count does not match actual leaf pages (declared {}, actual {}, diff {}).",
                                declared, actual, tolerance
                            )
                        )
                    };

                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "page_tree_mismatch".into(),
                        severity,
                        confidence: Confidence::Strong, // Upgraded: count mismatch is definitive check
                        title: "Page tree count mismatch".into(),
                        description,
                        objects: vec!["page_tree".into()],
                        evidence: vec![],
                        remediation: Some(
                            "Inspect page tree structure for missing or hidden pages.".into(),
                        ),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }
            }
            let page_tree = build_page_tree(&ctx.graph);
            let tree_pages: HashSet<ObjRef> =
                page_tree.pages.iter().map(|p| ObjRef { obj: p.obj, gen: p.gen }).collect();
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
            let orphaned_pages: Vec<ObjRef> = all_pages.difference(&tree_pages).copied().collect();
            if !orphaned_pages.is_empty() {
                let mut meta = std::collections::HashMap::new();
                meta.insert("page_tree.orphaned".into(), orphaned_pages.len().to_string());
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
                    confidence: Confidence::Strong, // Upgraded: orphaned pages are definitively unreachable
                    title: "Orphaned page objects".into(),
                    description: "Some /Page objects are not reachable from the page tree.".into(),
                    objects,
                    evidence: vec![],
                    remediation: Some("Inspect page tree references and catalog root.".into()),
                    meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                    ..Finding::default()
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
        entry_dict(entry).map(|d| d.has_name(b"/Type", b"/Pages")).unwrap_or(false)
    })?;
    findings.push(Finding {
        id: String::new(),
        surface: AttackSurface::FileStructure,
        kind: "page_tree_fallback".into(),
        severity: Severity::Low,
        confidence: Confidence::Heuristic,
            impact: None,
        title: "Fallback /Pages root".into(),
        description: "Page tree root resolved by scanning the object graph, not by the catalog /Root.".into(),
        objects: vec!["page_tree".into()],
        evidence: vec![span_to_evidence(entry.body_span, "Fallback /Pages root")],
        remediation: Some("Inspect catalog /Root and /Pages references for consistency.".into()),
        meta: Default::default(),
            action_type: None,
            action_target: None,
            action_initiation: None,        yara: None,
        position: None,
        positions: Vec::new(),
    });
    Some(PdfObj { span: entry.body_span, atom: entry.atom.clone() })
}

fn root_pages_obj<'a>(ctx: &'a sis_pdf_core::scan::ScanContext<'a>) -> Option<PdfObj<'a>> {
    let root =
        ctx.graph.trailers.last().and_then(|t| t.get_first(b"/Root")).map(|(_, v)| v.clone())?;
    let catalog = resolve_dict(&ctx.graph, &root)?;
    catalog.get_first(b"/Pages").map(|(_, v)| v.clone())
}

fn detect_cycles(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &PdfObj<'_>,
    visited: &mut HashSet<ObjRef>,
    stack: &mut Vec<ObjRef>,
    findings: &mut Vec<Finding>,
    depth: usize,
) {
    // Guard against excessive recursion depth
    if depth > MAX_PAGE_TREE_DEPTH {
        let mut meta = std::collections::HashMap::new();
        meta.insert("page_tree.depth".into(), depth.to_string());
        meta.insert("page_tree.max_depth".into(), MAX_PAGE_TREE_DEPTH.to_string());
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: "page_tree_depth_exceeded".into(),
            severity: Severity::Medium,
            confidence: Confidence::Strong,
            title: "Page tree depth exceeded".into(),
            description: format!(
                "Page tree nesting exceeds maximum safe depth of {}. \
                This may indicate a malformed or malicious PDF designed to exhaust parser resources.",
                MAX_PAGE_TREE_DEPTH
            ),
            objects: vec!["page_tree".into()],
            evidence: vec![],
            remediation: Some("Inspect page tree structure for excessive nesting.".into()),
            meta,
            yara: None,
            position: None,
            positions: Vec::new(),
            ..Finding::default()
        });
        return;
    }

    let Some(dict) = resolve_dict(&ctx.graph, obj) else {
        return;
    };
    if !dict.has_name(b"/Type", b"/Pages") {
        return;
    }
    let node_ref = object_ref(&ctx.graph, obj);
    if let Some(node_ref) = node_ref {
        if stack.contains(&node_ref) {
            let mut meta = std::collections::HashMap::new();
            meta.insert(
                "page_tree.cycle_node".into(),
                format!("{} {}", node_ref.obj, node_ref.gen),
            );
            meta.insert("page_tree.stack_depth".into(), stack.len().to_string());
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::FileStructure,
                kind: "page_tree_cycle".into(),
                severity: Severity::Medium,
                confidence: Confidence::Strong, // Upgraded: cycle detection is definitive
                title: "Page tree cycle detected".into(),
                description: "Page tree contains a circular reference, which can cause infinite \
                    loops in PDF parsers. This may indicate a malformed or malicious PDF designed \
                    to exhaust parser resources or exploit traversal vulnerabilities."
                    .into(),
                objects: vec![format!("{} {} obj", node_ref.obj, node_ref.gen)],
                evidence: vec![span_to_evidence(dict.span, "Pages node")],
                remediation: Some("Inspect /Kids references for cycles.".into()),
                meta,
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
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
                detect_cycles(ctx, kid, visited, stack, findings, depth + 1);
            }
        }
    }
    if let Some(node_ref) = node_ref {
        if stack.last() == Some(&node_ref) {
            stack.pop();
        }
    }
}

fn count_pages(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &PdfObj<'_>,
    seen: &mut HashSet<ObjRef>,
    depth: usize,
) -> usize {
    // Guard against excessive recursion depth
    if depth > MAX_PAGE_TREE_DEPTH {
        return 0;
    }
    let Some(dict) = resolve_dict(&ctx.graph, obj) else {
        return 0;
    };
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
            return arr.iter().map(|k| count_pages(ctx, k, seen, depth + 1)).sum();
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

fn resolve_dict<'a>(
    graph: &'a sis_pdf_pdf::ObjectGraph<'a>,
    obj: &PdfObj<'a>,
) -> Option<PdfDict<'a>> {
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

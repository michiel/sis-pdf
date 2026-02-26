use anyhow::Result;
use std::collections::{HashMap, HashSet};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::graph_walk::ObjRef;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_pdf::object::PdfAtom;

pub struct ObjectReferenceCycleDetector;

impl Detector for ObjectReferenceCycleDetector {
    fn id(&self) -> &'static str {
        "object_reference_cycle"
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
        let mut findings = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = Vec::new();
        let mut depths: HashMap<ObjRef, usize> = HashMap::new();
        let mut max_depth = 0;
        let executable_refs = collect_executable_refs(ctx);

        // Check all objects for circular references and track depth
        for entry in &ctx.graph.objects {
            let obj_ref = ObjRef { obj: entry.obj, gen: entry.gen };
            if !visited.contains(&obj_ref) {
                let depth = detect_cycles_from(
                    ctx,
                    &obj_ref,
                    &mut visited,
                    &mut stack,
                    &mut depths,
                    &mut findings,
                    &executable_refs,
                    0,
                );
                if depth > max_depth {
                    max_depth = depth;
                }
            }
        }

        // Report excessive reference depth (>20 levels)
        if max_depth > 20 {
            let mut meta = std::collections::HashMap::new();
            meta.insert("reference.max_depth".into(), max_depth.to_string());
            meta.insert("graph.evasion_kind".into(), "deep_indirection".into());
            meta.insert("graph.depth".into(), max_depth.to_string());
            meta.insert("graph.conflict_count".into(), "0".into());
            meta.insert("graph.execute_surface_count".into(), executable_refs.len().to_string());
            meta.insert("chain.stage".into(), "decode".into());
            meta.insert("chain.capability".into(), "graph_indirection".into());
            meta.insert("chain.trigger".into(), "object_graph".into());

            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "object_reference_depth_high".into(),
                severity: if max_depth > 50 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                confidence: Confidence::Strong,
            impact: Impact::Unknown,
                title: format!("Excessive reference depth: {} levels", max_depth),
                description: format!(
                    "Object reference depth of {} exceeds reasonable threshold (20). May cause stack overflow.",
                    max_depth
                ),
                objects: vec!["object_graph".into()],
                evidence: Vec::new(),
                remediation: Some("Inspect object reference chains for potential DoS attacks.".into()),
                meta,
                yara: None,
                positions: Vec::new(),
            ..Finding::default()
            });
        }

        Ok(findings)
    }
}

/// Classify a cycle based on its characteristics to assign appropriate severity
fn classify_cycle(
    ctx: &sis_pdf_core::scan::ScanContext,
    cycle_refs: &[ObjRef],
) -> (Severity, &'static str) {
    let cycle_length = cycle_refs.len();

    // Self-reference (A -> A) - High severity, classic DoS pattern
    if cycle_length == 1 {
        return (Severity::High, "self_reference");
    }

    // Check if this is a page tree cycle (Page <-> Pages parent-child relationship)
    if cycle_length == 2 {
        let obj1 = cycle_refs[0];
        let obj2 = cycle_refs[1];

        if let (Some(entry1), Some(entry2)) = (
            ctx.graph.objects.iter().find(|e| e.obj == obj1.obj && e.gen == obj1.gen),
            ctx.graph.objects.iter().find(|e| e.obj == obj2.obj && e.gen == obj2.gen),
        ) {
            let type1 = get_dict_type(&entry1.atom);
            let type2 = get_dict_type(&entry2.atom);

            // Check for Page <-> Pages relationship
            if (type1 == Some("/Page") && type2 == Some("/Pages"))
                || (type1 == Some("/Pages") && type2 == Some("/Page"))
                || (type1 == Some("/Pages") && type2 == Some("/Pages"))
            {
                return (Severity::Info, "page_tree_parent_child");
            }
        }
    }

    // Small cycles (3-6 objects) - Could be legitimate cross-references (fonts, resources)
    if cycle_length <= 6 {
        // Check if all objects are page-related
        let mut all_page_related = true;
        for obj_ref in cycle_refs {
            if let Some(entry) =
                ctx.graph.objects.iter().find(|e| e.obj == obj_ref.obj && e.gen == obj_ref.gen)
            {
                let obj_type = get_dict_type(&entry.atom);
                if obj_type != Some("/Page") && obj_type != Some("/Pages") {
                    all_page_related = false;
                    break;
                }
            }
        }

        if all_page_related {
            return (Severity::Low, "page_tree_small_cycle");
        }

        return (Severity::Medium, "small_cycle");
    }

    // Large cycles (>6 objects) - Tag structure bombs, resource exhaustion
    if cycle_length > 100 {
        return (Severity::Critical, "extremely_large_cycle");
    }
    (Severity::High, "large_cycle")
}

/// Get the /Type value from a PDF object if it exists
fn get_dict_type<'a>(atom: &'a PdfAtom) -> Option<&'a str> {
    match atom {
        PdfAtom::Dict(dict) => {
            for (key, value) in &dict.entries {
                if key.decoded.as_slice() == b"/Type" || key.decoded.as_slice() == b"Type" {
                    if let PdfAtom::Name(name) = &value.atom {
                        return std::str::from_utf8(&name.decoded).ok();
                    }
                }
            }
            None
        }
        PdfAtom::Stream(stream) => {
            for (key, value) in &stream.dict.entries {
                if key.decoded.as_slice() == b"/Type" || key.decoded.as_slice() == b"Type" {
                    if let PdfAtom::Name(name) = &value.atom {
                        return std::str::from_utf8(&name.decoded).ok();
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn detect_cycles_from(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj_ref: &ObjRef,
    visited: &mut HashSet<ObjRef>,
    stack: &mut Vec<ObjRef>,
    depths: &mut HashMap<ObjRef, usize>,
    findings: &mut Vec<Finding>,
    executable_refs: &HashSet<ObjRef>,
    depth: usize,
) -> usize {
    // Check if we've found a cycle
    if let Some(cycle_start) = stack.iter().position(|r| r == obj_ref) {
        let cycle_refs: Vec<ObjRef> = stack[cycle_start..].to_vec();
        let cycle_objects: Vec<String> =
            cycle_refs.iter().map(|r| format!("{} {} obj", r.obj, r.gen)).collect();

        let cycle_length = cycle_refs.len();

        // Determine severity based on cycle characteristics
        let (severity, cycle_type) = classify_cycle(ctx, &cycle_refs);

        let mut meta = std::collections::HashMap::new();
        meta.insert("cycle.length".into(), cycle_length.to_string());
        meta.insert("cycle.objects".into(), cycle_objects.join(", "));
        meta.insert("cycle.type".into(), cycle_type.to_string());
        let execute_overlap =
            cycle_refs.iter().filter(|obj| executable_refs.contains(*obj)).count();
        meta.insert(
            "graph.evasion_kind".into(),
            if execute_overlap > 0 {
                "cycle_near_execute".into()
            } else {
                "reference_cycle".into()
            },
        );
        meta.insert("graph.depth".into(), cycle_length.to_string());
        meta.insert("graph.conflict_count".into(), "1".into());
        meta.insert("graph.execute_overlap_count".into(), execute_overlap.to_string());
        meta.insert("chain.stage".into(), "decode".into());
        meta.insert("chain.capability".into(), "graph_cycle".into());
        meta.insert("chain.trigger".into(), "object_graph".into());

        let (title, description) = match severity {
            Severity::Info => (
                "Benign reference cycle detected (page tree structure)".into(),
                format!(
                    "Circular reference chain of {} objects detected in page tree. This is normal PDF parent-child structure.",
                    cycle_length
                )
            ),
            Severity::Low => (
                "Minor reference cycle detected".into(),
                format!(
                    "Circular reference chain of {} objects detected. Likely benign structural relationship.",
                    cycle_length
                )
            ),
            Severity::Medium => (
                "Reference cycle detected".into(),
                format!(
                    "Circular reference chain of {} objects detected. May indicate complex structure or potential parser stress.",
                    cycle_length
                )
            ),
            Severity::High => (
                "Suspicious reference cycle detected".into(),
                format!(
                    "Circular reference chain of {} objects detected. Can cause infinite recursion and parser DoS.",
                    cycle_length
                )
            ),
            Severity::Critical => (
                "Critical reference cycle detected".into(),
                format!(
                    "Circular reference chain of {} objects detected. High risk of infinite recursion and parser DoS.",
                    cycle_length
                )
            ),
        };

        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: "object_reference_cycle".into(),
            severity,
            confidence: Confidence::Strong,
            impact: Impact::Unknown,
            title,
            description,
            objects: cycle_objects,
            evidence: Vec::new(),
            remediation: Some("Inspect object references for malicious cycle construction.".into()),
            meta,
            yara: None,
            positions: Vec::new(),
            ..Finding::default()
        });

        // CRITICAL FIX: Mark this node as visited even when it's part of a cycle
        // This prevents exponential re-traversal of cyclic subgraphs
        visited.insert(*obj_ref);

        return depth;
    }

    // Already fully explored - return cached depth
    if visited.contains(obj_ref) {
        return depths.get(obj_ref).copied().unwrap_or(0);
    }

    // Mark as visited before recursing
    visited.insert(*obj_ref);
    stack.push(*obj_ref);

    let mut max_child_depth = depth;

    // Find the object entry
    if let Some(entry) =
        ctx.graph.objects.iter().find(|e| e.obj == obj_ref.obj && e.gen == obj_ref.gen)
    {
        // Collect all references in this object
        let mut refs = Vec::new();
        collect_refs(&entry.atom, &mut refs);

        // Recursively check all references
        for child_ref in refs {
            let child_depth = detect_cycles_from(
                ctx,
                &child_ref,
                visited,
                stack,
                depths,
                findings,
                executable_refs,
                depth + 1,
            );
            if child_depth > max_child_depth {
                max_child_depth = child_depth;
            }
        }
    }

    stack.pop();
    depths.insert(*obj_ref, max_child_depth);
    max_child_depth
}

fn collect_refs(atom: &PdfAtom, refs: &mut Vec<ObjRef>) {
    match atom {
        PdfAtom::Ref { obj, gen } => {
            refs.push(ObjRef { obj: *obj, gen: *gen });
        }
        PdfAtom::Dict(dict) => {
            for (_, value) in &dict.entries {
                collect_refs(&value.atom, refs);
            }
        }
        PdfAtom::Array(arr) => {
            for item in arr {
                collect_refs(&item.atom, refs);
            }
        }
        PdfAtom::Stream(st) => {
            for (_, value) in &st.dict.entries {
                collect_refs(&value.atom, refs);
            }
        }
        _ => {}
    }
}

fn collect_executable_refs(ctx: &sis_pdf_core::scan::ScanContext) -> HashSet<ObjRef> {
    let mut refs = HashSet::new();
    for entry in &ctx.graph.objects {
        if atom_has_execute_surface(&entry.atom) {
            refs.insert(ObjRef { obj: entry.obj, gen: entry.gen });
        }
    }
    refs
}

fn atom_has_execute_surface(atom: &PdfAtom<'_>) -> bool {
    match atom {
        PdfAtom::Dict(dict) => dict_has_execute_surface(dict),
        PdfAtom::Stream(stream) => dict_has_execute_surface(&stream.dict),
        _ => false,
    }
}

fn dict_has_execute_surface(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> bool {
    dict.has_name(b"/S", b"/JavaScript")
        || dict.has_name(b"/S", b"/Launch")
        || dict.has_name(b"/S", b"/URI")
        || dict.has_name(b"/S", b"/GoToR")
        || dict.has_name(b"/S", b"/GoToE")
        || dict.has_name(b"/S", b"/SubmitForm")
        || dict.get_first(b"/JS").is_some()
        || dict.get_first(b"/OpenAction").is_some()
        || dict.get_first(b"/AA").is_some()
}

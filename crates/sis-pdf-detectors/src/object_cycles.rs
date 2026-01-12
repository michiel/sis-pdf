use anyhow::Result;
use std::collections::{HashMap, HashSet};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::graph_walk::ObjRef;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
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

        // Check all objects for circular references and track depth
        for entry in &ctx.graph.objects {
            let obj_ref = ObjRef {
                obj: entry.obj,
                gen: entry.gen,
            };
            if !visited.contains(&obj_ref) {
                let depth = detect_cycles_from(
                    ctx,
                    &obj_ref,
                    &mut visited,
                    &mut stack,
                    &mut depths,
                    &mut findings,
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
                position: None,
                positions: Vec::new(),
            });
        }

        Ok(findings)
    }
}

fn detect_cycles_from(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj_ref: &ObjRef,
    visited: &mut HashSet<ObjRef>,
    stack: &mut Vec<ObjRef>,
    depths: &mut HashMap<ObjRef, usize>,
    findings: &mut Vec<Finding>,
    depth: usize,
) -> usize {
    // Check if we've found a cycle
    if stack.contains(obj_ref) {
        let cycle_start = stack.iter().position(|r| r == obj_ref).unwrap();
        let cycle_objects: Vec<String> = stack[cycle_start..]
            .iter()
            .map(|r| format!("{} {} obj", r.obj, r.gen))
            .collect();

        let mut meta = std::collections::HashMap::new();
        meta.insert("cycle.length".into(), cycle_objects.len().to_string());
        meta.insert("cycle.objects".into(), cycle_objects.join(", "));

        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::FileStructure,
            kind: "object_reference_cycle".into(),
            severity: Severity::High,
            confidence: Confidence::Strong,
            title: "Circular object reference detected".into(),
            description: format!(
                "Circular reference chain of {} objects detected. Can cause infinite recursion and parser DoS.",
                cycle_objects.len()
            ),
            objects: cycle_objects,
            evidence: Vec::new(),
            remediation: Some("Inspect object references for malicious cycle construction.".into()),
            meta,
            yara: None,
            position: None,
            positions: Vec::new(),
        });
        return depth;
    }

    // Already fully explored
    if visited.contains(obj_ref) {
        return depths.get(obj_ref).copied().unwrap_or(0);
    }

    visited.insert(*obj_ref);
    stack.push(*obj_ref);

    let mut max_child_depth = depth;

    // Find the object entry
    if let Some(entry) = ctx
        .graph
        .objects
        .iter()
        .find(|e| e.obj == obj_ref.obj && e.gen == obj_ref.gen)
    {
        // Collect all references in this object
        let mut refs = Vec::new();
        collect_refs(&entry.atom, &mut refs);

        // Recursively check all references
        for child_ref in refs {
            let child_depth =
                detect_cycles_from(ctx, &child_ref, visited, stack, depths, findings, depth + 1);
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
            refs.push(ObjRef {
                obj: *obj,
                gen: *gen,
            });
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

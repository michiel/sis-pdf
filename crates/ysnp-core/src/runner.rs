use anyhow::Result;
use std::collections::{HashMap, HashSet};

use crate::model::Finding;
use crate::report::Report;
use crate::scan::{DecodedCache, ScanContext, ScanOptions};
use ysnp_pdf::{parse_pdf, ObjectGraph, ParseOptions};
use ysnp_pdf::object::{PdfAtom, PdfDict, PdfObj};
use crate::graph_walk::{build_adjacency, reachable_from, ObjRef};

pub fn run_scan_with_detectors(
    bytes: &[u8],
    options: ScanOptions,
    detectors: &[Box<dyn crate::detect::Detector>],
) -> Result<Report> {
    let mut graph = parse_pdf(
        bytes,
        ParseOptions {
            recover_xref: options.recover_xref,
            deep: options.deep,
            strict: options.strict,
            max_objstm_bytes: options.max_decode_bytes,
        },
    )?;
    let mut focus_filtered = false;
    if let Some(trigger) = options.focus_trigger.as_deref() {
        let seeds = focus_seeds_for_trigger(&graph, trigger);
        if !seeds.is_empty() {
            let adjacency = build_adjacency(&graph.objects);
            let reachable = reachable_from(&adjacency, &seeds, options.focus_depth);
            if !reachable.is_empty() {
                graph = filter_graph_by_refs(&graph, &reachable);
                focus_filtered = true;
            }
        }
    }
    let ctx = ScanContext {
        bytes,
        graph,
        decoded: DecodedCache::new(options.max_decode_bytes, options.max_total_decoded_bytes),
        options,
    };

    let mut findings: Vec<Finding> = if ctx.options.parallel {
        use rayon::prelude::*;
        detectors
            .par_iter()
            .filter(|d| {
                if ctx.options.fast {
                    d.cost() == crate::detect::Cost::Cheap
                } else {
                    ctx.options.deep || d.cost() != crate::detect::Cost::Expensive
                }
            })
            .map(|d| d.run(&ctx))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect()
    } else {
        let mut out = Vec::new();
        for d in detectors {
            if ctx.options.fast && d.cost() != crate::detect::Cost::Cheap {
                continue;
            }
            if !ctx.options.fast && !ctx.options.deep && d.cost() == crate::detect::Cost::Expensive {
                continue;
            }
            out.extend(d.run(&ctx)?);
        }
        out
    };

    if ctx.graph.objects.len() > ctx.options.max_objects {
        let evidence = ctx
            .graph
            .objects
            .last()
            .map(|e| vec![crate::scan::span_to_evidence(e.full_span, "Last object span")])
            .unwrap_or_else(Vec::new);
        findings.push(Finding {
            id: String::new(),
            surface: crate::model::AttackSurface::FileStructure,
            kind: "object_count_exceeded".into(),
            severity: crate::model::Severity::Medium,
            confidence: crate::model::Confidence::Probable,
            title: "Object count exceeds budget".into(),
            description: format!(
                "Object count {} exceeds configured budget {}.",
                ctx.graph.objects.len(),
                ctx.options.max_objects
            ),
            objects: vec!["object_graph".into()],
            evidence,
            remediation: Some("Reduce scan scope or raise max_objects.".into()),
            meta: Default::default(),
            yara: None,
        });
    }

    if ctx.options.diff_parser {
        findings.extend(crate::diff::diff_with_lopdf(ctx.bytes, &ctx.graph));
    }

    if let Some(ref trigger) = ctx.options.focus_trigger {
        if !focus_filtered {
            let target = map_focus_trigger(trigger);
            findings.retain(|f| match &target {
                Some(kind) => &f.kind == kind,
                None => f.kind.contains(trigger),
            });
        }
    }
    for f in &mut findings {
        if f.id.is_empty() {
            f.id = stable_id(f);
        }
    }
    let intent_summary = Some(crate::intent::apply_intent(&mut findings));
    let yara_rules = crate::yara::annotate_findings(&mut findings, ctx.options.yara_scope.as_deref());
    findings.sort_by(|a, b| (a.surface as u32, &a.kind, &a.id).cmp(&(b.surface as u32, &b.kind, &b.id)));
    let (chains, templates) = crate::chain_synth::synthesise_chains(&findings);
    Ok(Report::from_findings(findings, chains, templates, yara_rules, intent_summary))
}

fn stable_id(f: &Finding) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(f.kind.as_bytes());
    hasher.update(format!("{:?}", f.surface).as_bytes());
    for o in &f.objects {
        hasher.update(o.as_bytes());
    }
    for e in &f.evidence {
        hasher.update(format!("{:?}", e.source).as_bytes());
        hasher.update(e.offset.to_string().as_bytes());
        hasher.update(e.length.to_string().as_bytes());
        if let Some(origin) = e.origin {
            hasher.update(origin.start.to_string().as_bytes());
            hasher.update(origin.end.to_string().as_bytes());
        }
    }
    format!("ysnp-{}", hasher.finalize().to_hex())
}

fn map_focus_trigger(trigger: &str) -> Option<String> {
    match trigger.to_lowercase().as_str() {
        "openaction" | "open_action" => Some("open_action_present".into()),
        "aa" | "aae" | "additional_actions" => Some("aa_present".into()),
        "javascript" | "js" => Some("js_present".into()),
        "uri" => Some("uri_present".into()),
        _ => None,
    }
}

fn focus_seeds_for_trigger(graph: &ObjectGraph<'_>, trigger: &str) -> Vec<ObjRef> {
    let mut seeds = Vec::new();
    let key = match trigger.to_lowercase().as_str() {
        "openaction" | "open_action" => b"/OpenAction".as_slice(),
        "aa" | "aae" | "additional_actions" => b"/AA".as_slice(),
        _ => return seeds,
    };
    for entry in &graph.objects {
        let dict = match entry_dict(entry) {
            Some(d) => d,
            None => continue,
        };
        if let Some((_, obj)) = dict.get_first(key) {
            seeds.push(ObjRef {
                obj: entry.obj,
                gen: entry.gen,
            });
            collect_refs_from_obj(obj, &mut seeds);
            if key == b"/AA" {
                if let PdfAtom::Dict(aa_dict) = &obj.atom {
                    for (_, v) in &aa_dict.entries {
                        collect_refs_from_obj(v, &mut seeds);
                    }
                }
            }
        }
    }
    seeds
}

fn entry_dict<'a>(entry: &'a ysnp_pdf::graph::ObjEntry<'a>) -> Option<&'a PdfDict<'a>> {
    match &entry.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    }
}

fn collect_refs_from_obj(obj: &PdfObj<'_>, out: &mut Vec<ObjRef>) {
    if let PdfAtom::Ref { obj, gen } = obj.atom {
        out.push(ObjRef { obj, gen });
    }
}

fn filter_graph_by_refs<'a>(
    graph: &ObjectGraph<'a>,
    keep: &HashSet<ObjRef>,
) -> ObjectGraph<'a> {
    let objects: Vec<_> = graph
        .objects
        .iter()
        .filter(|e| keep.contains(&ObjRef { obj: e.obj, gen: e.gen }))
        .cloned()
        .collect();
    let mut index: HashMap<(u32, u16), Vec<usize>> = HashMap::new();
    for (i, o) in objects.iter().enumerate() {
        index.entry((o.obj, o.gen)).or_default().push(i);
    }
    ObjectGraph {
        bytes: graph.bytes,
        objects,
        index,
        trailers: graph.trailers.clone(),
        startxrefs: graph.startxrefs.clone(),
        deviations: graph.deviations.clone(),
        decoded_buffers: graph.decoded_buffers.clone(),
    }
}

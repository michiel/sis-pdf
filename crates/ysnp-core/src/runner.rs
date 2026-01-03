use anyhow::Result;

use crate::model::Finding;
use crate::report::Report;
use crate::scan::{DecodedCache, ScanContext, ScanOptions};
use ysnp_pdf::{parse_pdf, ParseOptions};

pub fn run_scan_with_detectors(
    bytes: &[u8],
    options: ScanOptions,
    detectors: &[Box<dyn crate::detect::Detector>],
) -> Result<Report> {
    let graph = parse_pdf(bytes, ParseOptions { recover_xref: options.recover_xref })?;
    let diff_graph = if options.diff_parser {
        Some(parse_pdf(bytes, ParseOptions { recover_xref: false })?)
    } else {
        None
    };
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
        });
    }

    if let Some(ref secondary) = diff_graph {
        findings.extend(crate::diff::diff_graphs(ctx.bytes, &ctx.graph, secondary));
    }

    if let Some(ref trigger) = ctx.options.focus_trigger {
        let target = map_focus_trigger(trigger);
        findings.retain(|f| match &target {
            Some(kind) => &f.kind == kind,
            None => f.kind.contains(trigger),
        });
    }
    for f in &mut findings {
        if f.id.is_empty() {
            f.id = stable_id(f);
        }
    }
    findings.sort_by(|a, b| (a.surface as u32, &a.kind, &a.id).cmp(&(b.surface as u32, &b.kind, &b.id)));
    let (chains, templates) = crate::chain_synth::synthesise_chains(&findings);
    Ok(Report::from_findings(findings, chains, templates))
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

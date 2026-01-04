use anyhow::Result;
use std::collections::{HashMap, HashSet};

use crate::model::Finding;
use crate::report::Report;
use crate::scan::{DecodedCache, ScanContext, ScanOptions};
use sis_pdf_pdf::{parse_pdf, ObjectGraph, ParseOptions};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
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
    if let Some(ml_cfg) = &ctx.options.ml_config {
        let feature_vec = crate::features::FeatureExtractor::extract(&ctx);
        let defense = crate::adversarial::AdversarialDefense;
        match crate::ml_models::load_stacking(&ml_cfg.model_path) {
            Ok(model) => {
                let prediction = model.predict(&feature_vec, ml_cfg.threshold);
                if prediction.label {
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("ml.score".into(), format!("{:.4}", prediction.score));
                    meta.insert("ml.threshold".into(), format!("{:.4}", prediction.threshold));
                    meta.insert(
                        "ml.base_scores".into(),
                        prediction
                            .base_scores
                            .iter()
                            .map(|v| format!("{:.4}", v))
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                    let stability = defense.validate_prediction_stability(&feature_vec);
                    meta.insert("ml.stability".into(), format!("{:.3}", stability.score));
                    if let Ok(fv_json) = serde_json::to_string(&feature_vec) {
                        meta.insert("ml.features".into(), fv_json);
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: crate::model::AttackSurface::Metadata,
                        kind: "ml_malware_score_high".into(),
                        severity: crate::model::Severity::High,
                        confidence: crate::model::Confidence::Probable,
                        title: "ML classifier score high".into(),
                        description: format!(
                            "Stacking classifier scored {:.4} (threshold {:.4}).",
                            prediction.score, prediction.threshold
                        ),
                        objects: vec!["ml".into()],
                        evidence: Vec::new(),
                        remediation: Some("Review ML features and validate with manual analysis.".into()),
                        meta,
                        yara: None,
                    });
                }
            }
            Err(err) => {
                findings.push(Finding {
                    id: String::new(),
                    surface: crate::model::AttackSurface::Metadata,
                    kind: "ml_model_error".into(),
                    severity: crate::model::Severity::Low,
                    confidence: crate::model::Confidence::Heuristic,
                    title: "ML model load failed".into(),
                    description: format!("Failed to load ML model: {}", err),
                    objects: vec!["ml".into()],
                    evidence: Vec::new(),
                    remediation: Some("Check ML model path and format.".into()),
                    meta: Default::default(),
                    yara: None,
                });
            }
        }
        if let Some(attempt) = defense.detect_adversarial(&feature_vec) {
            let mut meta = std::collections::HashMap::new();
            meta.insert("ml.adversarial_score".into(), format!("{:.2}", attempt.score));
            meta.insert("ml.adversarial_reason".into(), attempt.reason);
            findings.push(Finding {
                id: String::new(),
                surface: crate::model::AttackSurface::Metadata,
                kind: "ml_adversarial_suspected".into(),
                severity: crate::model::Severity::Low,
                confidence: crate::model::Confidence::Heuristic,
                title: "Potential adversarial ML sample".into(),
                description: "Feature profile suggests adversarial manipulation attempts.".into(),
                objects: vec!["ml".into()],
                evidence: Vec::new(),
                remediation: Some("Validate findings against alternate detectors.".into()),
                meta,
                yara: None,
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
    let behavior_summary = Some(crate::behavior::correlate_findings(&findings));
    let future_threats = behavior_summary
        .as_ref()
        .map(|s| crate::predictor::BehavioralPredictor.predict_evolution(&s.patterns))
        .unwrap_or_default();
    let network_intents = extract_network_intents(&findings);
    let response_rules = behavior_summary
        .as_ref()
        .map(|s| {
            let generator = crate::response::ResponseGenerator;
            s.patterns
                .iter()
                .flat_map(|p| generator.generate_yara_variants(p))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(Report::from_findings(
        findings,
        chains,
        templates,
        yara_rules,
        intent_summary,
        behavior_summary,
        future_threats,
        network_intents,
        response_rules,
    ))
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
    format!("sis-{}", hasher.finalize().to_hex())
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

fn entry_dict<'a>(entry: &'a sis_pdf_pdf::graph::ObjEntry<'a>) -> Option<&'a PdfDict<'a>> {
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

fn extract_network_intents(findings: &[Finding]) -> Vec<crate::campaign::NetworkIntent> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for f in findings {
        for (k, v) in &f.meta {
            if k == "action.target"
                || k == "supply_chain.action_targets"
                || k == "js.ast_urls"
                || k.starts_with("js.")
            {
                for url in extract_urls(v) {
                    if seen.insert(url.clone()) {
                        out.push(crate::campaign::NetworkIntent {
                            domain: crate::campaign::extract_domain(&url),
                            url,
                        });
                    }
                }
            }
        }
    }
    out
}

fn extract_urls(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in input
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|s| !s.is_empty())
    {
        if token.starts_with("http://") || token.starts_with("https://") {
            out.push(token.trim_matches(['"', '\'']).to_string());
        }
    }
    out
}

use anyhow::Result;
use std::collections::{HashMap, HashSet};

use crate::model::Finding;
use crate::report::{MlRunSummary, MlSummary, Report, SecondaryParserSummary, StructuralSummary};
use crate::scan::{DecodedCache, ScanContext, ScanOptions};
use sis_pdf_pdf::{parse_pdf, ObjectGraph, ParseOptions};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
use crate::graph_walk::{build_adjacency, reachable_from, ObjRef};

const PARALLEL_DETECTOR_THREADS: usize = 4;

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
            max_objects: options.max_objects,
            max_objstm_total_bytes: options.max_total_decoded_bytes,
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
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(PARALLEL_DETECTOR_THREADS)
            .build();
        match pool {
            Ok(pool) => pool.install(|| {
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
                    .collect::<Result<Vec<_>, _>>()
            })?
            .into_iter()
            .flatten()
            .collect(),
            Err(err) => {
                eprintln!(
                    "security_boundary: failed to build parallel detector pool; falling back to sequential ({})",
                    err
                );
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
            }
        }
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
        eprintln!(
            "security_boundary: object count {} exceeded max_objects {}",
            ctx.graph.objects.len(),
            ctx.options.max_objects
        );
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

    let mut diff_result = None;
    if ctx.options.diff_parser {
        let mut diff = crate::diff::diff_with_lopdf(ctx.bytes, &ctx.graph);
        findings.append(&mut diff.findings);
        diff_result = Some(diff);
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
    let mut ml_summary_override: Option<MlSummary> = None;
    if let Some(ml_cfg) = &ctx.options.ml_config {
        ml_summary_override = Some(MlSummary {
            graph: None,
            traditional: None,
        });
        match ml_cfg.mode {
            crate::ml::MlMode::Traditional => {
                let feature_vec = crate::features::FeatureExtractor::extract(&ctx);
                let defense = crate::adversarial::AdversarialDefense;
                match crate::ml_models::load_stacking(&ml_cfg.model_path) {
                    Ok(model) => {
                        let prediction = model.predict(&feature_vec, ml_cfg.threshold);
                        if let Some(summary) = &mut ml_summary_override {
                            summary.traditional = Some(MlRunSummary {
                                score: prediction.score,
                                threshold: prediction.threshold,
                                label: prediction.label,
                                kind: "ml_malware_score".into(),
                                top_nodes: None,
                            });
                        }
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
                        eprintln!("warning: ml_model_error: failed to load ML model: {}", err);
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
            crate::ml::MlMode::Graph => {
                #[cfg(feature = "ml-graph")]
                {
                    let ir_opts = sis_pdf_pdf::ir::IrOptions::default();
                    let ir_graph = crate::ir_pipeline::build_ir_graph(&ctx.graph, &ir_opts);
                    let edge_index = ir_graph.org.edge_index();
                    let prediction = sis_pdf_ml_graph::load_and_predict(
                        &ml_cfg.model_path,
                        &ir_graph.node_texts,
                        &edge_index,
                        ml_cfg.threshold,
                    );
                    match prediction {
                        Ok(prediction) => {
                            if let Some(summary) = &mut ml_summary_override {
                                summary.graph = Some(MlRunSummary {
                                    score: prediction.score,
                                    threshold: prediction.threshold,
                                    label: prediction.label,
                                    kind: "ml_graph_score".into(),
                                    top_nodes: None,
                                });
                            }
                            if prediction.label {
                                let mut meta = std::collections::HashMap::new();
                                meta.insert("ml.graph.score".into(), format!("{:.4}", prediction.score));
                                meta.insert(
                                    "ml.graph.threshold".into(),
                                    format!("{:.4}", prediction.threshold),
                                );
                                findings.push(Finding {
                                    id: String::new(),
                                    surface: crate::model::AttackSurface::Metadata,
                                    kind: "ml_graph_score_high".into(),
                                    severity: crate::model::Severity::High,
                                    confidence: crate::model::Confidence::Probable,
                                    title: "Graph ML classifier score high".into(),
                                    description: format!(
                                        "Graph classifier scored {:.4} (threshold {:.4}).",
                                        prediction.score, prediction.threshold
                                    ),
                                    objects: vec!["ml".into()],
                                    evidence: Vec::new(),
                                    remediation: Some(
                                        "Review graph ML output and corroborate with findings.".into(),
                                    ),
                                    meta,
                                    yara: None,
                                });
                            }
                        }
                        Err(err) => {
                            eprintln!("warning: ml_model_error: graph ML failed: {}", err);
                            findings.push(Finding {
                                id: String::new(),
                                surface: crate::model::AttackSurface::Metadata,
                                kind: "ml_model_error".into(),
                                severity: crate::model::Severity::Low,
                                confidence: crate::model::Confidence::Heuristic,
                                title: "ML model load failed".into(),
                                description: format!("Graph ML failed: {}", err),
                                objects: vec!["ml".into()],
                                evidence: Vec::new(),
                                remediation: Some("Check graph model files and format.".into()),
                                meta: Default::default(),
                                yara: None,
                            });
                        }
                    }
                }
                #[cfg(not(feature = "ml-graph"))]
                {
                    eprintln!(
                        "error: ml_model_error: graph ML mode requested but not compiled (enable feature ml-graph)"
                    );
                    findings.push(Finding {
                        id: String::new(),
                        surface: crate::model::AttackSurface::Metadata,
                        kind: "ml_model_error".into(),
                        severity: crate::model::Severity::Low,
                        confidence: crate::model::Confidence::Heuristic,
                        title: "ML graph mode unavailable".into(),
                        description:
                            "Graph ML mode requested but not compiled (enable feature ml-graph)."
                                .into(),
                        objects: vec!["ml".into()],
                        evidence: Vec::new(),
                        remediation: Some("Rebuild with --features ml-graph.".into()),
                        meta: Default::default(),
                        yara: None,
                    });
                }
            }
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
    let structural_summary = Some(build_structural_summary(
        &ctx,
        diff_result.as_ref(),
        &findings,
    ));
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
        structural_summary,
        ml_summary_override,
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

fn build_structural_summary(
    ctx: &ScanContext<'_>,
    diff: Option<&crate::diff::DiffResult>,
    findings: &[Finding],
) -> StructuralSummary {
    let objstm_count = ctx
        .graph
        .objects
        .iter()
        .filter(|entry| {
            entry_dict(entry)
                .map(|d| d.has_name(b"/Type", b"/ObjStm"))
                .unwrap_or(false)
        })
        .count();
    let object_count = ctx.graph.objects.len();
    let objstm_ratio = if object_count == 0 {
        0.0
    } else {
        objstm_count as f64 / object_count as f64
    };
    let header_offset = find_first(ctx.bytes, b"%PDF-").map(|v| v as u64);
    let eof_offset = find_last(ctx.bytes, b"%%EOF").map(|v| v as u64);
    let eof_distance_to_end = eof_offset.map(|off| {
        ctx.bytes
            .len()
            .saturating_sub(off as usize + 5) as u64
    });
    let (polyglot_risk, polyglot_signatures) = polyglot_meta(findings);
    let secondary_parser = diff.and_then(|d| d.summary.as_ref()).map(|s| SecondaryParserSummary {
        parser: "lopdf".into(),
        object_count: s.secondary_objects,
        trailer_count: s.secondary_trailers,
        missing_in_secondary: s.missing_in_secondary,
        missing_in_primary: s.missing_in_primary,
    });
    let secondary_parser_error = diff.and_then(|d| d.error.clone());
    let ir_summary = if ctx.options.ir {
        let ir_opts = sis_pdf_pdf::ir::IrOptions::default();
        let ir_graph = crate::ir_pipeline::build_ir_graph(&ctx.graph, &ir_opts);
        let summary = crate::ir_pipeline::summarize_ir_graph(&ir_graph);
        Some(crate::report::IrSummary {
            object_count: summary.object_count,
            line_count: summary.line_count,
            action_object_count: summary.action_object_count,
            payload_object_count: summary.payload_object_count,
            edge_count: summary.edge_count,
        })
    } else {
        None
    };
    StructuralSummary {
        startxref_count: ctx.graph.startxrefs.len(),
        trailer_count: ctx.graph.trailers.len(),
        object_count,
        objstm_count,
        objstm_ratio,
        recover_xref: ctx.options.recover_xref,
        deep_scan: ctx.options.deep,
        header_offset,
        eof_offset,
        eof_distance_to_end,
        polyglot_risk,
        polyglot_signatures,
        secondary_parser,
        secondary_parser_error,
        ir_summary,
    }
}

fn find_first(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let mut i = haystack.len().saturating_sub(needle.len());
    loop {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    None
}

fn polyglot_meta(findings: &[Finding]) -> (bool, Vec<String>) {
    let mut sigs = Vec::new();
    let mut found = false;
    for f in findings {
        if f.kind == "polyglot_signature_conflict" {
            found = true;
            if let Some(list) = f.meta.get("polyglot.signatures") {
                sigs.extend(
                    list.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                );
            }
        }
    }
    sigs.sort();
    sigs.dedup();
    (found, sigs)
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

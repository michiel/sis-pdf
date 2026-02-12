use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::correlation;
use crate::evidence::preview_ascii;
use crate::graph_walk::{build_adjacency, reachable_from, ObjRef};
use crate::model::{AttackSurface, Confidence, Finding, Severity};
use crate::position;
use crate::profiler::{DocumentInfo, Profiler};
#[cfg(feature = "ml-graph")]
use crate::report::MlNodeAttribution;
use crate::report::{MlRunSummary, MlSummary, Report, SecondaryParserSummary, StructuralSummary};
use crate::scan::{ScanContext, ScanOptions};
use crate::security_log::{SecurityDomain, SecurityEvent};
use sis_pdf_pdf::decode::stream_filters;
#[cfg(feature = "ml-graph")]
use sis_pdf_pdf::ir::PdfIrObject;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
use sis_pdf_pdf::{parse_pdf, ObjectGraph, ParseOptions};
use tracing::{debug, error, info, warn, Level};

const PARALLEL_DETECTOR_THREADS: usize = 4;
const CARVED_OBJECT_LIMIT_DEFAULT: usize = 2000;
const RESOURCE_CONSUMPTION_THRESHOLD_MS: u64 = 5_000;
const RESOURCE_CONTRIBUTION_KIND_LIMIT: usize = 8;
const RESOURCE_CONTRIBUTION_SAMPLE_OBJECT_LIMIT: usize = 8;
const RESOURCE_CONTRIBUTION_SAMPLE_POSITION_LIMIT: usize = 8;
const RESOURCE_STRUCTURAL_FINDING_KINDS: &[&str] = &[
    "object_shadow_mismatch",
    "parser_diff_structural",
    "parser_object_count_diff",
    "parser_trailer_count_diff",
    "pdf.trailer_inconsistent",
    "label_mismatch_stream_type",
    "objstm_embedded_summary",
];

fn resource_contribution_bucket(kind: &str) -> Option<&'static str> {
    if RESOURCE_STRUCTURAL_FINDING_KINDS.contains(&kind)
        || kind.starts_with("parser_")
        || kind == "pdf.trailer_inconsistent"
    {
        return Some("structural");
    }
    if kind.starts_with("decoder_")
        || kind.starts_with("decompression_")
        || kind.contains("decode")
        || kind == "declared_filter_invalid"
    {
        return Some("decode");
    }
    if kind.starts_with("font.") || kind.starts_with("font_") {
        return Some("font");
    }
    if kind.starts_with("content_") || kind.starts_with("content.") {
        return Some("content");
    }
    if kind.starts_with("js_") {
        return Some("js-runtime");
    }
    None
}

fn format_count_pairs(counts: &std::collections::HashMap<String, usize>, limit: usize) -> String {
    let mut pairs: Vec<(String, usize)> =
        counts.iter().map(|(kind, count)| (kind.clone(), *count)).collect();
    pairs.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    pairs
        .into_iter()
        .take(limit)
        .map(|(kind, count)| format!("{kind}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn run_scan_with_detectors(
    bytes: &[u8],
    options: ScanOptions,
    detectors: &[Box<dyn crate::detect::Detector>],
) -> Result<Report> {
    let scan_span = tracing::info_span!(
        "scan",
        bytes_len = bytes.len(),
        deep = options.deep,
        strict = options.strict,
        recover_xref = options.recover_xref,
        diff_parser = options.diff_parser
    );
    let _scan_guard = scan_span.enter();
    info!("Starting scan");

    // Create and enable profiler if requested
    let profiler = Profiler::new();
    if options.profile {
        profiler.enable();
    }

    profiler.begin_phase("parse");
    let mut graph = parse_pdf(
        bytes,
        ParseOptions {
            recover_xref: options.recover_xref,
            deep: options.deep,
            strict: options.strict,
            max_objstm_bytes: options.max_decode_bytes,
            max_objects: options.max_objects,
            max_objstm_total_bytes: options.max_total_decoded_bytes,
            carve_stream_objects: options.deep,
            max_carved_objects: carved_object_limit(options.max_objects),
            max_carved_bytes: options.max_decode_bytes,
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
                debug!(
                    trigger = trigger,
                    depth = options.focus_depth,
                    reachable = reachable.len(),
                    "Applied focus trigger filtering"
                );
            }
        }
    }
    profiler.end_phase();

    let ctx = ScanContext::new(bytes, graph, options);

    let detection_start = Instant::now();
    profiler.begin_phase("detection");
    let mut findings: Vec<Finding> = if ctx.options.parallel {
        use rayon::prelude::*;
        let pool = rayon::ThreadPoolBuilder::new().num_threads(PARALLEL_DETECTOR_THREADS).build();
        match pool {
            Ok(pool) => {
                // For parallel execution, we need to track timing separately
                // since detectors run concurrently
                let results: Vec<(String, String, Duration, Vec<Finding>)> = pool
                    .install(|| {
                        detectors
                            .par_iter()
                            .filter(|d| {
                                if ctx.options.fast {
                                    d.cost() == crate::detect::Cost::Cheap
                                } else {
                                    ctx.options.deep || d.cost() != crate::detect::Cost::Expensive
                                }
                            })
                            .filter_map(|d| {
                                let start = Instant::now();
                                let cost_str = match d.cost() {
                                    crate::detect::Cost::Cheap => "Cheap",
                                    crate::detect::Cost::Moderate => "Moderate",
                                    crate::detect::Cost::Expensive => "Expensive",
                                };
                                match d.run(&ctx) {
                                    Ok(findings) => {
                                        let elapsed = start.elapsed();
                                        Some((d.id().to_string(), cost_str.to_string(), elapsed, findings))
                                    }
                                    Err(e) => {
                                        error!(
                                            detector = d.id(),
                                            error = %e,
                                            "[NON-FATAL][finding:detector_execution_failed] Detector failed in parallel execution"
                                        );
                                        let mut meta = std::collections::HashMap::new();
                                        meta.insert("detector.id".into(), d.id().to_string());
                                        meta.insert("detector.error".into(), e.to_string());
                                        let finding = Finding {
                                            id: String::new(),
                                            surface: AttackSurface::Metadata,
                                            kind: "detector_execution_failed".into(),
                                            severity: Severity::Medium,
                                            confidence: Confidence::Strong,
                                            impact: Some(crate::model::Impact::Medium),
                                            title: "Detector execution failed".into(),
                                            description: format!(
                                                "Detector '{}' failed during parallel execution: {}",
                                                d.id(),
                                                e
                                            ),
                                            objects: vec!["detectors".into()],
                                            evidence: Vec::new(),
                                            remediation: Some(
                                                "Review detector error details and rerun with targeted scope."
                                                    .into(),
                                            ),
                                            meta,
                                            reader_impacts: Vec::new(),
                                            action_type: None,
                                            action_target: None,
                                            action_initiation: None,
                                            yara: None,
                                            position: None,
                                            positions: Vec::new(),
                                        };
                                        let elapsed = start.elapsed();
                                        Some((
                                            d.id().to_string(),
                                            cost_str.to_string(),
                                            elapsed,
                                            vec![finding],
                                        ))
                                    }
                                }
                            })
                            .collect::<Vec<_>>()
                    });

                // Record all detector timings to profiler
                for (id, cost, elapsed, ref findings) in &results {
                    profiler.record_detector(id, cost, *elapsed, findings.len());
                    if elapsed.as_millis() > 100 {
                        debug!(
                            detector = id,
                            elapsed_ms = elapsed.as_millis(),
                            findings = findings.len(),
                            "Detector execution time"
                        );
                    }
                }

                // Flatten findings
                results.into_iter().flat_map(|(_, _, _, findings)| findings).collect()
            }
            Err(_err) => {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::Detection,
                    severity: crate::model::Severity::Low,
                    kind: "detector_pool_fallback",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    fatal: false,
                    message: "Failed to build parallel detector pool; falling back to sequential",
                }
                .emit();
                let mut out = Vec::new();
                for d in detectors {
                    if ctx.options.fast && d.cost() != crate::detect::Cost::Cheap {
                        continue;
                    }
                    if !ctx.options.fast
                        && !ctx.options.deep
                        && d.cost() == crate::detect::Cost::Expensive
                    {
                        continue;
                    }
                    let start = Instant::now();
                    let cost_str = match d.cost() {
                        crate::detect::Cost::Cheap => "Cheap",
                        crate::detect::Cost::Moderate => "Moderate",
                        crate::detect::Cost::Expensive => "Expensive",
                    };
                    profiler.begin_detector(d.id(), cost_str);
                    let findings = d.run(&ctx)?;
                    let elapsed = start.elapsed();
                    profiler.end_detector(findings.len());
                    if elapsed.as_millis() > 100 {
                        debug!(
                            detector = d.id(),
                            elapsed_ms = elapsed.as_millis(),
                            findings = findings.len(),
                            "Detector execution time"
                        );
                    }
                    out.extend(findings);
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
            if !ctx.options.fast && !ctx.options.deep && d.cost() == crate::detect::Cost::Expensive
            {
                continue;
            }
            let start = Instant::now();
            let cost_str = match d.cost() {
                crate::detect::Cost::Cheap => "Cheap",
                crate::detect::Cost::Moderate => "Moderate",
                crate::detect::Cost::Expensive => "Expensive",
            };
            profiler.begin_detector(d.id(), cost_str);
            let findings = d.run(&ctx)?;
            let elapsed = start.elapsed();
            profiler.end_detector(findings.len());
            if elapsed.as_millis() > 100 {
                debug!(
                    detector = d.id(),
                    elapsed_ms = elapsed.as_millis(),
                    findings = findings.len(),
                    "Detector execution time"
                );
            }
            out.extend(findings);
        }
        out
    };
    profiler.end_phase();
    let detection_duration_ms = detection_start.elapsed().as_millis() as u64;

    if ctx.graph.objects.len() > ctx.options.max_objects {
        SecurityEvent {
            level: Level::WARN,
            domain: SecurityDomain::PdfStructure,
            severity: crate::model::Severity::Medium,
            kind: "object_count_exceeded",
            policy: None,
            object_id: None,
            object_type: None,
            vector: None,
            technique: None,
            confidence: None,
            fatal: false,
            message: "Object count exceeded max_objects",
        }
        .emit();
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
            impact: None,
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
            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            position: None,
            positions: Vec::new(),
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
    maybe_record_parser_resource_exhaustion(&mut findings, detection_duration_ms);
    escalate_declared_filter_invalid_with_context(&mut findings);
    recalibrate_findings_with_context(&mut findings);

    let font_findings = findings.iter().filter(|f| f.kind.starts_with("font.")).count();
    let js_findings = findings
        .iter()
        .filter(|f| {
            f.surface == crate::model::AttackSurface::JavaScript || f.kind.starts_with("js_")
        })
        .count();
    if font_findings > 0 && js_findings > 0 {
        let mut meta = HashMap::new();
        meta.insert("font.finding_count".into(), font_findings.to_string());
        meta.insert("js.finding_count".into(), js_findings.to_string());
        findings.push(Finding {
            id: String::new(),
            surface: crate::model::AttackSurface::JavaScript,
            kind: "js_font_exploitation".into(),
            severity: crate::model::Severity::High,
            confidence: crate::model::Confidence::Probable,
            impact: None,
            title: "Font exploitation chain suspected".into(),
            description: "JavaScript findings coincide with suspicious embedded fonts.".into(),
            objects: vec!["fonts".into(), "javascript".into()],
            evidence: Vec::new(),
            remediation: Some(
                "Review JavaScript payloads and embedded font tables together.".into(),
            ),
            meta,
            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            position: None,
            positions: Vec::new(),
        });
    }
    let mut ml_summary_override: Option<MlSummary> = None;
    if let Some(ml_cfg) = &ctx.options.ml_config {
        ml_summary_override = Some(MlSummary {
            mode: Some(
                match ml_cfg.mode {
                    crate::ml::MlMode::Traditional => "traditional",
                    crate::ml::MlMode::Graph => "graph",
                }
                .to_string(),
            ),
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
                            meta.insert(
                                "ml.threshold".into(),
                                format!("{:.4}", prediction.threshold),
                            );
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
                                impact: None,
                                title: "ML classifier score high".into(),
                                description: format!(
                                    "Stacking classifier scored {:.4} (threshold {:.4}).",
                                    prediction.score, prediction.threshold
                                ),
                                objects: vec!["ml".into()],
                                evidence: Vec::new(),
                                remediation: Some(
                                    "Review ML features and validate with manual analysis.".into(),
                                ),
                                meta,
                                reader_impacts: Vec::new(),
                                action_type: None,
                                action_target: None,
                                action_initiation: None,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                            });
                        }
                    }
                    Err(err) => {
                        warn!(
                            error = %err,
                            "[NON-FATAL][finding:ml_model_error] ML model load failed"
                        );
                        findings.push(Finding {
                            id: String::new(),
                            surface: crate::model::AttackSurface::Metadata,
                            kind: "ml_model_error".into(),
                            severity: crate::model::Severity::Low,
                            confidence: crate::model::Confidence::Heuristic,
                            impact: None,
                            title: "ML model load failed".into(),
                            description: format!("Failed to load ML model: {}", err),
                            objects: vec!["ml".into()],
                            evidence: Vec::new(),
                            remediation: Some("Check ML model path and format.".into()),
                            meta: Default::default(),
                            reader_impacts: Vec::new(),
                            action_type: None,
                            action_target: None,
                            action_initiation: None,
                            yara: None,
                            position: None,
                            positions: Vec::new(),
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
                        impact: None,
                        title: "Potential adversarial ML sample".into(),
                        description: "Feature profile suggests adversarial manipulation attempts."
                            .into(),
                        objects: vec!["ml".into()],
                        evidence: Vec::new(),
                        remediation: Some("Validate findings against alternate detectors.".into()),
                        meta,
                        reader_impacts: Vec::new(),
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }
            crate::ml::MlMode::Graph => {
                #[cfg(feature = "ml-graph")]
                {
                    let ir_opts = sis_pdf_pdf::ir::IrOptions::default();
                    let ir_graph = crate::ir_pipeline::build_ir_graph(&ctx.graph, &ir_opts);
                    let edge_index = ir_graph.org.edge_index();
                    let runtime = sis_pdf_ml_graph::RuntimeSettings {
                        provider: ml_cfg.runtime.provider.clone(),
                        provider_order: ml_cfg.runtime.provider_order.clone(),
                        ort_dylib_path: ml_cfg.runtime.ort_dylib_path.clone(),
                        prefer_quantized: ml_cfg.runtime.prefer_quantized,
                        max_embedding_batch_size: ml_cfg.runtime.max_embedding_batch_size,
                        print_provider: ml_cfg.runtime.print_provider,
                    };
                    let prediction = sis_pdf_ml_graph::load_and_predict_with_runtime(
                        &ml_cfg.model_path,
                        &ir_graph.node_texts,
                        &edge_index,
                        ml_cfg.threshold,
                        &runtime,
                    );
                    match prediction {
                        Ok(prediction) => {
                            let top_nodes = prediction
                                .node_scores
                                .as_ref()
                                .map(|scores| top_node_attributions(scores, &ir_graph));
                            if let Some(summary) = &mut ml_summary_override {
                                summary.graph = Some(MlRunSummary {
                                    score: prediction.score,
                                    threshold: prediction.threshold,
                                    label: prediction.label,
                                    kind: "ml_graph_score".into(),
                                    top_nodes,
                                });
                            }
                            if prediction.label {
                                let mut meta = std::collections::HashMap::new();
                                meta.insert(
                                    "ml.graph.score".into(),
                                    format!("{:.4}", prediction.score),
                                );
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
                                    impact: None,
                                    title: "Graph ML classifier score high".into(),
                                    description: format!(
                                        "Graph classifier scored {:.4} (threshold {:.4}).",
                                        prediction.score, prediction.threshold
                                    ),
                                    objects: vec!["ml".into()],
                                    evidence: Vec::new(),
                                    remediation: Some(
                                        "Review graph ML output and corroborate with findings."
                                            .into(),
                                    ),
                                    meta,
                                    reader_impacts: Vec::new(),
                                    action_type: None,
                                    action_target: None,
                                    action_initiation: None,
                                    yara: None,
                                    position: None,
                                    positions: Vec::new(),
                                    ..Finding::default()
                                });
                            }
                        }
                        Err(err) => {
                            warn!(
                                error = %err,
                                "[NON-FATAL][finding:ml_model_error] Graph ML inference failed"
                            );
                            findings.push(Finding {
                                id: String::new(),
                                surface: crate::model::AttackSurface::Metadata,
                                kind: "ml_model_error".into(),
                                severity: crate::model::Severity::Low,
                                confidence: crate::model::Confidence::Heuristic,
                                impact: None,
                                title: "ML model load failed".into(),
                                description: format!("Graph ML failed: {}", err),
                                objects: vec!["ml".into()],
                                evidence: Vec::new(),
                                remediation: Some("Check graph model files and format.".into()),
                                meta: Default::default(),
                                reader_impacts: Vec::new(),
                                action_type: None,
                                action_target: None,
                                action_initiation: None,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                                ..Finding::default()
                            });
                        }
                    }
                }
                #[cfg(not(feature = "ml-graph"))]
                {
                    error!(
                        "[NON-FATAL][finding:ml_model_error] Graph ML mode requested but not compiled (enable feature ml-graph)"
                    );
                    findings.push(Finding {
                        id: String::new(),
                        surface: crate::model::AttackSurface::Metadata,
                        kind: "ml_model_error".into(),
                        severity: crate::model::Severity::Low,
                        confidence: crate::model::Confidence::Heuristic,
                        impact: None,
                        title: "ML graph mode unavailable".into(),
                        description:
                            "Graph ML mode requested but not compiled (enable feature ml-graph)."
                                .into(),
                        objects: vec!["ml".into()],
                        evidence: Vec::new(),
                        remediation: Some("Rebuild with --features ml-graph.".into()),
                        meta: Default::default(),
                        reader_impacts: Vec::new(),
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }
        }
    }
    annotate_positions(&ctx, &mut findings);
    annotate_orphaned_page_context(&mut findings);
    correlate_font_js(&mut findings);
    let composites = correlation::correlate_findings(&findings, &ctx.options.correlation);
    findings.extend(composites);
    assign_stable_ids(&mut findings);
    let intent_summary = Some(crate::intent::apply_intent(&mut findings));
    let yara_rules =
        crate::yara::annotate_findings(&mut findings, ctx.options.yara_scope.as_deref());
    findings.sort_by(|a, b| {
        (a.surface as u32, &a.kind, &a.id).cmp(&(b.surface as u32, &b.kind, &b.id))
    });
    let (chains, templates) =
        crate::chain_synth::synthesise_chains(&findings, ctx.options.group_chains);
    let behavior_summary = Some(crate::behavior::correlate_findings(&findings));
    let future_threats = behavior_summary
        .as_ref()
        .map(|s| crate::predictor::BehavioralPredictor.predict_evolution(&s.patterns))
        .unwrap_or_default();
    let network_intents =
        crate::campaign::extract_network_intents_from_findings(&findings, &Default::default());
    let response_rules = behavior_summary
        .as_ref()
        .map(|s| {
            let generator = crate::response::ResponseGenerator;
            s.patterns.iter().flat_map(|p| generator.generate_yara_variants(p)).collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let structural_summary = Some(build_structural_summary(&ctx, diff_result.as_ref(), &findings));

    // Finalize profiler and output if enabled
    if ctx.options.profile {
        let doc_info = DocumentInfo {
            file_size_bytes: bytes.len() as u64,
            object_count: ctx.graph.objects.len(),
            stream_count: ctx
                .graph
                .objects
                .iter()
                .filter(|e| matches!(e.atom, sis_pdf_pdf::object::PdfAtom::Stream(_)))
                .count(),
            page_count: structural_summary
                .as_ref()
                .and_then(|s| s.ir_summary.as_ref())
                .map(|ir| ir.object_count)
                .unwrap_or(0),
        };

        if let Some(report) = profiler.finalize(doc_info) {
            let output = match ctx.options.profile_format {
                crate::scan::ProfileFormat::Text => crate::profiler::format_text(&report),
                crate::scan::ProfileFormat::Json => crate::profiler::format_json(&report)
                    .unwrap_or_else(|e| format!("Error formatting profile JSON: {}", e)),
            };
            eprintln!("{}", output);
        }
    }

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
    )
    .with_detection_duration(Some(detection_duration_ms)))
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

pub fn assign_stable_ids(findings: &mut [Finding]) {
    for f in findings {
        if f.id.is_empty() {
            f.id = stable_id(f);
        }
    }
}

pub fn annotate_positions(ctx: &ScanContext, findings: &mut [Finding]) {
    let classifications = ctx.classifications();
    let path_map = position::build_path_map(&ctx.graph);
    for finding in findings {
        if !finding.positions.is_empty() || finding.position.is_some() {
            continue;
        }
        let mut positions = Vec::new();
        for obj in &finding.objects {
            let Some((obj_id, gen_id)) = position::parse_obj_ref(obj) else {
                continue;
            };
            let path_hint = path_map.get(&(obj_id, gen_id)).map(|path| path.as_str());
            let pos = position::canonical_position_for_obj(
                &ctx.graph,
                classifications,
                obj_id,
                gen_id,
                path_hint,
            );
            positions.push(pos);
            if let Some(preview) = raw_node_preview(&ctx.graph, obj_id, gen_id, 120) {
                let key = format!("position.preview.{}:{}", obj_id, gen_id);
                finding.meta.entry(key).or_insert(preview);
            }
        }
        positions.sort();
        positions.dedup();
        if let Some(first) = positions.first().cloned() {
            finding.position = Some(first);
            finding.positions = positions;
        }
    }
}

fn annotate_orphaned_page_context(findings: &mut [Finding]) {
    let mut suspicious_by_obj: HashMap<String, Vec<String>> = HashMap::new();
    for finding in findings.iter() {
        if !is_suspicious_orphan_payload(finding) {
            continue;
        }
        for obj in &finding.objects {
            if let Some((obj_id, gen_id)) = position::parse_obj_ref(obj) {
                let key = format!("{} {}", obj_id, gen_id);
                suspicious_by_obj.entry(key).or_default().push(finding.id.clone());
            }
        }
    }

    for finding in findings.iter_mut() {
        if finding.kind != "page_tree_mismatch" {
            continue;
        }
        if finding.meta.get("page_tree.orphaned").map(|v| v == "0").unwrap_or(true) {
            continue;
        }
        let mut related = Vec::new();
        for obj in &finding.objects {
            let Some((obj_id, gen_id)) = position::parse_obj_ref(obj) else {
                continue;
            };
            let key = format!("{} {}", obj_id, gen_id);
            if let Some(ids) = suspicious_by_obj.get(&key) {
                related.extend(ids.iter().cloned());
            }
        }
        related.sort();
        related.dedup();
        if !related.is_empty() {
            finding.meta.insert("page_tree.orphaned_has_payload".into(), "true".into());
            finding
                .meta
                .insert("page_tree.orphaned_payload_count".into(), related.len().to_string());
            let list = related.into_iter().take(8).collect::<Vec<_>>().join(", ");
            finding.meta.insert("page_tree.orphaned_payload_findings".into(), list);
        }
    }
}

/// Correlate font and JavaScript findings to detect combined exploitation attempts
fn correlate_font_js(findings: &mut Vec<Finding>) {
    // Check if we have both font and JavaScript findings
    let has_high_font = findings.iter().any(|f| {
        f.kind.starts_with("font.")
            && matches!(f.severity, crate::model::Severity::High | crate::model::Severity::Critical)
    });

    let has_js_obfuscation = findings.iter().any(|f| {
        f.kind.contains("js_") && (f.kind.contains("obfusc") || f.kind.contains("polymorphic"))
    });

    let has_js_exploit = findings.iter().any(|f| {
        f.kind.contains("js_")
            && matches!(f.severity, crate::model::Severity::High | crate::model::Severity::Critical)
    });

    // High severity font + JavaScript exploit = combined attack pattern
    if has_high_font && has_js_exploit {
        let font_ids: Vec<String> = findings
            .iter()
            .filter(|f| {
                f.kind.starts_with("font.")
                    && matches!(
                        f.severity,
                        crate::model::Severity::High | crate::model::Severity::Critical
                    )
            })
            .map(|f| f.id.clone())
            .take(5)
            .collect();

        let js_ids: Vec<String> = findings
            .iter()
            .filter(|f| {
                f.kind.contains("js_")
                    && matches!(
                        f.severity,
                        crate::model::Severity::High | crate::model::Severity::Critical
                    )
            })
            .map(|f| f.id.clone())
            .take(5)
            .collect();

        let mut meta = std::collections::HashMap::new();
        meta.insert("font_finding_count".into(), font_ids.len().to_string());
        meta.insert("js_finding_count".into(), js_ids.len().to_string());
        meta.insert("font_findings".into(), font_ids.join(", "));
        meta.insert("js_findings".into(), js_ids.join(", "));

        findings.push(Finding {
            id: String::new(), // Will be filled by stable_id
            surface: crate::model::AttackSurface::StreamsAndFilters,
            kind: "pdf.font_js_combined_exploit".into(),
            severity: crate::model::Severity::Critical,
            confidence: crate::model::Confidence::Probable,
            impact: None,
            title: "Font and JavaScript combined exploitation pattern".into(),
            description: "Document contains both high-severity font vulnerabilities and JavaScript exploits, suggesting a multi-vector attack.".into(),
            objects: Vec::new(),
            evidence: Vec::new(),
            remediation: Some("This document shows signs of a sophisticated multi-vector attack. Block or quarantine immediately.".into()),
            meta,
            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            position: None,
            positions: Vec::new(),
        });
    }

    // Medium font + JavaScript obfuscation = escalate font severity
    if has_js_obfuscation {
        for finding in findings.iter_mut() {
            if finding.kind.starts_with("font.")
                && finding.severity == crate::model::Severity::Medium
            {
                finding.severity = crate::model::Severity::High;
                finding.meta.insert("severity_escalated".into(), "js_obfuscation_present".into());
                finding.description = format!(
                    "{} Severity escalated due to presence of obfuscated JavaScript.",
                    finding.description
                );
            }
        }
    }
}

fn is_suspicious_orphan_payload(finding: &Finding) -> bool {
    if finding.kind == "page_tree_mismatch" || finding.kind == "page_tree_cycle" {
        return false;
    }
    matches!(
        finding.surface,
        crate::model::AttackSurface::JavaScript
            | crate::model::AttackSurface::Actions
            | crate::model::AttackSurface::EmbeddedFiles
            | crate::model::AttackSurface::ContentPhishing
            | crate::model::AttackSurface::RichMedia3D
    ) || finding.kind.contains("js_")
        || finding.kind.contains("uri_")
        || finding.kind.contains("embedded")
        || finding.kind.contains("launch")
}

fn raw_node_preview(graph: &ObjectGraph<'_>, obj: u32, gen: u16, max_len: usize) -> Option<String> {
    let entry = graph.get_object(obj, gen)?;
    let preview = match &entry.atom {
        PdfAtom::Dict(dict) => dict_preview(dict),
        PdfAtom::Stream(stream) => stream_preview(stream),
        PdfAtom::Array(items) => array_preview(items),
        PdfAtom::Ref { obj, gen } => format!("ref {}:{}", obj, gen),
        PdfAtom::Name(name) => name_preview(name),
        PdfAtom::Str(s) => string_preview(s),
        PdfAtom::Int(v) => format!("int {}", v),
        PdfAtom::Real(v) => format!("real {:.6}", v),
        PdfAtom::Bool(v) => format!("bool {}", v),
        PdfAtom::Null => "null".to_string(),
    };
    Some(truncate_preview(preview, max_len))
}

fn dict_preview(dict: &PdfDict<'_>) -> String {
    let mut parts = vec!["dict".to_string()];
    if let Some(type_name) = dict.get_first(b"/Type").and_then(|(_, v)| name_value(&v.atom)) {
        parts.push(format!("Type={}", type_name.trim_start_matches('/')));
    }
    if let Some(subtype) = dict.get_first(b"/Subtype").and_then(|(_, v)| name_value(&v.atom)) {
        parts.push(format!("Subtype={}", subtype.trim_start_matches('/')));
    }
    let mut keys: Vec<String> = dict.entries.iter().map(|(k, _)| name_preview(k)).collect();
    keys.sort();
    keys.dedup();
    if !keys.is_empty() {
        let keys_preview = keys.into_iter().take(6).collect::<Vec<_>>().join(",");
        parts.push(format!("keys={}", keys_preview));
    }
    parts.join(" ")
}

fn stream_preview(stream: &sis_pdf_pdf::object::PdfStream<'_>) -> String {
    let filters = stream_filters(&stream.dict);
    let filter_list = if filters.is_empty() { "-".to_string() } else { filters.join(",") };
    let mut parts = vec![
        "stream".to_string(),
        format!("len={}", stream.data_span.len()),
        format!("filters={}", filter_list),
    ];
    let mut keys: Vec<String> = stream.dict.entries.iter().map(|(k, _)| name_preview(k)).collect();
    keys.sort();
    keys.dedup();
    if !keys.is_empty() {
        let keys_preview = keys.into_iter().take(6).collect::<Vec<_>>().join(",");
        parts.push(format!("keys={}", keys_preview));
    }
    parts.join(" ")
}

fn array_preview(items: &[PdfObj<'_>]) -> String {
    let mut item_preview = Vec::new();
    for item in items.iter().take(3) {
        item_preview.push(atom_compact_preview(&item.atom));
    }
    let suffix = if items.len() > 3 { ", ..." } else { "" };
    format!("array len={} [{}{}]", items.len(), item_preview.join(", "), suffix)
}

fn atom_compact_preview(atom: &PdfAtom<'_>) -> String {
    match atom {
        PdfAtom::Ref { obj, gen } => format!("ref {}:{}", obj, gen),
        PdfAtom::Name(name) => name_preview(name),
        PdfAtom::Str(s) => string_preview(s),
        PdfAtom::Int(v) => v.to_string(),
        PdfAtom::Real(v) => format!("{:.6}", v),
        PdfAtom::Bool(v) => v.to_string(),
        PdfAtom::Null => "null".to_string(),
        PdfAtom::Dict(_) => "dict".to_string(),
        PdfAtom::Stream(_) => "stream".to_string(),
        PdfAtom::Array(arr) => format!("array len={}", arr.len()),
    }
}

fn name_preview(name: &sis_pdf_pdf::object::PdfName<'_>) -> String {
    let decoded = String::from_utf8_lossy(&name.decoded);
    if decoded.starts_with('/') {
        decoded.to_string()
    } else {
        format!("/{}", decoded)
    }
}

fn name_value(atom: &PdfAtom<'_>) -> Option<String> {
    match atom {
        PdfAtom::Name(name) => Some(name_preview(name)),
        _ => None,
    }
}

fn string_preview(value: &sis_pdf_pdf::object::PdfStr<'_>) -> String {
    let decoded = match value {
        sis_pdf_pdf::object::PdfStr::Literal { decoded, .. } => decoded,
        sis_pdf_pdf::object::PdfStr::Hex { decoded, .. } => decoded,
    };
    let preview = preview_ascii(decoded, 48);
    format!("str \"{}\"", preview)
}

fn truncate_preview(mut preview: String, max_len: usize) -> String {
    if max_len == 0 {
        return String::new();
    }
    if preview.len() > max_len {
        if max_len > 3 {
            preview.truncate(max_len - 3);
            preview.push_str("...");
        } else {
            preview.truncate(max_len);
        }
    }
    preview
}

#[cfg(feature = "ml-graph")]
fn summarize_ir_object(obj: &PdfIrObject) -> String {
    let mut parts = Vec::new();
    for line in obj.lines.iter().take(3) {
        let mut piece = format!("{} {}", line.path, line.value_type);
        if !line.value.is_empty() {
            let mut value = line.value.clone();
            if value.len() > 40 {
                value.truncate(40);
                value.push_str("...");
            }
            piece.push(' ');
            piece.push_str(&value);
        }
        parts.push(piece);
    }
    if parts.is_empty() {
        "<no_ir_lines>".into()
    } else {
        parts.join(" ; ")
    }
}

#[cfg(feature = "ml-graph")]
fn top_node_attributions(
    node_scores: &[f32],
    ir_graph: &crate::ir_pipeline::IrGraphArtifacts,
) -> Vec<MlNodeAttribution> {
    let mut ir_map: std::collections::HashMap<ObjRef, &PdfIrObject> =
        std::collections::HashMap::new();
    for obj in &ir_graph.ir_objects {
        let key = ObjRef { obj: obj.obj_ref.0, gen: obj.obj_ref.1 };
        ir_map.insert(key, obj);
    }
    let mut entries = Vec::new();
    let node_count = ir_graph.org.nodes.len();
    for (idx, score) in node_scores.iter().enumerate() {
        if idx >= node_count {
            break;
        }
        let node_ref = ir_graph.org.nodes[idx];
        let summary = ir_map
            .get(&node_ref)
            .map(|obj| summarize_ir_object(obj))
            .unwrap_or_else(|| "<missing_object>".into());
        entries.push(MlNodeAttribution {
            obj_ref: format!("{} {}", node_ref.obj, node_ref.gen),
            summary,
            score: *score,
        });
    }
    entries.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    entries.truncate(5);
    entries
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
            seeds.push(ObjRef { obj: entry.obj, gen: entry.gen });
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
            entry_dict(entry).map(|d| d.has_name(b"/Type", b"/ObjStm")).unwrap_or(false)
        })
        .count();
    let object_count = ctx.graph.objects.len();
    let objstm_ratio =
        if object_count == 0 { 0.0 } else { objstm_count as f64 / object_count as f64 };
    let header_offset = find_first(ctx.bytes, b"%PDF-").map(|v| v as u64);
    let eof_offset = find_last(ctx.bytes, b"%%EOF").map(|v| v as u64);
    let eof_distance_to_end =
        eof_offset.map(|off| ctx.bytes.len().saturating_sub(off as usize + 5) as u64);
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
    let canonical = ctx.canonical_view();
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
        canonical_object_count: canonical.indices.len(),
        incremental_updates_removed: canonical.incremental_removed,
        normalized_name_changes: canonical.normalized_name_changes,
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
                    list.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
                );
            }
        }
    }
    sigs.sort();
    sigs.dedup();
    (found, sigs)
}

fn maybe_record_parser_resource_exhaustion(
    findings: &mut Vec<Finding>,
    detection_duration_ms: u64,
) {
    if detection_duration_ms < RESOURCE_CONSUMPTION_THRESHOLD_MS {
        return;
    }
    let structural: Vec<String> = findings
        .iter()
        .filter(|f| RESOURCE_STRUCTURAL_FINDING_KINDS.contains(&f.kind.as_str()))
        .map(|f| f.kind.clone())
        .collect();
    if structural.is_empty() {
        return;
    }
    let mut contribution_kind_counts: HashMap<String, usize> = HashMap::new();
    let mut contribution_bucket_counts: HashMap<String, usize> = HashMap::new();
    let mut sample_objects: Vec<String> = Vec::new();
    let mut sample_positions: Vec<String> = Vec::new();
    let mut sample_object_seen: HashSet<String> = HashSet::new();
    let mut sample_position_seen: HashSet<String> = HashSet::new();
    for finding in findings.iter() {
        if finding.kind == "parser_resource_exhaustion" {
            continue;
        }
        let Some(bucket) = resource_contribution_bucket(&finding.kind) else {
            continue;
        };
        *contribution_kind_counts.entry(finding.kind.clone()).or_insert(0) += 1;
        *contribution_bucket_counts.entry(bucket.to_string()).or_insert(0) += 1;
        if sample_objects.len() < RESOURCE_CONTRIBUTION_SAMPLE_OBJECT_LIMIT {
            for object in &finding.objects {
                if sample_object_seen.insert(object.clone()) {
                    sample_objects.push(object.clone());
                    if sample_objects.len() >= RESOURCE_CONTRIBUTION_SAMPLE_OBJECT_LIMIT {
                        break;
                    }
                }
            }
        }
        if let Some(position) = &finding.position {
            if sample_position_seen.insert(position.clone()) {
                sample_positions.push(position.clone());
            }
        }
        for position in &finding.positions {
            if sample_position_seen.insert(position.clone()) {
                sample_positions.push(position.clone());
                if sample_positions.len() >= RESOURCE_CONTRIBUTION_SAMPLE_POSITION_LIMIT {
                    break;
                }
            }
        }
        if sample_positions.len() > RESOURCE_CONTRIBUTION_SAMPLE_POSITION_LIMIT {
            sample_positions.truncate(RESOURCE_CONTRIBUTION_SAMPLE_POSITION_LIMIT);
        }
    }
    let top_kind_counts =
        format_count_pairs(&contribution_kind_counts, RESOURCE_CONTRIBUTION_KIND_LIMIT);
    let bucket_counts = format_count_pairs(&contribution_bucket_counts, 5);
    let mut meta = HashMap::new();
    meta.insert("detection_duration_ms".into(), detection_duration_ms.to_string());
    meta.insert("structural_finding_count".into(), structural.len().to_string());
    meta.insert("structural_findings".into(), structural.join(", "));
    meta.insert(
        "resource_contribution_total_count".into(),
        contribution_kind_counts.values().sum::<usize>().to_string(),
    );
    meta.insert(
        "resource_contribution_unique_kind_count".into(),
        contribution_kind_counts.len().to_string(),
    );
    meta.insert("resource_contribution_top_kinds".into(), top_kind_counts.clone());
    meta.insert("resource_contribution_bucket_counts".into(), bucket_counts.clone());
    if !sample_objects.is_empty() {
        meta.insert("resource_contribution_sample_objects".into(), sample_objects.join(", "));
    }
    if !sample_positions.is_empty() {
        meta.insert("resource_contribution_sample_positions".into(), sample_positions.join(", "));
    }
    findings.push(Finding {
        id: String::new(),
        surface: AttackSurface::FileStructure,
        kind: "parser_resource_exhaustion".into(),
        severity: Severity::High,
        confidence: Confidence::Probable,
        impact: Some(crate::model::Impact::High),
        title: "Parser resource exhaustion detected".into(),
        description: format!(
            "The parser spent {}ms re-processing malformed structures. Top contributors: {}. Buckets: {}. Treat it as a possible refusal-of-service attempt.",
            detection_duration_ms,
            if top_kind_counts.is_empty() {
                "none".to_string()
            } else {
                top_kind_counts
            },
            if bucket_counts.is_empty() {
                "none".to_string()
            } else {
                bucket_counts
            }
        ),
        objects: sample_objects,
        evidence: Vec::new(),
        remediation: Some(
            "Reject malformed structures early or run detection with reduced scope/--fast.".into(),
        ),
        meta,
        reader_impacts: Vec::new(),
        action_type: None,
        action_target: None,
        action_initiation: None,
        yara: None,
        position: None,
        positions: Vec::new(),
    });
}

fn escalate_declared_filter_invalid_with_context(findings: &mut [Finding]) {
    let has_js_runtime_anomaly = findings.iter().any(|finding| {
        matches!(
            finding.kind.as_str(),
            "js_emulation_breakpoint"
                | "js_runtime_unknown_behaviour_pattern"
                | "js_sandbox_timeout"
                | "js_runtime_error"
        )
    });
    let has_decoder_pressure = findings.iter().any(|finding| {
        matches!(
            finding.kind.as_str(),
            "decoder_risk_present"
                | "decompression_ratio_suspicious"
                | "parser_resource_exhaustion"
        )
    });

    if !has_js_runtime_anomaly && !has_decoder_pressure {
        return;
    }

    for finding in findings.iter_mut().filter(|finding| finding.kind == "declared_filter_invalid") {
        let (new_severity, new_confidence, reason) =
            match (has_js_runtime_anomaly, has_decoder_pressure) {
                (true, true) => (
                    Severity::Critical,
                    Confidence::Certain,
                    "paired_with_js_runtime_anomaly_and_decoder_pressure",
                ),
                (true, false) => {
                    (Severity::High, Confidence::Strong, "paired_with_js_runtime_anomaly")
                }
                (false, true) => {
                    (Severity::High, Confidence::Strong, "paired_with_decoder_pressure")
                }
                (false, false) => continue,
            };

        if finding.severity < new_severity {
            finding.severity = new_severity;
        }
        if finding.confidence > new_confidence {
            finding.confidence = new_confidence;
        }
        finding.meta.insert("triage.severity_escalated".into(), "true".into());
        finding.meta.insert("triage.escalation_reason".into(), reason.to_string());
    }
}

fn recalibrate_findings_with_context(findings: &mut [Finding]) {
    let has_filter_anomaly = findings.iter().any(|finding| {
        matches!(
            finding.kind.as_str(),
            "declared_filter_invalid"
                | "filter_chain_unusual"
                | "filter_order_invalid"
                | "filter_combination_unusual"
                | "label_mismatch_stream_type"
        )
    });
    let has_runtime_anomaly = findings.iter().any(|finding| {
        matches!(
            finding.kind.as_str(),
            "js_emulation_breakpoint"
                | "js_runtime_unknown_behaviour_pattern"
                | "js_sandbox_timeout"
                | "js_runtime_error"
                | "js_runtime_error_recovery_patterns"
                | "js_runtime_heap_manipulation"
                | "js_runtime_recursion_limit"
        )
    });
    let has_decode_risk = findings.iter().any(|finding| {
        matches!(finding.kind.as_str(), "decoder_risk_present" | "decompression_ratio_suspicious")
    });
    let has_structural_inconsistency = findings.iter().any(|finding| {
        matches!(
            finding.kind.as_str(),
            "pdf.trailer_inconsistent"
                | "xref_conflict"
                | "xref_start_offset_oob"
                | "xref_phantom_entries"
                | "structural_evasion_composite"
                | "parser_trailer_count_diff"
                | "parser_diff_structural"
        )
    });
    let has_resource_exhaustion =
        findings.iter().any(|finding| finding.kind == "parser_resource_exhaustion");
    let has_action_chain = findings.iter().any(|finding| {
        matches!(
            finding.kind.as_str(),
            "action_chain_complex"
                | "action_chain_malicious"
                | "annotation_action_chain"
                | "action_automatic_trigger"
        )
    });
    let has_js_intent = findings.iter().any(|finding| {
        matches!(
            finding.kind.as_str(),
            "js_intent_user_interaction"
                | "js_runtime_network_intent"
                | "js_runtime_downloader_pattern"
                | "js_obfuscation_deep"
                | "js_malicious_pattern"
        ) || finding.meta.contains_key("js.intent.primary")
    });
    let has_external_launch = findings.iter().any(|finding| {
        matches!(
            finding.kind.as_str(),
            "launch_action_present"
                | "launch_external_program"
                | "launch_embedded_file"
                | "launch_obfuscated_executable"
        )
    });

    if has_filter_anomaly && has_runtime_anomaly {
        for finding in findings.iter_mut().filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "declared_filter_invalid"
                    | "filter_chain_unusual"
                    | "filter_order_invalid"
                    | "filter_combination_unusual"
                    | "label_mismatch_stream_type"
            )
        }) {
            apply_context_recalibration(
                finding,
                Severity::High,
                Confidence::Strong,
                "filter_runtime_anomaly_cooccurrence",
            );
        }
    }

    if has_decode_risk && has_structural_inconsistency && has_resource_exhaustion {
        for finding in findings.iter_mut().filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "decoder_risk_present"
                    | "decompression_ratio_suspicious"
                    | "image_decoder_exploit_chain"
            )
        }) {
            apply_context_recalibration(
                finding,
                Severity::Critical,
                Confidence::Strong,
                "decode_structural_exhaustion_chain",
            );
        }
        for finding in findings.iter_mut().filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "parser_resource_exhaustion"
                    | "pdf.trailer_inconsistent"
                    | "xref_conflict"
                    | "structural_evasion_composite"
            )
        }) {
            apply_context_recalibration(
                finding,
                Severity::High,
                Confidence::Strong,
                "decode_structural_exhaustion_chain",
            );
        }
    }

    if has_action_chain && has_js_intent && has_external_launch {
        for finding in findings.iter_mut().filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "action_chain_complex"
                    | "action_chain_malicious"
                    | "annotation_action_chain"
                    | "action_automatic_trigger"
                    | "launch_action_present"
                    | "launch_external_program"
                    | "launch_embedded_file"
            )
        }) {
            apply_context_recalibration(
                finding,
                Severity::High,
                Confidence::Strong,
                "action_js_launch_chain",
            );
        }
    }
}

fn apply_context_recalibration(
    finding: &mut Finding,
    target_severity: Severity,
    target_confidence: Confidence,
    reason: &str,
) {
    let old_severity = finding.severity;
    let old_confidence = finding.confidence;

    if finding.severity < target_severity {
        finding.severity = target_severity;
    }
    if finding.confidence > target_confidence {
        finding.confidence = target_confidence;
    }

    if finding.severity == old_severity && finding.confidence == old_confidence {
        return;
    }

    finding.meta.insert("triage.context_recalibrated".into(), "true".into());
    append_meta_csv(&mut finding.meta, "triage.context_reasons", reason);
    finding.meta.insert(
        "triage.severity_adjustment".into(),
        format!("{}->{}", severity_label(old_severity), severity_label(finding.severity)),
    );
    finding.meta.insert(
        "triage.confidence_adjustment".into(),
        format!("{}->{}", old_confidence.as_str(), finding.confidence.as_str()),
    );
}

fn append_meta_csv(meta: &mut HashMap<String, String>, key: &str, value: &str) {
    match meta.get_mut(key) {
        Some(existing) => {
            let values = existing.split(',').map(|entry| entry.trim()).collect::<Vec<_>>();
            if !values.contains(&value) {
                if !existing.is_empty() {
                    existing.push(',');
                }
                existing.push_str(value);
            }
        }
        None => {
            meta.insert(key.to_string(), value.to_string());
        }
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn collect_refs_from_obj(obj: &PdfObj<'_>, out: &mut Vec<ObjRef>) {
    if let PdfAtom::Ref { obj, gen } = obj.atom {
        out.push(ObjRef { obj, gen });
    }
}

fn filter_graph_by_refs<'a>(graph: &ObjectGraph<'a>, keep: &HashSet<ObjRef>) -> ObjectGraph<'a> {
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
        xref_sections: graph.xref_sections.clone(),
        deviations: graph.deviations.clone(),
        telemetry_events: graph.telemetry_events.clone(),
    }
}

fn carved_object_limit(max_objects: usize) -> usize {
    if max_objects == 0 {
        return CARVED_OBJECT_LIMIT_DEFAULT;
    }
    max_objects.min(CARVED_OBJECT_LIMIT_DEFAULT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_font_js_correlation_critical() {
        let mut findings = vec![
            Finding {
                id: "font1".into(),
                surface: crate::model::AttackSurface::StreamsAndFilters,
                kind: "font.type1_blend_exploit".into(),
                severity: crate::model::Severity::High,
                confidence: crate::model::Confidence::Probable,
                impact: None,
                title: "Font exploit".into(),
                description: "Test font finding".into(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: std::collections::HashMap::new(),

                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: vec![],
            },
            Finding {
                id: "js1".into(),
                surface: crate::model::AttackSurface::JavaScript,
                kind: "js_malicious_pattern".into(),
                severity: crate::model::Severity::High,
                confidence: crate::model::Confidence::Probable,
                impact: None,
                title: "JS exploit".into(),
                description: "Test JS finding".into(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: std::collections::HashMap::new(),

                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: vec![],
            },
        ];

        correlate_font_js(&mut findings);

        // Should have created a combined exploit finding
        let has_combined = findings.iter().any(|f| f.kind == "pdf.font_js_combined_exploit");
        assert!(
            has_combined,
            "Should create combined exploit finding. Findings: {:?}",
            findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
        );

        // Combined finding should be CRITICAL
        let combined = match findings.iter().find(|f| f.kind == "pdf.font_js_combined_exploit") {
            Some(value) => value,
            None => panic!(
                "expected combined exploit finding, findings: {:?}",
                findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
            ),
        };
        assert_eq!(combined.severity, crate::model::Severity::Critical);
    }

    #[test]
    fn test_font_js_correlation_escalation() {
        let mut findings = vec![
            Finding {
                id: "font1".into(),
                surface: crate::model::AttackSurface::StreamsAndFilters,
                kind: "font.type1_large_charstring".into(),
                severity: crate::model::Severity::Medium,
                confidence: crate::model::Confidence::Probable,
                impact: None,
                title: "Font anomaly".into(),
                description: "Test font finding".into(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: std::collections::HashMap::new(),

                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: vec![],
            },
            Finding {
                id: "js1".into(),
                surface: crate::model::AttackSurface::JavaScript,
                kind: "js_obfuscation_detected".into(),
                severity: crate::model::Severity::Medium,
                confidence: crate::model::Confidence::Probable,
                impact: None,
                title: "JS obfuscation".into(),
                description: "Test JS obfuscation".into(),
                objects: vec![],
                evidence: vec![],
                remediation: None,
                meta: std::collections::HashMap::new(),

                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: vec![],
            },
        ];

        correlate_font_js(&mut findings);

        // Font finding should be escalated from MEDIUM to HIGH
        let font_finding = match findings.iter().find(|f| f.kind == "font.type1_large_charstring") {
            Some(value) => value,
            None => panic!("font finding missing after correlation"),
        };
        assert_eq!(font_finding.severity, crate::model::Severity::High);

        // Should have escalation metadata
        assert!(font_finding.meta.contains_key("severity_escalated"));
    }

    #[test]
    fn test_font_js_correlation_no_action() {
        let mut findings = vec![Finding {
            id: "font1".into(),
            surface: crate::model::AttackSurface::StreamsAndFilters,
            kind: "font.type1_excessive_stack".into(),
            severity: crate::model::Severity::Low,
            confidence: crate::model::Confidence::Probable,
            impact: None,
            title: "Font anomaly".into(),
            description: "Test font finding".into(),
            objects: vec![],
            evidence: vec![],
            remediation: None,
            meta: std::collections::HashMap::new(),

            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            position: None,
            positions: vec![],
        }];

        let original_count = findings.len();
        correlate_font_js(&mut findings);

        // Should not create new findings or escalate severity
        assert_eq!(findings.len(), original_count, "Should not create new findings");
        assert_eq!(findings[0].severity, crate::model::Severity::Low);
    }

    #[test]
    fn parser_resource_exhaustion_logged() {
        let mut findings = vec![Finding::template(
            AttackSurface::FileStructure,
            "parser_trailer_count_diff",
            Severity::Medium,
            Confidence::Certain,
            "Trailer mismatch",
            "Test",
        )];
        maybe_record_parser_resource_exhaustion(
            &mut findings,
            RESOURCE_CONSUMPTION_THRESHOLD_MS + 1,
        );
        let last = findings.last().expect("finding added");
        assert_eq!(last.kind, "parser_resource_exhaustion");
        assert_eq!(last.meta.get("structural_finding_count"), Some(&"1".to_string()));
        assert_eq!(
            last.meta.get("resource_contribution_top_kinds"),
            Some(&"parser_trailer_count_diff=1".to_string())
        );
        assert_eq!(
            last.meta.get("resource_contribution_bucket_counts"),
            Some(&"structural=1".to_string())
        );
    }

    #[test]
    fn parser_resource_exhaustion_includes_counts_buckets_and_samples() {
        let mut trailer = Finding::template(
            AttackSurface::FileStructure,
            "parser_trailer_count_diff",
            Severity::Medium,
            Confidence::Certain,
            "Trailer mismatch",
            "Test",
        );
        trailer.objects = vec!["trailer.0".into()];
        trailer.position = Some("doc:r0/trailer.0".into());
        let mut label = Finding::template(
            AttackSurface::StreamsAndFilters,
            "label_mismatch_stream_type",
            Severity::Medium,
            Confidence::Strong,
            "Label mismatch",
            "Test",
        );
        label.objects = vec!["8 0 obj".into()];
        label.positions = vec!["doc:r0/obj.8".into()];
        let mut font = Finding::template(
            AttackSurface::StreamsAndFilters,
            "font.dynamic_parse_failure",
            Severity::Low,
            Confidence::Probable,
            "Font parse failure",
            "Test",
        );
        font.objects = vec!["9 0 obj".into()];
        let mut decode = Finding::template(
            AttackSurface::StreamsAndFilters,
            "decompression_ratio_suspicious",
            Severity::High,
            Confidence::Strong,
            "Decompression ratio suspicious",
            "Test",
        );
        decode.objects = vec!["12 0 obj".into()];
        let mut content = Finding::template(
            AttackSurface::ContentPhishing,
            "content_stream_anomaly",
            Severity::Medium,
            Confidence::Probable,
            "Content anomaly",
            "Test",
        );
        content.objects = vec!["16 0 obj".into()];
        let mut js = Finding::template(
            AttackSurface::JavaScript,
            "js_runtime_error_recovery_patterns",
            Severity::Low,
            Confidence::Probable,
            "JS runtime error recovery",
            "Test",
        );
        js.objects = vec!["20 0 obj".into()];
        let mut findings = vec![trailer, label, font, decode, content, js];

        maybe_record_parser_resource_exhaustion(
            &mut findings,
            RESOURCE_CONSUMPTION_THRESHOLD_MS + 10,
        );

        let last = findings.last().expect("exhaustion finding should be added");
        assert_eq!(last.kind, "parser_resource_exhaustion");
        assert_eq!(last.meta.get("resource_contribution_total_count"), Some(&"6".to_string()));
        assert_eq!(
            last.meta.get("resource_contribution_unique_kind_count"),
            Some(&"6".to_string())
        );
        assert_eq!(
            last.meta.get("resource_contribution_bucket_counts"),
            Some(&"structural=2, content=1, decode=1, font=1, js-runtime=1".to_string())
        );
        let top = last.meta.get("resource_contribution_top_kinds").expect("top kind counts");
        assert!(top.contains("parser_trailer_count_diff=1"));
        assert!(top.contains("label_mismatch_stream_type=1"));
        assert!(top.contains("font.dynamic_parse_failure=1"));
        assert!(top.contains("decompression_ratio_suspicious=1"));
        assert!(top.contains("content_stream_anomaly=1"));
        assert!(top.contains("js_runtime_error_recovery_patterns=1"));
        assert!(last.objects.contains(&"trailer.0".to_string()));
        assert!(last.objects.contains(&"8 0 obj".to_string()));
        assert_eq!(
            last.meta.get("resource_contribution_sample_positions"),
            Some(&"doc:r0/trailer.0, doc:r0/obj.8".to_string())
        );
    }

    #[test]
    fn declared_filter_invalid_escalates_with_runtime_and_decoder_context() {
        let mut findings = vec![
            Finding::template(
                AttackSurface::StreamsAndFilters,
                "declared_filter_invalid",
                Severity::High,
                Confidence::Probable,
                "Declared filters mismatched stream data",
                "Test",
            ),
            Finding::template(
                AttackSurface::JavaScript,
                "js_emulation_breakpoint",
                Severity::Medium,
                Confidence::Probable,
                "JS emulation breakpoint",
                "Test",
            ),
            Finding::template(
                AttackSurface::StreamsAndFilters,
                "decoder_risk_present",
                Severity::High,
                Confidence::Strong,
                "Decoder risk present",
                "Test",
            ),
        ];

        escalate_declared_filter_invalid_with_context(&mut findings);

        let finding = findings
            .iter()
            .find(|finding| finding.kind == "declared_filter_invalid")
            .expect("declared_filter_invalid finding should exist");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.confidence, Confidence::Certain);
        assert_eq!(
            finding.meta.get("triage.escalation_reason"),
            Some(&"paired_with_js_runtime_anomaly_and_decoder_pressure".to_string())
        );
    }

    #[test]
    fn context_recalibration_escalates_filter_anomalies_with_runtime_context() {
        let mut findings = vec![
            Finding::template(
                AttackSurface::StreamsAndFilters,
                "filter_chain_unusual",
                Severity::Medium,
                Confidence::Probable,
                "Filter chain unusual",
                "Test",
            ),
            Finding::template(
                AttackSurface::JavaScript,
                "js_runtime_error",
                Severity::Medium,
                Confidence::Probable,
                "JS runtime error",
                "Test",
            ),
        ];

        recalibrate_findings_with_context(&mut findings);

        let filter_finding = findings
            .iter()
            .find(|finding| finding.kind == "filter_chain_unusual")
            .expect("filter_chain_unusual should be present");
        assert_eq!(filter_finding.severity, Severity::High);
        assert_eq!(filter_finding.confidence, Confidence::Strong);
        assert_eq!(
            filter_finding.meta.get("triage.context_reasons"),
            Some(&"filter_runtime_anomaly_cooccurrence".to_string())
        );
    }

    #[test]
    fn context_recalibration_requires_all_decode_structural_exhaustion_signals() {
        let mut findings = vec![
            Finding::template(
                AttackSurface::StreamsAndFilters,
                "decoder_risk_present",
                Severity::High,
                Confidence::Probable,
                "Decoder risk",
                "Test",
            ),
            Finding::template(
                AttackSurface::FileStructure,
                "pdf.trailer_inconsistent",
                Severity::Medium,
                Confidence::Strong,
                "Trailer inconsistent",
                "Test",
            ),
        ];

        recalibrate_findings_with_context(&mut findings);
        let decoder_without_exhaustion = findings
            .iter()
            .find(|finding| finding.kind == "decoder_risk_present")
            .expect("decoder_risk_present should be present");
        assert_eq!(decoder_without_exhaustion.severity, Severity::High);
        assert_eq!(decoder_without_exhaustion.confidence, Confidence::Probable);
        assert!(!decoder_without_exhaustion.meta.contains_key("triage.context_recalibrated"));

        findings.push(Finding::template(
            AttackSurface::FileStructure,
            "parser_resource_exhaustion",
            Severity::High,
            Confidence::Probable,
            "Resource exhaustion",
            "Test",
        ));
        recalibrate_findings_with_context(&mut findings);
        let decoder_with_exhaustion = findings
            .iter()
            .find(|finding| finding.kind == "decoder_risk_present")
            .expect("decoder_risk_present should be present");
        assert_eq!(decoder_with_exhaustion.severity, Severity::Critical);
        assert_eq!(decoder_with_exhaustion.confidence, Confidence::Strong);
        assert_eq!(
            decoder_with_exhaustion.meta.get("triage.context_reasons"),
            Some(&"decode_structural_exhaustion_chain".to_string())
        );
    }

    #[test]
    fn context_recalibration_escalates_action_chain_with_js_and_launch_context() {
        let mut js_present = Finding::template(
            AttackSurface::JavaScript,
            "js_present",
            Severity::Medium,
            Confidence::Strong,
            "JavaScript present",
            "Test",
        );
        js_present.meta.insert("js.intent.primary".into(), "user_interaction".into());
        let mut findings = vec![
            Finding::template(
                AttackSurface::Actions,
                "action_chain_complex",
                Severity::Medium,
                Confidence::Probable,
                "Action chain",
                "Test",
            ),
            Finding::template(
                AttackSurface::Actions,
                "launch_embedded_file",
                Severity::Medium,
                Confidence::Probable,
                "Launch embedded file",
                "Test",
            ),
            js_present,
        ];

        recalibrate_findings_with_context(&mut findings);

        let chain = findings
            .iter()
            .find(|finding| finding.kind == "action_chain_complex")
            .expect("action_chain_complex should be present");
        assert_eq!(chain.severity, Severity::High);
        assert_eq!(chain.confidence, Confidence::Strong);
        assert_eq!(
            chain.meta.get("triage.context_reasons"),
            Some(&"action_js_launch_chain".to_string())
        );
    }
}

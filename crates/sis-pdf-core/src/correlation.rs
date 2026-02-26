use crate::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use crate::scan::CorrelationOptions;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

/// Produce correlated composite findings based on existing detectors.
pub fn correlate_findings(findings: &[Finding], config: &CorrelationOptions) -> Vec<Finding> {
    correlate_findings_with_event_graph(findings, config, None)
}

pub fn correlate_findings_with_event_graph(
    findings: &[Finding],
    config: &CorrelationOptions,
    event_graph: Option<&crate::event_graph::EventGraph>,
) -> Vec<Finding> {
    if !config.enabled {
        return Vec::new();
    }
    let mut composites = Vec::new();
    composites.extend(correlate_launch_obfuscated_executable(findings, config));
    composites.extend(correlate_action_chain_malicious(findings, config));
    composites.extend(correlate_xfa_data_exfiltration(findings, config));
    composites.extend(correlate_encrypted_payload_delivery(findings, config));
    composites.extend(correlate_obfuscated_payload(findings, config));
    composites.extend(correlate_content_stream_exec_outcome_alignment(
        findings,
        config,
        event_graph,
    ));
    composites.extend(correlate_image_decoder_exploit_chain(findings));
    composites.extend(correlate_font_structure_with_provenance_evasion(findings));
    composites.extend(correlate_image_structure_with_hidden_path(findings));
    composites.extend(correlate_resource_external_with_trigger_surface(findings));
    composites.extend(correlate_decode_amplification_chain(findings));
    composites.extend(correlate_injection_edge_bridges(findings));
    composites.extend(correlate_embedded_relationship_action(findings));
    composites.extend(correlate_graph_evasion_with_execute(findings));
    composites.extend(correlate_richmedia_execute_paths(findings));
    composites.extend(correlate_hidden_layer_action(findings));
    composites
}

fn correlate_launch_obfuscated_executable(
    findings: &[Finding],
    config: &CorrelationOptions,
) -> Vec<Finding> {
    let mut composites = Vec::new();
    if !config.launch_obfuscated_enabled {
        return composites;
    }
    let exe_map: HashMap<String, &Finding> = findings
        .iter()
        .filter(|f| f.kind == "embedded_executable_present")
        .filter_map(|f| get_meta(f, "hash.sha256").map(|hash| (hash.to_string(), f)))
        .collect();

    for launch in findings.iter().filter(|f| f.kind == "launch_embedded_file") {
        if let Some(hash) = get_meta(launch, "launch.embedded_file_hash") {
            if let Some(exe) = exe_map.get(hash) {
                if has_high_entropy(exe, config.high_entropy_threshold) {
                    composites.push(build_composite(CompositeConfig {
                        kind: "launch_obfuscated_executable",
                        title: "Obfuscated embedded executable launch",
                        description: "Launch action targets an embedded executable with high entropy, indicating obfuscated delivery.",
                        surface: AttackSurface::Actions,
                        severity: Severity::Critical,
                        confidence: Confidence::Strong,
                        sources: &[launch, *exe],
                        extra_meta: vec![
                            (
                                "launch.target_path",
                                get_meta(launch, "launch.target_path").map(str::to_string),
                            ),
                            ("embedded.hash", Some(hash.to_string())),
                            (
                                "embedded.entropy",
                                get_meta(exe, "entropy").map(str::to_string),
                            ),
                        ],
                    }));
                }
            }
        }
    }

    composites
}

fn correlate_action_chain_malicious(
    findings: &[Finding],
    config: &CorrelationOptions,
) -> Vec<Finding> {
    let mut composites = Vec::new();
    if !config.action_chain_malicious_enabled {
        return composites;
    }
    let complex = findings.iter().filter(|f| f.kind == "action_chain_complex").collect::<Vec<_>>();
    let automatic =
        findings.iter().filter(|f| f.kind == "action_automatic_trigger").collect::<Vec<_>>();
    let js_candidates = findings
        .iter()
        .filter(|f| {
            let kind = f.kind.to_ascii_lowercase();
            kind.contains("js") || kind.contains("script")
        })
        .collect::<Vec<_>>();

    for chain in complex {
        if !meets_chain_depth(chain, config.action_chain_depth_threshold) {
            continue;
        }
        let related_automatic =
            automatic.iter().filter(|a| shares_object(chain, a)).copied().collect::<Vec<_>>();
        let related_js =
            js_candidates.iter().filter(|js| shares_object(chain, js)).copied().collect::<Vec<_>>();
        if !related_automatic.is_empty() && !related_js.is_empty() {
            let mut sources = vec![chain];
            sources.extend(related_automatic.iter().copied());
            sources.extend(related_js.iter().copied());
            composites.push(build_composite(CompositeConfig {
                kind: "action_chain_malicious",
                title: "Malicious action chain",
                description:
                    "Complex action chain runs automatically and involves JavaScript payloads.",
                surface: AttackSurface::Actions,
                severity: Severity::High,
                confidence: Confidence::Strong,
                sources: &sources,
                extra_meta: vec![
                    ("chain.depth", get_meta(chain, "action.chain_depth").map(str::to_string)),
                    ("chain.trigger", get_meta(chain, "action.trigger").map(str::to_string)),
                    ("js.source_classes", collect_distinct_meta_values(&related_js, "js.source")),
                    (
                        "js.container_paths",
                        collect_distinct_meta_values(&related_js, "js.container_path"),
                    ),
                    (
                        "js.object_ref_chains",
                        collect_distinct_meta_values(&related_js, "js.object_ref_chain"),
                    ),
                ],
            }));
        }
    }

    composites
}

fn correlate_xfa_data_exfiltration(
    findings: &[Finding],
    config: &CorrelationOptions,
) -> Vec<Finding> {
    let mut composites = Vec::new();
    if !config.xfa_data_exfiltration_enabled {
        return composites;
    }
    let submit_urls: Vec<String> = findings
        .iter()
        .filter(|f| f.kind == "xfa_submit")
        .filter_map(|f| {
            get_meta(f, "xfa.submit.url").filter(|url| is_external_url(url)).map(str::to_string)
        })
        .collect();
    let sensitive_fields: Vec<String> = findings
        .iter()
        .filter(|f| f.kind == "xfa_sensitive_field")
        .filter_map(|f| get_meta(f, "xfa.field.name"))
        .map(str::to_string)
        .collect();

    if !submit_urls.is_empty() && sensitive_fields.len() >= config.xfa_sensitive_field_threshold {
        let relevant_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.kind == "xfa_submit" || f.kind == "xfa_sensitive_field")
            .collect();
        composites.push(build_composite(CompositeConfig {
            kind: "xfa_data_exfiltration_risk",
            title: "Potential XFA data exfiltration",
            description:
                "XFA form combines submit actions and sensitive fields targeting external servers.",
            surface: AttackSurface::Forms,
            severity: Severity::High,
            confidence: Confidence::Probable,
            sources: &relevant_findings,
            extra_meta: vec![
                ("xfa.submit_urls", Some(submit_urls.join(","))),
                ("xfa.sensitive_fields", Some(sensitive_fields.join(","))),
            ],
        }));
    }

    composites
}

fn correlate_encrypted_payload_delivery(
    findings: &[Finding],
    config: &CorrelationOptions,
) -> Vec<Finding> {
    let mut composites = Vec::new();
    if !config.encrypted_payload_delivery_enabled {
        return composites;
    }
    let archives =
        findings.iter().filter(|f| f.kind == "embedded_archive_encrypted").collect::<Vec<_>>();
    let targets = findings
        .iter()
        .filter(|f| f.kind == "launch_embedded_file" || f.kind == "swf_embedded")
        .collect::<Vec<_>>();

    for archive in &archives {
        if targets.iter().any(|target| shares_object(archive, target)) || !targets.is_empty() {
            let mut sources: Vec<&Finding> = targets.to_vec();
            sources.push(*archive);
            composites.push(build_composite(CompositeConfig {
                kind: "encrypted_payload_delivery",
                title: "Encrypted payload delivery",
                description:
                    "Encrypted archive delivery links to launch actions or embedded SWF payloads.",
                surface: AttackSurface::EmbeddedFiles,
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                sources: &sources,
                extra_meta: vec![("archive.encrypted", Some("true".into()))],
            }));
        }
    }

    composites
}

fn correlate_obfuscated_payload(findings: &[Finding], config: &CorrelationOptions) -> Vec<Finding> {
    let mut composites = Vec::new();
    if !config.obfuscated_payload_enabled {
        return composites;
    }
    let filters = findings
        .iter()
        .filter(|f| {
            ["filter_chain_unusual", "filter_order_invalid", "filter_combination_unusual"]
                .contains(&f.kind.as_str())
        })
        .collect::<Vec<_>>();
    let entropic = findings.iter().filter(|f| f.kind == "stream_high_entropy").collect::<Vec<_>>();

    for filter in &filters {
        for stream in &entropic {
            if shares_object(filter, stream) {
                composites.push(build_composite(CompositeConfig {
                    kind: "obfuscated_payload",
                    title: "Obfuscated payload detected",
                    description: "Unusual filter chain coincides with a high entropy stream.",
                    surface: AttackSurface::StreamsAndFilters,
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    sources: &[filter, stream],
                    extra_meta: vec![(
                        "filter.violations",
                        get_meta(filter, "violation_type").map(str::to_string),
                    )],
                }));
            }
        }
    }

    composites
}

fn correlate_content_stream_exec_outcome_alignment(
    findings: &[Finding],
    config: &CorrelationOptions,
    event_graph: Option<&crate::event_graph::EventGraph>,
) -> Vec<Finding> {
    if !config.content_stream_exec_alignment_enabled {
        return Vec::new();
    }

    let stream_signals = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "content_stream_anomaly"
                    | "content_stream_gstate_abuse"
                    | "content_stream_marked_evasion"
                    | "content_stream_resource_name_obfuscation"
            )
        })
        .collect::<Vec<_>>();
    if stream_signals.is_empty() {
        return Vec::new();
    }

    let high_risk_outcomes = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "action_remote_target_suspicious"
                    | "launch_embedded_file"
                    | "submitform_present"
                    | "xfa_submit"
                    | "js_suspicious"
                    | "js_obfuscated"
            ) || matches!(get_meta(finding, "chain.stage"), Some("execute" | "egress"))
        })
        .collect::<Vec<_>>();
    if high_risk_outcomes.is_empty() {
        return Vec::new();
    }

    let mut emitted = HashSet::new();
    let mut composites = Vec::new();
    let (stream_nodes_by_finding, outcome_nodes_by_finding) = event_graph
        .map(index_finding_event_nodes)
        .unwrap_or_else(|| (HashMap::new(), HashMap::new()));

    for stream_signal in &stream_signals {
        for outcome in &high_risk_outcomes {
            let mut matched_path = None;
            if let Some(graph) = event_graph {
                if !stream_signal.id.is_empty() && !outcome.id.is_empty() {
                    let stream_nodes =
                        stream_nodes_by_finding.get(&stream_signal.id).cloned().unwrap_or_default();
                    let outcome_nodes =
                        outcome_nodes_by_finding.get(&outcome.id).cloned().unwrap_or_default();
                    for stream_node in &stream_nodes {
                        for outcome_node in &outcome_nodes {
                            if let Some(hops) =
                                shortest_hops_within(graph, stream_node, outcome_node, 3)
                            {
                                matched_path =
                                    Some((stream_node.clone(), outcome_node.clone(), hops));
                                break;
                            }
                        }
                        if matched_path.is_some() {
                            break;
                        }
                    }
                }
            } else if shares_object(stream_signal, outcome) {
                matched_path = Some((
                    get_meta(stream_signal, "event.node_id")
                        .unwrap_or("unknown_event_node")
                        .to_string(),
                    get_meta(outcome, "event.node_id")
                        .unwrap_or("unknown_outcome_node")
                        .to_string(),
                    1usize,
                ));
            }

            let Some((event_node_id, outcome_node_id, hops)) = matched_path else {
                continue;
            };

            let key = format!(
                "{event_node_id}|{outcome_node_id}|{}|{}",
                stream_signal.kind, outcome.kind
            );
            if !emitted.insert(key) {
                continue;
            }

            let mut aligned_ids = vec![stream_signal.id.clone(), outcome.id.clone()];
            aligned_ids.retain(|id| !id.is_empty());
            aligned_ids.sort();
            aligned_ids.dedup();
            composites.push(build_composite(CompositeConfig {
                kind: "content_stream_exec_outcome_alignment",
                title: "Content stream execution aligns with high-risk outcome",
                description:
                    "Content-stream execution anomaly signals align with high-risk execute/egress outcomes over a bounded event-graph path.",
                surface: AttackSurface::FileStructure,
                severity: Severity::High,
                confidence: Confidence::Strong,
                sources: &[stream_signal, outcome],
                extra_meta: vec![
                    ("event.node_id", Some(event_node_id)),
                    ("outcome.node_id", Some(outcome_node_id)),
                    ("path.length", Some(hops.to_string())),
                    (
                        "aligned.finding_ids",
                        if aligned_ids.is_empty() {
                            None
                        } else {
                            Some(aligned_ids.join(","))
                        },
                    ),
                ],
            }));
        }
    }

    composites
}

fn index_finding_event_nodes(
    event_graph: &crate::event_graph::EventGraph,
) -> (HashMap<String, BTreeSet<String>>, HashMap<String, BTreeSet<String>>) {
    use crate::event_graph::{EdgeProvenance, EventNodeKind, EventType};

    let mut stream_nodes_by_finding = HashMap::<String, BTreeSet<String>>::new();
    let mut outcome_nodes_by_finding = HashMap::<String, BTreeSet<String>>::new();

    for edge in &event_graph.edges {
        let EdgeProvenance::Finding { finding_id } = &edge.provenance else {
            continue;
        };
        let candidates = [edge.from.as_str(), edge.to.as_str()];
        for node_id in candidates {
            let Some(node_idx) = event_graph.node_index.get(node_id) else {
                continue;
            };
            let Some(node) = event_graph.nodes.get(*node_idx) else {
                continue;
            };
            match &node.kind {
                EventNodeKind::Event { event_type: EventType::ContentStreamExec, .. } => {
                    stream_nodes_by_finding
                        .entry(finding_id.clone())
                        .or_default()
                        .insert(node_id.to_string());
                }
                EventNodeKind::Outcome { outcome_type, .. }
                    if is_high_risk_outcome(*outcome_type) =>
                {
                    outcome_nodes_by_finding
                        .entry(finding_id.clone())
                        .or_default()
                        .insert(node_id.to_string());
                }
                _ => {}
            }
        }
    }

    (stream_nodes_by_finding, outcome_nodes_by_finding)
}

fn shortest_hops_within(
    event_graph: &crate::event_graph::EventGraph,
    src: &str,
    dst: &str,
    max_hops: usize,
) -> Option<usize> {
    if src == dst {
        return Some(0);
    }
    let mut seen = HashSet::<String>::new();
    let mut queue = VecDeque::<(String, usize)>::new();
    seen.insert(src.to_string());
    queue.push_back((src.to_string(), 0));

    while let Some((node_id, depth)) = queue.pop_front() {
        if depth >= max_hops {
            continue;
        }

        if let Some(outgoing) = event_graph.forward_index.get(&node_id) {
            for edge_idx in outgoing {
                let Some(edge) = event_graph.edges.get(*edge_idx) else {
                    continue;
                };
                if edge.to == dst {
                    return Some(depth + 1);
                }
                if seen.insert(edge.to.clone()) {
                    queue.push_back((edge.to.clone(), depth + 1));
                }
            }
        }
        if let Some(incoming) = event_graph.reverse_index.get(&node_id) {
            for edge_idx in incoming {
                let Some(edge) = event_graph.edges.get(*edge_idx) else {
                    continue;
                };
                if edge.from == dst {
                    return Some(depth + 1);
                }
                if seen.insert(edge.from.clone()) {
                    queue.push_back((edge.from.clone(), depth + 1));
                }
            }
        }
    }

    None
}

fn is_high_risk_outcome(outcome: crate::event_graph::OutcomeType) -> bool {
    matches!(
        outcome,
        crate::event_graph::OutcomeType::CodeExecution
            | crate::event_graph::OutcomeType::NetworkEgress
            | crate::event_graph::OutcomeType::FormSubmission
            | crate::event_graph::OutcomeType::ExternalLaunch
    )
}

fn correlate_image_decoder_exploit_chain(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let jbig2 = findings
        .iter()
        .filter(|finding| finding.kind == "image.zero_click_jbig2")
        .collect::<Vec<_>>();
    let decoder = findings
        .iter()
        .filter(|finding| finding.kind == "decoder_risk_present")
        .collect::<Vec<_>>();
    let exhaustion = findings
        .iter()
        .filter(|finding| finding.kind == "parser_resource_exhaustion")
        .collect::<Vec<_>>();

    if jbig2.is_empty() || decoder.is_empty() || exhaustion.is_empty() {
        return composites;
    }

    let mut sources = Vec::new();
    sources.extend(jbig2.iter().copied());
    sources.extend(decoder.iter().copied());
    sources.extend(exhaustion.iter().copied());

    composites.push(build_composite(CompositeConfig {
        kind: "image_decoder_exploit_chain",
        title: "Image decoder exploit chain indicators",
        description:
            "JBIG2 exploit indicators coincide with decoder risk and parser resource exhaustion.",
        surface: AttackSurface::Images,
        severity: Severity::High,
        confidence: Confidence::Strong,
        sources: &sources,
        extra_meta: vec![
            ("chain.image.zero_click_jbig2_count", Some(jbig2.len().to_string())),
            ("chain.decoder_risk_count", Some(decoder.len().to_string())),
            ("chain.parser_exhaustion_count", Some(exhaustion.len().to_string())),
        ],
    }));

    composites
}

fn correlate_font_structure_with_provenance_evasion(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let structure = findings
        .iter()
        .filter(|finding| finding.kind.starts_with("font.structure_"))
        .collect::<Vec<_>>();
    let provenance = findings
        .iter()
        .filter(|finding| {
            finding.kind == "font.provenance_incremental_override"
                || finding.kind == "resource.provenance_xref_conflict"
        })
        .collect::<Vec<_>>();
    if structure.is_empty() || provenance.is_empty() {
        return composites;
    }
    let mut sources = Vec::new();
    sources.extend(structure.iter().copied());
    sources.extend(provenance.iter().copied());
    composites.push(build_composite(CompositeConfig {
        kind: "composite.font_structure_with_provenance_evasion",
        title: "Font structure and provenance evasion composite",
        description: "Font structure anomalies co-occur with revision/provenance conflict signals.",
        surface: AttackSurface::StreamsAndFilters,
        severity: Severity::High,
        confidence: Confidence::Strong,
        sources: &sources,
        extra_meta: vec![
            ("composite.font_structure_count", Some(structure.len().to_string())),
            ("composite.provenance_count", Some(provenance.len().to_string())),
        ],
    }));
    composites
}

fn correlate_image_structure_with_hidden_path(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let structure = findings
        .iter()
        .filter(|finding| finding.kind.starts_with("image.structure_"))
        .collect::<Vec<_>>();
    let hidden = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "resource.hidden_render_path" | "image.orphaned_but_reachable"
            )
        })
        .collect::<Vec<_>>();
    if structure.is_empty() || hidden.is_empty() {
        return composites;
    }
    let mut sources = Vec::new();
    sources.extend(structure.iter().copied());
    sources.extend(hidden.iter().copied());
    composites.push(build_composite(CompositeConfig {
        kind: "composite.image_structure_with_hidden_path",
        title: "Image structure with hidden render path",
        description:
            "Image structure anomalies coincide with hidden or orphaned render-path indicators.",
        surface: AttackSurface::Images,
        severity: Severity::High,
        confidence: Confidence::Strong,
        sources: &sources,
        extra_meta: vec![
            ("composite.image_structure_count", Some(structure.len().to_string())),
            ("composite.hidden_path_count", Some(hidden.len().to_string())),
        ],
    }));
    composites
}

fn correlate_resource_external_with_trigger_surface(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let external = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "resource.external_reference_high_risk_scheme"
                    | "resource.external_reference_obfuscated"
                    | "passive_credential_leak_risk"
            )
        })
        .collect::<Vec<_>>();
    let triggers = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "action_automatic_trigger"
                    | "open_action_present"
                    | "action_hidden_trigger"
                    | "aa_present"
                    | "aa_event_present"
                    | "passive_render_pipeline_risk_composite"
            )
        })
        .collect::<Vec<_>>();
    if external.is_empty() || triggers.is_empty() {
        return composites;
    }
    let automatic_trigger_count =
        triggers.iter().filter(|finding| trigger_initiation(*finding) == "automatic").count();
    let user_trigger_count =
        triggers.iter().filter(|finding| trigger_initiation(*finding) == "user").count();
    let hidden_trigger_count =
        triggers.iter().filter(|finding| trigger_initiation(*finding) == "hidden").count();
    let unknown_trigger_count = triggers
        .len()
        .saturating_sub(automatic_trigger_count + user_trigger_count + hidden_trigger_count);
    let (severity, confidence, trigger_path) = if automatic_trigger_count > 0 {
        (Severity::High, Confidence::Strong, "automatic_or_hidden")
    } else {
        (Severity::Medium, Confidence::Probable, "user_only")
    };
    let mut sources = Vec::new();
    sources.extend(external.iter().copied());
    sources.extend(triggers.iter().copied());
    let description = if automatic_trigger_count > 0 {
        "High-risk external resource references co-occur with automatic trigger surfaces."
    } else {
        "High-risk external resource references co-occur with user-triggered action surfaces."
    };
    composites.push(build_composite(CompositeConfig {
        kind: "composite.resource_external_with_trigger_surface",
        title: "External resource and trigger surface composite",
        description,
        surface: AttackSurface::Actions,
        severity,
        confidence,
        sources: &sources,
        extra_meta: vec![
            ("composite.external_signal_count", Some(external.len().to_string())),
            ("composite.trigger_signal_count", Some(triggers.len().to_string())),
            ("composite.trigger_path", Some(trigger_path.to_string())),
            ("composite.trigger_automatic_count", Some(automatic_trigger_count.to_string())),
            ("composite.trigger_user_count", Some(user_trigger_count.to_string())),
            ("composite.trigger_hidden_count", Some(hidden_trigger_count.to_string())),
            ("composite.trigger_unknown_count", Some(unknown_trigger_count.to_string())),
        ],
    }));
    composites
}

fn correlate_decode_amplification_chain(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let decode_pressure = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "image.decode_too_large"
                    | "image.pixel_buffer_overflow"
                    | "image.metadata_oversized"
                    | "font_payload_present"
                    | "icc_profile_oversized"
            )
        })
        .collect::<Vec<_>>();
    let provenance = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "image.provenance_incremental_override"
                    | "font.provenance_incremental_override"
                    | "resource.provenance_xref_conflict"
                    | "resource.override_outside_signature_scope"
            )
        })
        .collect::<Vec<_>>();

    if decode_pressure.len() >= 2 {
        composites.push(build_composite(CompositeConfig {
            kind: "composite.decode_amplification_chain",
            title: "Decode amplification chain indicators",
            description:
                "Multiple decode-pressure signals co-occur across image/font/metadata structures.",
            surface: AttackSurface::StreamsAndFilters,
            severity: Severity::High,
            confidence: Confidence::Strong,
            sources: &decode_pressure,
            extra_meta: vec![(
                "composite.decode_pressure_count",
                Some(decode_pressure.len().to_string()),
            )],
        }));
    }

    if !decode_pressure.is_empty() && !provenance.is_empty() {
        let mut sources = Vec::new();
        sources.extend(decode_pressure.iter().copied());
        sources.extend(provenance.iter().copied());
        composites.push(build_composite(CompositeConfig {
            kind: "composite.resource_overrides_with_decoder_pressure",
            title: "Resource override with decoder pressure",
            description:
                "Resource provenance override signals co-occur with decode pressure indicators.",
            surface: AttackSurface::FileStructure,
            severity: Severity::High,
            confidence: Confidence::Probable,
            sources: &sources,
            extra_meta: vec![
                ("composite.decode_pressure_count", Some(decode_pressure.len().to_string())),
                ("composite.provenance_count", Some(provenance.len().to_string())),
            ],
        }));
    }
    composites
}

fn correlate_hidden_layer_action(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let ocg = findings.iter().filter(|finding| finding.kind == "ocg_present").collect::<Vec<_>>();
    if ocg.is_empty() {
        return composites;
    }

    let action = findings.iter().filter(|finding| is_action_finding(finding)).collect::<Vec<_>>();
    if action.is_empty() {
        return composites;
    }

    let mut shared_sources: Vec<&Finding> = Vec::new();
    for ocg_finding in &ocg {
        for action_finding in &action {
            if shares_object(ocg_finding, action_finding) {
                shared_sources.push(*ocg_finding);
                shared_sources.push(*action_finding);
            }
        }
    }

    let (sources, confidence, description) = if shared_sources.is_empty() {
        let mut fallback_sources = Vec::new();
        fallback_sources.extend(ocg.iter().copied());
        fallback_sources.extend(action.iter().copied().take(3));
        (
            fallback_sources,
            Confidence::Probable,
            "Optional content groups and action execution surfaces co-occur; hidden-layer action paths may exist.",
        )
    } else {
        (
            shared_sources,
            Confidence::Strong,
            "Action execution surfaces are co-located with optional-content (OCG/OCProperties) structures, indicating hidden-layer action risk.",
        )
    };

    let shared_count = sources
        .iter()
        .map(|finding| finding.kind.as_str())
        .filter(|kind| *kind == "ocg_present")
        .count();

    composites.push(build_composite(CompositeConfig {
        kind: "hidden_layer_action",
        title: "Hidden-layer action risk",
        description,
        surface: AttackSurface::Actions,
        severity: Severity::High,
        confidence,
        sources: &sources,
        extra_meta: vec![
            ("context.hidden_layer", Some("true".into())),
            ("context.ocg_signal_count", Some(shared_count.to_string())),
        ],
    }));

    composites
}

fn correlate_injection_edge_bridges(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let mut emitted = HashSet::new();

    let html =
        findings.iter().filter(|finding| finding.kind == "form_html_injection").collect::<Vec<_>>();
    let injection = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "form_html_injection" | "pdfjs_form_injection" | "pdfjs_annotation_injection"
            )
        })
        .collect::<Vec<_>>();
    let pdfjs_injection = findings
        .iter()
        .filter(|finding| finding.kind == "pdfjs_form_injection")
        .collect::<Vec<_>>();
    let annotation_injection = findings
        .iter()
        .filter(|finding| finding.kind == "pdfjs_annotation_injection")
        .collect::<Vec<_>>();
    let annotation_action = findings
        .iter()
        .filter(|finding| finding.kind == "annotation_action_chain")
        .collect::<Vec<_>>();
    let annotation_js = findings
        .iter()
        .filter(|finding| {
            finding.kind == "js_present"
                && get_meta(finding, "js.source")
                    .map(|source| source.starts_with("annotation"))
                    .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    let submitform =
        findings.iter().filter(|finding| finding.kind == "submitform_present").collect::<Vec<_>>();
    let suspicious_remote = findings
        .iter()
        .filter(|finding| finding.kind == "action_remote_target_suspicious")
        .collect::<Vec<_>>();
    let pdfjs_eval = findings
        .iter()
        .filter(|finding| finding.kind == "pdfjs_eval_path_risk")
        .collect::<Vec<_>>();
    let scatter = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "scattered_payload_assembly" | "cross_stream_payload_assembly"
            )
        })
        .collect::<Vec<_>>();
    let name_obfuscation = findings
        .iter()
        .filter(|finding| finding.kind == "obfuscated_name_encoding")
        .collect::<Vec<_>>();
    let action = findings.iter().filter(|finding| is_action_finding(finding)).collect::<Vec<_>>();

    for src in &html {
        for dst in &pdfjs_injection {
            if !shares_object_or_form_lineage(src, dst) {
                continue;
            }
            maybe_push_edge_composite(
                &mut composites,
                &mut emitted,
                "form_html_to_pdfjs_form",
                "Form HTML to PDF.js injection bridge",
                "Form HTML injection and PDF.js form injection co-locate, indicating an exploit bridge from input into renderer script handling.",
                Confidence::Strong,
                Severity::High,
                src,
                dst,
            );
        }
    }

    for src in &injection {
        for dst in &submitform {
            if !shares_object(src, dst) {
                continue;
            }
            maybe_push_edge_composite(
                &mut composites,
                &mut emitted,
                "injection_to_submitform",
                "Injection to SubmitForm bridge",
                "Injection indicators co-locate with SubmitForm actions, indicating a possible data egress path.",
                Confidence::Probable,
                Severity::Medium,
                src,
                dst,
            );
        }
    }

    for src in &injection {
        for dst in &suspicious_remote {
            if !shares_object(src, dst) {
                continue;
            }
            maybe_push_edge_composite(
                &mut composites,
                &mut emitted,
                "injection_to_remote_action",
                "Injection to remote action bridge",
                "Injection indicators co-locate with suspicious remote-capable actions, indicating an execution-to-egress exploit path.",
                Confidence::Probable,
                Severity::Medium,
                src,
                dst,
            );
        }
    }

    for src in &annotation_injection {
        for dst in &annotation_action {
            if !shares_object(src, dst) {
                continue;
            }
            maybe_push_edge_composite(
                &mut composites,
                &mut emitted,
                "annotation_injection_to_action",
                "Annotation injection to action bridge",
                "Annotation render-path injection indicators co-locate with annotation action chains, indicating a render-to-execute exploit path.",
                Confidence::Strong,
                Severity::High,
                src,
                dst,
            );
        }
    }

    for src in &annotation_injection {
        for dst in &annotation_js {
            if !shares_object(src, dst) {
                continue;
            }
            maybe_push_edge_composite(
                &mut composites,
                &mut emitted,
                "annotation_injection_to_js",
                "Annotation injection to JavaScript bridge",
                "Annotation render-path injection indicators co-locate with annotation-sourced JavaScript payloads, indicating script execution staging within annotation containers.",
                Confidence::Strong,
                Severity::High,
                src,
                dst,
            );
        }
    }

    for src in &pdfjs_injection {
        for dst in &pdfjs_eval {
            if !shares_object(src, dst) {
                continue;
            }
            maybe_push_edge_composite(
                &mut composites,
                &mut emitted,
                "pdfjs_injection_to_eval_path",
                "PDF.js injection to eval-path bridge",
                "PDF.js form injection indicators co-locate with eval-path risk, strengthening renderer execution concern.",
                Confidence::Strong,
                Severity::High,
                src,
                dst,
            );
        }
    }

    for src in &scatter {
        for dst in &injection {
            if !shares_object(src, dst) {
                continue;
            }
            maybe_push_edge_composite(
                &mut composites,
                &mut emitted,
                "scatter_to_injection",
                "Scattered payload to injection bridge",
                "Scattered payload assembly feeds an injection-capable object, indicating a distributed exploit preparation path.",
                Confidence::Strong,
                Severity::High,
                src,
                dst,
            );
        }
    }

    for src in &name_obfuscation {
        for dst in &action {
            if !shares_object(src, dst) {
                continue;
            }
            maybe_push_edge_composite(
                &mut composites,
                &mut emitted,
                "name_obfuscation_to_action",
                "Name obfuscation to action bridge",
                "Hex-encoded PDF name obfuscation co-locates with action execution surfaces.",
                Confidence::Probable,
                Severity::Medium,
                src,
                dst,
            );
        }
    }

    composites
}

fn correlate_embedded_relationship_action(findings: &[Finding]) -> Vec<Finding> {
    let embedded_mismatch = findings
        .iter()
        .filter(|finding| finding.kind == "embedded_type_mismatch")
        .collect::<Vec<_>>();
    let embedded_actions = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "launch_embedded_file"
                    | "launch_action_present"
                    | "gotor_present"
                    | "gotoe_present"
            )
        })
        .collect::<Vec<_>>();
    let mut composites = Vec::new();
    let mut emitted = HashSet::new();

    for mismatch in &embedded_mismatch {
        for action in &embedded_actions {
            let hash_link = match (
                get_meta(mismatch, "hash.sha256"),
                get_meta(action, "launch.embedded_file_hash"),
            ) {
                (Some(lhs), Some(rhs)) => lhs == rhs,
                _ => false,
            };
            let linked = shares_object(mismatch, action) || hash_link;
            if !linked {
                continue;
            }
            let key = format!(
                "{}|{}|{}",
                mismatch.objects.join(","),
                action.objects.join(","),
                if hash_link { "hash" } else { "object" }
            );
            if !emitted.insert(key) {
                continue;
            }
            let mismatch_axes =
                get_meta(mismatch, "embedded.mismatch_axes").unwrap_or("unknown_axes");
            composites.push(build_composite(CompositeConfig {
                kind: "composite.embedded_relationship_action",
                title: "Embedded relationship action bridge",
                description:
                    "Embedded artefact type mismatch is linked to an executable action surface.",
                surface: AttackSurface::EmbeddedFiles,
                severity: Severity::High,
                confidence: if hash_link { Confidence::Strong } else { Confidence::Probable },
                sources: &[mismatch, action],
                extra_meta: vec![
                    (
                        "composite.link_reason",
                        Some(if hash_link { "hash" } else { "object" }.into()),
                    ),
                    ("embedded.mismatch_axes", Some(mismatch_axes.to_string())),
                    (
                        "exploit.preconditions",
                        Some("embedded_payload_reachable; action_surface_reachable".into()),
                    ),
                    (
                        "exploit.blockers",
                        Some("attachment_policy_restrictions; launch_action_controls".into()),
                    ),
                    (
                        "exploit.outcomes",
                        Some("payload_execution; disguised_attachment_delivery".into()),
                    ),
                ],
            }));
        }
    }

    composites
}

fn correlate_graph_evasion_with_execute(findings: &[Finding]) -> Vec<Finding> {
    let graph_evasion = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "xref_conflict"
                    | "incremental_update_chain"
                    | "object_id_shadowing"
                    | "shadow_object_payload_divergence"
                    | "parse_disagreement"
                    | "xref_phantom_entries"
                    | "structural_evasion_composite"
                    | "object_reference_cycle"
                    | "object_reference_depth_high"
            )
        })
        .collect::<Vec<_>>();
    let execute_surface = findings
        .iter()
        .filter(|finding| {
            is_action_finding(finding)
                || finding.kind == "js_present"
                || matches!(get_meta(finding, "chain.stage"), Some("execute"))
        })
        .collect::<Vec<_>>();
    if graph_evasion.is_empty() || execute_surface.is_empty() {
        return Vec::new();
    }

    let mut sources = Vec::new();
    let mut evasion_kinds = HashSet::new();
    for finding in &graph_evasion {
        sources.push(*finding);
        evasion_kinds.insert(
            get_meta(finding, "graph.evasion_kind")
                .map(str::to_string)
                .unwrap_or_else(|| finding.kind.clone()),
        );
    }
    for finding in execute_surface.iter().take(3) {
        sources.push(*finding);
    }

    let mut evasion_list = evasion_kinds.into_iter().collect::<Vec<_>>();
    evasion_list.sort();
    vec![build_composite(CompositeConfig {
        kind: "composite.graph_evasion_with_execute",
        title: "Graph evasion with execute surface composite",
        description:
            "Structural graph-evasion indicators co-occur with executable surfaces, indicating exploit-delivery hardening.",
        surface: AttackSurface::FileStructure,
        severity: Severity::High,
        confidence: Confidence::Probable,
        sources: &sources,
        extra_meta: vec![
            ("graph.evasion_kinds", Some(evasion_list.join(","))),
            ("graph.evasion_count", Some(graph_evasion.len().to_string())),
            ("execute.surface_count", Some(execute_surface.len().to_string())),
            ("exploit.preconditions", Some("graph_evasion_path_present; execute_surface_reachable".into())),
            ("exploit.blockers", Some("strict_graph_validation; action_policy_restrictions".into())),
            ("exploit.outcomes", Some("evasion_assisted_execution; analysis_bypass".into())),
        ],
    })]
}

fn correlate_richmedia_execute_paths(findings: &[Finding]) -> Vec<Finding> {
    let richmedia = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind.as_str(),
                "richmedia_present"
                    | "3d_present"
                    | "sound_movie_present"
                    | "swf_embedded"
                    | "swf_actionscript_detected"
                    | "richmedia_3d_structure_anomaly"
                    | "richmedia_3d_decoder_risk"
            )
        })
        .collect::<Vec<_>>();
    if richmedia.is_empty() {
        return Vec::new();
    }
    let execute = findings
        .iter()
        .filter(|finding| {
            is_action_finding(finding)
                || finding.kind == "js_present"
                || matches!(get_meta(finding, "chain.stage"), Some("execute" | "egress"))
        })
        .collect::<Vec<_>>();
    if execute.is_empty() {
        return Vec::new();
    }

    let mut composites = Vec::new();
    let mut emitted = HashSet::new();
    for src in &richmedia {
        for dst in &execute {
            let shared = shared_objects(src, dst);
            if shared.is_empty() {
                continue;
            }
            let edge_key = format!("{}|{}|{}", src.kind, dst.kind, shared.join(","));
            if !emitted.insert(edge_key) {
                continue;
            }
            let mut preconditions = "viewer_supports_media_runtime".to_string();
            if let Some(precondition) = get_meta(src, "renderer.precondition") {
                preconditions.push(';');
                preconditions.push_str(precondition);
            }
            let outcomes = if matches!(get_meta(dst, "chain.stage"), Some("egress")) {
                "media_triggered_egress; external_fetch_or_submission"
            } else {
                "media_triggered_execution"
            };
            composites.push(build_composite(CompositeConfig {
                kind: "composite.richmedia_execute_path",
                title: "Rich media execute-path bridge",
                description:
                    "Rich media/3D surfaces co-locate with execute or egress findings, indicating a viewer-dependent exploit path.",
                surface: AttackSurface::RichMedia3D,
                severity: if outcomes.contains("egress") {
                    Severity::High
                } else {
                    Severity::Medium
                },
                confidence: Confidence::Probable,
                sources: &[src, dst],
                extra_meta: vec![
                    ("edge.from", Some(src.kind.clone())),
                    ("edge.to", Some(dst.kind.clone())),
                    ("edge.shared_objects", Some(shared.join(","))),
                    ("exploit.preconditions", Some(preconditions)),
                    (
                        "exploit.blockers",
                        Some("viewer_feature_disabled; media_runtime_sandboxing".into()),
                    ),
                    ("exploit.outcomes", Some(outcomes.into())),
                ],
            }));
        }
    }
    composites
}

struct CompositeConfig<'a> {
    kind: &'static str,
    title: &'static str,
    description: &'static str,
    surface: AttackSurface,
    severity: Severity,
    confidence: Confidence,
    sources: &'a [&'a Finding],
    extra_meta: Vec<(&'static str, Option<String>)>,
}

fn build_composite(config: CompositeConfig<'_>) -> Finding {
    let CompositeConfig {
        kind,
        title,
        description,
        surface,
        severity,
        confidence,
        sources,
        extra_meta,
    } = config;
    let mut objects = Vec::new();
    let mut evidence = Vec::new();
    let mut meta = HashMap::new();

    for source in sources {
        objects.extend(source.objects.clone());
        evidence.extend(source.evidence.clone());
    }

    meta.insert("is_composite".into(), "true".into());
    meta.insert("composite.pattern".into(), kind.into());
    meta.insert(
        "composite.sources".into(),
        sources.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>().join(","),
    );

    for (key, value) in extra_meta {
        if let Some(value) = value {
            meta.insert(key.into(), value);
        }
    }

    Finding {
        id: String::new(),
        surface,
        kind: kind.into(),
        severity,
        confidence,
        title: title.into(),
        description: description.into(),
        objects: unique_values(objects),
        evidence,
        remediation: Some("Review correlated findings and take appropriate response.".into()),
        meta,
        yara: None,
        positions: Vec::new(),
        impact: Impact::Unknown,
        action_type: None,
        action_target: None,
        action_initiation: None,
    }
}

fn is_action_finding(finding: &Finding) -> bool {
    finding.kind.starts_with("action_")
        || finding.meta.contains_key("action.s")
        || matches!(
            finding.kind.as_str(),
            "submitform_present"
                | "launch_action_present"
                | "gotor_present"
                | "gotoe_present"
                | "uri_action_present"
                | "launch_embedded_file"
        )
}

fn shares_object_or_form_lineage(a: &Finding, b: &Finding) -> bool {
    if shares_object(a, b) {
        return true;
    }
    let a_field = get_meta(a, "field.name");
    let b_field = get_meta(b, "field.name");
    matches!((a_field, b_field), (Some(left), Some(right)) if left == right)
}

fn shared_objects(a: &Finding, b: &Finding) -> Vec<String> {
    a.objects
        .iter()
        .filter(|obj| b.objects.contains(*obj))
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
}

fn maybe_push_edge_composite(
    composites: &mut Vec<Finding>,
    emitted: &mut HashSet<String>,
    edge_reason: &'static str,
    title: &'static str,
    description: &'static str,
    edge_confidence: Confidence,
    severity: Severity,
    source: &Finding,
    target: &Finding,
) {
    let shared = shared_objects(source, target);
    let edge_key = format!("{edge_reason}|{}|{}|{}", source.kind, target.kind, shared.join(","));
    if !emitted.insert(edge_key) {
        return;
    }

    let (preconditions, blockers, outcomes) = edge_exploit_context(edge_reason);
    let chain_confidence =
        compose_chain_confidence(edge_confidence, source.confidence, target.confidence);
    let chain_severity = compose_chain_severity(edge_reason, source, target);

    let mut extra_meta = vec![
        ("edge.reason", Some(edge_reason.to_string())),
        ("edge.confidence", Some(format!("{edge_confidence:?}"))),
        ("edge.from", Some(source.kind.clone())),
        ("edge.to", Some(target.kind.clone())),
        ("exploit.preconditions", Some(preconditions.to_string())),
        ("exploit.blockers", Some(blockers.to_string())),
        ("exploit.outcomes", Some(outcomes.to_string())),
        ("chain.confidence", Some(format!("{chain_confidence:?}"))),
        ("chain.severity", Some(format!("{chain_severity:?}"))),
    ];
    if !shared.is_empty() {
        extra_meta.push(("edge.shared_objects", Some(shared.join(","))));
    }
    if let Some(stage) = get_meta(source, "chain.stage") {
        extra_meta.push(("edge.stage.from", Some(stage.to_string())));
    }
    if let Some(stage) = get_meta(target, "chain.stage") {
        extra_meta.push(("edge.stage.to", Some(stage.to_string())));
    }
    if let Some(initiation) = action_initiation(source) {
        extra_meta.push(("edge.initiation.from", Some(initiation.to_string())));
    }
    if let Some(initiation) = action_initiation(target) {
        extra_meta.push(("edge.initiation.to", Some(initiation.to_string())));
    }
    if let Some(source_class) = get_meta(source, "js.source") {
        extra_meta.push(("edge.js.source.from", Some(source_class.to_string())));
    }
    if let Some(source_class) = get_meta(target, "js.source") {
        extra_meta.push(("edge.js.source.to", Some(source_class.to_string())));
    }
    if let Some(container_path) = get_meta(source, "js.container_path") {
        extra_meta.push(("edge.js.container_path.from", Some(container_path.to_string())));
    }
    if let Some(container_path) = get_meta(target, "js.container_path") {
        extra_meta.push(("edge.js.container_path.to", Some(container_path.to_string())));
    }

    composites.push(build_composite(CompositeConfig {
        kind: "composite.injection_edge_bridge",
        title,
        description,
        surface: AttackSurface::Forms,
        severity,
        confidence: edge_confidence,
        sources: &[source, target],
        extra_meta,
    }));
}

fn edge_exploit_context(edge_reason: &str) -> (&'static str, &'static str, &'static str) {
    match edge_reason {
        "form_html_to_pdfjs_form" => (
            "viewer=pdfjs; form_value_render_path=enabled",
            "viewer_input_sanitisation; javascript_disabled",
            "dom_injection; script_staging",
        ),
        "injection_to_submitform" => (
            "submitform_action_enabled; form_payload_reachable",
            "network_egress_controls; action_policy_restrictions",
            "data_exfiltration",
        ),
        "injection_to_remote_action" => (
            "remote_action_target_reachable; script_or_render_payload_reachable",
            "network_egress_controls; action_policy_restrictions",
            "data_exfiltration; remote_content_retrieval",
        ),
        "annotation_injection_to_action" => (
            "annotation_render_path_reachable; annotation_action_chain_reachable",
            "annotation_action_restrictions; renderer_input_sanitisation",
            "script_execution; action_execution",
        ),
        "annotation_injection_to_js" => (
            "annotation_render_path_reachable; annotation_js_payload_reachable",
            "annotation_payload_sanitisation; javascript_disabled",
            "script_execution; payload_staging",
        ),
        "pdfjs_injection_to_eval_path" => (
            "pdfjs_eval_path_reachable",
            "eval_path_hardening; renderer_sandbox_restrictions",
            "script_execution",
        ),
        "scatter_to_injection" => (
            "fragment_assembly_path_reachable; decode_chain_success",
            "fragment_validation; decode_limits",
            "payload_staging; render_path_injection",
        ),
        "name_obfuscation_to_action" => (
            "name_token_obfuscation_present; action_path_reachable",
            "strict_name_validation; action_restrictions",
            "evasion_assisted_action_execution",
        ),
        _ => ("unknown", "unknown", "unknown"),
    }
}

fn compose_chain_confidence(
    edge_confidence: Confidence,
    source_confidence: Confidence,
    target_confidence: Confidence,
) -> Confidence {
    let min_score = [
        confidence_score(edge_confidence),
        confidence_score(source_confidence),
        confidence_score(target_confidence),
    ]
    .into_iter()
    .min()
    .unwrap_or(1);
    confidence_from_score(min_score)
}

fn confidence_score(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Certain => 6,
        Confidence::Strong => 5,
        Confidence::Probable => 4,
        Confidence::Tentative => 3,
        Confidence::Weak => 2,
        Confidence::Heuristic => 1,
    }
}

fn confidence_from_score(score: u8) -> Confidence {
    match score {
        6 => Confidence::Certain,
        5 => Confidence::Strong,
        4 => Confidence::Probable,
        3 => Confidence::Tentative,
        2 => Confidence::Weak,
        _ => Confidence::Heuristic,
    }
}

fn compose_chain_severity(edge_reason: &str, source: &Finding, target: &Finding) -> Severity {
    let source_stage = get_meta(source, "chain.stage");
    let target_stage = get_meta(target, "chain.stage");
    let has_execute =
        matches!(source_stage, Some("execute")) || matches!(target_stage, Some("execute"));
    let has_egress =
        matches!(source_stage, Some("egress")) || matches!(target_stage, Some("egress"));

    if has_execute && has_egress {
        return Severity::High;
    }
    if edge_reason == "scatter_to_injection" {
        return Severity::Medium;
    }
    Severity::Medium
}

fn unique_values(mut values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values.retain(|v| seen.insert(v.clone()));
    values
}

fn get_meta<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
    finding.meta.get(key).map(String::as_str)
}

fn collect_distinct_meta_values(findings: &[&Finding], key: &str) -> Option<String> {
    let mut values = findings
        .iter()
        .filter_map(|finding| get_meta(finding, key))
        .map(str::to_string)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    if values.is_empty() {
        None
    } else {
        Some(values.join(","))
    }
}

fn action_initiation<'a>(finding: &'a Finding) -> Option<&'a str> {
    get_meta(finding, "action.initiation").or_else(|| get_meta(finding, "action.trigger_type"))
}

fn trigger_initiation(finding: &Finding) -> &str {
    if let Some(initiation) = action_initiation(finding) {
        return initiation;
    }
    match finding.kind.as_str() {
        "action_automatic_trigger" | "open_action_present" => "automatic",
        "action_hidden_trigger" => "hidden",
        "aa_event_present" => "user",
        "aa_present" => "unknown",
        _ => "unknown",
    }
}

fn parse_float(value: Option<&str>) -> Option<f64> {
    value.and_then(|v| v.parse::<f64>().ok())
}

fn has_high_entropy(finding: &Finding, threshold: f64) -> bool {
    parse_float(get_meta(finding, "entropy")).map(|entropy| entropy >= threshold).unwrap_or(false)
}

fn shares_object(a: &Finding, b: &Finding) -> bool {
    a.objects.iter().any(|obj| b.objects.contains(obj))
}

fn meets_chain_depth(finding: &Finding, threshold: usize) -> bool {
    get_meta(finding, "action.chain_depth")
        .and_then(|value| value.parse::<usize>().ok())
        .map(|depth| depth >= threshold)
        .unwrap_or(false)
}

fn is_external_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return false;
    }
    !(lower.contains("localhost")
        || lower.contains("127.0.0.1")
        || lower.contains("::1")
        || lower.contains("intranet")
        || lower.contains("internal"))
}

#[cfg(test)]
mod tests {
    use super::{correlate_findings, correlate_findings_with_event_graph};
    use crate::event_graph::{
        EdgeProvenance, EventEdge, EventEdgeKind, EventGraph, EventNode, EventNodeKind, EventType,
        OutcomeType, TriggerClass,
    };
    use crate::model::{AttackSurface, Confidence, Finding, Impact, Severity};
    use crate::scan::CorrelationOptions;
    use std::collections::HashMap;

    fn finding(kind: &str, object: &str) -> Finding {
        Finding {
            id: String::new(),
            surface: AttackSurface::Actions,
            kind: kind.to_string(),
            severity: Severity::Low,
            confidence: Confidence::Probable,
            title: kind.to_string(),
            description: kind.to_string(),
            objects: vec![object.to_string()],
            evidence: Vec::new(),
            remediation: None,
            positions: Vec::new(),
            meta: HashMap::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            impact: Impact::Unknown,
        }
    }

    #[test]
    fn correlation_emits_font_structure_provenance_composite() {
        let findings = vec![
            finding("font.structure_subtype_mismatch", "10 0 obj"),
            finding("font.provenance_incremental_override", "10 0 obj"),
        ];
        let composites = correlate_findings(&findings, &CorrelationOptions::default());
        assert!(composites
            .iter()
            .any(|f| { f.kind == "composite.font_structure_with_provenance_evasion" }));
    }

    #[test]
    fn correlation_emits_image_structure_hidden_path_composite() {
        let findings = vec![
            finding("image.structure_mask_inconsistent", "11 0 obj"),
            finding("resource.hidden_render_path", "11 0 obj"),
        ];
        let composites = correlate_findings(&findings, &CorrelationOptions::default());
        assert!(composites
            .iter()
            .any(|f| { f.kind == "composite.image_structure_with_hidden_path" }));
    }

    #[test]
    fn correlation_emits_content_stream_exec_outcome_alignment() {
        let findings = vec![
            finding("content_stream_gstate_abuse", "20 0 obj"),
            finding("launch_embedded_file", "20 0 obj"),
        ];
        let composites = correlate_findings(&findings, &CorrelationOptions::default());
        assert!(composites.iter().any(|f| f.kind == "content_stream_exec_outcome_alignment"));
    }

    #[test]
    fn correlation_skips_content_stream_alignment_without_outcome() {
        let findings = vec![
            finding("content_stream_marked_evasion", "21 0 obj"),
            finding("resource.declared_but_unused", "21 0 obj"),
        ];
        let composites = correlate_findings(&findings, &CorrelationOptions::default());
        assert!(composites.iter().all(|f| f.kind != "content_stream_exec_outcome_alignment"));
    }

    fn build_event_graph(nodes: Vec<EventNode>, edges: Vec<EventEdge>) -> EventGraph {
        let mut node_index = HashMap::new();
        for (idx, node) in nodes.iter().enumerate() {
            node_index.insert(node.id.clone(), idx);
        }
        let mut forward_index = HashMap::new();
        let mut reverse_index = HashMap::new();
        for (idx, edge) in edges.iter().enumerate() {
            forward_index.entry(edge.from.clone()).or_insert_with(Vec::new).push(idx);
            reverse_index.entry(edge.to.clone()).or_insert_with(Vec::new).push(idx);
        }
        EventGraph {
            schema_version: "1.0",
            nodes,
            edges,
            node_index,
            forward_index,
            reverse_index,
            truncation: None,
        }
    }

    #[test]
    fn correlation_uses_event_graph_path_length_for_stream_alignment() {
        let mut stream = finding("content_stream_gstate_abuse", "30 0 obj");
        stream.id = "finding-stream".into();
        let mut outcome = finding("launch_embedded_file", "31 0 obj");
        outcome.id = "finding-outcome".into();
        let findings = vec![stream.clone(), outcome.clone()];

        let graph = build_event_graph(
            vec![
                EventNode {
                    id: "ev:stream".into(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Event {
                        event_type: EventType::ContentStreamExec,
                        trigger: TriggerClass::Automatic,
                        label: "stream exec".into(),
                        source_obj: Some((30, 0)),
                    },
                },
                EventNode {
                    id: "obj:30:0".into(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Object {
                        obj: 30,
                        gen: 0,
                        obj_type: Some("Stream".into()),
                    },
                },
                EventNode {
                    id: "out:launch".into(),
                    mitre_techniques: Vec::new(),
                    kind: EventNodeKind::Outcome {
                        outcome_type: OutcomeType::ExternalLaunch,
                        label: "launch".into(),
                        target: None,
                        source_obj: Some((31, 0)),
                        evidence: Vec::new(),
                        confidence_source: None,
                        confidence_score: None,
                        severity_hint: None,
                    },
                },
            ],
            vec![
                EventEdge {
                    from: "ev:stream".into(),
                    to: "obj:30:0".into(),
                    kind: EventEdgeKind::Executes,
                    provenance: EdgeProvenance::Finding { finding_id: "finding-stream".into() },
                    metadata: None,
                },
                EventEdge {
                    from: "obj:30:0".into(),
                    to: "out:launch".into(),
                    kind: EventEdgeKind::References,
                    provenance: EdgeProvenance::Heuristic,
                    metadata: None,
                },
                EventEdge {
                    from: "ev:stream".into(),
                    to: "out:launch".into(),
                    kind: EventEdgeKind::ProducesOutcome,
                    provenance: EdgeProvenance::Finding { finding_id: "finding-outcome".into() },
                    metadata: None,
                },
            ],
        );

        let composites = correlate_findings_with_event_graph(
            &findings,
            &CorrelationOptions::default(),
            Some(&graph),
        );
        let composite = composites
            .iter()
            .find(|f| f.kind == "content_stream_exec_outcome_alignment")
            .expect("expected alignment composite");
        assert_eq!(composite.meta.get("event.node_id"), Some(&"ev:stream".to_string()));
        assert_eq!(composite.meta.get("outcome.node_id"), Some(&"out:launch".to_string()));
        assert_eq!(composite.meta.get("path.length"), Some(&"1".to_string()));
    }
}

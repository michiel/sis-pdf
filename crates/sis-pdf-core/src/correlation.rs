use crate::model::{AttackSurface, Confidence, Finding, Severity};
use crate::scan::CorrelationOptions;
use std::collections::{HashMap, HashSet};

/// Produce correlated composite findings based on existing detectors.
pub fn correlate_findings(findings: &[Finding], config: &CorrelationOptions) -> Vec<Finding> {
    if !config.enabled {
        return Vec::new();
    }
    let mut composites = Vec::new();
    composites.extend(correlate_launch_obfuscated_executable(findings, config));
    composites.extend(correlate_action_chain_malicious(findings, config));
    composites.extend(correlate_xfa_data_exfiltration(findings, config));
    composites.extend(correlate_encrypted_payload_delivery(findings, config));
    composites.extend(correlate_obfuscated_payload(findings, config));
    composites.extend(correlate_image_decoder_exploit_chain(findings));
    composites.extend(correlate_font_structure_with_provenance_evasion(findings));
    composites.extend(correlate_image_structure_with_hidden_path(findings));
    composites.extend(correlate_resource_external_with_trigger_surface(findings));
    composites.extend(correlate_decode_amplification_chain(findings));
    composites.extend(correlate_injection_edge_bridges(findings));
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
        if automatic.iter().any(|a| shares_object(chain, a))
            && js_candidates.iter().any(|js| shares_object(chain, js))
        {
            composites.push(build_composite(CompositeConfig {
                kind: "action_chain_malicious",
                title: "Malicious action chain",
                description:
                    "Complex action chain runs automatically and involves JavaScript payloads.",
                surface: AttackSurface::Actions,
                severity: Severity::High,
                confidence: Confidence::Strong,
                sources: &[chain],
                extra_meta: vec![
                    ("chain.depth", get_meta(chain, "action.chain_depth").map(str::to_string)),
                    ("chain.trigger", get_meta(chain, "action.trigger").map(str::to_string)),
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
                "action_automatic_trigger" | "passive_render_pipeline_risk_composite"
            )
        })
        .collect::<Vec<_>>();
    if external.is_empty() || triggers.is_empty() {
        return composites;
    }
    let mut sources = Vec::new();
    sources.extend(external.iter().copied());
    sources.extend(triggers.iter().copied());
    composites.push(build_composite(CompositeConfig {
        kind: "composite.resource_external_with_trigger_surface",
        title: "External resource and trigger surface composite",
        description:
            "High-risk external resource references co-occur with automatic trigger surfaces.",
        surface: AttackSurface::Actions,
        severity: Severity::High,
        confidence: Confidence::Strong,
        sources: &sources,
        extra_meta: vec![
            ("composite.external_signal_count", Some(external.len().to_string())),
            ("composite.trigger_signal_count", Some(triggers.len().to_string())),
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

fn correlate_injection_edge_bridges(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let mut emitted = HashSet::new();

    let html =
        findings.iter().filter(|finding| finding.kind == "form_html_injection").collect::<Vec<_>>();
    let injection = findings
        .iter()
        .filter(|finding| {
            matches!(finding.kind.as_str(), "form_html_injection" | "pdfjs_form_injection")
        })
        .collect::<Vec<_>>();
    let pdfjs_injection = findings
        .iter()
        .filter(|finding| finding.kind == "pdfjs_form_injection")
        .collect::<Vec<_>>();
    let submitform =
        findings.iter().filter(|finding| finding.kind == "submitform_present").collect::<Vec<_>>();
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
        position: None,
        positions: Vec::new(),
        impact: None,
        reader_impacts: Vec::new(),
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

    let mut extra_meta = vec![
        ("edge.reason", Some(edge_reason.to_string())),
        ("edge.confidence", Some(format!("{edge_confidence:?}"))),
        ("edge.from", Some(source.kind.clone())),
        ("edge.to", Some(target.kind.clone())),
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

fn unique_values(mut values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values.retain(|v| seen.insert(v.clone()));
    values
}

fn get_meta<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
    finding.meta.get(key).map(String::as_str)
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
    use super::correlate_findings;
    use crate::model::{AttackSurface, Confidence, Finding, Severity};
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
            position: None,
            positions: Vec::new(),
            meta: HashMap::new(),
            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            impact: None,
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
}

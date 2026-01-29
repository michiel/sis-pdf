use crate::model::{AttackSurface, Confidence, Finding, Severity};
use std::collections::{HashMap, HashSet};

const HIGH_ENTROPY_THRESHOLD: f64 = 7.5;

/// Produce correlated composite findings based on existing detectors.
pub fn correlate_findings(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    composites.extend(correlate_launch_obfuscated_executable(findings));
    composites.extend(correlate_action_chain_malicious(findings));
    composites.extend(correlate_xfa_data_exfiltration(findings));
    composites.extend(correlate_encrypted_payload_delivery(findings));
    composites.extend(correlate_obfuscated_payload(findings));
    composites
}

fn correlate_launch_obfuscated_executable(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let exe_map: HashMap<String, &Finding> = findings
        .iter()
        .filter(|f| f.kind == "embedded_executable_present")
        .filter_map(|f| get_meta(f, "hash.sha256").map(|hash| (hash.to_string(), f)))
        .collect();

    for launch in findings.iter().filter(|f| f.kind == "launch_embedded_file") {
        if let Some(hash) = get_meta(launch, "launch.embedded_file_hash") {
            if let Some(exe) = exe_map.get(hash) {
                if has_high_entropy(exe) {
                    composites.push(build_composite(
                        "launch_obfuscated_executable",
                        "Obfuscated embedded executable launch",
                        "Launch action targets an embedded executable with high entropy, indicating obfuscated delivery.",
                        AttackSurface::Actions,
                        Severity::Critical,
                        Confidence::Strong,
                        &[launch, *exe],
                        vec![
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
                    ));
                }
            }
        }
    }

    composites
}

fn correlate_action_chain_malicious(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let complex = findings
        .iter()
        .filter(|f| f.kind == "action_chain_complex")
        .collect::<Vec<_>>();
    let automatic = findings
        .iter()
        .filter(|f| f.kind == "action_automatic_trigger")
        .collect::<Vec<_>>();
    let js_candidates = findings
        .iter()
        .filter(|f| {
            let kind = f.kind.to_ascii_lowercase();
            kind.contains("js") || kind.contains("script")
        })
        .collect::<Vec<_>>();

    for chain in complex {
        if automatic.iter().any(|a| shares_object(chain, a))
            && js_candidates.iter().any(|js| shares_object(chain, js))
        {
            composites.push(build_composite(
                "action_chain_malicious",
                "Malicious action chain",
                "Complex action chain runs automatically and involves JavaScript payloads.",
                AttackSurface::Actions,
                Severity::High,
                Confidence::Strong,
                &[chain],
                vec![
                    (
                        "chain.depth",
                        get_meta(chain, "action.chain_depth").map(str::to_string),
                    ),
                    (
                        "chain.trigger",
                        get_meta(chain, "action.trigger").map(str::to_string),
                    ),
                ],
            ));
        }
    }

    composites
}

fn correlate_xfa_data_exfiltration(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let submit_urls: Vec<String> = findings
        .iter()
        .filter(|f| f.kind == "xfa_submit")
        .filter_map(|f| {
            get_meta(f, "xfa.submit.url")
                .filter(|url| is_external_url(url))
                .map(str::to_string)
        })
        .collect();
    let sensitive_fields: Vec<String> = findings
        .iter()
        .filter(|f| f.kind == "xfa_sensitive_field")
        .filter_map(|f| get_meta(f, "xfa.field.name"))
        .map(str::to_string)
        .collect();

    if !submit_urls.is_empty() && !sensitive_fields.is_empty() {
        composites.push(build_composite(
            "xfa_data_exfiltration_risk",
            "Potential XFA data exfiltration",
            "XFA form combines submit actions and sensitive fields targeting external servers.",
            AttackSurface::Forms,
            Severity::High,
            Confidence::Probable,
            &findings
                .iter()
                .filter(|f| f.kind == "xfa_submit" || f.kind == "xfa_sensitive_field")
                .collect::<Vec<_>>(),
            vec![
                ("xfa.submit_urls", Some(submit_urls.join(","))),
                ("xfa.sensitive_fields", Some(sensitive_fields.join(","))),
            ],
        ));
    }

    composites
}

fn correlate_encrypted_payload_delivery(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let archives = findings
        .iter()
        .filter(|f| f.kind == "embedded_archive_encrypted")
        .collect::<Vec<_>>();
    let targets = findings
        .iter()
        .filter(|f| f.kind == "launch_embedded_file" || f.kind == "swf_embedded")
        .collect::<Vec<_>>();

    for archive in &archives {
        if targets.iter().any(|target| shares_object(archive, target)) || !targets.is_empty() {
            let mut sources: Vec<&Finding> = targets.iter().copied().collect();
            sources.push(*archive);
            composites.push(build_composite(
                "encrypted_payload_delivery",
                "Encrypted payload delivery",
                "Encrypted archive delivery links to launch actions or embedded SWF payloads.",
                AttackSurface::EmbeddedFiles,
                Severity::Medium,
                Confidence::Probable,
                &sources,
                vec![("archive.encrypted", Some("true".into()))],
            ));
        }
    }

    composites
}

fn correlate_obfuscated_payload(findings: &[Finding]) -> Vec<Finding> {
    let mut composites = Vec::new();
    let filters = findings
        .iter()
        .filter(|f| {
            [
                "filter_chain_unusual",
                "filter_order_invalid",
                "filter_combination_unusual",
            ]
            .contains(&f.kind.as_str())
        })
        .collect::<Vec<_>>();
    let entropic = findings
        .iter()
        .filter(|f| f.kind == "stream_high_entropy")
        .collect::<Vec<_>>();

    for filter in &filters {
        for stream in &entropic {
            if shares_object(filter, stream) {
                composites.push(build_composite(
                    "obfuscated_payload",
                    "Obfuscated payload detected",
                    "Unusual filter chain coincides with a high entropy stream.",
                    AttackSurface::StreamsAndFilters,
                    Severity::Medium,
                    Confidence::Probable,
                    &[filter, stream],
                    vec![(
                        "filter.violations",
                        get_meta(filter, "violation_type").map(str::to_string),
                    )],
                ));
            }
        }
    }

    composites
}

fn build_composite(
    kind: &'static str,
    title: &'static str,
    description: &'static str,
    surface: AttackSurface,
    severity: Severity,
    confidence: Confidence,
    sources: &[&Finding],
    extra_meta: Vec<(&'static str, Option<String>)>,
) -> Finding {
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
        sources
            .iter()
            .map(|f| f.kind.as_str())
            .collect::<Vec<_>>()
            .join(","),
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
    }
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

fn has_high_entropy(finding: &Finding) -> bool {
    parse_float(get_meta(finding, "entropy"))
        .map(|entropy| entropy >= HIGH_ENTROPY_THRESHOLD)
        .unwrap_or(false)
}

fn shares_object(a: &Finding, b: &Finding) -> bool {
    a.objects.iter().any(|obj| b.objects.contains(obj))
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

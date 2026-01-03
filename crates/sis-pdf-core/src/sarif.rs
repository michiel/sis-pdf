use crate::model::{EvidenceSource, Finding, Severity};

pub fn to_sarif(report: &crate::report::Report, input_path: Option<&str>) -> serde_json::Value {
    let mut rules = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for f in &report.findings {
        if seen.insert(f.kind.clone()) {
            rules.push(serde_json::json!({
                "id": f.kind,
                "name": f.title,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.description },
                "helpUri": format!("https://example.invalid/sis-pdf/rules/{}", f.kind),
                "defaultConfiguration": {
                    "level": match f.severity {
                        Severity::Critical | Severity::High => "error",
                        Severity::Medium => "warning",
                        _ => "note",
                    }
                },
                "properties": {
                    "surface": format!("{:?}", f.surface),
                    "confidence": format!("{:?}", f.confidence),
                    "tags": [format!("{:?}", f.surface), f.kind],
                }
            }));
        }
    }
    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            };
            let locations = sarif_locations(f, input_path);
            serde_json::json!({
                "ruleId": f.kind,
                "level": level,
                "message": { "text": f.title },
                "locations": locations,
                "fingerprints": {
                    "sis-pdf": f.id
                },
                "properties": {
                    "confidence": format!("{:?}", f.confidence),
                    "objects": f.objects,
                    "surface": format!("{:?}", f.surface),
                    "impact": f.meta.get("impact").cloned().unwrap_or_else(|| crate::report::impact_for_finding(f)),
                    "meta": f.meta,
                    "yara": f.yara.as_ref().map(|y| {
                        serde_json::json!({
                            "rule_name": y.rule_name,
                            "tags": y.tags,
                            "strings": y.strings,
                            "namespace": y.namespace
                        })
                    }),
                    "evidence": f.evidence.iter().map(|ev| {
                        serde_json::json!({
                            "source": format!("{:?}", ev.source),
                            "offset": ev.offset,
                            "length": ev.length,
                            "origin": ev.origin.map(|o| serde_json::json!({"start": o.start, "end": o.end})),
                            "note": ev.note
                        })
                    }).collect::<Vec<_>>(),
                }
            })
        })
        .collect();

    let artifacts = input_path.map(|p| {
        serde_json::json!([{
            "location": { "uri": p },
            "roles": ["analysisTarget"]
        }])
    });
    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sis-pdf",
                    "rules": rules
                }
            },
            "artifacts": artifacts,
            "invocations": [{
                "executionSuccessful": true,
                "properties": {
                    "input_path": input_path
                }
            }],
            "results": results
        }]
    })
}

pub fn sarif_rule_count(report: &crate::report::Report) -> usize {
    let mut seen = std::collections::HashSet::new();
    for f in &report.findings {
        seen.insert(f.kind.clone());
    }
    seen.len()
}

fn sarif_locations(f: &Finding, input_path: Option<&str>) -> Vec<serde_json::Value> {
    let uri = input_path.unwrap_or("input");
    let mut out = Vec::new();
    for ev in &f.evidence {
        match ev.source {
            EvidenceSource::File => {
                out.push(serde_json::json!({
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": {
                            "byteOffset": ev.offset,
                            "byteLength": ev.length
                        }
                    },
                    "properties": {
                        "source": "File",
                        "note": ev.note,
                    }
                }));
            }
            EvidenceSource::Decoded => {
                if let Some(origin) = ev.origin {
                    out.push(serde_json::json!({
                        "physicalLocation": {
                            "artifactLocation": { "uri": uri },
                            "region": {
                                "byteOffset": origin.start,
                                "byteLength": (origin.end - origin.start) as u64
                            }
                        },
                        "properties": {
                            "source": "Decoded",
                            "decoded_offset": ev.offset,
                            "decoded_length": ev.length,
                            "note": ev.note,
                        }
                    }));
                }
            }
        }
    }
    out
}

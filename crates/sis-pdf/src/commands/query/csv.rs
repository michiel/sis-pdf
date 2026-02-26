use sis_pdf_core::model::Finding;
use std::collections::BTreeMap;

fn csv_escape(input: &str) -> String {
    if input.contains(',') || input.contains('"') || input.contains('\n') || input.contains('\r') {
        format!("\"{}\"", input.replace('"', "\"\""))
    } else {
        input.to_string()
    }
}

pub fn findings_to_csv_rows(findings: &[Finding]) -> Vec<String> {
    let mut rows = Vec::with_capacity(findings.len() + 1);
    rows.push(
        "id,kind,severity,impact,confidence,surface,title,description,objects,evidence_count,remediation,meta_json".to_string(),
    );
    for finding in findings {
        let mut meta_sorted = BTreeMap::new();
        for (key, value) in &finding.meta {
            meta_sorted.insert(key.clone(), value.clone());
        }
        let meta_json = serde_json::to_string(&meta_sorted).unwrap_or_else(|_| "{}".to_string());
        let object_refs = finding.objects.join("|");
        let remediation = finding.remediation.clone().unwrap_or_default();
        let fields = [
            csv_escape(&finding.id),
            csv_escape(&finding.kind),
            csv_escape(&format!("{:?}", finding.severity)),
            csv_escape(&format!("{:?}", finding.impact)),
            csv_escape(&format!("{:?}", finding.confidence)),
            csv_escape(&format!("{:?}", finding.surface)),
            csv_escape(&finding.title),
            csv_escape(&finding.description),
            csv_escape(&object_refs),
            finding.evidence.len().to_string(),
            csv_escape(&remediation),
            csv_escape(&meta_json),
        ];
        rows.push(fields.join(","));
    }
    rows
}

pub fn events_to_csv_rows(events: &[serde_json::Value]) -> Vec<String> {
    let mut rows = Vec::with_capacity(events.len() + 1);
    rows.push(
        "node_id,event_type,level,trigger,source_object,linked_finding_count,linked_finding_ids"
            .to_string(),
    );
    for event in events {
        let node_id = event.get("node_id").and_then(|v| v.as_str()).unwrap_or_default();
        let event_type = event.get("event_type").and_then(|v| v.as_str()).unwrap_or_default();
        let level = event.get("level").and_then(|v| v.as_str()).unwrap_or_default();
        let trigger = event.get("trigger").and_then(|v| v.as_str()).unwrap_or_default();
        let source_object = event.get("source_object").and_then(|v| v.as_str()).unwrap_or_default();
        let linked_ids = event
            .get("linked_finding_ids")
            .and_then(|v| v.as_array())
            .map(|items| {
                items.iter().filter_map(|entry| entry.as_str()).collect::<Vec<_>>().join("|")
            })
            .unwrap_or_default();
        let linked_count = event
            .get("linked_finding_ids")
            .and_then(|v| v.as_array())
            .map(|items| items.len())
            .unwrap_or(0);
        let fields = [
            csv_escape(node_id),
            csv_escape(event_type),
            csv_escape(level),
            csv_escape(trigger),
            csv_escape(source_object),
            linked_count.to_string(),
            csv_escape(&linked_ids),
        ];
        rows.push(fields.join(","));
    }
    rows
}

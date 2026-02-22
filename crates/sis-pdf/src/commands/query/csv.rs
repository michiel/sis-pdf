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
            csv_escape(&finding.impact.map(|value| format!("{:?}", value)).unwrap_or_default()),
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

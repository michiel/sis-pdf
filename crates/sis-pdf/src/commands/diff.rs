use anyhow::{anyhow, Result};
use serde::Serialize;
use sis_pdf_core::model::{Confidence, Finding, Severity};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffOutputFormat {
    Text,
    Json,
}

impl DiffOutputFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(anyhow!("unsupported diff format '{other}' (expected text or json)")),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ChangedFinding {
    pub kind: String,
    pub objects: Vec<String>,
    pub baseline: FindingDeltaSide,
    pub comparison: FindingDeltaSide,
}

#[derive(Debug, Serialize)]
pub struct FindingDeltaSide {
    pub severity: Severity,
    pub confidence: Confidence,
}

#[derive(Debug, Serialize)]
pub struct DiffResult {
    pub new_findings: Vec<Finding>,
    pub removed_findings: Vec<Finding>,
    pub changed_findings: Vec<ChangedFinding>,
}

pub fn run_diff(
    baseline_path: &Path,
    comparison_path: &Path,
    format: DiffOutputFormat,
) -> Result<bool> {
    let baseline = load_findings_from_jsonl(baseline_path)?;
    let comparison = load_findings_from_jsonl(comparison_path)?;
    let result = diff_findings(&baseline, &comparison);

    match format {
        DiffOutputFormat::Text => print_text(&result),
        DiffOutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
    }

    let has_new_high_or_critical = result
        .new_findings
        .iter()
        .any(|finding| matches!(finding.severity, Severity::High | Severity::Critical));
    Ok(has_new_high_or_critical)
}

fn print_text(result: &DiffResult) {
    for finding in &result.new_findings {
        println!(
            "+ NEW   [{:?}/{:?}]   {} ({})",
            finding.severity,
            finding.confidence,
            finding.kind,
            finding.objects.join(", ")
        );
    }
    for finding in &result.removed_findings {
        println!(
            "- GONE  [{:?}/{:?}]   {} ({})",
            finding.severity,
            finding.confidence,
            finding.kind,
            finding.objects.join(", ")
        );
    }
    for changed in &result.changed_findings {
        println!(
            "~ CHANGED {} {:?}/{:?} -> {:?}/{:?}",
            changed.kind,
            changed.baseline.severity,
            changed.baseline.confidence,
            changed.comparison.severity,
            changed.comparison.confidence
        );
    }
}

fn load_findings_from_jsonl(path: &Path) -> Result<Vec<Finding>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut findings = Vec::new();
    for (line_no, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
            anyhow!("invalid JSON at {}:{}: {}", path.display(), line_no + 1, err)
        })?;
        if value.get("findings").is_some() {
            let report: sis_pdf_core::report::Report =
                serde_json::from_value(value).map_err(|err| {
                    anyhow!("invalid report payload at {}:{}: {}", path.display(), line_no + 1, err)
                })?;
            findings.extend(report.findings);
        } else {
            let finding: Finding = serde_json::from_value(value).map_err(|err| {
                anyhow!("invalid finding payload at {}:{}: {}", path.display(), line_no + 1, err)
            })?;
            findings.push(finding);
        }
    }
    Ok(findings)
}

fn diff_findings(baseline: &[Finding], comparison: &[Finding]) -> DiffResult {
    let baseline_map = findings_by_fingerprint(baseline);
    let comparison_map = findings_by_fingerprint(comparison);
    let baseline_keys: HashSet<String> = baseline_map.keys().cloned().collect();
    let comparison_keys: HashSet<String> = comparison_map.keys().cloned().collect();

    let mut new_findings = Vec::new();
    let mut removed_findings = Vec::new();
    let mut changed_findings = Vec::new();

    for key in comparison_keys.difference(&baseline_keys) {
        if let Some(finding) = comparison_map.get(key) {
            new_findings.push(finding.clone());
        }
    }
    for key in baseline_keys.difference(&comparison_keys) {
        if let Some(finding) = baseline_map.get(key) {
            removed_findings.push(finding.clone());
        }
    }
    for key in baseline_keys.intersection(&comparison_keys) {
        let Some(before) = baseline_map.get(key) else {
            continue;
        };
        let Some(after) = comparison_map.get(key) else {
            continue;
        };
        if before.severity != after.severity || before.confidence != after.confidence {
            changed_findings.push(ChangedFinding {
                kind: after.kind.clone(),
                objects: canonical_objects(after),
                baseline: FindingDeltaSide {
                    severity: before.severity,
                    confidence: before.confidence,
                },
                comparison: FindingDeltaSide {
                    severity: after.severity,
                    confidence: after.confidence,
                },
            });
        }
    }

    sort_findings(&mut new_findings);
    sort_findings(&mut removed_findings);
    changed_findings.sort_by(|left, right| left.kind.cmp(&right.kind));

    DiffResult { new_findings, removed_findings, changed_findings }
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| canonical_objects(left).cmp(&canonical_objects(right)))
    });
}

fn findings_by_fingerprint(findings: &[Finding]) -> BTreeMap<String, Finding> {
    let mut map: BTreeMap<String, Finding> = BTreeMap::new();
    for finding in findings {
        let fingerprint = finding_fingerprint(finding);
        match map.get(&fingerprint) {
            Some(existing) => {
                if finding.confidence < existing.confidence
                    || (finding.confidence == existing.confidence && finding.kind < existing.kind)
                {
                    map.insert(fingerprint, finding.clone());
                }
            }
            None => {
                map.insert(fingerprint, finding.clone());
            }
        }
    }
    map
}

fn finding_fingerprint(finding: &Finding) -> String {
    let objects = canonical_objects(finding).join("|");
    let mut stable_meta = Vec::new();
    for key in ["chain.stage", "action_type", "action_target", "edge.reason"] {
        if let Some(value) = finding.meta.get(key).or_else(|| match key {
            "action_type" => finding.action_type.as_ref(),
            "action_target" => finding.action_target.as_ref(),
            _ => None,
        }) {
            stable_meta.push(format!("{key}={value}"));
        }
    }
    stable_meta.sort();
    let anchor = finding.evidence.first().map(|span| span.offset).unwrap_or(0);
    format!("{}::{}::{}::{}", finding.kind, objects, stable_meta.join(";"), anchor)
}

fn canonical_objects(finding: &Finding) -> Vec<String> {
    let mut objects = finding.objects.clone();
    objects.sort();
    objects.dedup();
    objects
}

#[cfg(test)]
mod tests {
    use super::*;
    use sis_pdf_core::model::{AttackSurface, FindingBuilder};

    fn finding(
        kind: &str,
        objects: &[&str],
        severity: Severity,
        confidence: Confidence,
    ) -> Finding {
        FindingBuilder::template(AttackSurface::Actions, kind, severity, confidence, kind, kind)
            .objects(objects.iter().map(|value| (*value).to_string()).collect::<Vec<_>>())
            .build()
    }

    #[test]
    fn diff_detects_new_removed_and_changed_findings() {
        let baseline = vec![
            finding("a", &["1 0 obj"], Severity::Low, Confidence::Strong),
            finding("b", &["2 0 obj"], Severity::Medium, Confidence::Probable),
        ];
        let comparison = vec![
            finding("a", &["1 0 obj"], Severity::High, Confidence::Strong),
            finding("c", &["3 0 obj"], Severity::Critical, Confidence::Certain),
        ];
        let result = diff_findings(&baseline, &comparison);
        assert_eq!(result.new_findings.len(), 1);
        assert_eq!(result.removed_findings.len(), 1);
        assert_eq!(result.changed_findings.len(), 1);
        assert_eq!(result.new_findings[0].kind, "c");
        assert_eq!(result.removed_findings[0].kind, "b");
        assert_eq!(result.changed_findings[0].kind, "a");
    }
}

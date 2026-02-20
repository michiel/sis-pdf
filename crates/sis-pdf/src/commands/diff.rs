use anyhow::{anyhow, Result};
use serde::Serialize;
use sis_pdf_core::model::{Confidence, Finding, Severity};
use std::collections::HashMap;
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

    let mut new_findings = Vec::new();
    let mut removed_findings = Vec::new();
    let mut changed_findings = Vec::new();

    for (key, comparison_idx) in &comparison_map {
        let Some(baseline_idx) = baseline_map.get(key) else {
            new_findings.push(comparison[*comparison_idx].clone());
            continue;
        };
        let before = &baseline[*baseline_idx];
        let after = &comparison[*comparison_idx];
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
    for (key, baseline_idx) in &baseline_map {
        if !comparison_map.contains_key(key) {
            removed_findings.push(baseline[*baseline_idx].clone());
        }
    }

    sort_findings(&mut new_findings);
    sort_findings(&mut removed_findings);
    changed_findings.sort_by(|left, right| {
        left.kind.cmp(&right.kind).then_with(|| left.objects.cmp(&right.objects))
    });

    DiffResult { new_findings, removed_findings, changed_findings }
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by_cached_key(|finding| (finding.kind.clone(), canonical_objects(finding)));
}

fn findings_by_fingerprint(findings: &[Finding]) -> HashMap<String, usize> {
    let mut map: HashMap<String, usize> = HashMap::with_capacity(findings.len());
    for (idx, finding) in findings.iter().enumerate() {
        let fingerprint = finding_fingerprint(finding);
        match map.get(&fingerprint).copied() {
            Some(existing_idx) => {
                let existing = &findings[existing_idx];
                if finding.confidence < existing.confidence
                    || (finding.confidence == existing.confidence && finding.kind < existing.kind)
                {
                    map.insert(fingerprint, idx);
                }
            }
            None => {
                map.insert(fingerprint, idx);
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
            let normalised = if key == "action_target" {
                normalise_action_target(value)
            } else {
                value.to_string()
            };
            stable_meta.push(format!("{key}={normalised}"));
        }
    }
    stable_meta.sort();
    let anchor = finding.evidence.first().map(|span| span.offset).unwrap_or(0);
    format!("{}::{}::{}::{}", finding.kind, objects, stable_meta.join(";"), anchor)
}

fn normalise_action_target(raw: &str) -> String {
    let without_fragment = raw.split('#').next().unwrap_or(raw);
    without_fragment.split('?').next().unwrap_or(without_fragment).to_string()
}

fn canonical_objects(finding: &Finding) -> Vec<String> {
    if finding.objects.len() <= 1 {
        return finding.objects.clone();
    }
    let mut objects = finding.objects.clone();
    objects.sort();
    objects.dedup();
    objects
}

#[cfg(test)]
mod tests {
    use super::*;
    use sis_pdf_core::model::{AttackSurface, FindingBuilder};
    use std::fs;
    use std::time::{Duration, Instant};

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

    #[test]
    fn fingerprint_normalises_action_target_query_and_fragment() {
        let mut baseline = finding(
            "action_remote_target_suspicious",
            &["10 0 obj"],
            Severity::Medium,
            Confidence::Strong,
        );
        baseline.action_target =
            Some("https://example.test/collect?sid=abc123&ts=1#fragment".to_string());
        let mut comparison = finding(
            "action_remote_target_suspicious",
            &["10 0 obj"],
            Severity::Medium,
            Confidence::Strong,
        );
        comparison.action_target = Some("https://example.test/collect?sid=def456".to_string());

        assert_eq!(finding_fingerprint(&baseline), finding_fingerprint(&comparison));
    }

    #[test]
    fn diff_large_input_budget() {
        let mut baseline = Vec::with_capacity(100_000);
        let mut comparison = Vec::with_capacity(100_000);
        for idx in 0..100_000u32 {
            let object = format!("{} 0 obj", idx + 1);
            baseline.push(finding("bulk_kind", &[&object], Severity::Low, Confidence::Strong));

            let severity = if idx % 10_000 == 0 { Severity::High } else { Severity::Low };
            comparison.push(finding("bulk_kind", &[&object], severity, Confidence::Strong));
        }
        let start = Instant::now();
        let diff = diff_findings(&baseline, &comparison);
        let elapsed = start.elapsed();
        assert!(elapsed <= Duration::from_secs(2), "diff exceeded 2.0s budget: {:?}", elapsed);
        assert_eq!(diff.changed_findings.len(), 10);
        assert!(diff.new_findings.is_empty());
        assert!(diff.removed_findings.is_empty());
        if let Some(rss_bytes) = process_rss_bytes() {
            const MAX_RSS_BYTES: u64 = 300 * 1024 * 1024;
            assert!(
                rss_bytes <= MAX_RSS_BYTES,
                "diff exceeded RSS budget: {} bytes (limit {})",
                rss_bytes,
                MAX_RSS_BYTES
            );
        }
    }

    fn process_rss_bytes() -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            let status = fs::read_to_string("/proc/self/status").ok()?;
            let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
            let kb = line.split_whitespace().nth(1).and_then(|value| value.parse::<u64>().ok())?;
            Some(kb * 1024)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

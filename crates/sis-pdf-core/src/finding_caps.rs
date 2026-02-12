use std::collections::HashMap;

use crate::model::Finding;

pub const DEFAULT_FINDINGS_PER_KIND_CAP: usize = 25;
pub const DEFAULT_AGGREGATE_SAMPLE_LIMIT: usize = 8;

#[derive(Default)]
struct SuppressedSamples {
    objects: Vec<String>,
    positions: Vec<String>,
}

pub fn apply_default_global_kind_cap(findings: &mut Vec<Finding>) {
    apply_global_kind_cap(findings, DEFAULT_FINDINGS_PER_KIND_CAP, DEFAULT_AGGREGATE_SAMPLE_LIMIT);
}

pub fn apply_global_kind_cap(
    findings: &mut Vec<Finding>,
    per_kind_cap: usize,
    sample_limit: usize,
) {
    if findings.is_empty() || per_kind_cap == 0 {
        return;
    }

    let mut totals_by_kind: HashMap<String, usize> = HashMap::new();
    for finding in findings.iter() {
        *totals_by_kind.entry(finding.kind.clone()).or_insert(0) += 1;
    }

    let mut seen_by_kind: HashMap<String, usize> = HashMap::new();
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed_samples: HashMap<String, SuppressedSamples> = HashMap::new();

    for finding in findings.iter() {
        let seen = seen_by_kind.entry(finding.kind.clone()).or_insert(0);
        *seen += 1;
        let keep = *seen <= per_kind_cap;
        kept.push(keep);
        if keep {
            continue;
        }

        let sample = suppressed_samples.entry(finding.kind.clone()).or_default();
        for object in finding.objects.iter().take(sample_limit) {
            if sample.objects.len() >= sample_limit {
                break;
            }
            if !sample.objects.contains(object) {
                sample.objects.push(object.clone());
            }
        }
        if let Some(position) = finding.position.as_deref() {
            if sample.positions.len() < sample_limit
                && !sample.positions.iter().any(|p| p == position)
            {
                sample.positions.push(position.to_string());
            }
        }
    }

    let mut retained = Vec::with_capacity(findings.len());
    for (index, finding) in findings.drain(..).enumerate() {
        if kept.get(index).copied().unwrap_or(false) {
            retained.push(finding);
        }
    }

    let mut first_idx_by_kind: HashMap<String, usize> = HashMap::new();
    for (idx, finding) in retained.iter().enumerate() {
        first_idx_by_kind.entry(finding.kind.clone()).or_insert(idx);
    }

    for (kind, total_count) in totals_by_kind {
        if total_count <= per_kind_cap {
            continue;
        }
        if let Some(first_idx) = first_idx_by_kind.get(&kind).copied() {
            let suppressed_count = total_count.saturating_sub(per_kind_cap);
            let sample = suppressed_samples.remove(&kind).unwrap_or_default();
            let finding = &mut retained[first_idx];
            finding.meta.insert("aggregate.global.enabled".into(), "true".into());
            finding.meta.insert("aggregate.global.kind".into(), kind.clone());
            finding.meta.insert("aggregate.global.total_count".into(), total_count.to_string());
            finding.meta.insert("aggregate.global.retained_count".into(), per_kind_cap.to_string());
            finding
                .meta
                .insert("aggregate.global.suppressed_count".into(), suppressed_count.to_string());
            if !sample.objects.is_empty() {
                finding.meta.insert(
                    "aggregate.global.sample_suppressed_objects".into(),
                    sample.objects.join(", "),
                );
            }
            if !sample.positions.is_empty() {
                finding.meta.insert(
                    "aggregate.global.sample_suppressed_positions".into(),
                    sample.positions.join(", "),
                );
            }
        }
    }

    *findings = retained;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AttackSurface, Confidence, Severity};

    fn test_finding(kind: &str, object: &str, position: Option<&str>) -> Finding {
        let mut finding = Finding::template(
            AttackSurface::FileStructure,
            kind,
            Severity::Low,
            Confidence::Strong,
            "t",
            "d",
        );
        finding.objects = vec![object.to_string()];
        finding.position = position.map(str::to_string);
        finding
    }

    #[test]
    fn global_kind_cap_suppresses_and_annotates() {
        let mut findings = vec![
            test_finding("kind_a", "1 0", Some("objects.1")),
            test_finding("kind_a", "2 0", Some("objects.2")),
            test_finding("kind_a", "3 0", Some("objects.3")),
            test_finding("kind_b", "4 0", Some("objects.4")),
        ];

        apply_global_kind_cap(&mut findings, 2, 4);

        assert_eq!(findings.len(), 3);
        let kind_a = findings.iter().filter(|f| f.kind == "kind_a").collect::<Vec<_>>();
        assert_eq!(kind_a.len(), 2);
        let aggregated = kind_a[0];
        assert_eq!(aggregated.meta.get("aggregate.global.enabled"), Some(&"true".to_string()));
        assert_eq!(aggregated.meta.get("aggregate.global.total_count"), Some(&"3".to_string()));
        assert_eq!(aggregated.meta.get("aggregate.global.retained_count"), Some(&"2".to_string()));
        assert_eq!(
            aggregated.meta.get("aggregate.global.suppressed_count"),
            Some(&"1".to_string())
        );
        assert_eq!(
            aggregated.meta.get("aggregate.global.sample_suppressed_objects"),
            Some(&"3 0".to_string())
        );
    }
}

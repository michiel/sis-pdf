use std::collections::{BTreeMap, BTreeSet};

use crate::model::{Finding, Severity};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatPattern {
    pub id: String,
    pub kinds: Vec<String>,
    pub objects: Vec<String>,
    pub severity: Severity,
    pub summary: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BehaviorSummary {
    pub patterns: Vec<ThreatPattern>,
}

pub fn correlate_findings(findings: &[Finding]) -> BehaviorSummary {
    let mut by_object: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        if f.objects.is_empty() {
            continue;
        }
        for obj in &f.objects {
            by_object.entry(obj.clone()).or_default().push(f);
        }
    }
    let mut patterns = Vec::new();
    for (obj, group) in by_object {
        if group.len() < 2 {
            continue;
        }
        let mut kinds: BTreeSet<String> = BTreeSet::new();
        let mut severity = Severity::Info;
        for f in &group {
            kinds.insert(f.kind.clone());
            severity = max_severity(severity, f.severity);
        }
        let kinds_vec: Vec<String> = kinds.into_iter().collect();
        let summary = format!(
            "{} findings share object {}",
            group.len(),
            obj
        );
        patterns.push(ThreatPattern {
            id: format!("object:{}", obj),
            kinds: kinds_vec,
            objects: vec![obj],
            severity,
            summary,
        });
    }

    let mut by_kind: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_kind.entry(f.kind.clone()).or_default().push(f);
    }
    for (kind, group) in by_kind {
        if group.len() < 3 {
            continue;
        }
        let mut objects: BTreeSet<String> = BTreeSet::new();
        let mut severity = Severity::Info;
        for f in &group {
            for obj in &f.objects {
                objects.insert(obj.clone());
            }
            severity = max_severity(severity, f.severity);
        }
        patterns.push(ThreatPattern {
            id: format!("kind:{}", kind),
            kinds: vec![kind.clone()],
            objects: objects.into_iter().collect(),
            severity,
            summary: format!("{} findings of kind {}", group.len(), kind),
        });
    }

    patterns.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then_with(|| a.id.cmp(&b.id))
    });
    BehaviorSummary { patterns }
}

fn max_severity(a: Severity, b: Severity) -> Severity {
    use Severity::*;
    match (a, b) {
        (Critical, _) | (_, Critical) => Critical,
        (High, _) | (_, High) => High,
        (Medium, _) | (_, Medium) => Medium,
        (Low, _) | (_, Low) => Low,
        _ => Info,
    }
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

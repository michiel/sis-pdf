use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::model::{Confidence, Finding, Severity};
use crate::position;
use crate::report::Report;
use crate::taint::Taint;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ObjectContextIndex {
    by_object: HashMap<(u32, u16), ObjectSecurityContext>,
    kind_set_counts: HashMap<Vec<String>, usize>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObjectSecurityContext {
    pub obj: u32,
    pub gen: u16,
    pub finding_count: usize,
    pub max_severity: Option<Severity>,
    pub max_confidence: Option<Confidence>,
    pub finding_ids: Vec<String>,
    pub severity_histogram: BTreeMap<String, usize>,
    pub tainted: bool,
    pub taint_source: bool,
    pub taint_incoming: Vec<(u32, u16)>,
    pub taint_outgoing: Vec<(u32, u16)>,
    pub taint_reasons: Vec<TaintReasonEntry>,
    pub taint_propagation_unavailable: bool,
    pub chains: Vec<ObjectChainMembership>,
    pub introduced_revision: Option<u32>,
    pub post_cert: bool,
    pub top_evidence_offset: Option<u64>,
    pub top_evidence_length: Option<u32>,
    pub similar_count: usize,
}

impl Default for ObjectSecurityContext {
    fn default() -> Self {
        Self {
            obj: 0,
            gen: 0,
            finding_count: 0,
            max_severity: None,
            max_confidence: None,
            finding_ids: Vec::new(),
            severity_histogram: BTreeMap::new(),
            tainted: false,
            taint_source: false,
            taint_incoming: Vec::new(),
            taint_outgoing: Vec::new(),
            taint_reasons: Vec::new(),
            taint_propagation_unavailable: false,
            chains: Vec::new(),
            introduced_revision: None,
            post_cert: false,
            top_evidence_offset: None,
            top_evidence_length: None,
            similar_count: 0,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaintReasonEntry {
    pub reason: String,
    pub finding_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObjectChainMembership {
    pub chain_index: usize,
    pub chain_id: String,
    pub path: String,
    pub score: f64,
    pub role: ObjectChainRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ObjectChainRole {
    Trigger,
    Action,
    Payload,
    Participant,
    PathNode,
}

impl ObjectContextIndex {
    pub fn iter(&self) -> impl Iterator<Item = (&(u32, u16), &ObjectSecurityContext)> {
        self.by_object.iter()
    }

    pub fn get(&self, obj: u32, gen: u16) -> Option<&ObjectSecurityContext> {
        self.by_object.get(&(obj, gen))
    }

    pub fn kind_set_counts(&self) -> &HashMap<Vec<String>, usize> {
        &self.kind_set_counts
    }
}

pub fn build_object_context_index(report: &Report, taint: &Taint) -> ObjectContextIndex {
    let mut by_object: HashMap<(u32, u16), ObjectSecurityContext> = HashMap::new();
    let mut top_evidence_severity: HashMap<(u32, u16), Severity> = HashMap::new();
    let mut object_kinds: HashMap<(u32, u16), BTreeSet<String>> = HashMap::new();

    for finding in &report.findings {
        for object in &finding.objects {
            let Some(object_ref) = position::parse_obj_ref(object) else {
                continue;
            };
            let context = by_object.entry(object_ref).or_insert_with(|| ObjectSecurityContext {
                obj: object_ref.0,
                gen: object_ref.1,
                ..ObjectSecurityContext::default()
            });
            context.finding_count += 1;
            *context.severity_histogram.entry(format!("{:?}", finding.severity)).or_insert(0) += 1;
            context.finding_ids.push(finding.id.clone());

            match context.max_severity {
                Some(current) if current >= finding.severity => {}
                _ => context.max_severity = Some(finding.severity),
            }
            match context.max_confidence {
                Some(current) if current >= finding.confidence => {}
                _ => context.max_confidence = Some(finding.confidence),
            }

            object_kinds.entry(object_ref).or_default().insert(finding.kind.clone());

            let should_update_top = match top_evidence_severity.get(&object_ref) {
                Some(current) => finding.severity >= *current,
                None => true,
            };
            if should_update_top {
                if let Some(evidence) = finding.evidence.first() {
                    context.top_evidence_offset = Some(evidence.offset);
                    context.top_evidence_length = Some(evidence.length);
                    top_evidence_severity.insert(object_ref, finding.severity);
                }
            }

            for position in &finding.positions {
                if let Some((rev, pos_obj_ref)) = parse_revision_and_object_from_position(position)
                {
                    if pos_obj_ref == object_ref {
                        context.introduced_revision = match context.introduced_revision {
                            Some(existing) => Some(existing.min(rev)),
                            None => Some(rev),
                        };
                    }
                }
            }
            if let Some(position) = &finding.position {
                if let Some((rev, pos_obj_ref)) = parse_revision_and_object_from_position(position)
                {
                    if pos_obj_ref == object_ref {
                        context.introduced_revision = match context.introduced_revision {
                            Some(existing) => Some(existing.min(rev)),
                            None => Some(rev),
                        };
                    }
                }
            }
        }
    }

    for context in by_object.values_mut() {
        context.finding_ids.sort();
        context.finding_ids.dedup();
    }

    let taint_sources: HashSet<(u32, u16)> = taint.taint_sources.iter().copied().collect();
    for source in &taint_sources {
        let context = by_object.entry(*source).or_insert_with(|| ObjectSecurityContext {
            obj: source.0,
            gen: source.1,
            ..ObjectSecurityContext::default()
        });
        context.tainted = true;
        context.taint_source = true;
    }

    for (from_ref, to_ref) in &taint.taint_propagation {
        let from_context = by_object.entry(*from_ref).or_insert_with(|| ObjectSecurityContext {
            obj: from_ref.0,
            gen: from_ref.1,
            ..ObjectSecurityContext::default()
        });
        from_context.tainted = true;
        from_context.taint_outgoing.push(*to_ref);

        let to_context = by_object.entry(*to_ref).or_insert_with(|| ObjectSecurityContext {
            obj: to_ref.0,
            gen: to_ref.1,
            ..ObjectSecurityContext::default()
        });
        to_context.tainted = true;
        to_context.taint_incoming.push(*from_ref);
    }

    let reason_map = build_taint_reason_map(&report.findings);

    let taint_reasons = taint
        .reasons
        .iter()
        .map(|reason| TaintReasonEntry {
            reason: reason.clone(),
            finding_id: reason_map.get(reason).and_then(|ids| ids.first().cloned()),
        })
        .collect::<Vec<_>>();

    for context in by_object.values_mut() {
        context.taint_incoming.sort_unstable();
        context.taint_incoming.dedup();
        context.taint_outgoing.sort_unstable();
        context.taint_outgoing.dedup();
        if context.tainted || context.taint_source {
            context.taint_reasons = taint_reasons.clone();
            // V3 taint model is authoritative; fallback derivation is removed.
            context.taint_propagation_unavailable = false;
        }
    }

    let finding_by_id: HashMap<&str, &Finding> =
        report.findings.iter().map(|finding| (finding.id.as_str(), finding)).collect();
    let mut memberships_by_object: HashMap<(u32, u16), HashMap<usize, ObjectChainMembership>> =
        HashMap::new();

    for (chain_index, chain) in report.chains.iter().enumerate() {
        for finding_id in &chain.findings {
            let Some(finding) = finding_by_id.get(finding_id.as_str()) else {
                continue;
            };
            let role = role_from_finding(chain.finding_roles.get(finding_id));
            for object in &finding.objects {
                let Some(object_ref) = position::parse_obj_ref(object) else {
                    continue;
                };
                upsert_membership(&mut memberships_by_object, object_ref, chain_index, chain, role);
            }
        }

        for node in &chain.nodes {
            let Some(object_ref) = parse_object_from_position(node) else {
                continue;
            };
            upsert_membership(
                &mut memberships_by_object,
                object_ref,
                chain_index,
                chain,
                ObjectChainRole::PathNode,
            );
        }
    }

    for (object_ref, membership_map) in memberships_by_object {
        let context = by_object.entry(object_ref).or_insert_with(|| ObjectSecurityContext {
            obj: object_ref.0,
            gen: object_ref.1,
            ..ObjectSecurityContext::default()
        });
        let mut memberships = membership_map.into_values().collect::<Vec<_>>();
        memberships.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.chain_index.cmp(&right.chain_index))
        });
        context.chains = memberships;
    }

    let mut kind_set_counts: HashMap<Vec<String>, usize> = HashMap::new();
    let kind_fingerprints = object_kinds
        .into_iter()
        .map(|(object_ref, kinds)| (object_ref, kinds.into_iter().collect::<Vec<_>>()))
        .collect::<Vec<_>>();

    for (_, fingerprint) in &kind_fingerprints {
        *kind_set_counts.entry(fingerprint.clone()).or_insert(0) += 1;
    }

    for (object_ref, fingerprint) in kind_fingerprints {
        let shared = kind_set_counts.get(&fingerprint).copied().unwrap_or(1);
        if let Some(context) = by_object.get_mut(&object_ref) {
            context.similar_count = shared.saturating_sub(1);
        }
    }

    ObjectContextIndex { by_object, kind_set_counts }
}

pub fn get_object_context(index: &ObjectContextIndex, obj: u32, gen: u16) -> ObjectSecurityContext {
    index.get(obj, gen).cloned().unwrap_or(ObjectSecurityContext {
        obj,
        gen,
        ..ObjectSecurityContext::default()
    })
}

pub fn has_context(index: &ObjectContextIndex, obj: u32, gen: u16) -> bool {
    index.get(obj, gen).is_some()
}

fn role_from_finding(role: Option<&String>) -> ObjectChainRole {
    match role.map(String::as_str) {
        Some("trigger") => ObjectChainRole::Trigger,
        Some("action") => ObjectChainRole::Action,
        Some("payload") => ObjectChainRole::Payload,
        _ => ObjectChainRole::Participant,
    }
}

fn role_rank(role: ObjectChainRole) -> u8 {
    match role {
        ObjectChainRole::Trigger => 5,
        ObjectChainRole::Action => 4,
        ObjectChainRole::Payload => 3,
        ObjectChainRole::Participant => 2,
        ObjectChainRole::PathNode => 1,
    }
}

fn upsert_membership(
    memberships_by_object: &mut HashMap<(u32, u16), HashMap<usize, ObjectChainMembership>>,
    object_ref: (u32, u16),
    chain_index: usize,
    chain: &crate::chain::ExploitChain,
    role: ObjectChainRole,
) {
    let membership_map = memberships_by_object.entry(object_ref).or_default();
    match membership_map.get_mut(&chain_index) {
        Some(existing) => {
            if role_rank(role) > role_rank(existing.role) {
                existing.role = role;
            }
        }
        None => {
            membership_map.insert(
                chain_index,
                ObjectChainMembership {
                    chain_index,
                    chain_id: chain.id.clone(),
                    path: chain.path.clone(),
                    score: chain.score,
                    role,
                },
            );
        }
    }
}

fn parse_object_from_position(position: &str) -> Option<(u32, u16)> {
    let (_, tail) = position.rsplit_once('@')?;
    let (obj_part, gen_part) = tail.split_once(':')?;
    let object = parse_leading_u32(obj_part)?;
    let generation = parse_leading_u16(gen_part)?;
    Some((object, generation))
}

fn parse_revision_and_object_from_position(position: &str) -> Option<(u32, (u32, u16))> {
    if !position.starts_with("doc:r") {
        return None;
    }
    let revision_part = position.strip_prefix("doc:r")?;
    let mut revision_chars = String::new();
    for ch in revision_part.chars() {
        if ch.is_ascii_digit() {
            revision_chars.push(ch);
        } else {
            break;
        }
    }
    let revision = revision_chars.parse::<u32>().ok()?;
    let object_ref = parse_object_from_position(position)?;
    Some((revision, object_ref))
}

fn parse_leading_u32(value: &str) -> Option<u32> {
    let digits = value
        .chars()
        .skip_while(|ch| !ch.is_ascii_digit())
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u32>().ok()
}

fn parse_leading_u16(value: &str) -> Option<u16> {
    parse_leading_u32(value).map(|v| v.min(u16::MAX as u32) as u16)
}

fn build_taint_reason_map(findings: &[Finding]) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for finding in findings {
        for reason in taint_reasons_for_finding(finding) {
            map.entry(reason).or_default().push(finding.id.clone());
        }
    }
    for ids in map.values_mut() {
        ids.sort();
        ids.dedup();
    }
    map
}

fn taint_reasons_for_finding(finding: &Finding) -> Vec<String> {
    match finding.kind.as_str() {
        "js_present" => vec![js_taint_reason(finding)],
        "embedded_file_present" => vec!["Embedded file present".into()],
        "decoder_risk_present" => vec!["High-risk decoder present".into()],
        "stream_length_mismatch" => vec!["Stream length mismatch".into()],
        "xref_conflict" => vec!["XRef conflict".into()],
        "image.jbig2_present" | "image.jpx_present" | "image.ccitt_present" => {
            vec!["Risky image decoder present".into()]
        }
        "image.jbig2_malformed"
        | "image.jpx_malformed"
        | "image.jpeg_malformed"
        | "image.ccitt_malformed"
        | "image.decode_failed"
        | "image.xfa_decode_failed" => vec!["Image decode failure observed".into()],
        "image.extreme_dimensions"
        | "image.pixel_count_excessive"
        | "image.suspect_strip_dimensions" => vec!["Suspicious image dimensions".into()],
        _ => Vec::new(),
    }
}

fn js_taint_reason(finding: &Finding) -> String {
    let mut details = Vec::new();
    if finding.meta.get("js.ast_parsed").map(|value| value == "true").unwrap_or(false) {
        details.push("AST");
    }
    if finding.meta.get("js.contains_eval").map(|value| value == "true").unwrap_or(false) {
        details.push("eval");
    }
    if finding.meta.get("js.suspicious_apis").map(|value| value == "true").unwrap_or(false) {
        details.push("suspicious APIs");
    }
    if finding.meta.get("js.obfuscation_suspected").map(|value| value == "true").unwrap_or(false) {
        details.push("obfuscation");
    }
    if details.is_empty() {
        "JavaScript present (no extra signals)".into()
    } else {
        format!("JavaScript present ({})", details.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_object_from_position() {
        assert_eq!(parse_object_from_position("doc:r2/catalog.openaction@9:0"), Some((9, 0)));
        assert_eq!(parse_object_from_position("invalid"), None);
    }

    #[test]
    fn parses_revision_and_object_from_position() {
        assert_eq!(
            parse_revision_and_object_from_position("doc:r3/catalog.openaction@9:0"),
            Some((3, (9, 0)))
        );
    }
}

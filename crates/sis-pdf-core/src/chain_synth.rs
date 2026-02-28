use std::collections::{BTreeSet, HashMap, HashSet};
use tracing::warn;

use crate::chain::{ChainTemplate, ExploitChain};
use crate::chain_render::{compose_chain_narrative, render_path};
use crate::chain_score::score_chain;
use crate::model::{Confidence, Finding};
use crate::position;
use crate::taint::taint_from_findings;

const EXPECTED_CHAIN_STAGES: [&str; 5] = ["input", "decode", "render", "execute", "egress"];

pub fn synthesise_chains(
    findings: &[Finding],
    group_chains: bool,
) -> (Vec<ExploitChain>, Vec<ChainTemplate>) {
    let mut finding_positions: HashMap<String, Vec<String>> = HashMap::new();
    let mut findings_by_id: HashMap<String, &Finding> = HashMap::new();
    for finding in findings {
        if !finding.positions.is_empty() {
            finding_positions.insert(finding.id.clone(), finding.positions.clone());
        }
        findings_by_id.insert(finding.id.clone(), finding);
    }
    let structural_count = findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind.as_str(),
                "xref_conflict"
                    | "incremental_update_chain"
                    | "object_id_shadowing"
                    | "objstm_density_high"
            )
        })
        .count();
    let taint = taint_from_findings(findings);
    let mut chains = Vec::new();
    chains.extend(build_object_chains(
        findings,
        structural_count,
        &taint,
        &finding_positions,
        &findings_by_id,
    ));
    for f in findings {
        let single = [f];
        let roles = assign_chain_roles(&single);
        let trigger = roles.trigger_key.clone();
        let action = roles.action_key.clone();
        let payload = roles.payload_key.clone();
        let mut notes = notes_from_findings(&single, structural_count, &taint);
        apply_role_labels(&mut notes, &roles);
        apply_chain_labels(&mut notes, trigger.as_deref(), action.as_deref(), payload.as_deref());
        let mut chain = ExploitChain {
            id: String::new(),
            label: String::new(),
            severity: String::new(),
            group_id: None,
            group_count: 1,
            group_members: Vec::new(),
            trigger,
            action,
            payload,
            findings: vec![f.id.clone()],
            score: 0.0,
            reasons: Vec::new(),
            path: String::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            confirmed_stages: Vec::new(),
            inferred_stages: Vec::new(),
            chain_completeness: 0.0,
            reader_risk: HashMap::new(),
            narrative: String::new(),
            finding_criticality: HashMap::new(),
            active_mitigations: Vec::new(),
            required_conditions: Vec::new(),
            unmet_conditions: Vec::new(),
            finding_roles: HashMap::new(),
            notes,
        };
        apply_finding_roles(&mut chain, &roles);
        finalize_chain(&mut chain, &finding_positions, &findings_by_id);
        chains.push(chain);
    }

    let chains = merge_singleton_clusters(chains, &findings_by_id);
    let chains = deduplicate_chains(chains);
    let chains = if group_chains {
        group_chains_by_signature(chains, &findings_by_id)
    } else {
        attach_group_metadata(chains)
    };

    let mut templates: HashMap<String, ChainTemplate> = HashMap::new();
    for c in &chains {
        let key = format!(
            "{}|{}|{}",
            c.trigger.as_deref().unwrap_or("-"),
            c.action.as_deref().unwrap_or("-"),
            c.payload.as_deref().unwrap_or("-")
        );
        let entry = templates.entry(key.clone()).or_insert_with(|| ChainTemplate {
            id: template_id(&key),
            trigger: c.trigger.clone(),
            action: c.action.clone(),
            payload: c.payload.clone(),
            instances: Vec::new(),
        });
        entry.instances.push(c.id.clone());
    }

    // Validate that all finding IDs referenced by chains exist in the input.
    let finding_ids: HashSet<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    for chain in &chains {
        for fid in &chain.findings {
            if !finding_ids.contains(fid.as_str()) {
                warn!(
                    chain_id = %chain.id,
                    missing_finding = %fid,
                    "chain references unknown finding id"
                );
            }
        }
    }

    (chains, templates.into_values().collect())
}

fn build_object_chains(
    findings: &[Finding],
    structural_count: usize,
    taint: &crate::taint::Taint,
    finding_positions: &HashMap<String, Vec<String>>,
    findings_by_id: &HashMap<String, &Finding>,
) -> Vec<ExploitChain> {
    let mut by_object: HashMap<String, Vec<&Finding>> = HashMap::new();
    for f in findings {
        for obj in &f.objects {
            if obj.contains("obj") {
                by_object.entry(obj.clone()).or_default().push(f);
            }
        }
    }
    let mut chains = Vec::new();
    for (obj, group) in by_object {
        let mut findings_ids = Vec::new();
        for f in &group {
            findings_ids.push(f.id.clone());
        }
        let roles = assign_chain_roles(&group);
        let trigger = roles.trigger_key.clone();
        let action = roles.action_key.clone();
        let payload = roles.payload_key.clone();
        let categories =
            [trigger.is_some(), action.is_some(), payload.is_some()].iter().filter(|v| **v).count();
        // Require either 2+ role categories (trigger/action/payload) OR 3+ co-located findings.
        // The 3+ co-located case covers structural/payload threats (e.g. polyglot PE droppers)
        // where all signals are on the same object but none qualify as explicit action triggers.
        if categories < 2 && group.len() < 3 {
            continue;
        }
        let mut notes = notes_from_findings(&group, structural_count, taint);
        apply_role_labels(&mut notes, &roles);
        notes.insert("correlation.object".into(), obj.clone());
        if action.is_some() && payload.is_some() {
            notes.insert("correlation.action_payload".into(), "true".into());
        }
        apply_chain_labels(&mut notes, trigger.as_deref(), action.as_deref(), payload.as_deref());
        let mut chain = ExploitChain {
            id: String::new(),
            label: String::new(),
            severity: String::new(),
            group_id: None,
            group_count: 1,
            group_members: Vec::new(),
            trigger,
            action,
            payload,
            findings: findings_ids,
            score: 0.0,
            reasons: Vec::new(),
            path: String::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            confirmed_stages: Vec::new(),
            inferred_stages: Vec::new(),
            chain_completeness: 0.0,
            reader_risk: HashMap::new(),
            narrative: String::new(),
            finding_criticality: HashMap::new(),
            active_mitigations: Vec::new(),
            required_conditions: Vec::new(),
            unmet_conditions: Vec::new(),
            finding_roles: HashMap::new(),
            notes,
        };
        apply_finding_roles(&mut chain, &roles);
        finalize_chain(&mut chain, finding_positions, findings_by_id);
        if !chain_is_noise(&chain, &group) {
            chains.push(chain);
        }
    }
    chains
}

fn chain_is_noise(_chain: &ExploitChain, _group: &[&Finding]) -> bool {
    false
}

fn chain_nodes(
    chain: &ExploitChain,
    finding_positions: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut nodes = Vec::new();
    let mut seen = HashSet::new();
    for finding_id in &chain.findings {
        if let Some(positions) = finding_positions.get(finding_id) {
            for pos in positions {
                if seen.insert(pos.clone()) {
                    nodes.push(pos.clone());
                }
            }
        }
    }
    nodes
}

fn trigger_from_kind(kind: &str) -> Option<String> {
    match kind {
        "open_action_present" | "aa_present" | "aa_event_present" => Some(kind.into()),
        _ => None,
    }
}

fn action_from_kind(kind: &str) -> Option<String> {
    match kind {
        "uri_listing" => Some("uri_content_analysis".into()),
        "launch_action_present"
        | "uri_content_analysis"
        | "submitform_present"
        | "gotor_present"
        | "js_present"
        | "open_action_present"
        | "aa_present"
        | "aa_event_present"
        | "uri_javascript_scheme"
        | "uri_file_scheme"
        | "uri_data_html_scheme"
        | "uri_command_injection" => Some(kind.into()),
        _ => None,
    }
}

fn payload_from_finding(f: &Finding) -> Option<String> {
    if let Some(v) = f.meta.get("payload.type") {
        return Some(v.clone());
    }
    if f.meta.contains_key("stream.filters")
        || f.meta.contains_key("decode.outcome")
        || f.meta.contains_key("decode.mismatch")
    {
        return Some("stream".into());
    }
    match f.kind.as_str() {
        "js_present" => Some("javascript".into()),
        "embedded_file_present" => Some("embedded_file".into()),
        "declared_filter_invalid"
        | "decode_recovery_used"
        | "undeclared_compression_present"
        | "decompression_ratio_suspicious"
        | "embedded_payload_carved" => Some("stream".into()),
        kind if kind.starts_with("image.") => Some("image".into()),
        _ => None,
    }
}

struct ChainRoles<'a> {
    trigger_key: Option<String>,
    action_key: Option<String>,
    payload_key: Option<String>,
    trigger_finding: Option<&'a Finding>,
    action_finding: Option<&'a Finding>,
    payload_finding: Option<&'a Finding>,
}

fn assign_chain_roles<'a>(findings: &'a [&'a Finding]) -> ChainRoles<'a> {
    let mut roles = ChainRoles {
        trigger_key: None,
        action_key: None,
        payload_key: None,
        trigger_finding: None,
        action_finding: None,
        payload_finding: None,
    };
    for f in findings {
        if roles.trigger_key.is_none() {
            if let Some(key) = trigger_from_kind(&f.kind) {
                roles.trigger_key = Some(key.clone());
                roles.trigger_finding = Some(f);
            }
        }
        if roles.action_key.is_none() {
            if let Some(key) = action_from_kind(&f.kind).or_else(|| action_from_meta(f)) {
                roles.action_key = Some(key.clone());
                roles.action_finding = Some(f);
            }
        }
        if roles.payload_key.is_none() {
            if let Some(key) = payload_from_finding(f) {
                roles.payload_key = Some(key.clone());
                roles.payload_finding = Some(f);
            }
        }
    }
    roles
}

// ---------------------------------------------------------------------------
// Stage 2.2: Kind-based singleton cluster merging
// ---------------------------------------------------------------------------

const CLUSTER_KINDS: &[&str] = &[
    "font",
    "image",
    "object_reference_cycle",
    "label_mismatch_stream_type",
    "declared_filter_invalid",
    "objstm",
    "secondary_parser",
    "parser",
    "embedded_payload_carved",
    "uri_content_analysis",
];
const MAX_CLUSTER_MEMBERS: usize = 50;

fn severity_rank(s: &str) -> u8 {
    match s {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    }
}

fn cluster_label_for_prefix(prefix: &str, count: usize) -> String {
    match prefix {
        "font" => format!("Font exploitation signals ({} fonts)", count),
        "image" => format!("Image anomaly cluster ({} images)", count),
        "object_reference_cycle" => format!("Reference cycle cluster ({} cycles)", count),
        "label_mismatch_stream_type" => {
            format!("Stream type mismatch cluster ({} streams)", count)
        }
        "declared_filter_invalid" => format!("Invalid filter cluster ({} streams)", count),
        "embedded_payload_carved" => format!("Embedded payload cluster ({} payloads)", count),
        "uri_content_analysis" => format!("URI analysis cluster ({} URIs)", count),
        _ => format!("{} cluster ({} findings)", prefix, count),
    }
}

fn cluster_context_note(prefix: &str, count: usize) -> &'static str {
    match prefix {
        "font" if count >= 10 => {
            "Pattern consistent with heap spray or font-based exploit targeting."
        }
        "font" => "Multiple font anomalies may indicate exploit preparation.",
        "image" => {
            "Multiple image anomalies may indicate steganographic payload or decoder exploit."
        }
        "object_reference_cycle" => {
            "Cycles in document graph may indicate parser confusion attempts."
        }
        "declared_filter_invalid" => {
            "Invalid filter chains may indicate obfuscation or malformed payload delivery."
        }
        "embedded_payload_carved" => {
            "Multiple carved payloads may indicate polyglot content or multi-stage delivery."
        }
        "uri_content_analysis" => {
            "Multiple URI findings may indicate network egress or phishing redirection chain."
        }
        _ => "",
    }
}

fn cluster_chain_id(prefix: &str, finding_ids: &[String]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prefix.as_bytes());
    for fid in finding_ids {
        hasher.update(fid.as_bytes());
    }
    format!("cluster-{}-{}", prefix, &hasher.finalize().to_hex()[..12])
}

/// Merge singleton chains whose findings share the same kind-prefix into cluster chains.
/// Example: 25 singleton font.ttf_hinting_suspicious chains → 1 cluster chain.
fn merge_singleton_clusters(
    mut chains: Vec<ExploitChain>,
    findings_by_id: &HashMap<String, &Finding>,
) -> Vec<ExploitChain> {
    let (singletons, mut multi): (Vec<_>, Vec<_>) =
        chains.drain(..).partition(|c| c.findings.len() == 1);

    let mut kind_groups: HashMap<String, Vec<ExploitChain>> = HashMap::new();
    let mut unmatched: Vec<ExploitChain> = Vec::new();

    for chain in singletons {
        let fid = &chain.findings[0];
        let kind = findings_by_id
            .get(fid.as_str())
            .map(|f| f.kind.as_str())
            .unwrap_or("");
        let prefix = CLUSTER_KINDS
            .iter()
            .find(|&&p| kind == p || kind.starts_with(&format!("{}.", p)))
            .copied();
        match prefix {
            Some(p) => kind_groups.entry(p.to_string()).or_default().push(chain),
            None => unmatched.push(chain),
        }
    }

    for (prefix, group) in kind_groups {
        if group.len() < 2 {
            unmatched.extend(group);
            continue;
        }
        let (cluster_members, remainder) = if group.len() <= MAX_CLUSTER_MEMBERS {
            (group, vec![])
        } else {
            let mut g = group;
            let remainder = g.split_off(MAX_CLUSTER_MEMBERS);
            (g, remainder)
        };

        let finding_ids: Vec<String> = cluster_members
            .iter()
            .flat_map(|c| c.findings.iter().cloned())
            .collect();
        let count = finding_ids.len();
        let max_score = cluster_members
            .iter()
            .map(|c| c.score)
            .fold(f64::NEG_INFINITY, f64::max);
        let max_severity = cluster_members
            .iter()
            .map(|c| c.severity.as_str())
            .max_by_key(|&s| severity_rank(s))
            .unwrap_or("Low")
            .to_string();

        let cluster_label = cluster_label_for_prefix(&prefix, count);
        let context_note = cluster_context_note(&prefix, count);

        let mut notes = HashMap::new();
        notes.insert("cluster.kind_prefix".into(), prefix.clone());
        notes.insert("cluster.member_count".into(), count.to_string());
        notes.insert("cluster.label".into(), cluster_label.clone());
        if !context_note.is_empty() {
            notes.insert("cluster.context".into(), context_note.into());
        }

        let cluster_id = cluster_chain_id(&prefix, &finding_ids);
        let narrative = format!(
            "{} {} signals detected. {}",
            count,
            prefix,
            context_note
        );

        // Aggregate finding_roles from all merged singleton chains
        let mut merged_finding_roles: HashMap<String, String> = HashMap::new();
        for member in &cluster_members {
            for (fid, role) in &member.finding_roles {
                merged_finding_roles.entry(fid.clone()).or_insert_with(|| role.clone());
            }
        }

        // Propagate the maximum stage completeness from merged singleton members so
        // the cluster chain is not incorrectly marked as 0% complete.
        let max_completeness = cluster_members
            .iter()
            .map(|c| c.chain_completeness)
            .fold(0.0_f64, f64::max);

        // Synthesize sequential edges between consecutive finding IDs (up to 5).
        // These represent co-occurrence within the same cluster pattern.
        let cluster_edges: Vec<String> = finding_ids
            .windows(2)
            .take(5)
            .map(|w| format!("{} -> {}", w[0], w[1]))
            .collect();

        let cluster_chain = ExploitChain {
            id: cluster_id,
            label: cluster_label.clone(),
            severity: max_severity,
            group_id: None,
            group_count: 1,
            group_members: Vec::new(),
            trigger: cluster_members[0].trigger.clone(),
            action: cluster_members[0].action.clone(),
            payload: cluster_members[0].payload.clone(),
            findings: finding_ids,
            score: max_score,
            reasons: vec![format!("Cluster of {} {} findings", count, prefix)],
            path: format!("Cluster: {} ({} findings)", prefix, count),
            nodes: cluster_members
                .iter()
                .flat_map(|c| c.nodes.iter().cloned())
                .collect(),
            edges: cluster_edges,
            confirmed_stages: Vec::new(),
            inferred_stages: Vec::new(),
            chain_completeness: max_completeness,
            reader_risk: HashMap::new(),
            narrative,
            finding_criticality: HashMap::new(),
            active_mitigations: Vec::new(),
            required_conditions: Vec::new(),
            unmet_conditions: Vec::new(),
            finding_roles: merged_finding_roles,
            notes,
        };
        multi.push(cluster_chain);
        unmatched.extend(remainder);
    }

    multi.extend(unmatched);
    multi
}

// ---------------------------------------------------------------------------
// Stage 2.3: Finding deduplication across chains
// ---------------------------------------------------------------------------

/// Remove singleton chains whose sole finding is already claimed by a multi-finding chain.
/// Only singleton chains (1 finding) are removed — multi-finding object chains always survive
/// to preserve role and completeness context for their objects.
/// Remove chains whose findings overlap heavily with higher-priority chains.
/// Priority order: highest finding count first, then highest score.
/// A chain is kept only if it contributes at least 50% new (unclaimed) findings.
/// Single-finding chains that duplicate a finding from a multi-chain are dropped.
fn deduplicate_chains(mut chains: Vec<ExploitChain>) -> Vec<ExploitChain> {
    // Sort: highest finding count first, then highest score
    chains.sort_by(|a, b| {
        b.findings
            .len()
            .cmp(&a.findings.len())
            .then(b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal))
    });

    let mut claimed: HashSet<String> = HashSet::new();
    let mut result: Vec<ExploitChain> = Vec::new();

    for mut chain in chains {
        let total = chain.findings.len();
        let unclaimed: Vec<String> =
            chain.findings.iter().filter(|id| !claimed.contains(id.as_str())).cloned().collect();

        if unclaimed.is_empty() {
            // All findings already claimed — drop this chain
            continue;
        }

        // If more than half the original findings are already claimed, drop the chain.
        // Exception: keep singleton chains that have unique findings.
        let claim_fraction = 1.0 - (unclaimed.len() as f64 / total as f64);
        if claim_fraction > 0.5 && total > 1 {
            continue;
        }

        // Claim unclaimed findings
        for id in &unclaimed {
            claimed.insert(id.clone());
        }

        // Trim already-claimed findings from the chain's finding list
        if unclaimed.len() != total {
            chain.findings = unclaimed;
        }

        result.push(chain);
    }

    result
}

fn chain_id(chain: &ExploitChain) -> String {
    let mut hasher = blake3::Hasher::new();
    if let Some(t) = &chain.trigger {
        hasher.update(t.as_bytes());
    }
    if let Some(a) = &chain.action {
        hasher.update(a.as_bytes());
    }
    if let Some(p) = &chain.payload {
        hasher.update(p.as_bytes());
    }
    for f in &chain.findings {
        hasher.update(f.as_bytes());
    }
    format!("chain-{}", hasher.finalize().to_hex())
}

fn template_id(key: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key.as_bytes());
    format!("template-{}", hasher.finalize().to_hex())
}

/// Synthesize directed edges for a chain based on finding roles and shared objects.
///
/// For chains with trigger/action/payload roles, edges follow the execution order:
///   trigger → action → payload
///
/// As a fallback (no role-based edges), edges are added between findings that share
/// at least one object reference (up to 5 pairs, checked over first 10 findings).
fn synthesize_chain_edges(chain: &mut ExploitChain, findings_by_id: &HashMap<String, &Finding>) {
    if chain.findings.len() < 2 {
        return;
    }
    let mut edges = Vec::new();

    let trigger_id: Option<String> = chain
        .finding_roles
        .iter()
        .find(|(_, r)| r.as_str() == "trigger")
        .map(|(id, _)| id.clone());
    let action_id: Option<String> = chain
        .finding_roles
        .iter()
        .find(|(_, r)| r.as_str() == "action")
        .map(|(id, _)| id.clone());
    let payload_id: Option<String> = chain
        .finding_roles
        .iter()
        .find(|(_, r)| r.as_str() == "payload")
        .map(|(id, _)| id.clone());

    if let (Some(ref t), Some(ref a)) = (&trigger_id, &action_id) {
        edges.push(format!("{} -> {}", t, a));
    }
    if let (Some(ref a), Some(ref p)) = (&action_id, &payload_id) {
        edges.push(format!("{} -> {}", a, p));
    }
    if trigger_id.is_some() && action_id.is_none() {
        if let (Some(ref t), Some(ref p)) = (&trigger_id, &payload_id) {
            edges.push(format!("{} -> {}", t, p));
        }
    }

    // Fallback: object-shared edges when no role-based edges could be synthesized.
    if edges.is_empty() {
        let findings: Vec<_> = chain
            .findings
            .iter()
            .filter_map(|id| findings_by_id.get(id.as_str()).map(|f| (id, f)))
            .take(10)
            .collect();
        'outer: for i in 0..findings.len() {
            for j in (i + 1)..findings.len() {
                let (id_i, f_i) = findings[i];
                let (id_j, f_j) = findings[j];
                if f_i.objects.iter().any(|o| f_j.objects.contains(o)) {
                    edges.push(format!("{} -> {}", id_i, id_j));
                    if edges.len() >= 5 {
                        break 'outer;
                    }
                }
            }
        }
    }

    chain.edges = edges;
}

fn finalize_chain(
    chain: &mut ExploitChain,
    finding_positions: &HashMap<String, Vec<String>>,
    findings_by_id: &HashMap<String, &Finding>,
) {
    chain.path = render_path(chain);
    chain.nodes = chain_nodes(chain, finding_positions);
    let (score, reasons) = score_chain(chain);
    chain.score = score;
    chain.reasons = reasons;
    populate_chain_enrichment(chain, findings_by_id);
    synthesize_chain_edges(chain, findings_by_id);
    annotate_low_completeness(chain);
    chain.id = chain_id(chain);
    chain.label = derive_chain_label(chain, findings_by_id);
    chain.severity = derive_chain_severity(chain.score, findings_by_id, &chain.findings);
}

fn derive_chain_label(chain: &ExploitChain, findings_by_id: &HashMap<String, &Finding>) -> String {
    // Priority 1: cluster label from merge pass
    if let Some(lbl) = chain.notes.get("cluster.label") {
        return lbl.clone();
    }
    // Priority 2: action + payload label from notes
    let action_label = chain.notes.get("action.label").map(|s| s.as_str()).unwrap_or("");
    let payload_label = chain.notes.get("payload.label").map(|s| s.as_str()).unwrap_or("");
    if !action_label.is_empty() && !payload_label.is_empty() {
        return format!("{} \u{2192} {}", action_label, payload_label);
    }
    if !action_label.is_empty() {
        if let Some(trigger) = &chain.trigger {
            return format!("{}:{}", trigger, action_label);
        }
        return action_label.to_string();
    }
    // Priority 3: first finding kind
    chain
        .findings
        .first()
        .and_then(|fid| findings_by_id.get(fid.as_str()))
        .map(|f| f.kind.clone())
        .unwrap_or_else(|| "unknown".into())
}

fn derive_chain_severity(
    score: f64,
    findings_by_id: &HashMap<String, &Finding>,
    finding_ids: &[String],
) -> String {
    // Base severity from score threshold
    let score_severity = if score >= 0.9 {
        "Critical"
    } else if score >= 0.75 {
        "High"
    } else if score >= 0.5 {
        "Medium"
    } else {
        "Low"
    };
    // Escalate to highest finding severity if it exceeds score-derived severity
    use crate::model::Severity;
    fn sev_rank(s: &Severity) -> u8 {
        match s {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }
    fn score_rank(s: &str) -> u8 {
        match s {
            "Critical" => 4,
            "High" => 3,
            "Medium" => 2,
            _ => 1,
        }
    }
    let max_finding_sev = finding_ids
        .iter()
        .filter_map(|fid| findings_by_id.get(fid.as_str()))
        .map(|f| &f.severity)
        .max_by_key(|s| sev_rank(s));
    let max_rank = max_finding_sev.map(sev_rank).unwrap_or(0);
    if max_rank > score_rank(score_severity) {
        match max_rank {
            4 => "Critical",
            3 => "High",
            2 => "Medium",
            _ => "Low",
        }
        .to_string()
    } else {
        score_severity.to_string()
    }
}

/// Annotate chains where completeness is below threshold relative to score.
///
/// Chains with very low completeness and a non-trivial score are likely
/// false positives assembled from insufficient evidence. Rather than
/// suppressing them, we add a note so downstream consumers can filter or
/// de-prioritise them.
fn annotate_low_completeness(chain: &mut ExploitChain) {
    const COMPLETENESS_THRESHOLD: f64 = 0.2;
    if chain.chain_completeness < COMPLETENESS_THRESHOLD {
        chain.notes.insert("low_completeness".into(), "true".into());
    }
}

fn populate_chain_enrichment(chain: &mut ExploitChain, findings_by_id: &HashMap<String, &Finding>) {
    chain.confirmed_stages = collect_chain_stages(chain, findings_by_id, true);
    chain.inferred_stages = collect_chain_stages(chain, findings_by_id, false);
    infer_and_score_stages(chain, findings_by_id);
    chain.reader_risk = HashMap::new();
    chain.active_mitigations = collect_unique_meta_values(
        chain,
        findings_by_id,
        &["exploit.blockers", "exploit.mitigations"],
    );
    chain.required_conditions =
        collect_unique_meta_values(chain, findings_by_id, &["exploit.preconditions"]);
    chain.unmet_conditions =
        derive_unmet_conditions(chain, findings_by_id, &chain.required_conditions);
    chain.finding_criticality = compute_finding_criticality(chain, findings_by_id);
    chain.narrative = compose_chain_narrative(chain);
}

/// Augment confirmed/inferred_stages from trigger/action/payload/finding kinds,
/// then compute chain_completeness using a blended formula.
///
/// Stage weights: confirmed = 1.0, inferred = 0.4, total = 5.0 stages.
fn infer_and_score_stages(chain: &mut ExploitChain, findings_by_id: &HashMap<String, &Finding>) {
    use std::collections::HashSet;

    let mut confirmed: HashSet<String> = chain.confirmed_stages.iter().cloned().collect();
    let mut inferred: HashSet<String> = chain.inferred_stages.iter().cloned().collect();

    // Infer "input" from trigger presence
    if chain.trigger.is_some() {
        confirmed.insert("input".into());
    }

    // Infer "execute" from action kind
    if let Some(action) = &chain.action {
        match action.as_str() {
            "js_present"
            | "launch_action_present"
            | "aa_event_present"
            | "uri_javascript_scheme"
            | "uri_file_scheme"
            | "uri_command_injection" => {
                confirmed.insert("execute".into());
            }
            _ => {
                inferred.insert("execute".into());
            }
        }
    }

    // Infer "decode" / "execute" from payload type
    if let Some(payload) = &chain.payload {
        match payload.as_str() {
            "stream" | "embedded_file" | "image" => {
                confirmed.insert("decode".into());
            }
            "javascript" => {
                inferred.insert("decode".into());
                confirmed.insert("execute".into());
            }
            _ => {}
        }
    }

    // Infer "egress" from network notes
    if chain.notes.get("chain.has_network_egress").map(|v| v == "true").unwrap_or(false) {
        inferred.insert("egress".into());
    }

    // Infer "render" from image/font/content_stream finding kinds
    let has_render_signal = chain.findings.iter().any(|fid| {
        findings_by_id
            .get(fid.as_str())
            .map(|f| {
                f.kind.starts_with("image.")
                    || f.kind.starts_with("font.")
                    || f.kind.starts_with("content_stream")
                    || f.kind == "content_image_only_page"
            })
            .unwrap_or(false)
    });
    if has_render_signal {
        inferred.insert("render".into());
    }

    // Remove from inferred anything that's already confirmed
    inferred.retain(|s| !confirmed.contains(s));

    // Write back sorted lists
    let mut confirmed_vec: Vec<String> = confirmed.into_iter().collect();
    confirmed_vec.sort_by_key(|s| {
        EXPECTED_CHAIN_STAGES.iter().position(|e| e == s).unwrap_or(usize::MAX)
    });
    let mut inferred_vec: Vec<String> = inferred.into_iter().collect();
    inferred_vec.sort();
    chain.confirmed_stages = confirmed_vec;
    chain.inferred_stages = inferred_vec;

    // Blended completeness: confirmed*1.0 + inferred*0.4 / 5 total stages
    const TOTAL_STAGES: f64 = EXPECTED_CHAIN_STAGES.len() as f64;
    let confirmed_score = chain.confirmed_stages.len() as f64;
    let inferred_score = chain.inferred_stages.len() as f64 * 0.4;
    chain.chain_completeness = ((confirmed_score + inferred_score) / TOTAL_STAGES).min(1.0);
}

fn is_confidence_probable_or_higher(confidence: Confidence) -> bool {
    matches!(confidence, Confidence::Certain | Confidence::Strong | Confidence::Probable)
}

fn collect_chain_stages(
    chain: &mut ExploitChain,
    findings_by_id: &HashMap<String, &Finding>,
    confirmed: bool,
) -> Vec<String> {
    let mut stages = Vec::new();
    let mut unknown_stages = Vec::new();
    for finding_id in &chain.findings {
        let Some(finding) = findings_by_id.get(finding_id) else {
            continue;
        };
        let Some(stage) = finding.meta.get("chain.stage") else {
            continue;
        };
        let stage_matches = EXPECTED_CHAIN_STAGES.contains(&stage.as_str());
        let confidence_matches = if confirmed {
            is_confidence_probable_or_higher(finding.confidence)
        } else {
            !is_confidence_probable_or_higher(finding.confidence)
        };
        if !confidence_matches {
            continue;
        }
        if stage_matches {
            if !stages.contains(stage) {
                stages.push(stage.clone());
            }
        } else if !unknown_stages.contains(stage) {
            unknown_stages.push(stage.clone());
        }
    }
    if !unknown_stages.is_empty() {
        unknown_stages.sort();
        chain.notes.insert("chain.unknown_stages".into(), unknown_stages.join(","));
    } else {
        chain.notes.remove("chain.unknown_stages");
    }
    if confirmed {
        stages.sort_by_key(|value| {
            EXPECTED_CHAIN_STAGES
                .iter()
                .position(|expected| expected == value)
                .unwrap_or(usize::MAX)
        });
    } else {
        stages.sort();
    }
    stages
}

fn split_meta_values(raw: &str) -> impl Iterator<Item = String> + '_ {
    raw.split([',', ';']).map(str::trim).filter(|token| !token.is_empty()).map(str::to_string)
}

fn collect_unique_meta_values(
    chain: &ExploitChain,
    findings_by_id: &HashMap<String, &Finding>,
    keys: &[&str],
) -> Vec<String> {
    let mut set = BTreeSet::new();
    for finding_id in &chain.findings {
        let Some(finding) = findings_by_id.get(finding_id) else {
            continue;
        };
        for key in keys {
            if let Some(value) = finding.meta.get(*key) {
                for parsed in split_meta_values(value) {
                    set.insert(parsed);
                }
            }
        }
    }
    set.into_iter().collect()
}

fn derive_unmet_conditions(
    chain: &ExploitChain,
    findings_by_id: &HashMap<String, &Finding>,
    required_conditions: &[String],
) -> Vec<String> {
    let mut satisfied = BTreeSet::new();
    for finding_id in &chain.findings {
        let Some(finding) = findings_by_id.get(finding_id) else {
            continue;
        };
        for key in ["exploit.conditions_met", "exploit.condition_met", "exploit.preconditions_met"]
        {
            if let Some(value) = finding.meta.get(key) {
                for parsed in split_meta_values(value) {
                    satisfied.insert(parsed);
                }
            }
        }
    }
    let mut unmet = Vec::new();
    for condition in required_conditions {
        if !satisfied.contains(condition) {
            unmet.push(condition.clone());
        }
    }
    unmet.sort();
    unmet.dedup();
    unmet
}

fn structural_count_for_findings(findings: &[&Finding]) -> usize {
    findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind.as_str(),
                "xref_conflict"
                    | "incremental_update_chain"
                    | "object_id_shadowing"
                    | "objstm_density_high"
            )
        })
        .count()
}

fn compute_finding_criticality(
    chain: &ExploitChain,
    findings_by_id: &HashMap<String, &Finding>,
) -> HashMap<String, f64> {
    if chain.findings.len() > 30 || chain.findings.len() <= 1 {
        return HashMap::new();
    }
    let baseline_score = chain.score;
    let mut criticality = HashMap::new();
    for finding_id in &chain.findings {
        let mut remaining: Vec<&Finding> = Vec::new();
        for candidate_id in &chain.findings {
            if candidate_id == finding_id {
                continue;
            }
            if let Some(finding) = findings_by_id.get(candidate_id) {
                remaining.push(*finding);
            }
        }
        if remaining.is_empty() {
            criticality.insert(finding_id.clone(), baseline_score.clamp(0.0, 1.0));
            continue;
        }

        let roles = assign_chain_roles(&remaining);
        let trigger = roles.trigger_key.clone();
        let action = roles.action_key.clone();
        let payload = roles.payload_key.clone();
        let structural_count = structural_count_for_findings(&remaining);
        let taint = taint_from_findings(
            &remaining.iter().map(|finding| (*finding).clone()).collect::<Vec<_>>(),
        );
        let mut notes = notes_from_findings(&remaining, structural_count, &taint);
        apply_role_labels(&mut notes, &roles);
        apply_chain_labels(&mut notes, trigger.as_deref(), action.as_deref(), payload.as_deref());
        let candidate = ExploitChain {
            id: String::new(),
            label: String::new(),
            severity: String::new(),
            group_id: None,
            group_count: 1,
            group_members: Vec::new(),
            trigger,
            action,
            payload,
            findings: remaining.iter().map(|finding| finding.id.clone()).collect(),
            score: 0.0,
            reasons: Vec::new(),
            path: String::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            confirmed_stages: Vec::new(),
            inferred_stages: Vec::new(),
            chain_completeness: 0.0,
            reader_risk: HashMap::new(),
            narrative: String::new(),
            finding_criticality: HashMap::new(),
            active_mitigations: Vec::new(),
            required_conditions: Vec::new(),
            unmet_conditions: Vec::new(),
            finding_roles: HashMap::new(),
            notes,
        };
        let score_without = score_chain(&candidate).0;
        criticality.insert(finding_id.clone(), (baseline_score - score_without).clamp(0.0, 1.0));
    }
    criticality
}

fn notes_from_findings(
    findings: &[&Finding],
    structural_count: usize,
    taint: &crate::taint::Taint,
) -> HashMap<String, String> {
    let mut notes = HashMap::new();
    for f in findings {
        if let Some(action_type) =
            f.meta.get("action.s").or_else(|| f.meta.get("action.type"))
        {
            notes.entry("action.type".into()).or_insert_with(|| action_type.clone());
        } else if let Some(action_type) = &f.action_type {
            notes.entry("action.type".into()).or_insert_with(|| action_type.clone());
        }
        if let Some(action_target) = f.meta.get("action.target") {
            notes.entry("action.target".into()).or_insert_with(|| action_target.clone());
        }
        if let Some(payload_type) = f.meta.get("payload.type") {
            notes.entry("payload.type".into()).or_insert_with(|| payload_type.clone());
        }
        for (k, v) in &f.meta {
            if k.starts_with("js.")
                || k.starts_with("payload.")
                || k.starts_with("edge.")
                || k.starts_with("exploit.")
                || matches!(
                    k.as_str(),
                    "chain.stage"
                        | "chain.capability"
                        | "chain.trigger"
                        | "chain.confidence"
                        | "chain.severity"
                        | "injection.sources"
                        | "scatter.fragment_count"
                )
            {
                if k == "js.sandbox_exec"
                    && matches!(notes.get(k).map(String::as_str), Some("true"))
                {
                    continue;
                }
                notes.entry(k.clone()).or_insert_with(|| v.clone());
            }
            if matches!(
                k.as_str(),
                "stream.filters"
                    | "decode.mismatch"
                    | "decode.outcome"
                    | "decode.recovered_filters"
            ) {
                notes.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    }
    if structural_count > 0 {
        notes.insert("structural.suspicious_count".into(), structural_count.to_string());
    }
    if taint.flagged {
        notes.insert("taint.flagged".into(), "true".into());
        notes.insert("taint.reasons".into(), taint.reasons.join("; "));
    }
    apply_payload_notes(&mut notes);
    notes
}

enum ChainRole {
    Trigger,
    Action,
    Payload,
}

fn apply_role_labels(notes: &mut HashMap<String, String>, roles: &ChainRoles<'_>) {
    if let Some(f) = roles.trigger_finding {
        set_note_if_missing(notes, "trigger.label", label_for_finding(ChainRole::Trigger, f));
        set_note_if_missing(notes, "trigger.summary", f.description.clone());
    }
    if let Some(f) = roles.action_finding {
        // Only set finding-specific action label when the finding has
        // enrichment (action.target); otherwise let chain classification
        // labels provide the default via apply_chain_labels.
        if f.meta.contains_key("action.target") {
            set_note_if_missing(notes, "action.label", label_for_finding(ChainRole::Action, f));
        }
        set_note_if_missing(notes, "action.summary", f.description.clone());
    }
    if let Some(f) = roles.payload_finding {
        // Only set finding-specific payload label when the finding has
        // enrichment metadata; otherwise let chain classification labels
        // provide the default.
        if f.meta.contains_key("payload.summary") || f.meta.contains_key("payload.preview") {
            set_note_if_missing(notes, "payload.label", label_for_finding(ChainRole::Payload, f));
        }
        let summary = f
            .meta
            .get("payload.summary")
            .cloned()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| f.description.clone());
        set_note_if_missing(notes, "payload.summary", summary);
        if let Some(preview) = f.meta.get("payload.preview") {
            set_note_if_missing(notes, "payload.preview", preview.clone());
        }
    }
}

fn apply_finding_roles(chain: &mut ExploitChain, roles: &ChainRoles<'_>) {
    if let Some(finding) = roles.trigger_finding {
        chain.finding_roles.insert(finding.id.clone(), "trigger".into());
    }
    if let Some(finding) = roles.action_finding {
        chain.finding_roles.entry(finding.id.clone()).or_insert_with(|| "action".into());
    }
    if let Some(finding) = roles.payload_finding {
        chain.finding_roles.entry(finding.id.clone()).or_insert_with(|| "payload".into());
    }
}

fn label_for_finding(role: ChainRole, finding: &Finding) -> String {
    let mut label =
        if !finding.title.is_empty() { finding.title.clone() } else { finding.kind.clone() };
    match role {
        ChainRole::Action => {
            if let Some(target) = finding.meta.get("action.target") {
                if !target.trim().is_empty() {
                    label = format!("{label} -> {}", target.trim());
                }
            }
        }
        ChainRole::Payload => {
            if let Some(summary) = finding.meta.get("payload.summary") {
                if !summary.trim().is_empty() {
                    label = format!("{label} [{summary}]");
                }
            } else if !finding.description.trim().is_empty() {
                label = format!("{label} [{}]", finding.description.trim());
            }
        }
        ChainRole::Trigger => {}
    }
    label
}

fn set_note_if_missing(notes: &mut HashMap<String, String>, key: &str, value: String) {
    if value.trim().is_empty() {
        return;
    }
    notes.entry(key.into()).or_insert(value);
}

fn apply_chain_labels(
    notes: &mut HashMap<String, String>,
    trigger_key: Option<&str>,
    action_key: Option<&str>,
    payload_key: Option<&str>,
) {
    if let Some(key) = trigger_key {
        notes.insert("trigger.key".into(), key.to_string());
        set_note_if_missing(notes, "trigger.label", trigger_label(key));
    }
    if let Some(key) = action_key {
        notes.insert("action.key".into(), key.to_string());
        let action_type = notes.get("action.type").map(String::as_str);
        set_note_if_missing(notes, "action.label", action_label(key, action_type));
    }
    if let Some(key) = payload_key {
        notes.insert("payload.key".into(), key.to_string());
        let payload_type = notes.get("payload.type").map(String::as_str);
        let payload_source = notes.get("payload.source").map(String::as_str);
        let payload_summary = notes.get("payload.summary").map(String::as_str);
        set_note_if_missing(
            notes,
            "payload.label",
            payload_label(key, payload_type, payload_source, payload_summary),
        );
    }
}

fn apply_payload_notes(notes: &mut HashMap<String, String>) {
    if let Some(source) = notes.get("js.source") {
        notes.insert("payload.source".into(), source.clone());
    }
    if let Some(preview) =
        notes.get("payload.deobfuscated_preview").or_else(|| notes.get("payload.decoded_preview"))
    {
        notes.insert("payload.preview".into(), preview.clone());
    }
    let mut parts = Vec::new();
    if let Some(len) = notes.get("payload.decoded_len") {
        parts.push(format!("len={len}"));
    }
    if let Some(layers) = notes.get("payload.decode_layers") {
        parts.push(format!("layers={layers}"));
    }
    if let Some(filters) = notes.get("stream.filters").or_else(|| notes.get("js.stream.filters")) {
        parts.push(format!("filters={filters}"));
    }
    if let Some(outcome) = notes.get("decode.outcome") {
        parts.push(format!("decode={outcome}"));
    }
    if let Some(mismatch) = notes.get("decode.mismatch") {
        parts.push(format!("mismatch={mismatch}"));
    }
    if let Some(recovered) = notes.get("decode.recovered_filters") {
        parts.push(format!("recovered={recovered}"));
    }
    if !parts.is_empty() {
        notes.insert("payload.summary".into(), parts.join(" "));
    }
}

fn trigger_label(key: &str) -> String {
    match key {
        "open_action_present" => "OpenAction".into(),
        "aa_present" | "aa_event_present" => "AdditionalAction".into(),
        other => other.to_string(),
    }
}

fn action_label(key: &str, action_type: Option<&str>) -> String {
    if let Some(action_type) = action_type {
        if action_type.contains("JavaScript") {
            return "JavaScript action".into();
        }
        if action_type.contains("URI") {
            return "URI action".into();
        }
        if action_type.contains("Launch") {
            return "Launch action".into();
        }
        if action_type.contains("SubmitForm") {
            return "SubmitForm action".into();
        }
        if action_type.contains("GoToR") {
            return "GoToR action".into();
        }
    }
    match key {
        "launch_action_present" => "Launch action".into(),
        "uri_content_analysis" => "URI action".into(),
        "submitform_present" => "SubmitForm action".into(),
        "gotor_present" => "GoToR action".into(),
        "js_present" => "JavaScript action".into(),
        "open_action_present" => "OpenAction".into(),
        "aa_present" | "aa_event_present" => "AdditionalAction".into(),
        other => other.to_string(),
    }
}

fn payload_label(
    key: &str,
    payload_type: Option<&str>,
    payload_source: Option<&str>,
    payload_summary: Option<&str>,
) -> String {
    let base = if let Some(payload_type) = payload_type {
        match payload_type {
            "javascript" => "JavaScript payload".into(),
            "embedded_file" => "Embedded file payload".into(),
            "stream" => "Stream payload".into(),
            "string" => "String payload".into(),
            "xfa_script" => "XFA script payload".into(),
            "image" => "Image payload".into(),
            other => format!("{other} payload"),
        }
    } else {
        match key {
            "javascript" => "JavaScript payload".into(),
            "embedded_file" => "Embedded file payload".into(),
            "stream" => "Stream payload".into(),
            "string" => "String payload".into(),
            "xfa_script" => "XFA script payload".into(),
            "image" => "Image payload".into(),
            other => format!("{other} payload"),
        }
    };
    let mut out = base;
    if let Some(source) = payload_source {
        out = format!("{out} ({source})");
    }
    if let Some(summary) = payload_summary {
        out = format!("{out} [{summary}]");
    }
    out
}

fn action_from_meta(finding: &Finding) -> Option<String> {
    let action_s = finding
        .meta
        .get("action.s")
        .or_else(|| finding.meta.get("action.type"))
        .map(String::as_str)
        .or_else(|| finding.action_type.as_deref())?;
    action_key_from_action_s(action_s)
}

fn action_key_from_action_s(action_s: &str) -> Option<String> {
    if action_s.contains("JavaScript") {
        return Some("js_present".into());
    }
    if action_s.contains("URI") {
        return Some("uri_content_analysis".into());
    }
    if action_s.contains("Launch") {
        return Some("launch_action_present".into());
    }
    if action_s.contains("SubmitForm") {
        return Some("submitform_present".into());
    }
    if action_s.contains("GoToR") {
        return Some("gotor_present".into());
    }
    None
}

fn attach_group_metadata(mut chains: Vec<ExploitChain>) -> Vec<ExploitChain> {
    for chain in &mut chains {
        chain.group_id = Some(chain.id.clone());
        chain.group_count = 1;
        chain.group_members = vec![chain.id.clone()];
    }
    chains
}

#[derive(Hash, Eq, PartialEq)]
struct ChainSignature {
    trigger: String,
    action: String,
    payload: String,
    object_refs: Vec<String>,
    finding_kinds: Vec<String>,
}

fn chain_signature(
    chain: &ExploitChain,
    findings_by_id: &HashMap<String, &Finding>,
) -> ChainSignature {
    let trigger = chain
        .notes
        .get("trigger.key")
        .cloned()
        .or_else(|| chain.trigger.clone())
        .unwrap_or_else(|| "-".into());
    let action = chain
        .notes
        .get("action.key")
        .cloned()
        .or_else(|| chain.action.clone())
        .unwrap_or_else(|| "-".into());
    let payload = chain
        .notes
        .get("payload.key")
        .cloned()
        .or_else(|| chain.payload.clone())
        .unwrap_or_else(|| "-".into());
    let mut object_refs = Vec::new();
    let mut finding_kinds = Vec::new();
    for id in &chain.findings {
        if let Some(finding) = findings_by_id.get(id) {
            finding_kinds.push(finding.kind.clone());
            object_refs.extend(extract_object_refs_from_finding(finding));
        }
    }
    object_refs.sort();
    object_refs.dedup();
    finding_kinds.sort();
    finding_kinds.dedup();
    ChainSignature { trigger, action, payload, object_refs, finding_kinds }
}

fn group_chains_by_signature(
    chains: Vec<ExploitChain>,
    findings_by_id: &HashMap<String, &Finding>,
) -> Vec<ExploitChain> {
    let mut groups: HashMap<ChainSignature, Vec<ExploitChain>> = HashMap::new();
    for chain in chains {
        let signature = chain_signature(&chain, findings_by_id);
        groups.entry(signature).or_default().push(chain);
    }
    let mut out = Vec::new();
    for (signature, mut members) in groups {
        members.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        let mut representative = members.remove(0);
        let mut member_ids = vec![representative.id.clone()];
        for chain in &members {
            member_ids.push(chain.id.clone());
        }
        let mut findings_set: BTreeSet<String> = representative.findings.iter().cloned().collect();
        let mut nodes_set: BTreeSet<String> = representative.nodes.iter().cloned().collect();
        for chain in &members {
            for id in &chain.findings {
                findings_set.insert(id.clone());
            }
            for node in &chain.nodes {
                nodes_set.insert(node.clone());
            }
            if representative.trigger.is_none() {
                representative.trigger = chain.trigger.clone();
            }
            if representative.action.is_none() {
                representative.action = chain.action.clone();
            }
            if representative.payload.is_none() {
                representative.payload = chain.payload.clone();
            }
            for (k, v) in &chain.notes {
                representative.notes.entry(k.clone()).or_insert_with(|| v.clone());
            }
            for (finding_id, role) in &chain.finding_roles {
                representative
                    .finding_roles
                    .entry(finding_id.clone())
                    .or_insert_with(|| role.clone());
            }
        }
        representative.findings = findings_set.into_iter().collect();
        representative.nodes = nodes_set.into_iter().collect();
        let group_id = group_id_from_signature(&signature);
        representative.id = group_id.clone();
        representative.group_id = Some(group_id);
        representative.group_count = member_ids.len();
        representative.group_members = member_ids;
        representative.path = render_path(&representative);
        let (score, reasons) = score_chain(&representative);
        representative.score = score;
        representative.reasons = reasons;
        populate_chain_enrichment(&mut representative, findings_by_id);
        annotate_low_completeness(&mut representative);
        out.push(representative);
    }
    out
}

fn group_id_from_signature(signature: &ChainSignature) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(signature.trigger.as_bytes());
    hasher.update(signature.action.as_bytes());
    hasher.update(signature.payload.as_bytes());
    for obj in &signature.object_refs {
        hasher.update(obj.as_bytes());
    }
    for kind in &signature.finding_kinds {
        hasher.update(kind.as_bytes());
    }
    format!("chain-{}", hasher.finalize().to_hex())
}

fn extract_object_refs_from_finding(finding: &Finding) -> Vec<String> {
    let mut out = Vec::new();
    for obj in &finding.objects {
        if let Some((object_id, generation)) = position::parse_obj_ref(obj) {
            out.push(format!("{object_id} {generation}"));
        }
    }
    out
}

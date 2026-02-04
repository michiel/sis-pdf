use std::collections::{BTreeSet, HashMap, HashSet};

use crate::chain::{ChainTemplate, ExploitChain};
use crate::chain_render::render_path;
use crate::chain_score::score_chain;
use crate::model::Finding;
use crate::taint::taint_from_findings;

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
    ));
    for f in findings {
        let single = [f];
        let roles = assign_chain_roles(&single);
        let trigger = roles.trigger_key.clone();
        let action = roles.action_key.clone();
        let payload = roles.payload_key.clone();
        let mut notes = notes_from_findings(&single, structural_count, &taint);
        apply_role_labels(&mut notes, &roles);
        apply_chain_labels(
            &mut notes,
            trigger.as_deref(),
            action.as_deref(),
            payload.as_deref(),
        );
        let mut chain = ExploitChain {
            id: String::new(),
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
            notes,
        };
        finalize_chain(&mut chain, &finding_positions);
        chains.push(chain);
    }

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
        let entry = templates
            .entry(key.clone())
            .or_insert_with(|| ChainTemplate {
                id: template_id(&key),
                trigger: c.trigger.clone(),
                action: c.action.clone(),
                payload: c.payload.clone(),
                instances: Vec::new(),
            });
        entry.instances.push(c.id.clone());
    }

    (chains, templates.into_values().collect())
}

fn build_object_chains(
    findings: &[Finding],
    structural_count: usize,
    taint: &crate::taint::Taint,
    finding_positions: &HashMap<String, Vec<String>>,
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
        let categories = [trigger.is_some(), action.is_some(), payload.is_some()]
            .iter()
            .filter(|v| **v)
            .count();
        if categories < 2 {
            continue;
        }
        let mut notes = notes_from_findings(&group, structural_count, taint);
        apply_role_labels(&mut notes, &roles);
        notes.insert("correlation.object".into(), obj.clone());
        if action.is_some() && payload.is_some() {
            notes.insert("correlation.action_payload".into(), "true".into());
        }
        apply_chain_labels(
            &mut notes,
            trigger.as_deref(),
            action.as_deref(),
            payload.as_deref(),
        );
        let mut chain = ExploitChain {
            id: String::new(),
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
            notes,
        };
        finalize_chain(&mut chain, finding_positions);
        chains.push(chain);
    }
    chains
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
        "launch_action_present"
        | "uri_present"
        | "submitform_present"
        | "gotor_present"
        | "js_present"
        | "open_action_present"
        | "aa_present"
        | "aa_event_present" => Some(kind.into()),
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

fn finalize_chain(chain: &mut ExploitChain, finding_positions: &HashMap<String, Vec<String>>) {
    chain.path = render_path(chain);
    chain.nodes = chain_nodes(chain, finding_positions);
    let (score, reasons) = score_chain(chain);
    chain.score = score;
    chain.reasons = reasons;
    chain.id = chain_id(chain);
}

fn notes_from_findings(
    findings: &[&Finding],
    structural_count: usize,
    taint: &crate::taint::Taint,
) -> HashMap<String, String> {
    let mut notes = HashMap::new();
    for f in findings {
        if let Some(action_type) = f.meta.get("action.s") {
            notes
                .entry("action.type".into())
                .or_insert_with(|| action_type.clone());
        }
        if let Some(action_target) = f.meta.get("action.target") {
            notes
                .entry("action.target".into())
                .or_insert_with(|| action_target.clone());
        }
        if let Some(payload_type) = f.meta.get("payload.type") {
            notes
                .entry("payload.type".into())
                .or_insert_with(|| payload_type.clone());
        }
        for (k, v) in &f.meta {
            if k.starts_with("js.") || k.starts_with("payload.") {
                if k == "js.sandbox_exec" && matches!(notes.get(k).map(String::as_str), Some("true")) {
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
        notes.insert(
            "structural.suspicious_count".into(),
            structural_count.to_string(),
        );
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
        set_note_if_missing(
            notes,
            "trigger.label",
            label_for_finding(ChainRole::Trigger, f),
        );
        set_note_if_missing(notes, "trigger.summary", f.description.clone());
    }
    if let Some(f) = roles.action_finding {
        // Only set finding-specific action label when the finding has
        // enrichment (action.target); otherwise let chain classification
        // labels provide the default via apply_chain_labels.
        if f.meta.contains_key("action.target") {
            set_note_if_missing(
                notes,
                "action.label",
                label_for_finding(ChainRole::Action, f),
            );
        }
        set_note_if_missing(notes, "action.summary", f.description.clone());
    }
    if let Some(f) = roles.payload_finding {
        // Only set finding-specific payload label when the finding has
        // enrichment metadata; otherwise let chain classification labels
        // provide the default.
        if f.meta.contains_key("payload.summary") || f.meta.contains_key("payload.preview") {
            set_note_if_missing(
                notes,
                "payload.label",
                label_for_finding(ChainRole::Payload, f),
            );
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

fn label_for_finding(role: ChainRole, finding: &Finding) -> String {
    let mut label = if !finding.title.is_empty() {
        finding.title.clone()
    } else {
        finding.kind.clone()
    };
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
    if let Some(preview) = notes
        .get("payload.deobfuscated_preview")
        .or_else(|| notes.get("payload.decoded_preview"))
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
    if let Some(filters) = notes
        .get("stream.filters")
        .or_else(|| notes.get("js.stream.filters"))
    {
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
        "uri_present" => "URI action".into(),
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
    let action_s = finding.meta.get("action.s")?;
    action_key_from_action_s(action_s)
}

fn action_key_from_action_s(action_s: &str) -> Option<String> {
    if action_s.contains("JavaScript") {
        return Some("js_present".into());
    }
    if action_s.contains("URI") {
        return Some("uri_present".into());
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
    ChainSignature {
        trigger,
        action,
        payload,
        object_refs,
        finding_kinds,
    }
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
        members.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
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
                representative
                    .notes
                    .entry(k.clone())
                    .or_insert_with(|| v.clone());
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
        if let Some(obj_ref) = parse_object_ref(obj) {
            out.push(obj_ref);
        }
    }
    out
}

fn parse_object_ref(value: &str) -> Option<String> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    for window in parts.windows(3) {
        if window[2] == "obj"
            && window[0].chars().all(|c| c.is_ascii_digit())
            && window[1].chars().all(|c| c.is_ascii_digit())
        {
            return Some(format!("{} {}", window[0], window[1]));
        }
    }
    None
}

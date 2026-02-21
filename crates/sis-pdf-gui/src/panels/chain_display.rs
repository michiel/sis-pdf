use sis_pdf_core::chain::ExploitChain;
use sis_pdf_core::chain_render::chain_stage_summary;

pub const UNRESOLVED_CHAIN_TEXT: &str = "Unresolved chain - see linked findings for details";

#[derive(Debug, Clone, PartialEq)]
pub struct ChainSummaryDisplay {
    pub chain_index: usize,
    pub score: f64,
    pub role_label: Option<String>,
    pub narrative_summary: Option<String>,
    pub trigger: Option<String>,
    pub action: Option<String>,
    pub payload: Option<String>,
    pub all_unresolved: bool,
}

pub fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..s.floor_char_boundary(max)]
    }
}

pub fn unresolved_summary(
    chain_index: usize,
    score: f64,
    role_label: Option<String>,
) -> ChainSummaryDisplay {
    ChainSummaryDisplay {
        chain_index,
        score,
        role_label,
        narrative_summary: None,
        trigger: None,
        action: None,
        payload: None,
        all_unresolved: true,
    }
}

pub fn summary_from_chain(
    chain_index: usize,
    score: f64,
    role_label: Option<String>,
    chain: &ExploitChain,
    narrative_max: usize,
) -> ChainSummaryDisplay {
    let stage_summary = chain_stage_summary(chain);
    let narrative_summary = {
        let trimmed = chain.narrative.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(truncate_str(trimmed, narrative_max).to_string())
        }
    };
    ChainSummaryDisplay {
        chain_index,
        score,
        role_label,
        narrative_summary,
        trigger: stage_summary.trigger,
        action: stage_summary.action,
        payload: stage_summary.payload,
        all_unresolved: stage_summary.all_unresolved,
    }
}

pub fn chain_header(entry: &ChainSummaryDisplay) -> String {
    if let Some(role) = &entry.role_label {
        format!("Chain #{} [{}] score {:.2}", entry.chain_index + 1, role, entry.score)
    } else {
        format!("Chain #{} [score {:.2}]", entry.chain_index + 1, entry.score)
    }
}

pub fn render_chain_summary(
    ui: &mut egui::Ui,
    entry: &ChainSummaryDisplay,
    stage_truncate: usize,
) -> bool {
    let mut clicked = false;
    ui.group(|ui| {
        if ui.link(chain_header(entry)).clicked() {
            clicked = true;
        }
        if entry.all_unresolved {
            ui.small(UNRESOLVED_CHAIN_TEXT);
            return;
        }
        if let Some(narrative_summary) = &entry.narrative_summary {
            ui.small(narrative_summary);
            return;
        }
        show_chain_stage_labels(
            ui,
            entry.trigger.as_deref(),
            entry.action.as_deref(),
            entry.payload.as_deref(),
            stage_truncate,
        );
    });
    clicked
}

fn show_chain_stage_labels(
    ui: &mut egui::Ui,
    trigger: Option<&str>,
    action: Option<&str>,
    payload: Option<&str>,
    stage_truncate: usize,
) {
    let stages = [("Trigger", trigger), ("Action", action), ("Payload", payload)];
    for (stage, text) in stages {
        let Some(text) = text else {
            continue;
        };
        ui.horizontal(|ui| {
            ui.monospace(format!("{stage}:"));
            ui.small(truncate_str(text, stage_truncate));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{
        chain_header, summary_from_chain, truncate_str, unresolved_summary, ChainSummaryDisplay,
    };
    use sis_pdf_core::chain::ExploitChain;
    use std::collections::HashMap;

    fn base_chain() -> ExploitChain {
        ExploitChain {
            id: "chain-1".into(),
            group_id: None,
            group_count: 1,
            group_members: Vec::new(),
            trigger: Some("open_action_present".into()),
            action: Some("js_present".into()),
            payload: Some("javascript".into()),
            findings: vec!["f1".into()],
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
            notes: HashMap::new(),
        }
    }

    #[test]
    fn truncate_str_handles_ascii_and_unicode_boundaries() {
        assert_eq!(truncate_str("hello world", 5), "hello");
        assert_eq!(truncate_str("héllo", 3), "hé");
    }

    #[test]
    fn summary_from_chain_uses_unresolved_fallback_when_all_unresolved() {
        let mut chain = base_chain();
        chain.trigger = None;
        chain.action = None;
        chain.payload = None;
        let summary = summary_from_chain(0, 0.8, None, &chain, 100);
        assert!(summary.all_unresolved);
        assert!(summary.trigger.is_none());
        assert!(summary.action.is_none());
        assert!(summary.payload.is_none());
        assert!(summary.narrative_summary.is_none());
    }

    #[test]
    fn summary_from_chain_prefers_narrative_then_stages() {
        let mut chain = base_chain();
        chain.narrative = "Document open action executes JavaScript payload".to_string();
        let summary = summary_from_chain(1, 0.9, Some("Participant".to_string()), &chain, 20);
        assert!(!summary.all_unresolved);
        assert_eq!(summary.narrative_summary.as_deref(), Some("Document open action"));
        assert_eq!(summary.trigger.as_deref(), Some("open_action_present"));
        assert_eq!(summary.action.as_deref(), Some("js_present"));
        assert_eq!(summary.payload.as_deref(), Some("javascript"));
    }

    #[test]
    fn unresolved_summary_keeps_index_score_and_role() {
        let summary = unresolved_summary(3, 0.75, Some("Payload".to_string()));
        assert_eq!(
            summary,
            ChainSummaryDisplay {
                chain_index: 3,
                score: 0.75,
                role_label: Some("Payload".to_string()),
                narrative_summary: None,
                trigger: None,
                action: None,
                payload: None,
                all_unresolved: true,
            }
        );
    }

    #[test]
    fn finding_detail_and_object_inspector_chain_headers_match_for_same_input() {
        let chain = base_chain();
        let object_summary = summary_from_chain(7, 0.8, None, &chain, 100);
        let detail_summary = summary_from_chain(7, 0.8, None, &chain, 120);
        assert_eq!(chain_header(&object_summary), chain_header(&detail_summary));
    }
}

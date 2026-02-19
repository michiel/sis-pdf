use anyhow::Result;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{
    AttackSurface, Confidence, Finding, Impact, ReaderImpact, ReaderProfile, Severity,
};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfDict};
use sis_pdf_pdf::typed_graph::EdgeType;
use std::collections::{BTreeSet, HashMap};

use crate::entry_dict;
use crate::external_target::{extract_text_target, normalise_external_target};

pub struct PassiveRenderPipelineDetector;

#[derive(Clone)]
struct ExternalTargetHit {
    object_id: (u32, u16),
    object_ref: String,
    object_span: sis_pdf_pdf::span::Span,
    source_key: String,
    source_context: String,
    target: String,
    normalised_target: String,
    protocol: String,
    high_risk_scheme: bool,
    obfuscated_target: bool,
    credential_leak_risk: bool,
    ntlm_host: Option<String>,
    ntlm_share: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PassiveTriggerMode {
    AutomaticOrAa,
    PassiveRenderOrIndexer,
    ManualOrUnknown,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProtocolRiskClass {
    Low,
    Medium,
    High,
}

impl ProtocolRiskClass {
    fn as_str(self) -> &'static str {
        match self {
            ProtocolRiskClass::Low => "low",
            ProtocolRiskClass::Medium => "medium",
            ProtocolRiskClass::High => "high",
        }
    }
}

impl PassiveTriggerMode {
    fn as_str(self) -> &'static str {
        match self {
            PassiveTriggerMode::AutomaticOrAa => "automatic_or_aa",
            PassiveTriggerMode::PassiveRenderOrIndexer => "passive_render_or_indexer",
            PassiveTriggerMode::ManualOrUnknown => "manual_or_unknown",
        }
    }
}

impl Detector for PassiveRenderPipelineDetector {
    fn id(&self) -> &'static str {
        "passive_render_pipeline"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let typed_graph = ctx.build_typed_graph();
        let has_automatic_trigger = typed_graph.edges.iter().any(|edge| {
            matches!(
                edge.edge_type,
                EdgeType::OpenAction
                    | EdgeType::AdditionalAction { .. }
                    | EdgeType::PageAction { .. }
                    | EdgeType::FormFieldAction { .. }
            )
        });

        let mut hits = Vec::new();
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            let context = classify_context(dict);
            if context == "other" {
                continue;
            }
            let object_ref = format!("{} {} obj", entry.obj, entry.gen);
            collect_external_targets(
                dict,
                &context,
                (entry.obj, entry.gen),
                &object_ref,
                entry.full_span,
                &mut hits,
            );
        }

        if hits.is_empty() {
            return Ok(Vec::new());
        }
        let mut hidden_path_objects = Vec::new();
        let mut orphaned_font_objects = Vec::new();
        let mut orphaned_image_objects = Vec::new();
        for hit in &hits {
            if !matches!(hit.source_context.as_str(), "font" | "image") {
                continue;
            }
            let incoming = typed_graph.incoming_edges(hit.object_id.0, hit.object_id.1);
            if incoming.is_empty() {
                continue;
            }
            let has_page_parent = incoming.iter().any(|edge| {
                typed_graph
                    .graph
                    .classify_objects()
                    .get(&edge.src)
                    .map(|classified| {
                        matches!(
                            classified.obj_type,
                            sis_pdf_pdf::classification::PdfObjectType::Page
                        )
                    })
                    .unwrap_or(false)
            });
            let has_resource_ref = incoming.iter().any(|edge| {
                matches!(
                    edge.edge_type,
                    EdgeType::PageResources | EdgeType::FontReference | EdgeType::XObjectReference
                )
            });
            if has_resource_ref && !has_page_parent {
                hidden_path_objects.push(hit.object_ref.clone());
                if hit.source_context == "font" {
                    orphaned_font_objects.push(hit.object_ref.clone());
                } else if hit.source_context == "image" {
                    orphaned_image_objects.push(hit.object_ref.clone());
                }
            }
        }
        hidden_path_objects.sort();
        hidden_path_objects.dedup();
        orphaned_font_objects.sort();
        orphaned_font_objects.dedup();
        orphaned_image_objects.sort();
        orphaned_image_objects.dedup();

        let protocols: BTreeSet<String> = hits.iter().map(|hit| hit.protocol.clone()).collect();
        let contexts: BTreeSet<String> =
            hits.iter().map(|hit| format!("{}:{}", hit.source_context, hit.source_key)).collect();
        let objects: BTreeSet<String> = hits.iter().map(|hit| hit.object_ref.clone()).collect();
        let credential_leak_hits = hits.iter().filter(|hit| hit.credential_leak_risk).count();
        let ntlm_targets = hits.iter().filter(|hit| hit.ntlm_host.is_some()).count();
        let obfuscated_targets = hits.iter().filter(|hit| hit.obfuscated_target).count();
        let high_risk_targets = hits.iter().filter(|hit| hit.high_risk_scheme).count();
        let max_protocol_risk = hits
            .iter()
            .map(|hit| protocol_risk_class(&hit.protocol))
            .max()
            .unwrap_or(ProtocolRiskClass::Low);
        let mut protocol_counts: HashMap<String, usize> = HashMap::new();
        let mut context_counts: HashMap<String, usize> = HashMap::new();
        for hit in &hits {
            *protocol_counts.entry(hit.protocol.clone()).or_insert(0) += 1;
            *context_counts.entry(hit.source_context.clone()).or_insert(0) += 1;
        }
        let preview_prone_context = hits.iter().any(|hit| {
            matches!(hit.source_context.as_str(), "font" | "image" | "metadata" | "forms")
        });
        let preview_indexer_context_count = hits
            .iter()
            .filter(|hit| {
                matches!(hit.source_context.as_str(), "font" | "image" | "metadata" | "forms")
            })
            .count();

        let trigger_mode = if has_automatic_trigger {
            PassiveTriggerMode::AutomaticOrAa
        } else if preview_prone_context {
            PassiveTriggerMode::PassiveRenderOrIndexer
        } else {
            PassiveTriggerMode::ManualOrUnknown
        };

        let mut base_meta = HashMap::new();
        base_meta.insert("passive.external_target_count".into(), hits.len().to_string());
        base_meta.insert(
            "passive.external_protocols".into(),
            protocols.into_iter().collect::<Vec<_>>().join(", "),
        );
        base_meta.insert("passive.protocol_breakdown".into(), render_breakdown(&protocol_counts));
        base_meta
            .insert("passive.source_context_breakdown".into(), render_breakdown(&context_counts));
        base_meta.insert("passive.protocol_risk_class".into(), max_protocol_risk.as_str().into());
        base_meta.insert(
            "passive.source_contexts".into(),
            contexts.into_iter().collect::<Vec<_>>().join(", "),
        );
        base_meta.insert("passive.trigger_mode".into(), trigger_mode.as_str().into());
        base_meta.insert(
            "passive.indexer_trigger_likelihood".into(),
            if matches!(
                trigger_mode,
                PassiveTriggerMode::AutomaticOrAa | PassiveTriggerMode::PassiveRenderOrIndexer
            ) {
                "elevated"
            } else {
                "low"
            }
            .into(),
        );
        base_meta.insert(
            "passive.credential_leak_risk".into(),
            if credential_leak_hits > 0 { "true" } else { "false" }.into(),
        );
        base_meta.insert("passive.ntlm_target_count".into(), ntlm_targets.to_string());
        base_meta.insert("passive.obfuscated_target_count".into(), obfuscated_targets.to_string());
        base_meta.insert("passive.high_risk_target_count".into(), high_risk_targets.to_string());
        base_meta.insert(
            "passive.ntlm_hash_leak_likelihood".into(),
            ntlm_hash_likelihood(trigger_mode, max_protocol_risk, credential_leak_hits).into(),
        );
        base_meta.insert(
            "passive.preview_prone_surface".into(),
            if preview_prone_context { "true" } else { "false" }.into(),
        );
        base_meta.insert(
            "passive.preview_indexer_context_count".into(),
            preview_indexer_context_count.to_string(),
        );
        let mut sample_targets = hits.iter().map(|hit| hit.target.clone()).collect::<Vec<_>>();
        sample_targets.sort();
        sample_targets.dedup();
        base_meta.insert(
            "passive.external_targets_sample".into(),
            sample_targets.into_iter().take(6).collect::<Vec<_>>().join(", "),
        );
        let mut ntlm_hosts =
            hits.iter().filter_map(|hit| hit.ntlm_host.clone()).collect::<Vec<_>>();
        ntlm_hosts.sort();
        ntlm_hosts.dedup();
        if !ntlm_hosts.is_empty() {
            base_meta.insert(
                "passive.ntlm_hosts".into(),
                ntlm_hosts.into_iter().take(6).collect::<Vec<_>>().join(", "),
            );
        }
        let mut ntlm_shares =
            hits.iter().filter_map(|hit| hit.ntlm_share.clone()).collect::<Vec<_>>();
        ntlm_shares.sort();
        ntlm_shares.dedup();
        if !ntlm_shares.is_empty() {
            base_meta.insert(
                "passive.ntlm_shares".into(),
                ntlm_shares.into_iter().take(6).collect::<Vec<_>>().join(", "),
            );
        }
        let mut sample_normalised =
            hits.iter().map(|hit| hit.normalised_target.clone()).collect::<Vec<_>>();
        sample_normalised.sort();
        sample_normalised.dedup();
        base_meta.insert(
            "passive.external_targets_normalised".into(),
            sample_normalised.into_iter().take(6).collect::<Vec<_>>().join(", "),
        );

        let mut findings = Vec::new();
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::Actions,
            kind: "passive_external_resource_fetch".into(),
            severity: passive_fetch_severity(trigger_mode, max_protocol_risk, preview_prone_context),
            confidence: passive_fetch_confidence(trigger_mode, max_protocol_risk),
            impact: Some(passive_fetch_impact(trigger_mode, max_protocol_risk, preview_prone_context)),
            title: "Passive external resource fetch surface".into(),
            description:
                "External fetch targets were found in rendering-related PDF objects, which may trigger outbound requests during preview, indexing, or open-time processing."
                    .into(),
            objects: objects.iter().cloned().collect(),
            evidence: hits
                .iter()
                .take(8)
                .map(|hit| span_to_evidence(hit.object_span, "Passive external target context"))
                .collect(),
            remediation: Some(
                "Block external fetch in untrusted documents and inspect target paths, especially UNC/SMB references.".into(),
            ),
            meta: base_meta.clone(),
            reader_impacts: vec![
                ReaderImpact {
                    profile: ReaderProfile::Preview,
                    surface: AttackSurface::Actions,
                    severity: if preview_prone_context { Severity::Medium } else { Severity::Low },
                    impact: if preview_prone_context { Impact::Medium } else { Impact::Low },
                    note: Some(
                        "Preview/index rendering may trigger outbound fetch for linked resources."
                            .into(),
                    ),
                },
                ReaderImpact {
                    profile: ReaderProfile::Acrobat,
                    surface: AttackSurface::Actions,
                    severity: Severity::Low,
                    impact: Impact::Low,
                    note: Some(
                        "Open-time resource resolution can expand attack surface for external targets."
                            .into(),
                    ),
                },
            ],
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            position: None,
            positions: Vec::new(),
        });

        if credential_leak_hits > 0 {
            let mut meta = base_meta.clone();
            meta.insert(
                "passive.credential_leak_hit_count".into(),
                credential_leak_hits.to_string(),
            );
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Actions,
                kind: "passive_credential_leak_risk".into(),
                severity: passive_credential_severity(trigger_mode, max_protocol_risk),
                confidence: if ntlm_targets > 0 { Confidence::Strong } else { Confidence::Probable },
                impact: Some(Impact::High),
                title: "Passive credential leak risk".into(),
                description:
                    "UNC/SMB-style external targets were detected in render-time contexts and may leak credentials through implicit authentication attempts."
                        .into(),
                objects: objects.iter().cloned().collect(),
                evidence: hits
                    .iter()
                    .filter(|hit| hit.credential_leak_risk)
                    .take(8)
                    .map(|hit| span_to_evidence(hit.object_span, "Credential-leak target context"))
                    .collect(),
                remediation: Some(
                    "Treat UNC/SMB targets as high-risk and isolate document rendering from credential-bearing network contexts.".into(),
                ),
                meta,
                reader_impacts: vec![
                    ReaderImpact {
                        profile: ReaderProfile::Preview,
                        surface: AttackSurface::Actions,
                        severity: Severity::High,
                        impact: Impact::High,
                        note: Some(
                            "Preview-style rendering can trigger network resolution of UNC/SMB targets."
                                .into(),
                        ),
                    },
                    ReaderImpact {
                        profile: ReaderProfile::Acrobat,
                        surface: AttackSurface::Actions,
                        severity: Severity::Medium,
                        impact: Impact::Medium,
                        note: Some(
                            "External target resolution may expose credentials depending on host policy."
                                .into(),
                        ),
                    },
                ],
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }

        if high_risk_targets > 0 {
            let mut meta = base_meta.clone();
            meta.insert("resource.high_risk_scheme_count".into(), high_risk_targets.to_string());
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Actions,
                kind: "resource.external_reference_high_risk_scheme".into(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                impact: Some(Impact::High),
                title: "High-risk external reference scheme".into(),
                description:
                    "External references use high-risk schemes (UNC/SMB/file/data) in renderable PDF contexts."
                        .into(),
                objects: objects.iter().cloned().collect(),
                evidence: hits
                    .iter()
                    .filter(|hit| hit.high_risk_scheme)
                    .take(8)
                    .map(|hit| span_to_evidence(hit.object_span, "High-risk external scheme"))
                    .collect(),
                remediation: Some(
                    "Block high-risk external schemes in untrusted documents and isolate rendering."
                        .into(),
                ),
                meta,
                reader_impacts: vec![],
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }

        if obfuscated_targets > 0 {
            let mut meta = base_meta.clone();
            meta.insert("resource.obfuscated_target_count".into(), obfuscated_targets.to_string());
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Actions,
                kind: "resource.external_reference_obfuscated".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                impact: Some(Impact::Medium),
                title: "Obfuscated external reference target".into(),
                description:
                    "External targets include obfuscation markers (encoding/normalisation deltas)."
                        .into(),
                objects: objects.iter().cloned().collect(),
                evidence: hits
                    .iter()
                    .filter(|hit| hit.obfuscated_target)
                    .take(8)
                    .map(|hit| span_to_evidence(hit.object_span, "Obfuscated external target"))
                    .collect(),
                remediation: Some(
                    "Normalise and inspect external targets before trust decisions.".into(),
                ),
                meta,
                reader_impacts: vec![],
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }

        if !hidden_path_objects.is_empty() {
            let mut meta = base_meta.clone();
            meta.insert(
                "resource.hidden_render_path_count".into(),
                hidden_path_objects.len().to_string(),
            );
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Actions,
                kind: "resource.hidden_render_path".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                impact: Some(Impact::Medium),
                title: "Hidden resource render path".into(),
                description:
                    "Image/font objects are reachable through resource references without clear direct page ancestry."
                        .into(),
                objects: hidden_path_objects.clone(),
                evidence: hits
                    .iter()
                    .filter(|hit| hidden_path_objects.contains(&hit.object_ref))
                    .take(8)
                    .map(|hit| span_to_evidence(hit.object_span, "Hidden resource render path"))
                    .collect(),
                remediation: Some(
                    "Inspect nested resource dictionaries and form XObject chains for concealed render paths."
                        .into(),
                ),
                meta,
                reader_impacts: vec![],
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }

        if !orphaned_font_objects.is_empty() {
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::StreamsAndFilters,
                kind: "font.orphaned_but_reachable".into(),
                severity: Severity::Low,
                confidence: Confidence::Tentative,
                impact: Some(Impact::Low),
                title: "Font appears orphaned but reachable".into(),
                description:
                    "Font objects appear reachable through indirect resource chains without direct page linkage."
                        .into(),
                objects: orphaned_font_objects.clone(),
                evidence: hits
                    .iter()
                    .filter(|hit| orphaned_font_objects.contains(&hit.object_ref))
                    .take(8)
                    .map(|hit| span_to_evidence(hit.object_span, "Orphaned font resource path"))
                    .collect(),
                remediation: Some(
                    "Trace resource inheritance and nested forms to verify expected font linkage.".into(),
                ),
                meta: HashMap::new(),
                reader_impacts: vec![],
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }

        if !orphaned_image_objects.is_empty() {
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Images,
                kind: "image.orphaned_but_reachable".into(),
                severity: Severity::Low,
                confidence: Confidence::Tentative,
                impact: Some(Impact::Low),
                title: "Image appears orphaned but reachable".into(),
                description:
                    "Image objects appear reachable through indirect resource chains without direct page linkage."
                        .into(),
                objects: orphaned_image_objects.clone(),
                evidence: hits
                    .iter()
                    .filter(|hit| orphaned_image_objects.contains(&hit.object_ref))
                    .take(8)
                    .map(|hit| span_to_evidence(hit.object_span, "Orphaned image resource path"))
                    .collect(),
                remediation: Some(
                    "Trace resource inheritance and nested forms to verify expected image linkage.".into(),
                ),
                meta: HashMap::new(),
                reader_impacts: vec![],
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }

        if hits.len() >= 2 && preview_prone_context && has_automatic_trigger {
            let mut meta = base_meta;
            meta.insert(
                "passive.composite_rule".into(),
                "auto_trigger+preview_context+external_targets".into(),
            );
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Actions,
                kind: "passive_render_pipeline_risk_composite".into(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                impact: Some(Impact::High),
                title: "Passive render pipeline exploitation chain".into(),
                description:
                    "Automatic trigger pathways, preview-prone contexts, and external fetch targets co-occur, consistent with passive render-pipeline exploitation techniques."
                        .into(),
                objects: objects.into_iter().collect(),
                evidence: hits
                    .iter()
                    .take(8)
                    .map(|hit| span_to_evidence(hit.object_span, "Passive render composite context"))
                    .collect(),
                remediation: Some(
                    "Apply strict render isolation, block outbound fetch from document renderers, and treat this document as high-risk.".into(),
                ),
                meta,
                reader_impacts: vec![
                    ReaderImpact {
                        profile: ReaderProfile::Preview,
                        surface: AttackSurface::Actions,
                        severity: Severity::High,
                        impact: Impact::High,
                        note: Some(
                            "Preview and indexing surfaces are likely to trigger passive execution pathways."
                                .into(),
                        ),
                    },
                    ReaderImpact {
                        profile: ReaderProfile::Pdfium,
                        surface: AttackSurface::Actions,
                        severity: Severity::Medium,
                        impact: Impact::Medium,
                        note: Some(
                            "Renderer behaviour may vary; treat differential fetch behaviour as suspicious."
                                .into(),
                        ),
                    },
                ],
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }

        Ok(findings)
    }
}

fn classify_context(dict: &PdfDict<'_>) -> String {
    if is_action_dict(dict) {
        return "action".into();
    }
    if is_font_related(dict) {
        return "font".into();
    }
    if is_image_related(dict) {
        return "image".into();
    }
    if dict.get_first(b"/XFA").is_some() || dict.get_first(b"/AcroForm").is_some() {
        return "forms".into();
    }
    if dict.get_first(b"/Metadata").is_some() {
        return "metadata".into();
    }
    "other".into()
}

fn is_action_dict(dict: &PdfDict<'_>) -> bool {
    if let Some((_, s_obj)) = dict.get_first(b"/S") {
        if let PdfAtom::Name(name) = &s_obj.atom {
            return matches!(
                name.decoded.as_slice(),
                b"/URI" | b"/Launch" | b"/SubmitForm" | b"/GoToR"
            );
        }
    }
    false
}

fn is_font_related(dict: &PdfDict<'_>) -> bool {
    dict.get_first(b"/FontFile").is_some()
        || dict.get_first(b"/FontFile2").is_some()
        || dict.get_first(b"/FontFile3").is_some()
        || dict.get_first(b"/BaseFont").is_some()
}

fn is_image_related(dict: &PdfDict<'_>) -> bool {
    if let Some((_, subtype_obj)) = dict.get_first(b"/Subtype") {
        if let PdfAtom::Name(name) = &subtype_obj.atom {
            return name.decoded.as_slice() == b"/Image";
        }
    }
    false
}

fn collect_external_targets(
    dict: &PdfDict<'_>,
    context: &str,
    object_id: (u32, u16),
    object_ref: &str,
    object_span: sis_pdf_pdf::span::Span,
    out: &mut Vec<ExternalTargetHit>,
) {
    for key in [
        b"/URI".as_slice(),
        b"/F".as_slice(),
        b"/UF".as_slice(),
        b"/FS".as_slice(),
        b"/Dest".as_slice(),
    ] {
        if let Some((_, value)) = dict.get_first(key) {
            if let Some(target) = extract_text_target(value) {
                if let Some(normalised) = normalise_external_target(&target) {
                    if let Some(protocol) = normalised.protocol.as_deref() {
                        out.push(ExternalTargetHit {
                            object_id,
                            object_ref: object_ref.to_string(),
                            object_span,
                            source_key: String::from_utf8_lossy(key).to_string(),
                            source_context: context.to_string(),
                            credential_leak_risk: normalised.credential_leak_risk,
                            ntlm_host: normalised.ntlm_host,
                            ntlm_share: normalised.ntlm_share,
                            high_risk_scheme: normalised.high_risk_scheme,
                            obfuscated_target: normalised.obfuscated,
                            normalised_target: normalised.normalised,
                            target: normalised.original,
                            protocol: protocol.to_string(),
                        });
                    }
                }
            }
        }
    }
}

fn protocol_risk_class(protocol: &str) -> ProtocolRiskClass {
    match protocol {
        "unc" | "smb" | "file" => ProtocolRiskClass::High,
        "ftp" => ProtocolRiskClass::Medium,
        "http" => ProtocolRiskClass::Low,
        _ => ProtocolRiskClass::Low,
    }
}

fn passive_fetch_severity(
    trigger_mode: PassiveTriggerMode,
    max_protocol_risk: ProtocolRiskClass,
    preview_prone_context: bool,
) -> Severity {
    if trigger_mode == PassiveTriggerMode::AutomaticOrAa
        && max_protocol_risk == ProtocolRiskClass::High
    {
        Severity::High
    } else if trigger_mode == PassiveTriggerMode::AutomaticOrAa
        || (preview_prone_context && max_protocol_risk == ProtocolRiskClass::High)
    {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn passive_fetch_confidence(
    trigger_mode: PassiveTriggerMode,
    max_protocol_risk: ProtocolRiskClass,
) -> Confidence {
    if trigger_mode == PassiveTriggerMode::AutomaticOrAa
        && max_protocol_risk == ProtocolRiskClass::High
    {
        Confidence::Strong
    } else if trigger_mode == PassiveTriggerMode::PassiveRenderOrIndexer {
        Confidence::Probable
    } else {
        Confidence::Strong
    }
}

fn passive_fetch_impact(
    trigger_mode: PassiveTriggerMode,
    max_protocol_risk: ProtocolRiskClass,
    preview_prone_context: bool,
) -> Impact {
    match max_protocol_risk {
        ProtocolRiskClass::High => {
            if trigger_mode == PassiveTriggerMode::AutomaticOrAa {
                Impact::High
            } else {
                Impact::Medium
            }
        }
        ProtocolRiskClass::Medium => Impact::Medium,
        ProtocolRiskClass::Low => {
            if preview_prone_context {
                Impact::Medium
            } else {
                Impact::Low
            }
        }
    }
}

fn passive_credential_severity(
    trigger_mode: PassiveTriggerMode,
    max_protocol_risk: ProtocolRiskClass,
) -> Severity {
    if trigger_mode == PassiveTriggerMode::AutomaticOrAa
        && max_protocol_risk == ProtocolRiskClass::High
    {
        Severity::High
    } else {
        Severity::Medium
    }
}

fn ntlm_hash_likelihood(
    trigger_mode: PassiveTriggerMode,
    max_protocol_risk: ProtocolRiskClass,
    credential_leak_hits: usize,
) -> &'static str {
    if credential_leak_hits == 0 {
        "low"
    } else if trigger_mode == PassiveTriggerMode::AutomaticOrAa
        && max_protocol_risk == ProtocolRiskClass::High
    {
        "high"
    } else {
        "elevated"
    }
}

fn render_breakdown(counts: &HashMap<String, usize>) -> String {
    let mut entries = counts.iter().collect::<Vec<_>>();
    entries.sort_by(|(lhs_key, _), (rhs_key, _)| lhs_key.cmp(rhs_key));
    entries
        .into_iter()
        .map(|(key, count)| format!("{}={}", key, count))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::{classify_context, render_breakdown, PassiveTriggerMode};
    use crate::external_target::classify_protocol;
    use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfName, PdfObj};
    use sis_pdf_pdf::span::Span;
    use std::borrow::Cow;
    use std::collections::HashMap;

    fn span() -> Span {
        Span { start: 0, end: 0 }
    }

    fn name(value: &'static str) -> PdfName<'static> {
        let bytes = value.as_bytes();
        PdfName { span: span(), raw: Cow::Borrowed(bytes), decoded: bytes.to_vec() }
    }

    #[test]
    fn protocol_classifier_recognises_unc_and_http() {
        assert_eq!(classify_protocol("\\\\host\\share\\file"), Some("unc"));
        assert_eq!(classify_protocol("SMB://example/share"), Some("smb"));
        assert_eq!(classify_protocol("https://example.test"), Some("http"));
        assert_eq!(classify_protocol("relative/path"), None);
    }

    #[test]
    fn classify_context_detects_action_dict() {
        let dict = PdfDict {
            span: span(),
            entries: vec![(name("/S"), PdfObj { span: span(), atom: PdfAtom::Name(name("/URI")) })],
        };
        assert_eq!(classify_context(&dict), "action");
    }

    #[test]
    fn passive_trigger_mode_strings_are_stable() {
        assert_eq!(PassiveTriggerMode::AutomaticOrAa.as_str(), "automatic_or_aa");
        assert_eq!(
            PassiveTriggerMode::PassiveRenderOrIndexer.as_str(),
            "passive_render_or_indexer"
        );
        assert_eq!(PassiveTriggerMode::ManualOrUnknown.as_str(), "manual_or_unknown");
    }

    #[test]
    fn render_breakdown_is_stable() {
        let mut counts = HashMap::new();
        counts.insert("font".to_string(), 2);
        counts.insert("action".to_string(), 1);
        assert_eq!(render_breakdown(&counts), "action=1, font=2");
    }
}

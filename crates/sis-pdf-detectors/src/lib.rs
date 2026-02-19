#![forbid(unsafe_code)]

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::collections::{BTreeSet, HashSet};
use std::str;

use crate::encryption_obfuscation::{encryption_meta_from_dict, resolve_encrypt_dict};
use sha2::{Digest, Sha256};
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::embedded_index::{build_embedded_artefact_index, EmbeddedArtefactRef};
use sis_pdf_core::evidence::{decoded_evidence_span, preview_ascii, EvidenceBuilder};
use sis_pdf_core::model::{
    AttackSurface, Confidence, Finding, Impact, ReaderImpact, ReaderProfile, Severity,
};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_core::stream_analysis::{analyse_stream, StreamLimits};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::blob_classify::{classify_blob, BlobKind};
use sis_pdf_pdf::classification::ObjectRole;
use sis_pdf_pdf::decode::stream_filters;
use sis_pdf_pdf::graph::{Deviation, ObjEntry, ObjProvenance, XrefSectionSummary};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfName, PdfObj, PdfStream};
use sis_pdf_pdf::xfa::extract_xfa_script_payloads;
use std::time::Duration;

pub mod actions_triggers;
pub mod advanced_crypto;
pub mod annotations_advanced;
pub mod content_first;
pub mod content_phishing;
pub mod encryption_obfuscation;
pub mod evasion_env;
pub mod evasion_time;
pub mod external_context;
pub mod external_target;
pub mod filter_chain_anomaly;
pub mod filter_depth;
pub mod font_exploits;
pub mod font_external_ref;
pub mod icc_profiles;
pub mod image_analysis;
pub mod ir_graph_static;
pub mod js_polymorphic;
#[cfg(feature = "js-sandbox")]
pub mod js_sandbox;
pub mod linearization;
pub mod metadata_analysis;
pub mod multi_stage;
pub mod object_cycles;
pub mod objstm_summary;
pub mod objstm_torture;
pub mod page_tree_anomalies;
pub mod parser_divergence;
pub mod passive_render_pipeline;
pub mod polyglot;
pub mod quantum_risk;
pub mod renderer_divergence;
pub mod resource_usage_semantics;
pub mod revision_forensics;
pub mod rich_media_analysis;
pub mod shadow_attacks;
pub mod strict;
pub mod structural_anomalies;
pub mod supply_chain;
pub mod telemetry_bridge;
pub mod uri_classification;
pub mod vector_graphics;
pub mod xfa_forms;
pub mod xref_deviation;

#[derive(Clone, Copy)]
pub struct DetectorSettings {
    pub js_ast: bool,
    pub js_sandbox: bool,
}

impl Default for DetectorSettings {
    fn default() -> Self {
        Self { js_ast: true, js_sandbox: true }
    }
}

pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    default_detectors_with_settings(DetectorSettings::default())
}

pub fn default_detectors_with_settings(settings: DetectorSettings) -> Vec<Box<dyn Detector>> {
    #[allow(unused_mut)]
    let mut detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(polyglot::PolyglotDetector),
        Box::new(XrefConflictDetector),
        Box::new(IncrementalUpdateDetector),
        Box::new(ObjectIdShadowingDetector),
        Box::new(ShadowObjectDivergenceDetector),
        Box::new(shadow_attacks::ShadowAttackDetector),
        Box::new(revision_forensics::RevisionForensicsDetector),
        Box::new(linearization::LinearizationDetector),
        Box::new(parser_divergence::ParserDivergenceDetector),
        Box::new(renderer_divergence::RendererDivergenceDetector),
        Box::new(ObjStmDensityDetector),
        Box::new(objstm_summary::ObjStmSummaryDetector),
        Box::new(OpenActionDetector),
        Box::new(AAPresentDetector),
        Box::new(AAEventDetector),
        Box::new(actions_triggers::ActionTriggerDetector),
        Box::new(JavaScriptDetector { enable_ast: settings.js_ast }),
        Box::new(js_polymorphic::JsPolymorphicDetector { enable_ast: settings.js_ast }),
        Box::new(evasion_time::TimingEvasionDetector),
        Box::new(evasion_env::EnvProbeDetector),
        Box::new(supply_chain::SupplyChainDetector),
        Box::new(advanced_crypto::AdvancedCryptoDetector),
        Box::new(multi_stage::MultiStageDetector),
        Box::new(content_first::ContentFirstDetector),
        Box::new(quantum_risk::QuantumRiskDetector),
        Box::new(LaunchActionDetector),
        Box::new(GoToRDetector),
        Box::new(ActionRemoteTargetSuspiciousDetector),
        Box::new(uri_classification::UriPresenceDetector),
        Box::new(uri_classification::UriContentDetector),
        Box::new(SubmitFormDetector),
        Box::new(external_context::ExternalActionContextDetector),
        Box::new(passive_render_pipeline::PassiveRenderPipelineDetector),
        Box::new(resource_usage_semantics::ResourceUsageSemanticsDetector),
        Box::new(FontMatrixDetector),
        Box::new(PdfjsFontInjectionDetector),
        Box::new(FontJsExploitationBridgeDetector { enable_ast: settings.js_ast }),
        Box::new(PdfjsRenderingIndicatorDetector),
        Box::new(ScatteredPayloadAssemblyDetector),
        Box::new(CrossStreamPayloadAssemblyDetector),
        Box::new(font_exploits::FontExploitDetector),
        Box::new(font_external_ref::FontExternalReferenceDetector),
        Box::new(image_analysis::ImageAnalysisDetector),
        Box::new(vector_graphics::VectorGraphicsDetector),
        Box::new(EmbeddedFileDetector),
        Box::new(RichMediaDetector),
        Box::new(rich_media_analysis::RichMediaContentDetector),
        Box::new(ThreeDDetector),
        Box::new(SoundMovieDetector),
        Box::new(FileSpecDetector),
        Box::new(icc_profiles::ICCProfileDetector),
        Box::new(annotations_advanced::AnnotationAttackDetector),
        Box::new(page_tree_anomalies::PageTreeManipulationDetector),
        Box::new(object_cycles::ObjectReferenceCycleDetector),
        Box::new(NullRefChainTerminationDetector),
        Box::new(CryptoDetector),
        Box::new(encryption_obfuscation::EncryptionObfuscationDetector),
        Box::new(XfaDetector),
        Box::new(AcroFormDetector),
        Box::new(FormFieldOversizedValueDetector),
        Box::new(xfa_forms::XfaFormDetector),
        Box::new(OCGDetector),
        Box::new(filter_depth::FilterChainDepthDetector),
        Box::new(filter_chain_anomaly::FilterChainAnomalyDetector),
        Box::new(DecoderRiskDetector),
        Box::new(DecompressionRatioDetector),
        Box::new(HugeImageDetector),
        Box::new(content_phishing::ContentPhishingDetector),
        Box::new(content_phishing::ContentDeceptionDetector),
        Box::new(metadata_analysis::MetadataAnalysisDetector),
        Box::new(ObfuscatedNameEncodingDetector),
        Box::new(PdfStringHexEncodedDetector),
        Box::new(strict::StrictParseDeviationDetector),
        Box::new(telemetry_bridge::TelemetryBridgeDetector),
        Box::new(ir_graph_static::IrGraphStaticDetector),
        Box::new(structural_anomalies::StructuralAnomaliesDetector),
        Box::new(xref_deviation::XrefTrailerSearchDetector),
        Box::new(objstm_torture::ObjStmTortureDetector),
    ];
    if settings.js_sandbox {
        #[cfg(feature = "js-sandbox")]
        detectors.push(Box::new(js_sandbox::JavaScriptSandboxDetector));
    }
    detectors
}

pub fn sandbox_available() -> bool {
    cfg!(feature = "js-sandbox")
}

pub fn sandbox_summary(requested: bool) -> sis_pdf_core::report::SandboxSummary {
    if !requested {
        return sis_pdf_core::report::SandboxSummary {
            enabled: false,
            disabled_reason: Some("disabled by --no-js-sandbox".into()),
        };
    }
    if !sandbox_available() {
        return sis_pdf_core::report::SandboxSummary {
            enabled: false,
            disabled_reason: Some("not compiled (js-sandbox feature disabled)".into()),
        };
    }
    sis_pdf_core::report::SandboxSummary { enabled: true, disabled_reason: None }
}

struct XrefConflictDetector;
struct ObfuscatedNameEncodingDetector;
struct PdfStringHexEncodedDetector;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XrefIntegrityLevel {
    Coherent,
    Warning,
    Broken,
}

impl XrefIntegrityLevel {
    fn as_str(self) -> &'static str {
        match self {
            XrefIntegrityLevel::Coherent => "coherent",
            XrefIntegrityLevel::Warning => "warning",
            XrefIntegrityLevel::Broken => "broken",
        }
    }
}

#[derive(Clone, Debug)]
struct XrefConflictAssessment {
    severity: Severity,
    description: String,
    integrity: XrefIntegrityLevel,
    prev_chain_valid: bool,
    prev_chain_length: usize,
    prev_chain_cycle: bool,
    offsets_in_bounds: bool,
    deviation_count: usize,
    deviation_kinds: String,
    section_count: usize,
    section_kinds: String,
}

fn assess_xref_conflict(
    bytes_len: usize,
    startxrefs: &[u64],
    sections: &[XrefSectionSummary],
    deviations: &[Deviation],
    has_signature: bool,
) -> XrefConflictAssessment {
    let startxref_count = startxrefs.len();
    let section_count = sections.len();
    let offsets_in_bounds = startxrefs.iter().all(|offset| *offset < bytes_len as u64)
        && sections.iter().all(|section| section.offset < bytes_len as u64);

    let mut section_kinds = sections.iter().map(|section| section.kind.clone()).collect::<Vec<_>>();
    section_kinds.sort();
    section_kinds.dedup();
    let section_kinds_joined = section_kinds.join(",");
    let has_unknown_section_kind =
        section_kinds.iter().any(|kind| kind.eq_ignore_ascii_case("unknown"));

    let xref_deviations = deviations
        .iter()
        .filter(|deviation| deviation.kind.starts_with("xref_"))
        .collect::<Vec<_>>();
    let deviation_count = xref_deviations.len();
    let mut deviation_kinds =
        xref_deviations.iter().map(|deviation| deviation.kind.clone()).collect::<Vec<_>>();
    deviation_kinds.sort();
    deviation_kinds.dedup();
    let deviation_kinds_joined = deviation_kinds.join(",");

    let offset_set = sections.iter().map(|section| section.offset).collect::<HashSet<_>>();
    let prev_links_resolvable =
        sections.iter().filter_map(|section| section.prev).all(|prev| offset_set.contains(&prev));

    let mut prev_map = std::collections::HashMap::new();
    for section in sections {
        prev_map.insert(section.offset, section.prev);
    }
    let mut visited = HashSet::new();
    let mut prev_chain_cycle = false;
    let mut prev_chain_length = 0usize;
    let mut current = sections.first().map(|section| section.offset);
    while let Some(offset) = current {
        if !visited.insert(offset) {
            prev_chain_cycle = true;
            break;
        }
        prev_chain_length += 1;
        current = prev_map.get(&offset).copied().flatten();
    }
    let chain_covers_sections = sections.is_empty() || prev_chain_length == sections.len();
    let prev_chain_valid = prev_links_resolvable && !prev_chain_cycle && chain_covers_sections;

    let mut trailer_roots = sections
        .iter()
        .filter_map(|section| section.trailer_root.as_ref())
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    trailer_roots.sort();
    trailer_roots.dedup();
    let root_mismatch = trailer_roots.len() > 1;

    let integrity = if !offsets_in_bounds || !prev_links_resolvable || prev_chain_cycle {
        XrefIntegrityLevel::Broken
    } else if deviation_count > 0 || has_unknown_section_kind || root_mismatch || !prev_chain_valid
    {
        XrefIntegrityLevel::Warning
    } else {
        XrefIntegrityLevel::Coherent
    };

    let severity = if startxref_count <= 1 {
        Severity::Info
    } else if section_count <= 1 {
        Severity::Info
    } else {
        match integrity {
            XrefIntegrityLevel::Coherent => {
                if has_signature {
                    Severity::Info
                } else {
                    Severity::Low
                }
            }
            XrefIntegrityLevel::Warning => Severity::Medium,
            XrefIntegrityLevel::Broken => {
                if prev_chain_cycle && deviation_count > 0 {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
        }
    };

    let description = match integrity {
        XrefIntegrityLevel::Coherent => format!(
            "Found {startxref_count} startxref markers; xref chain is coherent across {section_count} linked sections."
        ),
        XrefIntegrityLevel::Warning => format!(
            "Found {startxref_count} startxref markers; xref chain has integrity warnings (prev_chain_valid={prev_chain_valid}, deviations={deviation_count})."
        ),
        XrefIntegrityLevel::Broken => format!(
            "Found {startxref_count} startxref markers; xref chain integrity is broken (prev_chain_valid={prev_chain_valid}, cycle={prev_chain_cycle}, offsets_in_bounds={offsets_in_bounds})."
        ),
    };

    XrefConflictAssessment {
        severity,
        description,
        integrity,
        prev_chain_valid,
        prev_chain_length,
        prev_chain_cycle,
        offsets_in_bounds,
        deviation_count,
        deviation_kinds: deviation_kinds_joined,
        section_count,
        section_kinds: section_kinds_joined,
    }
}

impl Detector for XrefConflictDetector {
    fn id(&self) -> &'static str {
        "xref_conflict"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::XRefTrailer
    }
    fn needs(&self) -> Needs {
        Needs::XREF
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        if ctx.graph.startxrefs.len() > 1 {
            // Check if document has signatures (legitimate multi-author scenario)
            let has_signature = ctx.graph.objects.iter().any(|entry| {
                if let Some(dict) = entry_dict(entry) {
                    dict.get_first(b"/ByteRange").is_some() || dict.has_name(b"/Type", b"/Sig")
                } else {
                    false
                }
            });

            let assessment = assess_xref_conflict(
                ctx.bytes.len(),
                &ctx.graph.startxrefs,
                &ctx.graph.xref_sections,
                &ctx.graph.deviations,
                has_signature,
            );
            let mut meta = std::collections::HashMap::new();
            meta.insert("xref.startxref_count".into(), ctx.graph.startxrefs.len().to_string());
            meta.insert("xref.startxref.count".into(), ctx.graph.startxrefs.len().to_string());
            meta.insert("xref.section.count".into(), assessment.section_count.to_string());
            meta.insert("xref.prev_chain.valid".into(), assessment.prev_chain_valid.to_string());
            meta.insert("xref.prev_chain.length".into(), assessment.prev_chain_length.to_string());
            meta.insert("xref.prev_chain.cycle".into(), assessment.prev_chain_cycle.to_string());
            meta.insert("xref.offsets.in_bounds".into(), assessment.offsets_in_bounds.to_string());
            meta.insert("xref.deviation.count".into(), assessment.deviation_count.to_string());
            meta.insert("xref.integrity.level".into(), assessment.integrity.as_str().to_string());
            meta.insert("xref.has_signature".into(), has_signature.to_string());
            let offsets = ctx
                .graph
                .startxrefs
                .iter()
                .map(|offset| offset.to_string())
                .collect::<Vec<_>>()
                .join(",");
            meta.insert("xref.offsets".into(), offsets);
            if !assessment.section_kinds.is_empty() {
                meta.insert("xref.section_kinds".into(), assessment.section_kinds.clone());
                meta.insert("xref.section.kinds".into(), assessment.section_kinds.clone());
            }
            if !assessment.deviation_kinds.is_empty() {
                meta.insert("xref.deviation.kinds".into(), assessment.deviation_kinds.clone());
            }
            meta.insert(
                "query.next".into(),
                "xref.sections; xref.trailers; xref.deviations; revisions".into(),
            );

            let evidence = keyword_evidence(ctx.bytes, b"startxref", "startxref marker", 5);
            Ok(vec![Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "xref_conflict".into(),
                severity: assessment.severity,
                confidence: Confidence::Probable,
                impact: None,
                title: "Multiple startxref entries".into(),
                description: assessment.description,
                objects: vec!["xref".into()],
                evidence,
                remediation: Some(
                    "Inspect xref sections, trailer chain, and deviations; prioritise broken /Prev chains and offset anomalies."
                        .into(),
                ),
                meta,
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            }])
        } else {
            Ok(Vec::new())
        }
    }
}

struct IncrementalUpdateDetector;

impl Detector for IncrementalUpdateDetector {
    fn id(&self) -> &'static str {
        "incremental_update_chain"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::XRefTrailer
    }
    fn needs(&self) -> Needs {
        Needs::XREF
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        if ctx.graph.startxrefs.len() > 1 {
            let evidence = keyword_evidence(ctx.bytes, b"startxref", "startxref marker", 5);
            let mut meta = std::collections::HashMap::new();
            meta.insert("xref.startxref_count".into(), ctx.graph.startxrefs.len().to_string());
            meta.insert(
                "xref.offsets".into(),
                ctx.graph
                    .startxrefs
                    .iter()
                    .map(|offset| offset.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
            Ok(vec![Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "incremental_update_chain".into(),
                severity: Severity::Low,
                confidence: Confidence::Probable,
                impact: None,
                title: "Incremental update chain present".into(),
                description: format!(
                    "PDF contains {} startxref markers suggesting incremental updates.",
                    ctx.graph.startxrefs.len()
                ),
                objects: vec!["xref".into()],
                evidence,
                remediation: Some("Review changes between revisions for hidden content.".into()),
                meta,

                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            }])
        } else {
            Ok(Vec::new())
        }
    }
}

struct ObjectIdShadowingDetector;

impl Detector for ObjectIdShadowingDetector {
    fn id(&self) -> &'static str {
        "object_id_shadowing"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::FileStructure
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let classifications = ctx.classifications();
        if !classifications.values().any(|c| c.has_role(ObjectRole::EmbeddedFile)) {
            return Ok(Vec::new());
        }
        let mut findings = Vec::new();

        // Count total shadowing instances across document
        let shadowing_count = ctx.graph.index.iter().filter(|(_, idxs)| idxs.len() > 1).count();

        // Determine severity based on count (benign incremental updates have low counts)
        let base_severity = match shadowing_count {
            0..=10 => Severity::Info,
            11..=50 => Severity::Low,
            51..=100 => Severity::Medium,
            _ => Severity::High,
        };

        for ((obj, gen), idxs) in &ctx.graph.index {
            if idxs.len() > 1 {
                let mut objects = Vec::new();
                let mut evidence = Vec::new();
                for idx in idxs {
                    if let Some(entry) = ctx.graph.objects.get(*idx) {
                        objects.push(format!("{} {} obj", obj, gen));
                        evidence.push(span_to_evidence(entry.full_span, "Object span"));
                    }
                }
                let mut meta = std::collections::HashMap::new();
                meta.insert("shadowing.total_count".into(), shadowing_count.to_string());
                meta.insert("shadowing.this_object_count".into(), idxs.len().to_string());

                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "object_id_shadowing".into(),
                    severity: base_severity,
                    confidence: Confidence::Probable,
            impact: None,
                    title: "Duplicate object IDs detected".into(),
                    description: format!(
                        "Object {} {} appears {} times ({} total shadowed objects); later revisions may shadow earlier content.",
                        obj,
                        gen,
                        idxs.len(),
                        shadowing_count
                    ),
                    objects,
                    evidence,
                    remediation: Some("Compare object bodies across revisions.".into()),
                    meta,
                    yara: None,
        position: None,
        positions: Vec::new(),
                ..Finding::default()
                });
            }
        }
        Ok(findings)
    }
}

struct ShadowObjectDivergenceDetector;

impl Detector for ShadowObjectDivergenceDetector {
    fn id(&self) -> &'static str {
        "shadow_object_payload_divergence"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::FileStructure
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Moderate
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let classifications = ctx.classifications();
        if !classifications.values().any(|c| c.has_role(ObjectRole::LaunchTarget)) {
            return Ok(Vec::new());
        }
        let mut findings = Vec::new();
        for ((obj, gen), idxs) in &ctx.graph.index {
            if idxs.len() <= 1 {
                continue;
            }
            let mut evidence = Vec::new();
            let mut kinds = HashSet::new();
            let mut hashes = HashSet::new();
            let mut provenance = Vec::new();
            let mut carved = 0usize;
            let mut non_carved = 0usize;

            for idx in idxs {
                let Some(entry) = ctx.graph.objects.get(*idx) else {
                    continue;
                };
                evidence.push(span_to_evidence(entry.full_span, "Shadowed object span"));
                provenance.push(provenance_label(entry.provenance));
                if matches!(entry.provenance, ObjProvenance::CarvedStream { .. }) {
                    carved += 1;
                } else {
                    non_carved += 1;
                }
                if let Some(payload) = entry_payload_bytes(ctx.bytes, entry) {
                    let kind = classify_blob(payload);
                    if kind != BlobKind::Unknown {
                        kinds.insert(kind.as_str().to_string());
                    }
                    hashes.insert(hash_bytes(payload));
                }
            }

            if kinds.len() > 1 {
                let mut meta = std::collections::HashMap::new();
                meta.insert("shadow.kinds".into(), join_list_sorted(&kinds));
                meta.insert("shadow.version_count".into(), idxs.len().to_string());
                meta.insert("shadow.provenance".into(), provenance.join(", "));
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "shadow_object_payload_divergence".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "Shadowed object payload divergence".into(),
                    description: format!(
                        "Object {} {} has multiple revisions with differing payload signatures.",
                        obj, gen
                    ),
                    objects: vec![format!("{} {} obj", obj, gen)],
                    evidence: evidence.clone(),
                    remediation: Some(
                        "Compare shadowed object revisions for concealed payloads.".into(),
                    ),
                    meta,
                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }

            if carved > 0 && non_carved > 0 && hashes.len() > 1 {
                let mut meta = std::collections::HashMap::new();
                meta.insert("parse.carved_count".into(), carved.to_string());
                meta.insert("parse.official_count".into(), non_carved.to_string());
                meta.insert("shadow.version_count".into(), idxs.len().to_string());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "parse_disagreement".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "Parser disagreement detected".into(),
                    description: format!(
                        "Carved objects disagree with parsed revisions for {} {}.",
                        obj, gen
                    ),
                    objects: vec![format!("{} {} obj", obj, gen)],
                    evidence,
                    remediation: Some(
                        "Investigate carved objects for hidden or conflicting revisions.".into(),
                    ),
                    meta,
                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }
        }
        Ok(findings)
    }
}

struct ObjStmDensityDetector;

impl Detector for ObjStmDensityDetector {
    fn id(&self) -> &'static str {
        "objstm_density_high"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::ObjectStreams
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut objstm = 0usize;
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.has_name(b"/Type", b"/ObjStm") {
                    objstm += 1;
                }
            }
        }
        if !ctx.graph.objects.is_empty() {
            let ratio = objstm as f64 / ctx.graph.objects.len() as f64;
            if ratio > 0.3 {
                let mut evidence = Vec::new();
                for entry in &ctx.graph.objects {
                    if let Some(dict) = entry_dict(entry) {
                        if dict.has_name(b"/Type", b"/ObjStm") {
                            evidence.push(span_to_evidence(entry.full_span, "ObjStm object"));
                            if evidence.len() >= 3 {
                                break;
                            }
                        }
                    }
                }
                return Ok(vec![Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "objstm_density_high".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "High object stream density".into(),
                    description: format!(
                        "{}/{} objects are /ObjStm (ratio {:.2}).",
                        objstm,
                        ctx.graph.objects.len(),
                        ratio
                    ),
                    objects: vec!["/ObjStm".into()],
                    evidence,
                    remediation: Some("Inspect object streams in deep scan.".into()),
                    meta: Default::default(),

                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                }]);
            }
        }
        Ok(Vec::new())
    }
}

struct OpenActionDetector;

impl Detector for OpenActionDetector {
    fn id(&self) -> &'static str {
        "open_action_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if let Some((k, v)) = dict.get_first(b"/OpenAction") {
                    let mut evidence = Vec::new();
                    evidence.push(span_to_evidence(k.span, "Key /OpenAction"));
                    evidence.push(span_to_evidence(v.span, "OpenAction value"));
                    let mut meta = std::collections::HashMap::new();
                    if let Some(details) = resolve_action_details(ctx, v) {
                        evidence.extend(details.evidence);
                        meta.extend(details.meta);
                    }
                    meta.insert("action.trigger".into(), "OpenAction".into());
                    meta.insert("action.trigger_event".into(), "OpenAction".into());
                    meta.insert("action.trigger_event_normalised".into(), "/OpenAction".into());
                    meta.insert("action.trigger_type".into(), "automatic".into());
                    meta.insert("action.trigger_context".into(), "open_action".into());
                    meta.insert("chain.stage".into(), "execute".into());
                    meta.insert("chain.capability".into(), "action_trigger_chain".into());
                    meta.insert("chain.trigger".into(), "open_action".into());
                    let action_type =
                        meta.get("action.s").cloned().unwrap_or_else(|| "/OpenAction".into());
                    let target = action_target_from_meta(&meta);
                    annotate_action_meta(&mut meta, &action_type, target.as_deref(), "automatic");
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "open_action_present".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Strong,
                        impact: None,
                        title: "Document OpenAction present".into(),
                        description: "OpenAction triggers when the PDF opens.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence,
                        remediation: Some(
                            "Validate the action target and disable auto-run.".into(),
                        ),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(findings)
    }
}

struct AAPresentDetector;

impl Detector for AAPresentDetector {
    fn id(&self) -> &'static str {
        "aa_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if let Some((k, v)) = dict.get_first(b"/AA") {
                    let mut evidence = Vec::new();
                    evidence.push(span_to_evidence(k.span, "Key /AA"));
                    evidence.push(span_to_evidence(v.span, "Value /AA"));
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("action.trigger".into(), "AA".into());
                    meta.insert("action.trigger_event".into(), "AA".into());
                    meta.insert("action.trigger_event_normalised".into(), "/AA".into());
                    meta.insert("action.trigger_type".into(), "mixed".into());
                    meta.insert("action.trigger_context".into(), "aa".into());
                    meta.insert("chain.stage".into(), "execute".into());
                    meta.insert("chain.capability".into(), "action_trigger_chain".into());
                    meta.insert("chain.trigger".into(), "additional_action".into());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "aa_present".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Strong,
                        impact: None,
                        title: "Additional Actions present".into(),
                        description: "Additional Actions can execute on user events.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence,
                        remediation: Some("Review event actions for unsafe behavior.".into()),
                        meta,

                        reader_impacts: Vec::new(),
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }
        }
        Ok(findings)
    }
}

struct AAEventDetector;

impl Detector for AAEventDetector {
    fn id(&self) -> &'static str {
        "aa_event_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let annot_parents = sis_pdf_core::page_tree::build_annotation_parent_map(&ctx.graph);
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if let Some((_, aa_obj)) = dict.get_first(b"/AA") {
                    if let PdfAtom::Dict(aa_dict) = &aa_obj.atom {
                        for (k, v) in &aa_dict.entries {
                            let mut meta = std::collections::HashMap::new();
                            let event_key = String::from_utf8_lossy(&k.decoded).to_string();
                            let trigger_type = if is_automatic_aa_event(k.decoded.as_slice()) {
                                "automatic"
                            } else {
                                "user"
                            };
                            meta.insert("aa.event_key".into(), event_key.clone());
                            meta.insert("action.trigger".into(), event_key.clone());
                            meta.insert("action.trigger_event".into(), event_key.clone());
                            meta.insert(
                                "action.trigger_event_normalised".into(),
                                normalise_action_trigger_event(&event_key),
                            );
                            meta.insert("action.trigger_type".into(), trigger_type.into());
                            meta.insert("action.trigger_context".into(), "aa".into());
                            meta.insert("chain.stage".into(), "execute".into());
                            meta.insert("chain.capability".into(), "action_trigger_chain".into());
                            meta.insert("chain.trigger".into(), "additional_action".into());
                            if let Some(page) =
                                annot_parents.get(&sis_pdf_core::graph_walk::ObjRef {
                                    obj: entry.obj,
                                    gen: entry.gen,
                                })
                            {
                                meta.insert("page.number".into(), page.number.to_string());
                                meta.insert(
                                    "page.object".into(),
                                    format!("{} {} obj", page.obj, page.gen),
                                );
                            }
                            let mut evidence = vec![
                                span_to_evidence(k.span, "AA event key"),
                                span_to_evidence(v.span, "AA event value"),
                            ];
                            if let Some(details) = resolve_action_details(ctx, v) {
                                evidence.extend(details.evidence);
                                meta.extend(details.meta);
                            }
                            let action_type =
                                meta.get("action.s").cloned().unwrap_or_else(|| event_key.clone());
                            let target = action_target_from_meta(&meta);
                            annotate_action_meta(
                                &mut meta,
                                &action_type,
                                target.as_deref(),
                                trigger_type,
                            );
                            if let Some(value) = aa_event_value(ctx, v) {
                                meta.insert("aa.event_value".into(), value);
                            }
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "aa_event_present".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::Probable,
                                impact: None,
                                title: "AA event action present".into(),
                                description: format!(
                                    "Additional Actions event {} present.",
                                    String::from_utf8_lossy(&k.decoded)
                                ),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence,
                                remediation: Some("Inspect event-specific actions.".into()),
                                meta,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

fn aa_event_value(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
) -> Option<String> {
    if let Some(details) = resolve_action_details(ctx, obj) {
        if let Some(s) = details.meta.get("action.s") {
            if let Some(t) = details.meta.get("action.target") {
                return Some(format!("{} {}", s, t));
            }
            return Some(s.clone());
        }
    }
    match &obj.atom {
        PdfAtom::Name(n) => Some(String::from_utf8_lossy(&n.decoded).to_string()),
        _ => None,
    }
}

fn is_automatic_aa_event(name: &[u8]) -> bool {
    matches!(name, b"/O" | b"/C" | b"/PV" | b"/PI" | b"/V" | b"/PO")
}

fn normalise_action_trigger_event(event: &str) -> String {
    if event == "OpenAction" {
        return "/OpenAction".into();
    }
    if event.starts_with('/') {
        return event.to_string();
    }
    format!("/{event}")
}

/// Check if a PDF name represents a JavaScript key
/// Matches /JS, /JavaScript, /JScript (case-insensitive, handles hex encoding)
fn is_javascript_key(name: &sis_pdf_pdf::object::PdfName<'_>) -> bool {
    let decoded = &name.decoded;
    // Remove leading slash if present
    let name_str = if decoded.starts_with(b"/") { &decoded[1..] } else { decoded };

    matches!(
        name_str,
        b"JS"
            | b"js"
            | b"Js"
            | b"jS"
            | b"JavaScript"
            | b"javascript"
            | b"JAVASCRIPT"
            | b"JScript"
            | b"jscript"
            | b"JSCRIPT"
    )
}

/// Find all JavaScript key-value pairs in a dictionary
fn find_javascript_entries<'a>(
    dict: &'a sis_pdf_pdf::object::PdfDict<'a>,
) -> Vec<(&'a sis_pdf_pdf::object::PdfName<'a>, &'a sis_pdf_pdf::object::PdfObj<'a>)> {
    dict.entries.iter().filter(|(k, _)| is_javascript_key(k)).map(|(k, v)| (k, v)).collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JsPayloadSource {
    Action,
    OpenAction,
    AaEvent,
    AnnotationAction,
    NameTree,
    CatalogJs,
    Uri,
    DataUri,
    Xfa,
    EmbeddedFile,
}

impl JsPayloadSource {
    fn priority(self) -> u8 {
        match self {
            JsPayloadSource::OpenAction => 0,
            JsPayloadSource::AaEvent => 1,
            JsPayloadSource::AnnotationAction => 2,
            JsPayloadSource::NameTree => 3,
            JsPayloadSource::CatalogJs => 4,
            JsPayloadSource::Action => 5,
            JsPayloadSource::Uri => 6,
            JsPayloadSource::DataUri => 7,
            JsPayloadSource::Xfa => 8,
            JsPayloadSource::EmbeddedFile => 9,
        }
    }

    fn meta_value(self) -> Option<&'static str> {
        match self {
            JsPayloadSource::Action => Some("action"),
            JsPayloadSource::OpenAction => Some("open_action"),
            JsPayloadSource::AaEvent => Some("aa_event"),
            JsPayloadSource::AnnotationAction => Some("annotation"),
            JsPayloadSource::NameTree => Some("name_tree"),
            JsPayloadSource::CatalogJs => Some("catalog_js"),
            JsPayloadSource::Uri => Some("uri"),
            JsPayloadSource::DataUri => Some("data_uri"),
            JsPayloadSource::Xfa => Some("xfa"),
            JsPayloadSource::EmbeddedFile => Some("embedded_file"),
        }
    }
}

pub(crate) struct JsPayloadCandidate {
    payload: PayloadInfo,
    evidence: Vec<sis_pdf_core::model::EvidenceSpan>,
    key_name: String,
    source: JsPayloadSource,
    container_path: String,
}

fn javascript_uri_payload_from_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut start = 0usize;
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    let bytes = &bytes[start..];
    let prefix = b"javascript:";
    if bytes.len() < prefix.len() {
        return None;
    }
    let matches_prefix =
        bytes.iter().take(prefix.len()).zip(prefix.iter()).all(|(a, b)| a.eq_ignore_ascii_case(b));
    if !matches_prefix {
        return None;
    }
    let mut rest = &bytes[prefix.len()..];
    while !rest.is_empty() && rest[0].is_ascii_whitespace() {
        rest = &rest[1..];
    }
    Some(rest.to_vec())
}

fn data_uri_payload_from_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut start = 0usize;
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    let bytes = &bytes[start..];
    let prefix = b"data:";
    if bytes.len() < prefix.len() {
        return None;
    }
    let matches_prefix =
        bytes.iter().take(prefix.len()).zip(prefix.iter()).all(|(a, b)| a.eq_ignore_ascii_case(b));
    if !matches_prefix {
        return None;
    }
    let payload = String::from_utf8_lossy(&bytes[prefix.len()..]);
    let mut parts = payload.splitn(2, ',');
    let meta = parts.next().unwrap_or("");
    let data = parts.next().unwrap_or("");
    if data.is_empty() {
        return None;
    }
    let meta_lower = meta.to_ascii_lowercase();
    let is_javascript = meta_lower.contains("javascript") || meta_lower.contains("ecmascript");
    if !is_javascript {
        return None;
    }
    let is_base64 = meta_lower.contains(";base64");
    if is_base64 {
        STANDARD.decode(data.as_bytes()).ok()
    } else {
        Some(percent_decode_bytes(data.as_bytes()))
    }
}

fn percent_decode_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0usize;
    while i < data.len() {
        if data[i] == b'%' && i + 2 < data.len() {
            let hi = data[i + 1];
            let lo = data[i + 2];
            if let (Some(hi), Some(lo)) = (from_hex(hi), from_hex(lo)) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        b'A'..=b'F' => Some(10 + (b - b'A')),
        _ => None,
    }
}

fn infer_js_intent(
    payload_bytes: &[u8],
    signals: &std::collections::HashMap<String, String>,
) -> Option<(&'static str, &'static str, &'static str)> {
    let lower = payload_bytes.to_ascii_lowercase();

    let has_network_tokens = has_any_token(
        &lower,
        &[
            b"app.launchurl(",
            b"this.submitform(",
            b"xmlhttp",
            b"fetch(",
            b"open(",
            b"ws://",
            b"wss://",
            b"http://",
            b"https://",
        ],
    );
    let has_ast_network = signals.get("js.ast_urls").map(|v| !v.trim().is_empty()).unwrap_or(false)
        || signals.get("js.ast_domains").map(|v| !v.trim().is_empty()).unwrap_or(false)
        || matches!(signals.get("js.encoded_transmission").map(String::as_str), Some("true"));
    if has_network_tokens || has_ast_network {
        return Some((
            "network_access",
            "JavaScript appears to initiate network-capable actions.",
            "strong",
        ));
    }

    if has_any_token(&lower, &[b"app.alert(", b"confirm(", b"prompt(", b"app.response("]) {
        return Some((
            "user_interaction",
            "JavaScript appears focused on user prompt or social-engineering interaction.",
            "strong",
        ));
    }

    let has_obfuscation_tokens = has_any_token(&lower, &[b"eval(", b"unescape(", b"fromcharcode"]);
    let has_obfuscation_signals =
        matches!(signals.get("js.obfuscation_suspected").map(String::as_str), Some("true"))
            || matches!(signals.get("js.contains_eval").map(String::as_str), Some("true"));
    if has_obfuscation_tokens || has_obfuscation_signals {
        return Some((
            "obfuscation_loader",
            "JavaScript contains obfuscation or dynamic execution indicators.",
            "probable",
        ));
    }

    None
}

fn js_present_severity_from_meta(meta: &std::collections::HashMap<String, String>) -> Severity {
    let intent = meta.get("js.intent.primary").map(String::as_str);
    if matches!(intent, Some("network_access" | "obfuscation_loader")) {
        return Severity::High;
    }
    let high_risk_flags = [
        "js.sandbox_evasion",
        "js.credential_harvesting",
        "js.encoded_transmission",
        "js.dynamic_eval_construction",
        "js.obfuscation_suspected",
    ];
    if high_risk_flags.iter().any(|k| matches!(meta.get(*k).map(String::as_str), Some("true"))) {
        return Severity::High;
    }
    if matches!(intent, Some("user_interaction")) {
        return Severity::Medium;
    }
    Severity::Low
}

fn has_any_token(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|needle| !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == *needle))
}

fn dedupe_evidence_spans(
    evidence: Vec<sis_pdf_core::model::EvidenceSpan>,
) -> Vec<sis_pdf_core::model::EvidenceSpan> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for ev in evidence {
        let source = match ev.source {
            sis_pdf_core::model::EvidenceSource::File => "file",
            sis_pdf_core::model::EvidenceSource::Decoded => "decoded",
        };
        let origin_key = ev
            .origin
            .map(|origin| format!("{}-{}", origin.start, origin.end))
            .unwrap_or_else(|| "-".into());
        let key = format!("{}:{}:{}:{}", source, ev.offset, ev.length, origin_key);
        if seen.insert(key) {
            out.push(ev);
        }
    }
    out
}

fn js_payload_candidates_from_action_dict(
    ctx: &sis_pdf_core::scan::ScanContext,
    dict: &sis_pdf_pdf::object::PdfDict<'_>,
) -> Vec<JsPayloadCandidate> {
    let mut out = Vec::new();
    for (k, v) in find_javascript_entries(dict) {
        let res = resolve_payload(ctx, v);
        let Some(payload) = res.payload else {
            continue;
        };
        let evidence = vec![
            span_to_evidence(k.span, "JavaScript key"),
            span_to_evidence(v.span, "JavaScript payload"),
        ];
        let key_name = String::from_utf8_lossy(&k.decoded).to_string();
        out.push(JsPayloadCandidate {
            payload,
            evidence,
            key_name,
            source: JsPayloadSource::Action,
            container_path: "/Action/JS".into(),
        });
    }

    if let Some((k, v)) = dict.get_first(b"/URI") {
        let res = resolve_payload(ctx, v);
        let Some(mut payload) = res.payload else {
            return out;
        };
        let evidence =
            vec![span_to_evidence(k.span, "Key /URI"), span_to_evidence(v.span, "URI value")];
        if let Some(stripped) = javascript_uri_payload_from_bytes(&payload.bytes) {
            payload.bytes = stripped;
            out.push(JsPayloadCandidate {
                payload,
                evidence,
                key_name: "/URI javascript".into(),
                source: JsPayloadSource::Uri,
                container_path: "/Action/URI".into(),
            });
        } else if let Some(stripped) = data_uri_payload_from_bytes(&payload.bytes) {
            payload.bytes = stripped;
            out.push(JsPayloadCandidate {
                payload,
                evidence,
                key_name: "/URI data javascript".into(),
                source: JsPayloadSource::DataUri,
                container_path: "/Action/URI".into(),
            });
        }
    }

    out
}

fn push_action_payload_candidates_with_source(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
    source: JsPayloadSource,
    container_path: &str,
    evidence_label: &str,
    out: &mut Vec<JsPayloadCandidate>,
) {
    let mut pushed = false;
    if let PdfAtom::Ref { .. } = &obj.atom {
        if let Some(entry) = ctx.graph.resolve_ref(obj) {
            let resolved = sis_pdf_pdf::object::PdfObj { span: entry.body_span, atom: entry.atom };
            push_action_payload_candidates_with_source(
                ctx,
                &resolved,
                source,
                container_path,
                evidence_label,
                out,
            );
            pushed = true;
        }
    }
    if pushed {
        return;
    }
    let PdfAtom::Dict(dict) = &obj.atom else {
        return;
    };
    for (k, v) in find_javascript_entries(dict) {
        let res = resolve_payload(ctx, v);
        let Some(payload) = res.payload else {
            continue;
        };
        out.push(JsPayloadCandidate {
            payload,
            evidence: vec![
                span_to_evidence(k.span, "JavaScript key"),
                span_to_evidence(v.span, evidence_label),
            ],
            key_name: String::from_utf8_lossy(&k.decoded).to_string(),
            source,
            container_path: container_path.to_string(),
        });
    }
}

fn collect_name_tree_js_candidates(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
    depth: usize,
    out: &mut Vec<JsPayloadCandidate>,
) {
    if depth >= 8 {
        return;
    }
    match &obj.atom {
        PdfAtom::Ref { .. } => {
            if let Some(entry) = ctx.graph.resolve_ref(obj) {
                let resolved =
                    sis_pdf_pdf::object::PdfObj { span: entry.body_span, atom: entry.atom };
                collect_name_tree_js_candidates(ctx, &resolved, depth + 1, out);
            }
        }
        PdfAtom::Dict(dict) => {
            for (k, v) in find_javascript_entries(dict) {
                let res = resolve_payload(ctx, v);
                let Some(payload) = res.payload else {
                    continue;
                };
                out.push(JsPayloadCandidate {
                    payload,
                    evidence: vec![
                        span_to_evidence(k.span, "Name tree JavaScript key"),
                        span_to_evidence(v.span, "Name tree JavaScript payload"),
                    ],
                    key_name: String::from_utf8_lossy(&k.decoded).to_string(),
                    source: JsPayloadSource::NameTree,
                    container_path: "/Catalog/Names/JavaScript".into(),
                });
            }
            if let Some((_, names_obj)) = dict.get_first(b"/Names") {
                if let PdfAtom::Array(items) = &names_obj.atom {
                    for (index, item) in items.iter().enumerate() {
                        if index % 2 == 0 {
                            continue;
                        }
                        let res = resolve_payload(ctx, item);
                        let Some(payload) = res.payload else {
                            continue;
                        };
                        if payload.bytes.is_empty() {
                            continue;
                        }
                        out.push(JsPayloadCandidate {
                            payload,
                            evidence: vec![span_to_evidence(
                                item.span,
                                "Name tree JavaScript value",
                            )],
                            key_name: "/Names value".into(),
                            source: JsPayloadSource::NameTree,
                            container_path: "/Catalog/Names/JavaScript/Names[]".into(),
                        });
                    }
                }
            }
            if let Some((_, kids_obj)) = dict.get_first(b"/Kids") {
                if let PdfAtom::Array(items) = &kids_obj.atom {
                    for item in items {
                        collect_name_tree_js_candidates(ctx, item, depth + 1, out);
                    }
                }
            }
            if let Some((_, js_root)) = dict.get_first(b"/JavaScript") {
                collect_name_tree_js_candidates(ctx, js_root, depth + 1, out);
            }
        }
        PdfAtom::Array(items) => {
            for item in items {
                collect_name_tree_js_candidates(ctx, item, depth + 1, out);
            }
        }
        _ => {}
    }
}

pub(crate) fn js_payload_candidates_from_entry(
    ctx: &sis_pdf_core::scan::ScanContext,
    entry: &ObjEntry<'_>,
) -> Vec<JsPayloadCandidate> {
    let mut out = Vec::new();
    if let Some(dict) = entry_dict(entry) {
        out.extend(js_payload_candidates_from_action_dict(ctx, dict));
        out.extend(js_payload_candidates_from_xfa(ctx, dict));
        if dict.has_name(b"/Type", b"/Catalog") {
            for (k, v) in find_javascript_entries(dict) {
                let res = resolve_payload(ctx, v);
                let Some(payload) = res.payload else {
                    continue;
                };
                out.push(JsPayloadCandidate {
                    payload,
                    evidence: vec![
                        span_to_evidence(k.span, "Catalog JavaScript key"),
                        span_to_evidence(v.span, "Catalog JavaScript payload"),
                    ],
                    key_name: String::from_utf8_lossy(&k.decoded).to_string(),
                    source: JsPayloadSource::CatalogJs,
                    container_path: "/Catalog/JS".into(),
                });
            }
            if let Some((_, open_action)) = dict.get_first(b"/OpenAction") {
                push_action_payload_candidates_with_source(
                    ctx,
                    open_action,
                    JsPayloadSource::OpenAction,
                    "/Catalog/OpenAction/JS",
                    "OpenAction JavaScript payload",
                    &mut out,
                );
            }
            if let Some((_, names_obj)) = dict.get_first(b"/Names") {
                if let PdfAtom::Dict(names_dict) = &names_obj.atom {
                    if let Some((_, js_obj)) = names_dict.get_first(b"/JavaScript") {
                        collect_name_tree_js_candidates(ctx, js_obj, 0, &mut out);
                    }
                }
            }
        }
        if is_name_tree_like_dict(dict) {
            let root =
                sis_pdf_pdf::object::PdfObj { span: dict.span, atom: PdfAtom::Dict(dict.clone()) };
            collect_name_tree_js_candidates(ctx, &root, 0, &mut out);
        }
        if is_annotation_dict(dict) {
            if let Some((_, action_obj)) = dict.get_first(b"/A") {
                push_action_payload_candidates_with_source(
                    ctx,
                    action_obj,
                    JsPayloadSource::AnnotationAction,
                    "/Annot/A/JS",
                    "Annotation action JavaScript payload",
                    &mut out,
                );
            }
            if let Some((_, aa_obj)) = dict.get_first(b"/AA") {
                if let PdfAtom::Dict(aa_dict) = &aa_obj.atom {
                    for (event, action_obj) in &aa_dict.entries {
                        let path =
                            format!("/Annot/AA/{}/JS", String::from_utf8_lossy(&event.decoded));
                        push_action_payload_candidates_with_source(
                            ctx,
                            action_obj,
                            JsPayloadSource::AnnotationAction,
                            &path,
                            "Annotation AA JavaScript payload",
                            &mut out,
                        );
                    }
                }
            }
        }
        if let Some((_, aa_obj)) = dict.get_first(b"/AA") {
            if let PdfAtom::Dict(aa_dict) = &aa_obj.atom {
                for (event, action_obj) in &aa_dict.entries {
                    let path = format!("/AA/{}/JS", String::from_utf8_lossy(&event.decoded));
                    push_action_payload_candidates_with_source(
                        ctx,
                        action_obj,
                        JsPayloadSource::AaEvent,
                        &path,
                        "AA event JavaScript payload",
                        &mut out,
                    );
                }
            }
        }
    }
    if let PdfAtom::Stream(st) = &entry.atom {
        if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
            out.extend(js_payload_candidates_from_embedded_stream(ctx, entry, st));
        }
    }
    out
}

fn is_name_tree_like_dict(dict: &PdfDict<'_>) -> bool {
    dict.get_first(b"/Names").is_some()
        || dict.get_first(b"/Kids").is_some()
        || dict.get_first(b"/Limits").is_some()
}

fn js_payload_candidates_from_xfa(
    ctx: &sis_pdf_core::scan::ScanContext,
    dict: &sis_pdf_pdf::object::PdfDict<'_>,
) -> Vec<JsPayloadCandidate> {
    let mut out = Vec::new();
    let Some((k, xfa_obj)) = dict.get_first(b"/XFA") else {
        return out;
    };
    let payloads = xfa_payloads_from_obj(ctx, xfa_obj);
    for payload in payloads {
        let scripts = extract_xfa_script_payloads(&payload.bytes);
        for script in scripts {
            let evidence = vec![
                span_to_evidence(k.span, "Key /XFA"),
                span_to_evidence(xfa_obj.span, "XFA payload"),
            ];
            out.push(JsPayloadCandidate {
                payload: PayloadInfo {
                    bytes: script,
                    kind: "xfa_script".into(),
                    ref_chain: payload.ref_chain.clone(),
                    origin: payload.origin,
                    filters: payload.filters.clone(),
                    decode_ratio: payload.decode_ratio,
                },
                evidence,
                key_name: "/XFA script".into(),
                source: JsPayloadSource::Xfa,
                container_path: "/XFA/script".into(),
            });
        }
    }
    out
}

pub(crate) fn xfa_payloads_from_obj(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
) -> Vec<PayloadInfo> {
    let mut out = Vec::new();
    match &obj.atom {
        PdfAtom::Array(items) => {
            let mut iter = items.iter().peekable();
            while let Some(item) = iter.next() {
                match &item.atom {
                    PdfAtom::Name(_) | PdfAtom::Str(_) => {
                        if let Some(next) = iter.next() {
                            if let Some(payload) = resolve_payload(ctx, next).payload {
                                out.push(payload);
                            }
                        }
                    }
                    _ => {
                        if let Some(payload) = resolve_payload(ctx, item).payload {
                            out.push(payload);
                        }
                    }
                }
            }
        }
        _ => {
            if let Some(payload) = resolve_payload(ctx, obj).payload {
                out.push(payload);
            }
        }
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn js_payload_candidates_from_embedded_stream(
    ctx: &sis_pdf_core::scan::ScanContext,
    entry: &ObjEntry<'_>,
    stream: &sis_pdf_pdf::object::PdfStream<'_>,
) -> Vec<JsPayloadCandidate> {
    let mut out = Vec::new();
    let payload = resolve_payload(
        ctx,
        &sis_pdf_pdf::object::PdfObj { span: entry.body_span, atom: entry.atom.clone() },
    );
    let Some(payload) = payload.payload else {
        return out;
    };
    if !embedded_file_looks_like_js(stream, &payload.bytes) {
        return out;
    }
    let mut evidence = vec![
        span_to_evidence(stream.dict.span, "EmbeddedFile dict"),
        span_to_evidence(stream.data_span, "EmbeddedFile stream"),
    ];
    if let Some(origin) = payload.origin {
        evidence.push(decoded_evidence_span(origin, &payload.bytes, "Embedded JS payload"));
    }
    let key_name = embedded_filename(&stream.dict)
        .map(|name| format!("EmbeddedFile {}", name))
        .unwrap_or_else(|| "EmbeddedFile".into());
    out.push(JsPayloadCandidate {
        payload: PayloadInfo {
            bytes: payload.bytes,
            kind: "embedded_file".into(),
            ref_chain: payload.ref_chain,
            origin: Some(stream.data_span),
            filters: payload.filters,
            decode_ratio: payload.decode_ratio,
        },
        evidence,
        key_name,
        source: JsPayloadSource::EmbeddedFile,
        container_path: "/EmbeddedFile".into(),
    });
    out
}

fn embedded_file_looks_like_js(stream: &sis_pdf_pdf::object::PdfStream<'_>, data: &[u8]) -> bool {
    if let Some(name) = embedded_filename(&stream.dict) {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".js")
            || lower.ends_with(".mjs")
            || lower.ends_with(".jse")
            || lower.ends_with(".jscript")
            || lower.ends_with(".jsx")
        {
            return true;
        }
    }
    if let Some(subtype) = embedded_subtype(&stream.dict) {
        let lower = subtype.to_ascii_lowercase();
        if lower.contains("javascript") || lower.contains("ecmascript") {
            return true;
        }
    }
    if looks_like_js_text(data) {
        return true;
    }
    if let Some(normalised) = normalise_text_bytes_for_script(data) {
        return looks_like_js_text(&normalised);
    }
    false
}

fn embedded_subtype(dict: &sis_pdf_pdf::object::PdfDict<'_>) -> Option<String> {
    let (_, obj) = dict.get_first(b"/Subtype")?;
    match &obj.atom {
        PdfAtom::Name(n) => Some(String::from_utf8_lossy(&n.decoded).to_string()),
        PdfAtom::Str(s) => Some(String::from_utf8_lossy(&string_bytes(s)).to_string()),
        _ => None,
    }
}

fn looks_like_js_text(data: &[u8]) -> bool {
    let max_scan_bytes = 64 * 1024;
    let slice = if data.len() > max_scan_bytes { &data[..max_scan_bytes] } else { data };
    let mut printable = 0usize;
    for b in slice {
        if b.is_ascii_graphic() || b.is_ascii_whitespace() {
            printable += 1;
        }
    }
    if slice.is_empty() || printable * 100 / slice.len() < 80 {
        return false;
    }
    let lower: Vec<u8> = slice.iter().map(|b| b.to_ascii_lowercase()).collect();
    contains_any(
        &lower,
        &[b"function", b"eval(", b"document.", b"window.", b"var ", b"let ", b"const ", b"=>"],
    )
}

fn contains_any(data: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|needle| find_subslice(data, needle).is_some())
}

fn normalise_text_bytes_for_script(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 4 {
        return None;
    }
    if data.starts_with(b"\xff\xfe") {
        return Some(data[2..].iter().step_by(2).cloned().collect());
    }
    if data.starts_with(b"\xfe\xff") {
        return Some(data[3..].iter().step_by(2).cloned().collect());
    }
    let sample_len = data.len().min(256);
    let mut even_zeros = 0usize;
    let mut odd_zeros = 0usize;
    for i in 0..sample_len {
        if data[i] == 0 {
            if i % 2 == 0 {
                even_zeros += 1;
            } else {
                odd_zeros += 1;
            }
        }
    }
    if even_zeros * 2 > sample_len {
        return Some(data.iter().skip(1).step_by(2).cloned().collect());
    }
    if odd_zeros * 2 > sample_len {
        return Some(data.iter().step_by(2).cloned().collect());
    }
    None
}

struct JavaScriptDetector {
    enable_ast: bool,
}

impl Detector for JavaScriptDetector {
    fn id(&self) -> &'static str {
        "js_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::JavaScript
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                // Find all JavaScript entries (handles /JS, /JavaScript, /JScript, hex-encoded variants)
                let js_entries = find_javascript_entries(dict);

                let mut js_payloads = js_payload_candidates_from_entry(ctx, entry);
                if dict.has_name(b"/S", b"/JavaScript")
                    || !js_entries.is_empty()
                    || !js_payloads.is_empty()
                {
                    let mut evidence = Vec::new();
                    let mut meta = std::collections::HashMap::new();

                    // Detect multiple JavaScript keys (evasion technique)
                    if js_entries.len() > 1 {
                        meta.insert("js.multiple_keys".into(), "true".into());
                        meta.insert("js.multiple_keys_count".into(), js_entries.len().to_string());
                    }

                    // Process all JavaScript entries
                    for (idx, (k, v)) in js_entries.iter().enumerate() {
                        evidence.push(span_to_evidence(
                            k.span,
                            &format!("JavaScript key #{}", idx + 1),
                        ));
                        evidence.push(span_to_evidence(
                            v.span,
                            &format!("JavaScript payload #{}", idx + 1),
                        ));

                        let key_name = String::from_utf8_lossy(&k.decoded).to_string();
                        if idx == 0 {
                            meta.insert("payload_key".into(), key_name.clone());
                        } else {
                            meta.insert(format!("payload_key_{}", idx + 1), key_name);
                        }
                    }

                    js_payloads.sort_by_key(|candidate| candidate.source.priority());
                    for candidate in js_payloads.iter() {
                        evidence.extend(candidate.evidence.clone());
                    }

                    // If no explicit JavaScript keys, but /S is /JavaScript
                    if js_entries.is_empty() && js_payloads.is_empty() {
                        evidence.push(span_to_evidence(dict.span, "Action dict"));
                        meta.insert("payload_key".into(), "/S /JavaScript".into());
                    }

                    meta.insert("js.stream.decoded".into(), "false".into());
                    meta.insert("js.stream.decode_error".into(), "-".into());

                    // Process the first (or only) JavaScript payload
                    if let Some(candidate) = js_payloads.first() {
                        let payload = &candidate.payload;
                        meta.insert("payload_key".into(), candidate.key_name.clone());
                        if let Some(label) = candidate.source.meta_value() {
                            meta.insert("js.source".into(), label.into());
                        }
                        meta.insert("js.container_path".into(), candidate.container_path.clone());
                        meta.insert("js.object_ref_chain".into(), payload.ref_chain.clone());
                        meta.insert("payload.type".into(), payload.kind.clone());
                        meta.insert("payload.decoded_len".into(), payload.bytes.len().to_string());
                        meta.insert("payload.ref_chain".into(), payload.ref_chain.clone());
                        if let Some(filters) = payload.filters.clone() {
                            meta.insert("js.stream.filters".into(), filters);
                        }
                        if let Some(ratio) = payload.decode_ratio {
                            meta.insert("js.decode_ratio".into(), format!("{:.2}", ratio));
                        }
                        if let Some(origin) = payload.origin {
                            evidence.push(decoded_evidence_span(
                                origin,
                                &payload.bytes,
                                "Decoded JS payload",
                            ));
                        }
                        let sig = js_analysis::static_analysis::extract_js_signals_with_ast(
                            &payload.bytes,
                            self.enable_ast,
                        );
                        for (k, v) in sig {
                            meta.insert(k, v);
                        }
                        if let Some((intent, summary, confidence)) =
                            infer_js_intent(&payload.bytes, &meta)
                        {
                            meta.insert("js.intent.primary".into(), intent.into());
                            meta.insert("js.intent.summary".into(), summary.into());
                            meta.insert("js.intent.confidence".into(), confidence.into());
                            if !meta.contains_key("payload.summary") {
                                meta.insert("payload.summary".into(), format!("intent={intent}"));
                            }
                        }
                        let decoded =
                            js_analysis::static_analysis::decode_layers(&payload.bytes, 3);
                        meta.insert("payload.decode_layers".into(), decoded.layers.to_string());
                        if decoded.layers > 0 && decoded.bytes != payload.bytes {
                            meta.insert(
                                "payload.deobfuscated_len".into(),
                                decoded.bytes.len().to_string(),
                            );
                            meta.insert(
                                "payload.deobfuscated_preview".into(),
                                preview_ascii(&decoded.bytes, 120),
                            );
                        }
                        meta.insert("js.stream.decoded".into(), "true".into());
                        meta.insert(
                            "payload.decoded_preview".into(),
                            preview_ascii(&payload.bytes, 120),
                        );
                    }
                    let deduped_evidence = dedupe_evidence_spans(evidence);
                    let object_ref = format!("{} {} obj", entry.obj, entry.gen);
                    let mut meta = meta;
                    meta.insert("object.ref".into(), object_ref.clone());
                    meta.insert("query.next".into(), format!("object {} {}", entry.obj, entry.gen));
                    let js_present_severity = js_present_severity_from_meta(&meta);
                    if matches!(
                        meta.get("js.intent.primary").map(String::as_str),
                        Some("user_interaction")
                    ) {
                        let mut intent_meta = std::collections::HashMap::new();
                        intent_meta.insert(
                            "js.intent.primary".into(),
                            meta.get("js.intent.primary")
                                .cloned()
                                .unwrap_or_else(|| "user_interaction".into()),
                        );
                        if let Some(summary) = meta.get("js.intent.summary") {
                            intent_meta.insert("js.intent.summary".into(), summary.clone());
                        }
                        if let Some(confidence) = meta.get("js.intent.confidence") {
                            intent_meta.insert("js.intent.confidence".into(), confidence.clone());
                        }
                        if let Some(preview) = meta.get("payload.decoded_preview") {
                            intent_meta.insert("payload.preview".into(), preview.clone());
                        }
                        intent_meta.insert("object.ref".into(), object_ref.clone());
                        intent_meta.insert(
                            "query.next".into(),
                            format!("object {} {}", entry.obj, entry.gen),
                        );
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "js_intent_user_interaction".into(),
                            severity: Severity::High,
                            confidence: Confidence::Strong,
                            impact: None,
                            title: "JavaScript user-interaction intent".into(),
                            description:
                                "JavaScript uses user interaction primitives (alert/confirm/prompt), consistent with social-engineering lure behaviour."
                                    .into(),
                            objects: vec![object_ref.clone()],
                            evidence: deduped_evidence.clone(),
                            remediation: Some(
                                "Treat as active social-engineering script and validate whether execution is automatic or user-triggered."
                                    .into(),
                            ),
                            meta: intent_meta,
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                            ..Default::default()
                        });
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "js_present".into(),
                        severity: js_present_severity,
                        confidence: Confidence::Strong,
                        impact: None,
                        title: "JavaScript present".into(),
                        description: "Inline or referenced JavaScript detected.".into(),
                        objects: vec![object_ref],
                        evidence: deduped_evidence,
                        remediation: Some("Extract and review the JavaScript payload.".into()),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(findings)
    }
}

struct LaunchActionDetector;

impl Detector for LaunchActionDetector {
    fn id(&self) -> &'static str {
        "launch_action_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let timeout = TimeoutChecker::new(Duration::from_millis(50));
        for entry in &ctx.graph.objects {
            if timeout.check().is_err() {
                break;
            }
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            if !dict.has_name(b"/S", b"/Launch") {
                continue;
            }

            let mut evidence = EvidenceBuilder::new()
                .file_offset(dict.span.start, dict.span.len() as u32, "Action dict")
                .build();
            let mut meta = std::collections::HashMap::new();
            if let Some(enriched) =
                payload_from_dict(ctx, dict, &[b"/F", b"/Win"], "Action payload")
            {
                evidence.extend(enriched.evidence);
                meta.extend(enriched.meta);
            }

            let mut tracker = LaunchTargetTracker::default();
            if let Some((_, value)) = dict.get_first(b"/F") {
                update_launch_targets(ctx, value, &mut tracker);
            }
            if let Some((_, value)) = dict.get_first(b"/Win") {
                if let PdfAtom::Dict(win_dict) = &value.atom {
                    if let Some((_, win_value)) = win_dict.get_first(b"/F") {
                        update_launch_targets(ctx, win_value, &mut tracker);
                    }
                }
            }

            if let Some(path) = tracker.target_path.clone() {
                meta.insert("launch.target_path".into(), path);
            }
            meta.insert("launch.target_type".into(), tracker.target_type().to_string());
            if let Some(hash) = tracker.embedded_file_hash.clone() {
                meta.insert("launch.embedded_file_hash".into(), hash);
            }
            let payload_target = action_target_from_meta(&meta);
            let action_target =
                tracker.target_path.as_deref().map(|s| s.to_string()).or(payload_target);
            let action_telemetry =
                annotate_action_meta(&mut meta, "/Launch", action_target.as_deref(), "automatic");
            let objects = vec![format!("{} {} obj", entry.obj, entry.gen)];
            let base_meta = meta.clone();
            let mut base_finding = Finding {
                id: String::new(),
                surface: AttackSurface::Actions,
                kind: "launch_action_present".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                impact: None,
                title: "Launch action present".into(),
                description: "Action dictionary with /S /Launch.".into(),
                objects: objects.clone(),
                evidence: evidence.clone(),
                remediation: Some("Review the action target.".into()),
                meta: base_meta,

                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            };
            apply_action_telemetry(&mut base_finding, &action_telemetry);
            findings.push(base_finding);

            if tracker.external {
                let mut extra_meta = meta.clone();
                extra_meta.insert("launch.target_type".into(), "external".into());
                let mut extra_finding = Finding {
                    id: String::new(),
                    surface: AttackSurface::Actions,
                    kind: "launch_external_program".into(),
                    severity: Severity::High,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "Launch action targets external program".into(),
                    description: "Launch action targets an external program or file path.".into(),
                    objects: objects.clone(),
                    evidence: evidence.clone(),
                    remediation: Some("Review the launch target for unsafe execution.".into()),
                    meta: extra_meta,

                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                };
                apply_action_telemetry(&mut extra_finding, &action_telemetry);
                findings.push(extra_finding);
            }

            if tracker.embedded {
                let mut extra_meta = meta.clone();
                extra_meta.insert("launch.target_type".into(), "embedded".into());
                let mut embedded_finding = Finding {
                    id: String::new(),
                    surface: AttackSurface::Actions,
                    kind: "launch_embedded_file".into(),
                    severity: Severity::High,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "Launch action targets embedded file".into(),
                    description: "Launch action targets an embedded file specification.".into(),
                    objects,
                    evidence,
                    remediation: Some("Extract and inspect the embedded target.".into()),
                    meta: extra_meta,

                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                };
                apply_action_telemetry(&mut embedded_finding, &action_telemetry);
                findings.push(embedded_finding);
            }
        }
        Ok(findings)
    }
}

struct PdfjsFontInjectionDetector;

impl Detector for PdfjsFontInjectionDetector {
    fn id(&self) -> &'static str {
        "pdfjs_font_injection"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Metadata
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            let subtype = font_subtype_name(dict);
            let mut add_subsignal = |subsignal: &str,
                                     title: &str,
                                     description: &str,
                                     evidence_note: &str| {
                let mut meta = std::collections::HashMap::new();
                meta.insert("pdfjs.subsignal".into(), subsignal.into());
                meta.insert("pdfjs.affected_versions".into(), "<4.2.67".into());
                meta.insert("reader_impacts".into(), "pdfjs<4.2.67".into());
                meta.insert("renderer.profile".into(), "pdfjs".into());
                meta.insert(
                    "renderer.precondition".into(),
                    "pdfjs_font_parse_path_reachable".into(),
                );
                meta.insert("chain.stage".into(), "render".into());
                meta.insert("chain.capability".into(), "font_renderer_injection".into());
                meta.insert("chain.trigger".into(), "pdfjs".into());
                if let Some(subtype) = &subtype {
                    meta.insert("font.subtype".into(), subtype.clone());
                }

                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "pdfjs_font_injection".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Strong,
                    impact: Some(Impact::Medium),
                    title: title.into(),
                    description: description.into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, evidence_note)],
                    remediation: Some(
                        "Review PDF.js-targeted font and rendering structures for script-capable payloads."
                            .into(),
                    ),
                    meta,
                    reader_impacts: vec![ReaderImpact {
                        profile: ReaderProfile::Pdfium,
                        surface: AttackSurface::Metadata,
                        severity: Severity::Medium,
                        impact: Impact::Medium,
                        note: Some("Pattern is associated with browser-side PDF.js rendering paths (<4.2.67).".into()),
                    }],
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            };

            if let Some((_, obj)) = dict.get_first(b"/FontMatrix") {
                if array_has_non_numeric(obj) {
                    add_subsignal(
                        "fontmatrix_non_numeric",
                        "PDF.js font injection risk (FontMatrix)",
                        "FontMatrix contains non-numeric entries in a font dictionary.",
                        "FontMatrix entry",
                    );
                }
            }

            if let Some((_, obj)) = dict.get_first(b"/FontBBox") {
                if array_has_non_numeric(obj) {
                    add_subsignal(
                        "fontbbox_non_numeric",
                        "PDF.js font injection risk (FontBBox)",
                        "FontBBox contains non-numeric entries in a font dictionary.",
                        "FontBBox entry",
                    );
                }
            }

            if let Some((_, encoding_obj)) = dict.get_first(b"/Encoding") {
                if encoding_contains_string_values(encoding_obj, ctx) {
                    add_subsignal(
                        "encoding_string_values",
                        "PDF.js font injection risk (Encoding)",
                        "Font /Encoding contains string-like values where numeric/name operands are expected.",
                        "Encoding entry",
                    );
                }
                if encoding_contains_script_like_names(encoding_obj, ctx) {
                    add_subsignal(
                        "encoding_scriptlike_names",
                        "PDF.js font injection risk (Encoding names)",
                        "Font /Encoding includes script-like or obfuscated name tokens that can disguise payload operators.",
                        "Encoding entry",
                    );
                }
            }

            if is_cmap_stream(entry) {
                if let Some(payload) = entry_payload_bytes(ctx.bytes, entry) {
                    if contains_pdfjs_injection_tokens(payload) {
                        add_subsignal(
                            "cmap_script_tokens",
                            "PDF.js font injection risk (CMap)",
                            "CMap stream contains script-like tokens consistent with injection payloads.",
                            "CMap stream",
                        );
                    }
                }
            }

            if has_uncommon_font_subtype_combo(dict) {
                add_subsignal(
                    "uncommon_subtype_combo",
                    "PDF.js font injection risk (uncommon subtype combination)",
                    "Font dictionary combines subtype and structural keys in an uncommon pattern associated with evasive renderer paths.",
                    "Font subtype structure",
                );
            }
        }
        Ok(findings)
    }
}

struct FontMatrixDetector;

impl Detector for FontMatrixDetector {
    fn id(&self) -> &'static str {
        "fontmatrix_payload_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Metadata
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            let dict = match entry_dict(entry) {
                Some(d) => d,
                None => continue,
            };
            if let Some((_, obj)) = dict.get_first(b"/FontMatrix") {
                if let PdfAtom::Array(arr) = &obj.atom {
                    if arr.iter().any(|o| !matches!(o.atom, PdfAtom::Int(_) | PdfAtom::Real(_))) {
                        let mut meta = std::collections::HashMap::new();
                        meta.insert("fontmatrix.non_numeric".into(), "true".into());
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "fontmatrix_payload_present".into(),
                            severity: Severity::Medium,
                            confidence: Confidence::Probable,
            impact: None,
                            title: "Suspicious FontMatrix payload".into(),
                            description: "FontMatrix contains non-numeric entries, suggesting script injection.".into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: vec![span_to_evidence(dict.span, "Font dict")],
                            remediation: Some("Review font dictionaries for injected scripts.".into()),
                            meta,
                            yara: None,
        position: None,
        positions: Vec::new(),
                        ..Finding::default()
                        });
                    }
                }
            }
        }
        Ok(findings)
    }
}

struct FontJsExploitationBridgeDetector {
    enable_ast: bool,
}

impl Detector for FontJsExploitationBridgeDetector {
    fn id(&self) -> &'static str {
        "font_js_exploitation_bridge"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Metadata
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Moderate
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut font_indicators = HashSet::new();
        let mut font_objects = HashSet::new();
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            let mut local = Vec::new();
            if let Some((_, obj)) = dict.get_first(b"/FontMatrix") {
                if array_has_non_numeric(obj) {
                    local.push("fontmatrix_non_numeric");
                }
            }
            if let Some((_, obj)) = dict.get_first(b"/FontBBox") {
                if array_has_non_numeric(obj) {
                    local.push("fontbbox_non_numeric");
                }
            }
            if let Some((_, obj)) = dict.get_first(b"/Encoding") {
                if encoding_contains_string_values(obj, ctx) {
                    local.push("encoding_string_values");
                }
                if encoding_contains_script_like_names(obj, ctx) {
                    local.push("encoding_scriptlike_names");
                }
            }
            if is_cmap_stream(entry) {
                if let Some(payload) = entry_payload_bytes(ctx.bytes, entry) {
                    if contains_pdfjs_injection_tokens(payload) {
                        local.push("cmap_script_tokens");
                    }
                }
            }
            if has_uncommon_font_subtype_combo(dict) {
                local.push("uncommon_subtype_combo");
            }
            if !local.is_empty() {
                font_objects.insert(format!("{} {} obj", entry.obj, entry.gen));
                for indicator in local {
                    font_indicators.insert(indicator);
                }
            }
        }

        let mut js_indicators = HashSet::new();
        let mut js_objects = HashSet::new();
        let mut js_high_risk = false;
        for entry in &ctx.graph.objects {
            let candidates = js_payload_candidates_from_entry(ctx, entry);
            if candidates.is_empty() {
                continue;
            }
            js_objects.insert(format!("{} {} obj", entry.obj, entry.gen));
            js_indicators.insert("js_payload_present");
            for candidate in candidates {
                let signals = js_analysis::static_analysis::extract_js_signals_with_ast(
                    &candidate.payload.bytes,
                    self.enable_ast,
                );
                if matches!(signals.get("js.contains_eval").map(String::as_str), Some("true"))
                    || matches!(
                        signals.get("js.dynamic_eval_construction").map(String::as_str),
                        Some("true")
                    )
                {
                    js_indicators.insert("js_dynamic_eval");
                    js_high_risk = true;
                }
                if matches!(
                    signals.get("js.obfuscation_suspected").map(String::as_str),
                    Some("true")
                ) || matches!(
                    signals.get("js.contains_fromcharcode").map(String::as_str),
                    Some("true")
                ) || matches!(
                    signals.get("js.contains_unescape").map(String::as_str),
                    Some("true")
                ) {
                    js_indicators.insert("js_obfuscation");
                }
                if matches!(
                    signals.get("js.environment_fingerprinting").map(String::as_str),
                    Some("true")
                ) {
                    js_indicators.insert("js_environment_fingerprinting");
                }
            }
        }

        if !font_indicators.is_empty() && !js_indicators.is_empty() {
            let shared_objects =
                font_objects.intersection(&js_objects).cloned().collect::<Vec<_>>();
            let co_located = !shared_objects.is_empty();
            let confidence = if font_indicators.len() >= 2 && js_high_risk && co_located {
                Confidence::Certain
            } else if font_indicators.len() >= 2 && js_high_risk {
                Confidence::Strong
            } else if co_located {
                Confidence::Strong
            } else {
                Confidence::Probable
            };
            let severity = if js_high_risk && (font_indicators.len() >= 2 || co_located) {
                Severity::High
            } else {
                Severity::Medium
            };
            let mut meta = std::collections::HashMap::new();
            let mut font_indicator_list = font_indicators.into_iter().collect::<Vec<_>>();
            font_indicator_list.sort_unstable();
            let mut js_indicator_list = js_indicators.into_iter().collect::<Vec<_>>();
            js_indicator_list.sort_unstable();
            meta.insert("bridge.kind".into(), "font_js_exploitation_bridge".into());
            meta.insert("bridge.confidence_adjusted".into(), "true".into());
            meta.insert("bridge.font_indicators".into(), font_indicator_list.join(","));
            meta.insert("bridge.js_indicators".into(), js_indicator_list.join(","));
            meta.insert(
                "bridge.font_indicator_count".into(),
                font_indicator_list.len().to_string(),
            );
            meta.insert("bridge.js_indicator_count".into(), js_indicator_list.len().to_string());
            meta.insert("bridge.js_high_risk".into(), js_high_risk.to_string());
            meta.insert(
                "bridge.co_location".into(),
                if co_located { "shared_object" } else { "document_level" }.into(),
            );
            meta.insert("bridge.shared_object_count".into(), shared_objects.len().to_string());
            if !shared_objects.is_empty() {
                meta.insert("bridge.shared_objects".into(), shared_objects.join(","));
            }
            meta.insert("renderer.profile".into(), "pdfjs".into());
            meta.insert(
                "renderer.precondition".into(),
                "pdfjs_font_eval_and_js_execution_paths_reachable".into(),
            );
            meta.insert("chain.stage".into(), "render".into());
            meta.insert("chain.capability".into(), "font_js_renderer_bridge".into());
            meta.insert("chain.trigger".into(), "pdfjs".into());

            let mut objects = font_objects.into_iter().collect::<Vec<_>>();
            objects.extend(js_objects);
            objects.sort();
            objects.dedup();

            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Metadata,
                kind: "font_js_exploitation_bridge".into(),
                severity,
                confidence,
                impact: Some(Impact::High),
                title: "Correlated font and JavaScript exploitation indicators".into(),
                description:
                    "Suspicious font structures co-occur with executable JavaScript indicators in the same PDF."
                        .into(),
                objects,
                evidence: vec![span_to_evidence(
                    sis_pdf_pdf::span::Span { start: 0, end: ctx.bytes.len() as u64 },
                    "Font/JavaScript correlation",
                )],
                remediation: Some(
                    "Prioritise combined triage of font dictionaries and JavaScript payload behaviour."
                        .into(),
                ),
                meta,
                reader_impacts: Vec::new(),
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

struct PdfjsRenderingIndicatorDetector;

impl Detector for PdfjsRenderingIndicatorDetector {
    fn id(&self) -> &'static str {
        "pdfjs_rendering_indicators"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Metadata
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut annotation_objects = Vec::new();
        let mut annotation_sources = BTreeSet::new();
        let mut annotation_subtypes = BTreeSet::new();
        let mut annotation_action_trigger_count = 0usize;
        let mut annotation_normalised = false;
        let mut annotation_decode_layers = 0u8;
        let mut form_js_objects = Vec::new();
        let mut form_html_objects = Vec::new();
        let mut form_js_sources = BTreeSet::new();
        let mut form_html_sources = BTreeSet::new();
        let mut form_js_normalised = false;
        let mut form_html_normalised = false;
        let mut form_js_decode_layers = 0u8;
        let mut form_html_decode_layers = 0u8;
        let mut eval_path_objects = Vec::new();
        let mut eval_path_subtypes = BTreeSet::new();

        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            if is_annotation_dict(dict) {
                let mut annotation_signals = InjectionSignals::default();
                if let Some((_, obj)) = dict.get_first(b"/AP") {
                    let signals = obj_collect_injection_signals(obj, ctx, 0);
                    if signals.classify().is_some() {
                        annotation_sources.insert("/AP");
                    }
                    annotation_signals.merge(signals);
                }
                if let Some((_, obj)) = dict.get_first(b"/Contents") {
                    let signals = obj_collect_injection_signals(obj, ctx, 0);
                    if signals.classify().is_some() {
                        annotation_sources.insert("/Contents");
                    }
                    annotation_signals.merge(signals);
                }
                if let Some((_, obj)) = dict.get_first(b"/RC") {
                    let signals = obj_collect_injection_signals(obj, ctx, 0);
                    if signals.classify().is_some() {
                        annotation_sources.insert("/RC");
                    }
                    annotation_signals.merge(signals);
                }
                let has_annotation_payload = annotation_signals.classify().is_some();
                if has_annotation_payload {
                    annotation_objects.push(format!("{} {} obj", entry.obj, entry.gen));
                    if let Some(subtype) = dict.get_first(b"/Subtype").and_then(|(_, value)| {
                        if let PdfAtom::Name(name) = &value.atom {
                            Some(String::from_utf8_lossy(&name.decoded).to_string())
                        } else {
                            None
                        }
                    }) {
                        annotation_subtypes.insert(subtype);
                    }
                    annotation_normalised |= annotation_signals.normalised;
                    annotation_decode_layers =
                        annotation_decode_layers.max(annotation_signals.decode_layers);
                    if dict.get_first(b"/A").is_some() || dict.get_first(b"/AA").is_some() {
                        annotation_action_trigger_count += 1;
                    }
                }
            }

            if is_form_dict(dict) {
                let mut signals = InjectionSignals::default();
                if let Some((_, obj)) = dict.get_first(b"/V") {
                    let field_signals = obj_collect_injection_signals(obj, ctx, 0);
                    if field_signals.has_js {
                        form_js_sources.insert("/V");
                    }
                    if field_signals.has_html {
                        form_html_sources.insert("/V");
                    }
                    signals.merge(field_signals);
                }
                if let Some((_, obj)) = dict.get_first(b"/DV") {
                    let field_signals = obj_collect_injection_signals(obj, ctx, 0);
                    if field_signals.has_js {
                        form_js_sources.insert("/DV");
                    }
                    if field_signals.has_html {
                        form_html_sources.insert("/DV");
                    }
                    signals.merge(field_signals);
                }
                if let Some((_, obj)) = dict.get_first(b"/AP") {
                    let field_signals = obj_collect_injection_signals(obj, ctx, 0);
                    if field_signals.has_js {
                        form_js_sources.insert("/AP");
                    }
                    if field_signals.has_html {
                        form_html_sources.insert("/AP");
                    }
                    signals.merge(field_signals);
                }

                let detected = signals.classify();
                let obj_ref = format!("{} {} obj", entry.obj, entry.gen);

                match detected {
                    Some(InjectionType::JavaScript) => {
                        form_js_objects.push(obj_ref);
                        form_js_normalised |= signals.normalised;
                        form_js_decode_layers = form_js_decode_layers.max(signals.decode_layers);
                    }
                    Some(InjectionType::Html) => {
                        form_html_objects.push(obj_ref);
                        form_html_normalised |= signals.normalised;
                        form_html_decode_layers =
                            form_html_decode_layers.max(signals.decode_layers);
                    }
                    Some(InjectionType::Both) => {
                        form_js_objects.push(obj_ref.clone());
                        form_html_objects.push(obj_ref);
                        form_js_normalised |= signals.normalised;
                        form_html_normalised |= signals.normalised;
                        form_js_decode_layers = form_js_decode_layers.max(signals.decode_layers);
                        form_html_decode_layers =
                            form_html_decode_layers.max(signals.decode_layers);
                    }
                    None => {}
                }
            }

            if is_pdfjs_eval_path_font(dict) {
                eval_path_objects.push(format!("{} {} obj", entry.obj, entry.gen));
                if let Some(subtype) = font_subtype_name(dict) {
                    eval_path_subtypes.insert(subtype);
                }
            }
        }

        annotation_objects.sort();
        annotation_objects.dedup();
        form_js_objects.sort();
        form_js_objects.dedup();
        form_html_objects.sort();
        form_html_objects.dedup();
        eval_path_objects.sort();
        eval_path_objects.dedup();

        if !annotation_objects.is_empty() {
            let mut meta = std::collections::HashMap::new();
            meta.insert("pdfjs.affected_versions".into(), "<4.2.67".into());
            meta.insert(
                "pdfjs.annotation_object_count".into(),
                annotation_objects.len().to_string(),
            );
            meta.insert("chain.stage".into(), "render".into());
            meta.insert("chain.capability".into(), "annotation_injection".into());
            meta.insert("chain.trigger".into(), "annotation_render".into());
            meta.insert(
                "annot.trigger_context".into(),
                if annotation_action_trigger_count == 0 {
                    "annotation_render_only".into()
                } else if annotation_action_trigger_count == annotation_objects.len() {
                    "annotation_action".into()
                } else {
                    "mixed".into()
                },
            );
            meta.insert(
                "annot.action_trigger_count".into(),
                annotation_action_trigger_count.to_string(),
            );
            if !annotation_subtypes.is_empty() {
                meta.insert(
                    "annot.subtype".into(),
                    annotation_subtypes.into_iter().collect::<Vec<_>>().join(","),
                );
            }
            if !annotation_sources.is_empty() {
                meta.insert(
                    "injection.sources".into(),
                    annotation_sources.iter().copied().collect::<Vec<_>>().join(","),
                );
            }
            if annotation_normalised {
                meta.insert("injection.normalised".into(), "true".into());
                meta.insert("injection.decode_layers".into(), annotation_decode_layers.to_string());
            }
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Actions,
                kind: "pdfjs_annotation_injection".into(),
                severity: Severity::Medium,
                confidence: Confidence::Strong,
                impact: Some(Impact::Medium),
                title: "PDF.js annotation injection indicator".into(),
                description:
                    "Annotation appearance/content fields contain script-like payload tokens.".into(),
                objects: annotation_objects,
                evidence: keyword_evidence(ctx.bytes, b"/AP", "Annotation appearance", 3),
                remediation: Some(
                    "Review annotation appearance and content payloads for browser-rendered script injection."
                        .into(),
                ),
                meta,
                reader_impacts: vec![ReaderImpact {
                    profile: ReaderProfile::Pdfium,
                    surface: AttackSurface::Actions,
                    severity: Severity::Medium,
                    impact: Impact::Medium,
                    note: Some("Annotation rendering paths can expose browser-side injection behaviour.".into()),
                }],
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }

        if !form_js_objects.is_empty() {
            let mut meta = std::collections::HashMap::new();
            meta.insert("pdfjs.affected_versions".into(), "<4.2.67".into());
            meta.insert("pdfjs.form_object_count".into(), form_js_objects.len().to_string());
            meta.insert("injection.type".into(), "javascript".into());
            meta.insert("chain.stage".into(), "render".into());
            meta.insert("chain.capability".into(), "js_injection".into());
            meta.insert("chain.trigger".into(), "pdfjs".into());
            if !form_js_sources.is_empty() {
                meta.insert(
                    "injection.sources".into(),
                    form_js_sources.iter().copied().collect::<Vec<_>>().join(","),
                );
            }
            if form_js_normalised {
                meta.insert("injection.normalised".into(), "true".into());
                meta.insert("injection.decode_layers".into(), form_js_decode_layers.to_string());
            }
            let confidence =
                if form_js_decode_layers > 1 { Confidence::Strong } else { Confidence::Probable };
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Forms,
                kind: "pdfjs_form_injection".into(),
                severity: Severity::Medium,
                confidence,
                impact: Some(Impact::Medium),
                title: "PDF.js form injection indicator".into(),
                description:
                    "Form value/appearance fields contain script-like payload tokens.".into(),
                objects: form_js_objects,
                evidence: form_injection_evidence(ctx.bytes, &form_js_sources, 2),
                remediation: Some(
                    "Inspect form default/value and appearance entries for injected JavaScript payload content."
                        .into(),
                ),
                meta,
                reader_impacts: vec![ReaderImpact {
                    profile: ReaderProfile::Pdfium,
                    surface: AttackSurface::Forms,
                    severity: Severity::Medium,
                    impact: Impact::Medium,
                    note: Some("Browser-rendered form values may expose DOM or script injection surfaces.".into()),
                }],
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }

        if !form_html_objects.is_empty() {
            let mut meta = std::collections::HashMap::new();
            meta.insert("injection.type".into(), "html_xss".into());
            meta.insert("form.html_object_count".into(), form_html_objects.len().to_string());
            meta.insert(
                "injection.patterns".into(),
                "html_tags,event_handlers,context_breaking".into(),
            );
            meta.insert("chain.stage".into(), "render".into());
            meta.insert("chain.capability".into(), "html_injection".into());
            meta.insert("chain.trigger".into(), "pdfjs".into());
            if !form_html_sources.is_empty() {
                meta.insert(
                    "injection.sources".into(),
                    form_html_sources.iter().copied().collect::<Vec<_>>().join(","),
                );
            }
            if form_html_normalised {
                meta.insert("injection.normalised".into(), "true".into());
                meta.insert("injection.decode_layers".into(), form_html_decode_layers.to_string());
            }
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Forms,
                kind: "form_html_injection".into(),
                severity: Severity::Medium,
                confidence: Confidence::Strong,
                impact: Some(Impact::Medium),
                title: "HTML injection in form field value".into(),
                description:
                    "Form field value contains HTML tags, event handlers, or context-breaking sequences that could enable XSS if rendered in web context.".into(),
                objects: form_html_objects,
                evidence: form_injection_evidence(ctx.bytes, &form_html_sources, 3),
                remediation: Some(
                    "Review form field /V (value) and /DV (default value) entries for HTML tag injection, event handler attributes, or tag-breaking sequences. Validate against web rendering contexts (PDF.js, form data export, HTML conversion).".into(),
                ),
                meta,
                reader_impacts: vec![
                    ReaderImpact {
                        profile: ReaderProfile::Pdfium,
                        surface: AttackSurface::Forms,
                        severity: Severity::Medium,
                        impact: Impact::Medium,
                        note: Some("PDF.js and browser-based renderers may interpret HTML in form values, enabling XSS attacks.".into()),
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

        if !eval_path_objects.is_empty() {
            let mut meta = std::collections::HashMap::new();
            meta.insert("pdfjs.affected_versions".into(), "<4.2.67".into());
            meta.insert("pdfjs.eval_path_object_count".into(), eval_path_objects.len().to_string());
            meta.insert("renderer.profile".into(), "pdfjs".into());
            meta.insert("renderer.precondition".into(), "pdfjs_font_eval_path_reachable".into());
            meta.insert("chain.stage".into(), "render".into());
            meta.insert("chain.capability".into(), "font_eval_path".into());
            meta.insert("chain.trigger".into(), "pdfjs".into());
            if !eval_path_subtypes.is_empty() {
                meta.insert(
                    "font.subtypes".into(),
                    eval_path_subtypes.iter().cloned().collect::<Vec<_>>().join(","),
                );
            }
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Metadata,
                kind: "pdfjs_eval_path_risk".into(),
                severity: Severity::Info,
                confidence: Confidence::Strong,
                impact: Some(Impact::Low),
                title: "PDF.js eval-path risk indicator".into(),
                description:
                    "Document contains font structures commonly associated with PDF.js eval-render paths."
                        .into(),
                objects: eval_path_objects,
                evidence: keyword_evidence(ctx.bytes, b"/Font", "Font dictionary", 3),
                remediation: Some(
                    "Review font subtype and encoding complexity when triaging browser PDF.js exposure."
                        .into(),
                ),
                meta,
                reader_impacts: vec![ReaderImpact {
                    profile: ReaderProfile::Pdfium,
                    surface: AttackSurface::Metadata,
                    severity: Severity::Low,
                    impact: Impact::Low,
                    note: Some("Indicator is informational and highlights potentially sensitive rendering paths.".into()),
                }],
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

fn is_annotation_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Subtype", b"/Annot")
        || dict.has_name(b"/Type", b"/Annot")
        || dict.get_first(b"/Annots").is_some()
}

fn is_form_dict(dict: &PdfDict<'_>) -> bool {
    dict.get_first(b"/AcroForm").is_some()
        || dict.get_first(b"/FT").is_some()
        || dict.get_first(b"/T").is_some()
        || dict.get_first(b"/Kids").is_some()
}

fn form_injection_evidence(
    bytes: &[u8],
    sources: &BTreeSet<&'static str>,
    context_lines: usize,
) -> Vec<sis_pdf_core::model::EvidenceSpan> {
    if sources.contains("/AP") {
        return keyword_evidence(bytes, b"/AP", "Form appearance", context_lines);
    }
    if sources.contains("/V") {
        return keyword_evidence(bytes, b"/V", "Form field value", context_lines);
    }
    if sources.contains("/DV") {
        return keyword_evidence(bytes, b"/DV", "Form default value", context_lines);
    }
    keyword_evidence(bytes, b"/AcroForm", "Form dictionary", context_lines)
}

fn is_pdfjs_eval_path_font(dict: &PdfDict<'_>) -> bool {
    let font_like = dict.has_name(b"/Type", b"/Font");
    let subtype_risky = dict.has_name(b"/Subtype", b"/Type1")
        || dict.has_name(b"/Subtype", b"/Type0")
        || dict.has_name(b"/Subtype", b"/CIDFontType0")
        || dict.has_name(b"/Subtype", b"/CIDFontType2");
    let has_custom_encoding = dict.get_first(b"/Encoding").is_some();
    let has_cmap_path =
        dict.get_first(b"/ToUnicode").is_some() || dict.get_first(b"/DescendantFonts").is_some();
    font_like && (subtype_risky || has_custom_encoding || has_cmap_path)
}

fn font_subtype_name(dict: &PdfDict<'_>) -> Option<String> {
    dict.get_first(b"/Subtype").and_then(|(_, value)| match &value.atom {
        PdfAtom::Name(name) => Some(String::from_utf8_lossy(&name.decoded).to_string()),
        _ => None,
    })
}

fn has_uncommon_font_subtype_combo(dict: &PdfDict<'_>) -> bool {
    if dict.has_name(b"/Subtype", b"/Type0")
        && (dict.get_first(b"/FontMatrix").is_some() || dict.get_first(b"/FontBBox").is_some())
    {
        return true;
    }
    if dict.has_name(b"/Subtype", b"/Type1") && dict.get_first(b"/DescendantFonts").is_some() {
        return true;
    }
    if (dict.has_name(b"/Subtype", b"/CIDFontType0")
        || dict.has_name(b"/Subtype", b"/CIDFontType2"))
        && dict.get_first(b"/Encoding").is_some()
    {
        return true;
    }
    false
}

fn obj_collect_injection_signals(
    obj: &PdfObj<'_>,
    ctx: &sis_pdf_core::scan::ScanContext,
    depth: usize,
) -> InjectionSignals {
    if depth >= 8 {
        return InjectionSignals::default();
    }
    match &obj.atom {
        PdfAtom::Str(s) => detect_injection_signals(&string_bytes(s)),
        PdfAtom::Name(name) => detect_injection_signals(&name.decoded),
        PdfAtom::Array(values) => {
            values.iter().fold(InjectionSignals::default(), |mut acc, value| {
                acc.merge(obj_collect_injection_signals(value, ctx, depth + 1));
                acc
            })
        }
        PdfAtom::Dict(dict) => {
            dict.entries.iter().fold(InjectionSignals::default(), |mut acc, (_, value)| {
                acc.merge(obj_collect_injection_signals(value, ctx, depth + 1));
                acc
            })
        }
        PdfAtom::Stream(stream) => {
            let start = stream.data_span.start as usize;
            let end = stream.data_span.end as usize;
            let mut signals = if start < end && end <= ctx.bytes.len() {
                detect_injection_signals(&ctx.bytes[start..end])
            } else {
                InjectionSignals::default()
            };
            for (_, value) in &stream.dict.entries {
                signals.merge(obj_collect_injection_signals(value, ctx, depth + 1));
            }
            signals
        }
        PdfAtom::Ref { .. } => ctx
            .graph
            .resolve_ref(obj)
            .map(|resolved| {
                let resolved_obj = PdfObj { span: resolved.body_span, atom: resolved.atom };
                obj_collect_injection_signals(&resolved_obj, ctx, depth + 1)
            })
            .unwrap_or_default(),
        _ => InjectionSignals::default(),
    }
}

const MAX_SCATTER_COLLECT_DEPTH: usize = 12;
const MAX_SCATTER_FRAGMENT_BYTES: usize = 32 * 1024;
const MAX_SCATTER_TOTAL_BYTES: usize = 256 * 1024;

struct InjectionFragment {
    bytes: Vec<u8>,
    object_ref: String,
    source_key: &'static str,
    source_type: &'static str,
}

struct ScatteredAssemblyCandidate {
    assembled: Vec<u8>,
    signals: InjectionSignals,
    fragment_count: usize,
    object_ids: BTreeSet<String>,
    sources: BTreeSet<&'static str>,
    source_types: BTreeSet<&'static str>,
}

#[derive(Clone, Copy)]
enum AssemblyCandidateScope {
    FormOnly,
    CrossStream,
}

fn collect_assembly_candidates(
    ctx: &sis_pdf_core::scan::ScanContext,
    scope: AssemblyCandidateScope,
) -> Vec<ScatteredAssemblyCandidate> {
    let mut out = Vec::new();
    for entry in &ctx.graph.objects {
        let Some(dict) = entry_dict(entry) else {
            continue;
        };
        let owner_ref = format!("{} {} obj", entry.obj, entry.gen);
        let mut fragments = Vec::new();
        if is_form_dict(dict) {
            if let Some((_, obj)) = dict.get_first(b"/V") {
                collect_injection_fragments_from_obj(
                    obj,
                    ctx,
                    0,
                    &owner_ref,
                    "/V",
                    "form",
                    &mut fragments,
                );
            }
            if let Some((_, obj)) = dict.get_first(b"/DV") {
                collect_injection_fragments_from_obj(
                    obj,
                    ctx,
                    0,
                    &owner_ref,
                    "/DV",
                    "form",
                    &mut fragments,
                );
            }
            if let Some((_, obj)) = dict.get_first(b"/AP") {
                collect_injection_fragments_from_obj(
                    obj,
                    ctx,
                    0,
                    &owner_ref,
                    "/AP",
                    "form",
                    &mut fragments,
                );
            }
        }

        if matches!(scope, AssemblyCandidateScope::CrossStream) {
            if is_annotation_dict(dict) {
                for key in [
                    b"/Contents".as_slice(),
                    b"/RC".as_slice(),
                    b"/TU".as_slice(),
                    b"/Subj".as_slice(),
                    b"/T".as_slice(),
                    b"/NM".as_slice(),
                ] {
                    if let Some((_, obj)) = dict.get_first(key) {
                        collect_injection_fragments_from_obj(
                            obj,
                            ctx,
                            0,
                            &owner_ref,
                            annotation_source_key(key),
                            "annotation",
                            &mut fragments,
                        );
                    }
                }
            }
            if is_metadata_like_dict(dict) {
                for key in METADATA_STRING_KEYS {
                    if let Some((_, obj)) = dict.get_first(key) {
                        collect_injection_fragments_from_obj(
                            obj,
                            ctx,
                            0,
                            &owner_ref,
                            metadata_source_key(key),
                            "metadata",
                            &mut fragments,
                        );
                    }
                }
            }
        }

        let min_fragments = match scope {
            AssemblyCandidateScope::FormOnly => 2,
            AssemblyCandidateScope::CrossStream => 1,
        };
        if fragments.len() < min_fragments {
            continue;
        }
        if matches!(scope, AssemblyCandidateScope::FormOnly)
            && fragments.iter().any(|fragment| fragment.source_type != "form")
        {
            continue;
        }

        let fragment_has_direct_signal = fragments
            .iter()
            .any(|fragment| detect_injection_signals(&fragment.bytes).classify().is_some());
        if matches!(scope, AssemblyCandidateScope::FormOnly) && fragment_has_direct_signal {
            continue;
        }

        let mut assembled = Vec::new();
        for fragment in &fragments {
            assembled.extend_from_slice(&fragment.bytes);
        }
        let assembled_signals = detect_injection_signals(&assembled);
        if assembled_signals.classify().is_none() {
            continue;
        }
        let normalised = normalise_injection_payload(&assembled);
        let assembled_for_matching =
            if normalised.decode_layers > 0 { normalised.bytes } else { assembled };

        let mut object_ids = BTreeSet::new();
        let mut sources = BTreeSet::new();
        let mut source_types = BTreeSet::new();
        for fragment in &fragments {
            object_ids.insert(fragment.object_ref.clone());
            sources.insert(fragment.source_key);
            source_types.insert(fragment.source_type);
        }

        out.push(ScatteredAssemblyCandidate {
            assembled: assembled_for_matching,
            signals: assembled_signals,
            fragment_count: fragments.len(),
            object_ids,
            sources,
            source_types,
        });
    }
    out
}

fn js_payload_has_assembly_pattern(
    payload: &[u8],
    js_meta: &std::collections::HashMap<String, String>,
) -> bool {
    if js_meta
        .get("payload.fromCharCode_reconstructed")
        .map(|value| value == "true")
        .unwrap_or(false)
    {
        return true;
    }
    let lower = payload.iter().map(|byte| byte.to_ascii_lowercase()).collect::<Vec<u8>>();
    let has_from_char_code = lower.windows("fromcharcode".len()).any(|w| w == b"fromcharcode");
    let has_split = lower.windows("split(".len()).any(|w| w == b"split(");
    let has_join = lower.windows("join(".len()).any(|w| w == b"join(");
    let has_concat = lower.windows(".concat(".len()).any(|w| w == b".concat(");
    has_from_char_code || (has_split && has_join) || has_concat
}

fn js_payload_matches_scattered_candidate(
    js_payload: &[u8],
    js_meta: &std::collections::HashMap<String, String>,
    assembled: &[u8],
) -> bool {
    if assembled.len() < 4 {
        return false;
    }

    if let Some(preview) = js_meta.get("payload.fromCharCode_preview") {
        let preview_bytes = preview.as_bytes();
        if !preview_bytes.is_empty()
            && (contains_subslice_case_insensitive(assembled, preview_bytes)
                || contains_subslice_case_insensitive(preview_bytes, assembled))
        {
            return true;
        }
    }

    for reconstructed in reconstruct_from_charcode_calls(js_payload) {
        if contains_subslice_case_insensitive(&reconstructed, assembled)
            || contains_subslice_case_insensitive(assembled, &reconstructed)
        {
            return true;
        }
    }

    contains_subslice_case_insensitive(js_payload, assembled)
        || contains_subslice_case_insensitive(assembled, js_payload)
}

fn reconstruct_from_charcode_calls(payload: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(payload);
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let marker = "fromcharcode(";

    while cursor < lower.len() {
        let Some(pos) = lower[cursor..].find(marker) else {
            break;
        };
        let args_start = cursor + pos + marker.len();
        let Some(end_rel) = lower[args_start..].find(')') else {
            break;
        };
        let args_end = args_start + end_rel;
        let args = &text[args_start..args_end];

        let mut reconstructed = String::new();
        let mut valid = true;
        for token in args.split(',').map(str::trim).filter(|token| !token.is_empty()) {
            let parsed = if token.starts_with("0x") || token.starts_with("0X") {
                u32::from_str_radix(&token[2..], 16).ok()
            } else {
                token.parse::<u32>().ok()
            };
            let Some(codepoint) = parsed else {
                valid = false;
                break;
            };
            let Some(ch) = char::from_u32(codepoint) else {
                valid = false;
                break;
            };
            reconstructed.push(ch);
        }
        if valid && !reconstructed.is_empty() {
            out.push(reconstructed.into_bytes());
        }

        cursor = args_end + 1;
    }

    out
}

fn contains_subslice_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let haystack_lower = haystack.iter().map(|byte| byte.to_ascii_lowercase()).collect::<Vec<u8>>();
    let needle_lower = needle.iter().map(|byte| byte.to_ascii_lowercase()).collect::<Vec<u8>>();
    haystack_lower.windows(needle_lower.len()).any(|window| window == needle_lower.as_slice())
}

fn collect_injection_fragments_from_obj(
    obj: &PdfObj<'_>,
    ctx: &sis_pdf_core::scan::ScanContext,
    depth: usize,
    current_object_ref: &str,
    source_key: &'static str,
    source_type: &'static str,
    out: &mut Vec<InjectionFragment>,
) {
    if depth >= MAX_SCATTER_COLLECT_DEPTH {
        return;
    }
    let current_total: usize = out.iter().map(|fragment| fragment.bytes.len()).sum();
    if current_total >= MAX_SCATTER_TOTAL_BYTES {
        return;
    }

    match &obj.atom {
        PdfAtom::Str(s) => {
            let mut bytes = string_bytes(s);
            if bytes.len() > MAX_SCATTER_FRAGMENT_BYTES {
                bytes.truncate(MAX_SCATTER_FRAGMENT_BYTES);
            }
            if !bytes.is_empty() {
                out.push(InjectionFragment {
                    bytes,
                    object_ref: current_object_ref.to_string(),
                    source_key,
                    source_type,
                });
            }
        }
        PdfAtom::Name(name) => {
            if !name.decoded.is_empty() {
                let mut bytes = name.decoded.clone();
                if bytes.len() > MAX_SCATTER_FRAGMENT_BYTES {
                    bytes.truncate(MAX_SCATTER_FRAGMENT_BYTES);
                }
                out.push(InjectionFragment {
                    bytes,
                    object_ref: current_object_ref.to_string(),
                    source_key,
                    source_type,
                });
            }
        }
        PdfAtom::Array(values) => {
            for value in values {
                collect_injection_fragments_from_obj(
                    value,
                    ctx,
                    depth + 1,
                    current_object_ref,
                    source_key,
                    source_type,
                    out,
                );
            }
        }
        PdfAtom::Dict(dict) => {
            for (_, value) in &dict.entries {
                collect_injection_fragments_from_obj(
                    value,
                    ctx,
                    depth + 1,
                    current_object_ref,
                    source_key,
                    source_type,
                    out,
                );
            }
        }
        PdfAtom::Stream(stream) => {
            let start = stream.data_span.start as usize;
            let end = stream.data_span.end as usize;
            if start < end && end <= ctx.bytes.len() {
                let mut bytes = ctx.bytes[start..end].to_vec();
                if bytes.len() > MAX_SCATTER_FRAGMENT_BYTES {
                    bytes.truncate(MAX_SCATTER_FRAGMENT_BYTES);
                }
                if !bytes.is_empty() {
                    out.push(InjectionFragment {
                        bytes,
                        object_ref: current_object_ref.to_string(),
                        source_key,
                        source_type,
                    });
                }
            }
            for (_, value) in &stream.dict.entries {
                collect_injection_fragments_from_obj(
                    value,
                    ctx,
                    depth + 1,
                    current_object_ref,
                    source_key,
                    source_type,
                    out,
                );
            }
        }
        PdfAtom::Ref { obj, gen } => {
            if let Some(resolved) = ctx.graph.get_object(*obj, *gen) {
                let resolved_obj = PdfObj { span: resolved.body_span, atom: resolved.atom.clone() };
                let resolved_ref = format!("{} {} obj", obj, gen);
                collect_injection_fragments_from_obj(
                    &resolved_obj,
                    ctx,
                    depth + 1,
                    &resolved_ref,
                    source_key,
                    source_type,
                    out,
                );
            }
        }
        _ => {}
    }
}

const METADATA_STRING_KEYS: [&[u8]; 9] = [
    b"/Title",
    b"/Author",
    b"/Subject",
    b"/Keywords",
    b"/Creator",
    b"/Producer",
    b"/CreationDate",
    b"/ModDate",
    b"/Trapped",
];

fn is_metadata_like_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Type", b"/Metadata")
        || METADATA_STRING_KEYS.iter().any(|key| dict.get_first(key).is_some())
}

fn metadata_source_key(key: &[u8]) -> &'static str {
    match key {
        b"/Title" => "/Title",
        b"/Author" => "/Author",
        b"/Subject" => "/Subject",
        b"/Keywords" => "/Keywords",
        b"/Creator" => "/Creator",
        b"/Producer" => "/Producer",
        b"/CreationDate" => "/CreationDate",
        b"/ModDate" => "/ModDate",
        _ => "/Trapped",
    }
}

fn annotation_source_key(key: &[u8]) -> &'static str {
    if key == b"/Contents" {
        "/Contents"
    } else if key == b"/RC" {
        "/RC"
    } else if key == b"/TU" {
        "/TU"
    } else if key == b"/Subj" {
        "/Subj"
    } else if key == b"/T" {
        "/T"
    } else {
        "/NM"
    }
}

fn array_has_non_numeric(obj: &PdfObj<'_>) -> bool {
    match &obj.atom {
        PdfAtom::Array(values) => {
            values.iter().any(|value| !matches!(value.atom, PdfAtom::Int(_) | PdfAtom::Real(_)))
        }
        _ => false,
    }
}

fn encoding_contains_string_values(
    obj: &PdfObj<'_>,
    ctx: &sis_pdf_core::scan::ScanContext,
) -> bool {
    encoding_contains_string_values_with_depth(obj, ctx, 0)
}

fn encoding_contains_script_like_names(
    obj: &PdfObj<'_>,
    ctx: &sis_pdf_core::scan::ScanContext,
) -> bool {
    encoding_contains_script_like_names_with_depth(obj, ctx, 0)
}

fn encoding_contains_string_values_with_depth(
    obj: &PdfObj<'_>,
    ctx: &sis_pdf_core::scan::ScanContext,
    depth: usize,
) -> bool {
    if depth >= 8 {
        return false;
    }
    match &obj.atom {
        PdfAtom::Str(_) => true,
        PdfAtom::Array(values) => values
            .iter()
            .any(|value| encoding_contains_string_values_with_depth(value, ctx, depth + 1)),
        PdfAtom::Dict(dict) => dict
            .entries
            .iter()
            .any(|(_, value)| encoding_contains_string_values_with_depth(value, ctx, depth + 1)),
        PdfAtom::Ref { .. } => ctx
            .graph
            .resolve_ref(obj)
            .map(|resolved| {
                let resolved_obj = PdfObj { span: resolved.body_span, atom: resolved.atom };
                encoding_contains_string_values_with_depth(&resolved_obj, ctx, depth + 1)
            })
            .unwrap_or(false),
        _ => false,
    }
}

fn encoding_contains_script_like_names_with_depth(
    obj: &PdfObj<'_>,
    ctx: &sis_pdf_core::scan::ScanContext,
    depth: usize,
) -> bool {
    if depth >= 8 {
        return false;
    }
    match &obj.atom {
        PdfAtom::Name(name) => encoded_name_is_script_like(&name.decoded),
        PdfAtom::Array(values) => values
            .iter()
            .any(|value| encoding_contains_script_like_names_with_depth(value, ctx, depth + 1)),
        PdfAtom::Dict(dict) => dict.entries.iter().any(|(key, value)| {
            encoded_name_is_script_like(&key.decoded)
                || encoding_contains_script_like_names_with_depth(value, ctx, depth + 1)
        }),
        PdfAtom::Ref { .. } => ctx
            .graph
            .resolve_ref(obj)
            .map(|resolved| {
                let resolved_obj = PdfObj { span: resolved.body_span, atom: resolved.atom };
                encoding_contains_script_like_names_with_depth(&resolved_obj, ctx, depth + 1)
            })
            .unwrap_or(false),
        _ => false,
    }
}

fn encoded_name_is_script_like(decoded_name: &[u8]) -> bool {
    if decoded_name.is_empty() {
        return false;
    }
    if decoded_name.contains(&b'#') {
        return true;
    }
    let lower = decoded_name.iter().map(|byte| byte.to_ascii_lowercase()).collect::<Vec<u8>>();
    [b"javascript".as_slice(), b"app.".as_slice(), b"eval".as_slice(), b"fromcharcode".as_slice()]
        .into_iter()
        .any(|needle| lower.windows(needle.len()).any(|window| window == needle))
}

fn is_cmap_stream(entry: &ObjEntry<'_>) -> bool {
    let PdfAtom::Stream(stream) = &entry.atom else {
        return false;
    };
    stream.dict.has_name(b"/Type", b"/CMap")
        || stream.dict.get_first(b"/CMapName").is_some()
        || stream.dict.get_first(b"/CIDSystemInfo").is_some()
}

fn contains_pdfjs_injection_tokens(payload: &[u8]) -> bool {
    let lower = payload.iter().map(|byte| byte.to_ascii_lowercase()).collect::<Vec<u8>>();
    let needles: &[&[u8]] = &[b"javascript", b"app.alert", b"eval(", b"function(", b"constructor("];
    needles.iter().any(|needle| {
        !needle.is_empty() && lower.windows(needle.len()).any(|window| window == *needle)
    })
}

const MAX_INJECTION_DECODE_LAYERS: u8 = 3;
const MAX_INJECTION_DECODE_BYTES: usize = 64 * 1024;

fn contains_html_injection_tokens(payload: &[u8]) -> bool {
    let lower = payload.iter().map(|byte| byte.to_ascii_lowercase()).collect::<Vec<u8>>();

    // HTML tag breaking and context escape sequences
    let context_break: &[&[u8]] = &[b"\">", b"'>", b"</", b"-->"];

    // HTML tags commonly used in XSS attacks
    let tags: &[&[u8]] = &[
        b"<script",
        b"<img",
        b"<iframe",
        b"<svg",
        b"<object",
        b"<embed",
        b"<details",
        b"<video",
        b"<audio",
        b"<base",
        b"<link",
        b"<meta",
        b"<form",
        b"<input",
        b"<button",
    ];

    // HTML event handlers
    let events: &[&[u8]] = &[
        b"onclick=",
        b"onerror=",
        b"onload=",
        b"ontoggle=",
        b"onmouseover=",
        b"onfocus=",
        b"onanimation",
        b"onbegin=",
        b"onblur=",
        b"onchange=",
        b"ondblclick=",
        b"ondrag=",
        b"onsubmit=",
        b"onkeydown=",
        b"onkeyup=",
        b"onmousedown=",
        b"onmouseenter=",
        b"onmouseleave=",
        b"onmousemove=",
        b"onmouseout=",
        b"onmouseup=",
        b"onscroll=",
    ];

    // Protocol handlers for XSS
    let protocols: &[&[u8]] = &[b"javascript:", b"data:text/html", b"data:image/svg"];

    [context_break, tags, events, protocols]
        .iter()
        .flat_map(|group| *group)
        .any(|needle| !needle.is_empty() && lower.windows(needle.len()).any(|w| w == *needle))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectionType {
    JavaScript,
    Html,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct InjectionSignals {
    has_js: bool,
    has_html: bool,
    normalised: bool,
    decode_layers: u8,
}

impl InjectionSignals {
    fn merge(&mut self, other: InjectionSignals) {
        self.has_js |= other.has_js;
        self.has_html |= other.has_html;
        self.normalised |= other.normalised;
        self.decode_layers = self.decode_layers.max(other.decode_layers);
    }

    fn classify(self) -> Option<InjectionType> {
        match (self.has_js, self.has_html) {
            (true, true) => Some(InjectionType::Both),
            (true, false) => Some(InjectionType::JavaScript),
            (false, true) => Some(InjectionType::Html),
            (false, false) => None,
        }
    }
}

fn detect_injection_signals(payload: &[u8]) -> InjectionSignals {
    let mut signals = InjectionSignals {
        has_js: contains_pdfjs_injection_tokens(payload),
        has_html: contains_html_injection_tokens(payload),
        ..InjectionSignals::default()
    };
    let normalised = normalise_injection_payload(payload);
    if normalised.decode_layers > 0 {
        signals.normalised = true;
        signals.decode_layers = normalised.decode_layers;
        signals.has_js |= contains_pdfjs_injection_tokens(&normalised.bytes);
        signals.has_html |= contains_html_injection_tokens(&normalised.bytes);
    }
    signals
}

struct NormalisedInjectionPayload {
    bytes: Vec<u8>,
    decode_layers: u8,
}

fn normalise_injection_payload(payload: &[u8]) -> NormalisedInjectionPayload {
    let mut current = truncate_decode_bytes(payload.to_vec());
    let mut decode_layers = 0u8;

    for _ in 0..MAX_INJECTION_DECODE_LAYERS {
        let mut changed = false;

        if let Some(next) = normalise_text_bytes_for_script(&current) {
            let next = truncate_decode_bytes(next);
            if next != current {
                current = next;
                changed = true;
            }
        }

        let (percent_decoded, percent_changed) = decode_percent_encoding(&current);
        if percent_changed {
            current = truncate_decode_bytes(percent_decoded);
            changed = true;
        }

        let (escape_decoded, escape_changed) = decode_js_escapes(&current);
        if escape_changed {
            current = truncate_decode_bytes(escape_decoded);
            changed = true;
        }

        let (entity_decoded, entity_changed) = decode_html_entities(&current);
        if entity_changed {
            current = truncate_decode_bytes(entity_decoded);
            changed = true;
        }

        if !changed {
            break;
        }
        decode_layers = decode_layers.saturating_add(1);
    }

    NormalisedInjectionPayload { bytes: current, decode_layers }
}

fn truncate_decode_bytes(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() > MAX_INJECTION_DECODE_BYTES {
        bytes.truncate(MAX_INJECTION_DECODE_BYTES);
    }
    bytes
}

fn decode_percent_encoding(input: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(input.len().min(MAX_INJECTION_DECODE_BYTES));
    let mut i = 0usize;
    let mut changed = false;
    while i < input.len() && out.len() < MAX_INJECTION_DECODE_BYTES {
        if input[i] == b'%' && i + 2 < input.len() {
            let hi = hex_value(input[i + 1]);
            let lo = hex_value(input[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi << 4) | lo);
                i += 3;
                changed = true;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    (out, changed)
}

fn decode_js_escapes(input: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(input.len().min(MAX_INJECTION_DECODE_BYTES));
    let mut i = 0usize;
    let mut changed = false;
    while i < input.len() && out.len() < MAX_INJECTION_DECODE_BYTES {
        if input[i] == b'\\' && i + 1 < input.len() {
            if input[i + 1] == b'x' && i + 3 < input.len() {
                let hi = hex_value(input[i + 2]);
                let lo = hex_value(input[i + 3]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi << 4) | lo);
                    i += 4;
                    changed = true;
                    continue;
                }
            }
            if input[i + 1] == b'u' && i + 5 < input.len() {
                let h1 = hex_value(input[i + 2]);
                let h2 = hex_value(input[i + 3]);
                let h3 = hex_value(input[i + 4]);
                let h4 = hex_value(input[i + 5]);
                if let (Some(h1), Some(h2), Some(h3), Some(h4)) = (h1, h2, h3, h4) {
                    let codepoint =
                        ((h1 as u32) << 12) | ((h2 as u32) << 8) | ((h3 as u32) << 4) | (h4 as u32);
                    if let Some(ch) = char::from_u32(codepoint) {
                        let mut buf = [0u8; 4];
                        let encoded = ch.encode_utf8(&mut buf);
                        let remaining = MAX_INJECTION_DECODE_BYTES.saturating_sub(out.len());
                        if remaining == 0 {
                            break;
                        }
                        let copy_len = encoded.len().min(remaining);
                        out.extend_from_slice(&encoded.as_bytes()[..copy_len]);
                        i += 6;
                        changed = true;
                        continue;
                    }
                }
            }
        }
        out.push(input[i]);
        i += 1;
    }
    (out, changed)
}

fn decode_html_entities(input: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(input.len().min(MAX_INJECTION_DECODE_BYTES));
    let mut i = 0usize;
    let mut changed = false;

    while i < input.len() && out.len() < MAX_INJECTION_DECODE_BYTES {
        if input[i] == b'&' {
            let search_end = (i + 12).min(input.len());
            if let Some(rel_end) = input[i + 1..search_end].iter().position(|b| *b == b';') {
                let end = i + 1 + rel_end;
                let entity_bytes = &input[i + 1..end];
                if let Some(decoded) = decode_single_html_entity(entity_bytes) {
                    let remaining = MAX_INJECTION_DECODE_BYTES.saturating_sub(out.len());
                    if remaining == 0 {
                        break;
                    }
                    let copy_len = decoded.len().min(remaining);
                    out.extend_from_slice(&decoded[..copy_len]);
                    i = end + 1;
                    changed = true;
                    continue;
                }
            }
        }
        out.push(input[i]);
        i += 1;
    }

    (out, changed)
}

fn decode_single_html_entity(entity: &[u8]) -> Option<Vec<u8>> {
    let lowered = entity.iter().map(|b| b.to_ascii_lowercase()).collect::<Vec<u8>>();
    match lowered.as_slice() {
        b"lt" => Some(vec![b'<']),
        b"gt" => Some(vec![b'>']),
        b"amp" => Some(vec![b'&']),
        b"quot" => Some(vec![b'"']),
        b"apos" => Some(vec![b'\'']),
        _ => {
            if let Some(hex) = lowered.strip_prefix(b"#x") {
                return decode_entity_codepoint(hex, 16);
            }
            if let Some(dec) = lowered.strip_prefix(b"#") {
                return decode_entity_codepoint(dec, 10);
            }
            None
        }
    }
}

fn decode_entity_codepoint(digits: &[u8], radix: u32) -> Option<Vec<u8>> {
    let text = str::from_utf8(digits).ok()?;
    let value = u32::from_str_radix(text, radix).ok()?;
    let ch = char::from_u32(value)?;
    let mut buf = [0u8; 4];
    let encoded = ch.encode_utf8(&mut buf);
    Some(encoded.as_bytes().to_vec())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
fn detect_injection_type(payload: &[u8]) -> Option<InjectionType> {
    detect_injection_signals(payload).classify()
}

struct SubmitFormDetector;

struct ScatteredPayloadAssemblyDetector;
struct CrossStreamPayloadAssemblyDetector;

impl Detector for ScatteredPayloadAssemblyDetector {
    fn id(&self) -> &'static str {
        "scattered_payload_assembly"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::Forms
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for candidate in collect_assembly_candidates(ctx, AssemblyCandidateScope::FormOnly) {
            let mut meta = std::collections::HashMap::new();
            meta.insert("chain.stage".into(), "decode".into());
            meta.insert("chain.capability".into(), "payload_scatter".into());
            meta.insert("chain.trigger".into(), "pdfjs".into());
            meta.insert("scatter.fragment_count".into(), candidate.fragment_count.to_string());
            meta.insert(
                "scatter.object_ids".into(),
                candidate.object_ids.iter().cloned().collect::<Vec<_>>().join(","),
            );
            meta.insert(
                "injection.sources".into(),
                candidate.sources.iter().copied().collect::<Vec<_>>().join(","),
            );
            meta.insert("injection.signal.js".into(), candidate.signals.has_js.to_string());
            meta.insert("injection.signal.html".into(), candidate.signals.has_html.to_string());
            if candidate.signals.normalised {
                meta.insert("injection.normalised".into(), "true".into());
                meta.insert(
                    "injection.decode_layers".into(),
                    candidate.signals.decode_layers.to_string(),
                );
            }

            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Forms,
                kind: "scattered_payload_assembly".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                impact: Some(Impact::Medium),
                title: "Scattered payload assembly indicator".into(),
                description:
                    "Form payload fragments are benign in isolation but assemble into an injection-capable payload."
                        .into(),
                objects: candidate.object_ids.iter().cloned().collect(),
                evidence: form_injection_evidence(ctx.bytes, &candidate.sources, 3),
                remediation: Some(
                    "Inspect fragmented form values/appearances and resolve indirect references to identify reconstructed payloads."
                        .into(),
                ),
                meta,
                reader_impacts: vec![ReaderImpact {
                    profile: ReaderProfile::Pdfium,
                    surface: AttackSurface::Forms,
                    severity: Severity::Medium,
                    impact: Impact::Medium,
                    note: Some(
                        "Distributed fragments can reconstruct executable payloads at render time or export-time."
                            .into(),
                    ),
                }],
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

impl Detector for CrossStreamPayloadAssemblyDetector {
    fn id(&self) -> &'static str {
        "cross_stream_payload_assembly"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::JavaScript
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let scattered_candidates =
            collect_assembly_candidates(ctx, AssemblyCandidateScope::CrossStream);
        if scattered_candidates.is_empty() {
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else {
                continue;
            };

            let js_payloads = js_payload_candidates_from_entry(ctx, entry);
            if js_payloads.is_empty() {
                continue;
            }

            let js_object_ref = format!("{} {} obj", entry.obj, entry.gen);
            for payload_candidate in &js_payloads {
                let js_meta = js_analysis::static_analysis::extract_js_signals_with_ast(
                    &payload_candidate.payload.bytes,
                    false,
                );
                if !js_payload_has_assembly_pattern(&payload_candidate.payload.bytes, &js_meta) {
                    continue;
                }

                let matched_candidates: Vec<&ScatteredAssemblyCandidate> = scattered_candidates
                    .iter()
                    .filter(|candidate| {
                        js_payload_matches_scattered_candidate(
                            &payload_candidate.payload.bytes,
                            &js_meta,
                            &candidate.assembled,
                        )
                    })
                    .collect();
                if matched_candidates.is_empty() {
                    continue;
                }

                let mut object_ids = BTreeSet::new();
                object_ids.insert(js_object_ref.clone());
                let mut matched_scatter_objects = BTreeSet::new();
                let mut matched_sources = BTreeSet::new();
                for candidate in &matched_candidates {
                    for object_ref in &candidate.object_ids {
                        object_ids.insert(object_ref.clone());
                        matched_scatter_objects.insert(object_ref.clone());
                    }
                    for source in &candidate.sources {
                        matched_sources.insert(*source);
                    }
                }

                let mut meta = std::collections::HashMap::new();
                meta.insert("chain.stage".into(), "decode".into());
                meta.insert("chain.capability".into(), "cross_stream_assembly".into());
                meta.insert("chain.trigger".into(), "pdfjs".into());
                meta.insert("js.object.ref".into(), js_object_ref.clone());
                meta.insert(
                    "scatter.object_ids".into(),
                    matched_scatter_objects.into_iter().collect::<Vec<_>>().join(","),
                );
                meta.insert(
                    "injection.sources".into(),
                    matched_sources.into_iter().collect::<Vec<_>>().join(","),
                );
                let mut matched_source_types = BTreeSet::new();
                for candidate in &matched_candidates {
                    for source_type in &candidate.source_types {
                        matched_source_types.insert(*source_type);
                    }
                }
                meta.insert(
                    "cross_stream.source_types".into(),
                    matched_source_types.into_iter().collect::<Vec<_>>().join(","),
                );
                if let Some(value) = js_meta.get("payload.fromCharCode_reconstructed") {
                    meta.insert("js.payload.fromcharcode_reconstructed".into(), value.clone());
                }
                if let Some(value) = js_meta.get("payload.fromCharCode_count") {
                    meta.insert("js.payload.fromcharcode_count".into(), value.clone());
                }
                if let Some(value) = js_meta.get("payload.fromCharCode_preview") {
                    meta.insert("js.payload.fromcharcode_preview".into(), value.clone());
                }

                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::JavaScript,
                    kind: "cross_stream_payload_assembly".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    impact: Some(Impact::Medium),
                    title: "Cross-stream payload assembly indicator".into(),
                    description:
                        "JavaScript assembly behaviour aligns with payload fragments reconstructed from form, annotation, or metadata objects."
                            .into(),
                    objects: object_ids.into_iter().collect(),
                    evidence: vec![span_to_evidence(dict.span, "JavaScript assembly context")],
                    remediation: Some(
                        "Correlate JavaScript reconstruction logic with fragmented form/object payload sources."
                            .into(),
                    ),
                    meta,
                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });

                break;
            }
        }

        Ok(findings)
    }
}

impl Detector for SubmitFormDetector {
    fn id(&self) -> &'static str {
        "submitform_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Forms
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        action_by_s(
            ctx,
            b"/SubmitForm",
            &[b"/F"],
            "submitform_present",
            "SubmitForm action present",
            "/SubmitForm",
            "user",
        )
    }
}

struct GoToRDetector;

impl Detector for GoToRDetector {
    fn id(&self) -> &'static str {
        "gotor_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        action_by_s(
            ctx,
            b"/GoToR",
            &[b"/F"],
            "gotor_present",
            "GoToR action present",
            "/GoToR",
            "automatic",
        )
    }
}

struct ActionRemoteTargetSuspiciousDetector;

impl Detector for ActionRemoteTargetSuspiciousDetector {
    fn id(&self) -> &'static str {
        "action_remote_target_suspicious"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            let Some(action_type) = action_s_name(dict) else {
                continue;
            };
            let target_keys = action_target_keys_for_type(&action_type);
            if target_keys.is_empty() {
                continue;
            }

            let mut evidence = vec![span_to_evidence(dict.span, "Action dict")];
            let mut meta = std::collections::HashMap::new();
            if let Some(enriched) =
                payload_from_dict(ctx, dict, &target_keys, "Action remote target value")
            {
                evidence.extend(enriched.evidence);
                meta.extend(enriched.meta);
            }

            let Some(target_analysis) = analyse_remote_target_from_dict(ctx, dict, &target_keys)
            else {
                continue;
            };
            if target_analysis.indicators.is_empty() {
                continue;
            }

            let target = target_analysis.preview.clone();
            let telemetry =
                annotate_action_meta(&mut meta, &action_type, Some(target.as_str()), "automatic");
            let egress_target_kind = egress_target_kind_for_remote_analysis(&target_analysis);
            meta.insert("action.s".into(), action_type.clone());
            meta.insert("action.remote.indicators".into(), target_analysis.indicators.join(","));
            meta.insert("action.remote.target_preview".into(), target_analysis.preview);
            meta.insert("action.remote.scheme".into(), target_analysis.scheme.clone());
            meta.insert("chain.stage".into(), "egress".into());
            meta.insert("chain.capability".into(), "remote_action_target".into());
            meta.insert("chain.trigger".into(), "action".into());
            meta.insert(
                "egress.channel".into(),
                egress_channel_for_action(action_type.as_str()).to_string(),
            );
            meta.insert("egress.target_kind".into(), egress_target_kind.to_string());
            meta.insert(
                "egress.user_interaction_required".into(),
                egress_user_interaction_required(action_type.as_str()).to_string(),
            );
            if target_analysis.decode_layers > 0 {
                meta.insert("injection.action_param_normalised".into(), "true".into());
                meta.insert(
                    "injection.decode_layers".into(),
                    target_analysis.decode_layers.to_string(),
                );
            }

            let (severity, confidence, impact) = if target_analysis
                .indicators
                .iter()
                .any(|indicator| matches!(indicator.as_str(), "javascript_scheme" | "data_uri"))
            {
                (Severity::High, Confidence::Strong, Some(Impact::High))
            } else {
                (Severity::Medium, Confidence::Probable, Some(Impact::Medium))
            };

            let mut finding = Finding {
                id: String::new(),
                surface: AttackSurface::Actions,
                kind: "action_remote_target_suspicious".into(),
                severity,
                confidence,
                impact,
                title: "Suspicious remote action target".into(),
                description: "Action target uses high-risk remote target patterns.".into(),
                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                evidence,
                remediation: Some(
                    "Inspect action target resolution and block remote target schemes or obfuscated paths."
                        .into(),
                ),
                meta,
                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            };
            apply_action_telemetry(&mut finding, &telemetry);
            findings.push(finding);
        }
        Ok(findings)
    }
}

#[derive(Default)]
struct ActionRemoteTargetAnalysis {
    indicators: Vec<String>,
    scheme: String,
    preview: String,
    decode_layers: u8,
}

fn action_s_name(dict: &PdfDict<'_>) -> Option<String> {
    let (_, value) = dict.get_first(b"/S")?;
    let PdfAtom::Name(name) = &value.atom else {
        return None;
    };
    Some(String::from_utf8_lossy(&name.decoded).to_string())
}

fn action_target_keys_for_type(action_type: &str) -> Vec<&'static [u8]> {
    match action_type.trim_start_matches('/') {
        "GoToR" | "GoToE" | "SubmitForm" | "Launch" => vec![b"/F"],
        "URI" => vec![b"/URI"],
        _ => Vec::new(),
    }
}

fn analyse_remote_target_from_dict(
    ctx: &sis_pdf_core::scan::ScanContext,
    dict: &PdfDict<'_>,
    keys: &[&[u8]],
) -> Option<ActionRemoteTargetAnalysis> {
    for key in keys {
        let Some((_, value)) = dict.get_first(key) else {
            continue;
        };
        let base = resolve_payload(ctx, value)
            .payload
            .map(|payload| payload.bytes)
            .unwrap_or_else(|| payload_string(value));
        if base.is_empty() {
            continue;
        }
        let normalised = normalise_injection_payload(&base);
        let decode_layers = normalised.decode_layers;
        let bytes = if decode_layers > 0 { normalised.bytes } else { base };
        let lower = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
        let mut indicators = Vec::new();
        if lower.starts_with("\\\\") || lower.starts_with("//") {
            indicators.push("unc_path".to_string());
        }
        if lower.starts_with("data:") {
            indicators.push("data_uri".to_string());
        }
        if lower.starts_with("javascript:") {
            indicators.push("javascript_scheme".to_string());
        }
        if lower.starts_with("file://") {
            indicators.push("file_scheme".to_string());
        }
        if decode_layers > 0 || lower.contains('%') {
            indicators.push("obfuscated_target".to_string());
        }
        indicators.sort();
        indicators.dedup();
        if indicators.is_empty() {
            return None;
        }
        let scheme = lower
            .split(':')
            .next()
            .filter(|token| !token.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| "unknown".into());
        return Some(ActionRemoteTargetAnalysis {
            indicators,
            scheme,
            preview: preview_ascii(&bytes, 160),
            decode_layers,
        });
    }
    None
}

fn egress_channel_for_action(action_type: &str) -> &'static str {
    match action_type.trim_start_matches('/') {
        "URI" => "uri_action",
        "SubmitForm" => "submit_form",
        "GoToR" | "GoToE" => "remote_goto",
        "Launch" => "launch_target",
        _ => "action_target",
    }
}

fn egress_target_kind_for_remote_analysis(analysis: &ActionRemoteTargetAnalysis) -> &'static str {
    if analysis.indicators.iter().any(|indicator| indicator == "javascript_scheme") {
        return "script_uri";
    }
    if analysis.indicators.iter().any(|indicator| indicator == "data_uri") {
        return "data_uri";
    }
    if analysis.indicators.iter().any(|indicator| indicator == "file_scheme") {
        return "file_uri";
    }
    if analysis.indicators.iter().any(|indicator| indicator == "unc_path") {
        return "unc_path";
    }
    "remote_target"
}

fn egress_user_interaction_required(action_type: &str) -> &'static str {
    match action_type.trim_start_matches('/') {
        "URI" | "SubmitForm" => "true",
        "GoToR" | "GoToE" | "Launch" => "false",
        _ => "unknown",
    }
}

struct EmbeddedFileDetector;
struct FormFieldOversizedValueDetector;
struct NullRefChainTerminationDetector;

#[derive(Clone, Debug)]
struct EmbeddedScriptAssessment {
    family: String,
    confidence: Confidence,
    signals: Vec<String>,
}

fn embedded_extension_family(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".sh") || lower.ends_with(".bash") || lower.ends_with(".zsh") {
        return Some("shell");
    }
    if lower.ends_with(".bat") || lower.ends_with(".cmd") {
        return Some("cmd");
    }
    if lower.ends_with(".ps1") || lower.ends_with(".psm1") {
        return Some("powershell");
    }
    if lower.ends_with(".vbs") {
        return Some("vbscript");
    }
    if lower.ends_with(".js") || lower.ends_with(".mjs") || lower.ends_with(".jse") {
        return Some("javascript");
    }
    None
}

fn embedded_extension_risk_family(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if [
        ".exe", ".dll", ".com", ".scr", ".msi", ".ps1", ".psm1", ".bat", ".cmd", ".js", ".jse",
        ".vbs", ".sh", ".bash", ".zsh",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
    {
        return Some("active");
    }
    if [".zip", ".rar", ".7z", ".tar", ".gz"].iter().any(|suffix| lower.ends_with(suffix)) {
        return Some("archive");
    }
    if [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
    {
        return Some("document");
    }
    if [".swf", ".mp4", ".mov", ".avi"].iter().any(|suffix| lower.ends_with(suffix)) {
        return Some("media");
    }
    None
}

fn magic_risk_family(magic_type: &str) -> Option<&'static str> {
    match magic_type {
        "pe" | "script" => Some("active"),
        "zip" | "rar" => Some("archive"),
        "pdf" => Some("document"),
        "swf" => Some("media"),
        _ => None,
    }
}

fn embedded_declared_subtype(dict: &PdfDict<'_>) -> Option<String> {
    dict.get_first(b"/Subtype").and_then(|(_, value)| match &value.atom {
        PdfAtom::Name(name) => Some(String::from_utf8_lossy(&name.decoded).to_string()),
        PdfAtom::Str(value) => Some(String::from_utf8_lossy(&string_bytes(value)).to_string()),
        _ => None,
    })
}

fn mime_risk_family(subtype: &str) -> Option<&'static str> {
    let lower = subtype.to_ascii_lowercase();
    if lower.contains("application/x-msdownload")
        || lower.contains("application/x-dosexec")
        || lower.contains("application/javascript")
        || lower.contains("application/x-sh")
        || lower.contains("application/x-bat")
        || lower.contains("text/javascript")
        || lower.contains("text/vbscript")
    {
        return Some("active");
    }
    if lower.contains("application/zip")
        || lower.contains("application/x-rar")
        || lower.contains("application/x-7z")
    {
        return Some("archive");
    }
    if lower.contains("application/pdf")
        || lower.contains("application/msword")
        || lower.contains("officedocument")
        || lower.contains("application/rtf")
    {
        return Some("document");
    }
    if lower.contains("application/x-shockwave-flash")
        || lower.contains("video/")
        || lower.contains("audio/")
    {
        return Some("media");
    }
    None
}

fn detect_script_signals(data: &[u8]) -> Vec<(&'static str, &'static str)> {
    let max_scan_bytes = 256 * 1024;
    let slice = if data.len() > max_scan_bytes { &data[..max_scan_bytes] } else { data };
    let mut signals = Vec::new();
    if slice.starts_with(b"#!") {
        signals.push(("shell", "header:shebang"));
    }
    if contains_any_ci(
        slice,
        &[
            b"/bin/sh".as_slice(),
            b"#!/bin/bash".as_slice(),
            b"bash -c".as_slice(),
            b"sh -c".as_slice(),
        ],
    ) {
        signals.push(("shell", "token:shell"));
    }
    if contains_any_ci(
        slice,
        &[
            b"@echo off".as_slice(),
            b"cmd /c".as_slice(),
            b"cmd.exe".as_slice(),
            b" %comspec% ".as_slice(),
        ],
    ) {
        signals.push(("cmd", "token:cmd"));
    }
    if contains_any_ci(
        slice,
        &[
            b"powershell".as_slice(),
            b"write-host".as_slice(),
            b"invoke-expression".as_slice(),
            b"iex ".as_slice(),
            b"$env:".as_slice(),
        ],
    ) {
        signals.push(("powershell", "token:powershell"));
    }
    if contains_any_ci(
        slice,
        &[b"vbscript".as_slice(), b"wscript.shell".as_slice(), b"createobject(".as_slice()],
    ) {
        signals.push(("vbscript", "token:vbscript"));
    }
    if looks_like_js_text(slice) {
        signals.push(("javascript", "token:javascript"));
    }
    signals
}

fn contains_any_ci(data: &[u8], needles: &[&[u8]]) -> bool {
    let lower = data.iter().map(|byte| byte.to_ascii_lowercase()).collect::<Vec<u8>>();
    needles.iter().any(|needle| lower.windows(needle.len()).any(|window| window == *needle))
}

fn printable_ascii_ratio(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    let printable =
        bytes.iter().filter(|byte| matches!(**byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7E)).count();
    (printable * 100) / bytes.len()
}

fn classify_embedded_script(
    filename: Option<&str>,
    magic_type: Option<&str>,
    bytes: &[u8],
) -> Option<EmbeddedScriptAssessment> {
    let printable_ratio = printable_ascii_ratio(bytes);
    if printable_ratio < 60 {
        return None;
    }

    let ext_family = filename.and_then(embedded_extension_family);
    let signals = detect_script_signals(bytes);
    let mut family_scores: std::collections::HashMap<String, i32> =
        std::collections::HashMap::new();
    let mut signal_labels = Vec::new();

    if let Some(family) = ext_family {
        *family_scores.entry(family.to_string()).or_insert(0) += 3;
        signal_labels.push(format!("extension:{family}"));
    }
    if matches!(magic_type, Some("script")) {
        let target_family = ext_family.unwrap_or("shell");
        *family_scores.entry(target_family.to_string()).or_insert(0) += 2;
        signal_labels.push("magic:script".into());
    }
    for (family, label) in signals {
        *family_scores.entry(family.to_string()).or_insert(0) += 2;
        signal_labels.push(label.to_string());
    }

    let Some((family, score)) = family_scores.into_iter().max_by_key(|(_, score)| *score) else {
        return None;
    };
    if score < 3 {
        return None;
    }

    let confidence = if score >= 6 {
        Confidence::Strong
    } else if score >= 4 {
        Confidence::Probable
    } else {
        Confidence::Tentative
    };
    signal_labels.sort();
    signal_labels.dedup();

    Some(EmbeddedScriptAssessment { family, confidence, signals: signal_labels })
}

impl Detector for EmbeddedFileDetector {
    fn id(&self) -> &'static str {
        "embedded_file_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::EmbeddedFiles
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let timeout = TimeoutChecker::new(Duration::from_millis(100));
        let embedded_index = build_embedded_artefact_index(&ctx.graph);
        for entry in &ctx.graph.objects {
            if timeout.check().is_err() {
                break;
            }
            if let PdfAtom::Stream(st) = &entry.atom {
                if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
                    let mut evidence = EvidenceBuilder::new()
                        .file_offset(
                            st.dict.span.start,
                            st.dict.span.len() as u32,
                            "EmbeddedFile dict",
                        )
                        .file_offset(
                            st.data_span.start,
                            st.data_span.len() as u32,
                            "EmbeddedFile stream",
                        )
                        .build();
                    let mut meta = std::collections::HashMap::new();
                    let mut magic = None;
                    let mut encrypted_container = false;
                    let mut has_double = false;
                    let stream_ref = (entry.obj, entry.gen);
                    let artefact_ref: Option<&EmbeddedArtefactRef> =
                        embedded_index.get(&stream_ref);
                    let filename = artefact_ref
                        .and_then(|record| record.filename.clone())
                        .or_else(|| embedded_filename(&st.dict));
                    let declared_subtype = embedded_declared_subtype(&st.dict);
                    let extension_family = filename
                        .as_deref()
                        .and_then(embedded_extension_risk_family)
                        .map(str::to_string);
                    let declared_family =
                        declared_subtype.as_deref().and_then(mime_risk_family).map(str::to_string);
                    meta.insert(
                        "embedded.stream_ref".into(),
                        format!("{} {}", stream_ref.0, stream_ref.1),
                    );
                    meta.insert(
                        "embedded.relationship.filespec_present".into(),
                        artefact_ref.and_then(|record| record.filespec_ref).is_some().to_string(),
                    );
                    meta.insert(
                        "embedded.relationship.binding".into(),
                        if artefact_ref.and_then(|record| record.filespec_ref).is_some() {
                            "filespec".into()
                        } else {
                            "stream_only".into()
                        },
                    );
                    if let Some((filespec_obj, filespec_gen)) =
                        artefact_ref.and_then(|record| record.filespec_ref)
                    {
                        meta.insert(
                            "embedded.filespec_ref".into(),
                            format!("{} {}", filespec_obj, filespec_gen),
                        );
                    }
                    if let Some(name) = &filename {
                        meta.insert("embedded.filename".into(), name.clone());
                        meta.insert("filename".into(), name.clone());
                        if let Some(family) = &extension_family {
                            meta.insert("embedded.extension_family".into(), family.clone());
                        }
                        has_double = has_double_extension(name);
                        if has_double {
                            meta.insert("embedded.double_extension".into(), "true".into());
                        }
                    }
                    if let Some(subtype) = &declared_subtype {
                        meta.insert("embedded.declared_subtype".into(), subtype.clone());
                    }
                    if let Some(family) = &declared_family {
                        meta.insert("embedded.declared_family".into(), family.clone());
                    }
                    let mut script_assessment: Option<EmbeddedScriptAssessment> = None;
                    let mut family_mismatch_axes = Vec::new();
                    if let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, st) {
                        let analysis = analyse_stream(&decoded.data, &StreamLimits::default());
                        let hash = sha256_hex(&decoded.data);
                        meta.insert("hash.sha256".into(), hash.clone());
                        meta.insert("embedded.sha256".into(), hash.clone());
                        meta.insert("hash.blake3".into(), analysis.blake3.clone());
                        meta.insert("embedded.blake3".into(), analysis.blake3.clone());
                        meta.insert("size_bytes".into(), analysis.size_bytes.to_string());
                        meta.insert("stream.size_bytes".into(), analysis.size_bytes.to_string());
                        meta.insert("entropy".into(), format!("{:.2}", analysis.entropy));
                        meta.insert("stream.entropy".into(), format!("{:.2}", analysis.entropy));
                        let mut encrypted_flag = "false";
                        let magic_value = analysis.magic_type.clone();
                        let is_zip = magic_value == "zip";
                        let is_rar = crate::is_rar_magic(&decoded.data);
                        let is_encrypted_archive = (is_zip && crate::zip_encrypted(&decoded.data))
                            || (is_rar && crate::rar_encrypted(&decoded.data));
                        meta.insert("embedded.magic".into(), magic_value.clone());
                        meta.insert("magic_type".into(), magic_value.clone());
                        meta.insert("stream.magic_type".into(), magic_value.clone());
                        if let Some(magic_family) = magic_risk_family(&magic_value) {
                            meta.insert("embedded.magic_family".into(), magic_family.into());
                            if let Some(ext_family) = extension_family.as_deref() {
                                if ext_family != magic_family {
                                    family_mismatch_axes.push("extension_vs_magic");
                                }
                            }
                            if let Some(declared_family) = declared_family.as_deref() {
                                if declared_family != magic_family {
                                    family_mismatch_axes.push("subtype_vs_magic");
                                }
                            }
                        }
                        if let (Some(ext_family), Some(declared_family)) =
                            (extension_family.as_deref(), declared_family.as_deref())
                        {
                            if ext_family != declared_family {
                                family_mismatch_axes.push("extension_vs_subtype");
                            }
                        }
                        magic = Some(magic_value);
                        script_assessment = classify_embedded_script(
                            filename.as_deref(),
                            magic.as_deref(),
                            &decoded.data,
                        );
                        if let Some(assessment) = &script_assessment {
                            meta.insert("embedded.script_family".into(), assessment.family.clone());
                            meta.insert(
                                "embedded.script_signals".into(),
                                assessment.signals.join(","),
                            );
                        }
                        if is_encrypted_archive {
                            meta.insert("embedded.encrypted_container".into(), "true".into());
                            encrypted_flag = "true";
                            encrypted_container = true;
                        }
                        meta.insert("encrypted".into(), encrypted_flag.into());
                        if decoded.input_len > 0 {
                            let ratio = decoded.data.len() as f64 / decoded.input_len as f64;
                            meta.insert("embedded.decode_ratio".into(), format!("{:.2}", ratio));
                        }
                        evidence.push(decoded_evidence_span(
                            st.data_span,
                            &decoded.data,
                            "Decoded embedded file",
                        ));
                        meta.insert(
                            "embedded.decoded_preview".into(),
                            preview_ascii(&decoded.data, 120),
                        );
                    }
                    let payload_target = action_target_from_meta(&meta);
                    let action_target = meta.get("embedded.filename").cloned().or(payload_target);
                    annotate_action_meta(
                        &mut meta,
                        "/EmbeddedFile",
                        action_target.as_deref(),
                        "automatic",
                    );
                    meta.insert("chain.stage".into(), "decode".into());
                    meta.insert("chain.capability".into(), "embedded_payload".into());
                    meta.insert("chain.trigger".into(), "embedded_file".into());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "embedded_file_present".into(),
                        severity: Severity::High,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "Embedded file stream present".into(),
                        description: "Embedded file detected inside PDF.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Extract and scan the embedded file.".into()),
                        meta: meta.clone(),

                        reader_impacts: Vec::new(),
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });

                    let mut objects = vec![format!("{} {} obj", entry.obj, entry.gen)];
                    if let Some((filespec_obj, filespec_gen)) =
                        artefact_ref.and_then(|record| record.filespec_ref)
                    {
                        objects.push(format!("{} {} obj", filespec_obj, filespec_gen));
                    }
                    if let Some(magic) = magic.as_deref() {
                        if magic == "pe" {
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "embedded_executable_present".into(),
                                severity: Severity::High,
                                confidence: Confidence::Probable,
                                impact: None,
                                title: "Embedded executable present".into(),
                                description: "Embedded file appears to be an executable.".into(),
                                objects: objects.clone(),
                                evidence: evidence.clone(),
                                remediation: Some("Extract and scan the executable.".into()),
                                meta: meta.clone(),

                                reader_impacts: Vec::new(),
                                action_type: None,
                                action_target: None,
                                action_initiation: None,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                            });
                        }
                        if magic == "script" || script_assessment.is_some() {
                            let script_confidence = script_assessment
                                .as_ref()
                                .map(|assessment| assessment.confidence)
                                .unwrap_or(Confidence::Probable);
                            let script_description = if let Some(assessment) = &script_assessment {
                                format!(
                                    "Embedded file appears to be {} script content.",
                                    assessment.family
                                )
                            } else {
                                "Embedded file appears to be a script.".to_string()
                            };
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "embedded_script_present".into(),
                                severity: Severity::Medium,
                                confidence: script_confidence,
                                impact: None,
                                title: "Embedded script present".into(),
                                description: script_description,
                                objects: objects.clone(),
                                evidence: evidence.clone(),
                                remediation: Some("Review the script content.".into()),
                                meta: meta.clone(),

                                reader_impacts: Vec::new(),
                                action_type: None,
                                action_target: None,
                                action_initiation: None,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                            });
                        }
                    }
                    if encrypted_container {
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "embedded_archive_encrypted".into(),
                            severity: Severity::Medium,
                            confidence: Confidence::Probable,
                            impact: None,
                            title: "Embedded archive appears encrypted".into(),
                            description: "Embedded archive indicates encryption flags.".into(),
                            objects: objects.clone(),
                            evidence: evidence.clone(),
                            remediation: Some(
                                "Extract and attempt to inspect archive contents.".into(),
                            ),
                            meta: meta.clone(),

                            reader_impacts: Vec::new(),
                            action_type: None,
                            action_target: None,
                            action_initiation: None,
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                        });
                    }
                    if !family_mismatch_axes.is_empty() {
                        family_mismatch_axes.sort_unstable();
                        family_mismatch_axes.dedup();
                        meta.insert("embedded.family_mismatch".into(), "true".into());
                        meta.insert(
                            "embedded.mismatch_axes".into(),
                            family_mismatch_axes.join(","),
                        );
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "embedded_type_mismatch".into(),
                            severity: Severity::Medium,
                            confidence: Confidence::Probable,
                            impact: Some(Impact::Medium),
                            title: "Embedded file type mismatch".into(),
                            description:
                                "Embedded file extension, declared subtype, and decoded magic markers disagree."
                                    .into(),
                            objects: objects.clone(),
                            evidence: evidence.clone(),
                            remediation: Some(
                                "Treat the embedded file as suspicious and validate true payload type independently."
                                    .into(),
                            ),
                            meta: meta.clone(),
                            reader_impacts: Vec::new(),
                            action_type: None,
                            action_target: None,
                            action_initiation: None,
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                        });
                    }
                    if has_double {
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "embedded_double_extension".into(),
                            severity: Severity::Low,
                            confidence: Confidence::Probable,
                            impact: None,
                            title: "Embedded file uses double extension".into(),
                            description: "Embedded filename uses multiple extensions.".into(),
                            objects,
                            evidence,
                            remediation: Some(
                                "Treat the file as suspicious and inspect carefully.".into(),
                            ),
                            meta: meta.clone(),

                            reader_impacts: Vec::new(),
                            action_type: None,
                            action_target: None,
                            action_initiation: None,
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                        });
                    }
                }
            }
        }
        Ok(findings)
    }
}

impl Detector for FormFieldOversizedValueDetector {
    fn id(&self) -> &'static str {
        "form_field_oversized_value"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Forms
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        const OVERSIZED_THRESHOLD_BYTES: usize = 4 * 1024;
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            if !is_form_field_dict(dict) {
                continue;
            }
            let field_name = extract_form_field_name(dict);
            for key in [b"/V".as_slice(), b"/DV".as_slice()] {
                let Some((key_obj, value_obj)) = dict.get_first(key) else {
                    continue;
                };
                let payload_result = resolve_payload(ctx, value_obj);
                let Some(payload) = payload_result.payload else {
                    continue;
                };
                if payload.bytes.len() <= OVERSIZED_THRESHOLD_BYTES {
                    continue;
                }
                let mut evidence = vec![
                    span_to_evidence(dict.span, "Form field dict"),
                    span_to_evidence(
                        key_obj.span,
                        &format!("Field key {}", String::from_utf8_lossy(key)),
                    ),
                    span_to_evidence(value_obj.span, "Oversized field value"),
                ];
                if let Some(origin) = payload.origin {
                    evidence.push(decoded_evidence_span(
                        origin,
                        &payload.bytes,
                        "Resolved field payload",
                    ));
                }

                let mut meta = std::collections::HashMap::new();
                meta.insert("field.name".into(), field_name.clone());
                meta.insert("field.source".into(), String::from_utf8_lossy(key).to_string());
                meta.insert("field.value_len".into(), payload.bytes.len().to_string());
                meta.insert(
                    "field.oversized_threshold".into(),
                    OVERSIZED_THRESHOLD_BYTES.to_string(),
                );
                meta.insert("payload.ref_chain".into(), payload.ref_chain);
                meta.insert("chain.stage".into(), "input".into());
                meta.insert("chain.capability".into(), "oversized_form_value".into());
                meta.insert("chain.trigger".into(), "acroform".into());

                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::Forms,
                    kind: "form_field_oversized_value".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Tentative,
                    impact: Some(Impact::Low),
                    title: "Oversized form field value".into(),
                    description:
                        "Form field value length exceeds expected interactive form bounds.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence,
                    remediation: Some(
                        "Inspect large form field payloads for encoded script, staged data, or obfuscated content."
                            .into(),
                    ),
                    meta,
                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }
        }
        Ok(findings)
    }
}

fn is_form_field_dict(dict: &PdfDict<'_>) -> bool {
    dict.get_first(b"/FT").is_some() || dict.has_name(b"/Subtype", b"/Widget")
}

fn extract_form_field_name(dict: &PdfDict<'_>) -> String {
    let Some((_, field_obj)) = dict.get_first(b"/T") else {
        return "unnamed".into();
    };
    match &field_obj.atom {
        PdfAtom::Str(s) => preview_ascii(&string_bytes(s), 120),
        _ => "unnamed".into(),
    }
}

impl Detector for NullRefChainTerminationDetector {
    fn id(&self) -> &'static str {
        "null_ref_chain_termination"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::FileStructure
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Moderate
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        const MAX_SCAN_DEPTH: usize = 16;
        const MAX_TERMINATIONS_PER_OBJECT: usize = 4;
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            let owner_ref = format!("{} {} obj", entry.obj, entry.gen);
            let mut per_object_count = 0usize;
            for key in [
                b"/OpenAction".as_slice(),
                b"/A".as_slice(),
                b"/AA".as_slice(),
                b"/V".as_slice(),
                b"/DV".as_slice(),
                b"/AP".as_slice(),
                b"/Contents".as_slice(),
            ] {
                let Some((key_obj, value_obj)) = dict.get_first(key) else {
                    continue;
                };
                let mut visited = HashSet::new();
                let mut chain = Vec::new();
                let mut terminations = Vec::new();
                collect_null_ref_terminations(
                    ctx,
                    value_obj,
                    &mut visited,
                    &mut chain,
                    0,
                    MAX_SCAN_DEPTH,
                    &mut terminations,
                );
                for termination in terminations.into_iter().take(MAX_TERMINATIONS_PER_OBJECT) {
                    if termination.ref_depth < 3 {
                        continue;
                    }
                    per_object_count += 1;
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("context.owner".into(), owner_ref.clone());
                    meta.insert("context.key".into(), String::from_utf8_lossy(key).to_string());
                    meta.insert("termination.kind".into(), termination.kind.clone());
                    meta.insert("termination.target".into(), termination.target.clone());
                    meta.insert("ref.depth".into(), termination.ref_depth.to_string());
                    meta.insert("ref.chain".into(), termination.ref_chain.join(" -> "));
                    meta.insert("chain.stage".into(), "decode".into());
                    meta.insert("chain.capability".into(), "null_ref_chain".into());
                    meta.insert("chain.trigger".into(), "parser".into());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "null_ref_chain_termination".into(),
                        severity: if termination.ref_depth >= 5 {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        confidence: Confidence::Probable,
                        impact: Some(Impact::Medium),
                        title: "Null/missing reference chain termination".into(),
                        description:
                            "Security-relevant reference chain terminates in null or missing object."
                                .into(),
                        objects: vec![owner_ref.clone()],
                        evidence: vec![
                            span_to_evidence(entry.body_span, "Owner object"),
                            span_to_evidence(key_obj.span, "Security-relevant key"),
                            span_to_evidence(value_obj.span, "Reference-chain entry"),
                        ],
                        remediation: Some(
                            "Inspect indirect reference chains for parser-state confusion and broken/null terminal references."
                                .into(),
                        ),
                        meta,
                        reader_impacts: Vec::new(),
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                    if per_object_count >= MAX_TERMINATIONS_PER_OBJECT {
                        break;
                    }
                }
                if per_object_count >= MAX_TERMINATIONS_PER_OBJECT {
                    break;
                }
            }
        }
        Ok(findings)
    }
}

#[derive(Clone)]
struct NullRefTermination {
    kind: String,
    target: String,
    ref_depth: usize,
    ref_chain: Vec<String>,
}

fn collect_null_ref_terminations(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &PdfObj<'_>,
    visited: &mut HashSet<(u32, u16)>,
    chain: &mut Vec<String>,
    depth: usize,
    max_depth: usize,
    out: &mut Vec<NullRefTermination>,
) {
    if depth > max_depth {
        return;
    }
    match &obj.atom {
        PdfAtom::Ref { obj, gen } => {
            if *obj == 0 && *gen == 0 {
                let mut chain_with_terminal = chain.clone();
                chain_with_terminal.push("0 0 R".into());
                out.push(NullRefTermination {
                    kind: "null_object_ref".into(),
                    target: "0 0 R".into(),
                    ref_depth: chain_with_terminal.len(),
                    ref_chain: chain_with_terminal,
                });
                return;
            }
            if !visited.insert((*obj, *gen)) {
                return;
            }
            chain.push(format!("{} {} R", obj, gen));
            if let Some(entry) = ctx.graph.get_object(*obj, *gen) {
                let resolved = PdfObj { span: entry.body_span, atom: entry.atom.clone() };
                collect_null_ref_terminations(
                    ctx,
                    &resolved,
                    visited,
                    chain,
                    depth + 1,
                    max_depth,
                    out,
                );
            } else {
                out.push(NullRefTermination {
                    kind: "missing_object".into(),
                    target: format!("{} {} R", obj, gen),
                    ref_depth: chain.len(),
                    ref_chain: chain.clone(),
                });
            }
            let _ = chain.pop();
            visited.remove(&(*obj, *gen));
        }
        PdfAtom::Null => {
            out.push(NullRefTermination {
                kind: "null_literal".into(),
                target: "null".into(),
                ref_depth: chain.len(),
                ref_chain: chain.clone(),
            });
        }
        PdfAtom::Array(values) => {
            for value in values {
                collect_null_ref_terminations(
                    ctx,
                    value,
                    visited,
                    chain,
                    depth + 1,
                    max_depth,
                    out,
                );
            }
        }
        PdfAtom::Dict(dict) => {
            for (_, value) in &dict.entries {
                collect_null_ref_terminations(
                    ctx,
                    value,
                    visited,
                    chain,
                    depth + 1,
                    max_depth,
                    out,
                );
            }
        }
        PdfAtom::Stream(stream) => {
            for (_, value) in &stream.dict.entries {
                collect_null_ref_terminations(
                    ctx,
                    value,
                    visited,
                    chain,
                    depth + 1,
                    max_depth,
                    out,
                );
            }
        }
        _ => {}
    }
}

struct RichMediaDetector;

impl Detector for RichMediaDetector {
    fn id(&self) -> &'static str {
        "richmedia_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::RichMedia3D
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.get_first(b"/RichMedia").is_some() || dict.has_name(b"/Type", b"/RichMedia")
                {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "richmedia_present".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "RichMedia content present".into(),
                        description: "RichMedia annotations or dictionaries detected.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "RichMedia object")],
                        remediation: Some("Inspect 3D or media assets.".into()),
                        meta: Default::default(),

                        reader_impacts: Vec::new(),
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }
        }
        Ok(findings)
    }
}

struct ThreeDDetector;

impl Detector for ThreeDDetector {
    fn id(&self) -> &'static str {
        "3d_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::RichMedia3D
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.has_name(b"/Type", b"/3D")
                    || dict.get_first(b"/3D").is_some()
                    || dict.get_first(b"/U3D").is_some()
                    || dict.get_first(b"/PRC").is_some()
                {
                    let mut meta = std::collections::HashMap::new();
                    if let Some(bytes) = entry_payload_bytes(ctx.bytes, entry) {
                        meta.insert("size_bytes".into(), bytes.len().to_string());
                        if let Some(media_type) = detect_3d_format(bytes) {
                            meta.insert("media_type".into(), media_type.to_string());
                        }
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "3d_present".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "3D content present".into(),
                        description: "3D content or stream detected (U3D/PRC).".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "3D object")],
                        remediation: Some("Inspect embedded 3D assets.".into()),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(findings)
    }
}

struct SoundMovieDetector;

impl Detector for SoundMovieDetector {
    fn id(&self) -> &'static str {
        "sound_movie_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::RichMedia3D
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.get_first(b"/Sound").is_some()
                    || dict.get_first(b"/Movie").is_some()
                    || dict.get_first(b"/Rendition").is_some()
                {
                    let mut meta = std::collections::HashMap::new();
                    if let Some(bytes) = entry_payload_bytes(ctx.bytes, entry) {
                        meta.insert("size_bytes".into(), bytes.len().to_string());
                        if let Some(media_format) = detect_media_format(bytes) {
                            meta.insert("media_format".into(), media_format.to_string());
                        }
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "sound_movie_present".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "Sound or movie content present".into(),
                        description: "Sound/Movie/Rendition objects detected.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "Sound/Movie object")],
                        remediation: Some("Inspect embedded media objects.".into()),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(findings)
    }
}

struct FileSpecDetector;

impl Detector for FileSpecDetector {
    fn id(&self) -> &'static str {
        "filespec_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::EmbeddedFiles
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.has_name(b"/Type", b"/Filespec")
                    || dict.get_first(b"/Filespec").is_some()
                    || dict.get_first(b"/AF").is_some()
                {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "filespec_present".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "File specification present".into(),
                        description: "Filespec or associated files detected.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "Filespec/AF object")],
                        remediation: Some("Inspect file specification targets.".into()),
                        meta: Default::default(),

                        reader_impacts: Vec::new(),
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }
        }
        Ok(findings)
    }
}

struct CryptoDetector;

impl Detector for CryptoDetector {
    fn id(&self) -> &'static str {
        "crypto_signatures"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::CryptoSignatures
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let mut encrypt_evidence = Vec::new();
        let mut encrypt_meta = std::collections::HashMap::new();
        for trailer in &ctx.graph.trailers {
            if let Some((_, enc_obj)) = trailer.get_first(b"/Encrypt") {
                encrypt_evidence.push(span_to_evidence(trailer.span, "Trailer /Encrypt"));
                if encrypt_meta.is_empty() {
                    if let Some(dict) = resolve_encrypt_dict(ctx, enc_obj) {
                        encrypt_meta = encryption_meta_from_dict(&dict);
                    }
                }
                if encrypt_evidence.len() >= 2 {
                    break;
                }
            }
        }
        if !encrypt_evidence.is_empty() {
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "encryption_present".into(),
                severity: Severity::Medium,
                confidence: Confidence::Strong, // Upgraded: /Encrypt dict presence is definitive
                title: "Encryption dictionary present".into(),
                description: "Trailer indicates encrypted content via /Encrypt.".into(),
                objects: vec!["trailer".into()],
                evidence: encrypt_evidence,
                remediation: Some("Decrypt with trusted tooling to inspect all objects.".into()),
                meta: encrypt_meta,

                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }

        let mut sig_evidence = Vec::new();
        let mut sig_meta = std::collections::HashMap::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.has_name(b"/Type", b"/Sig") || dict.get_first(b"/ByteRange").is_some() {
                    sig_evidence.push(span_to_evidence(entry.full_span, "Signature object"));
                    if !sig_meta.contains_key("signature.subfilter") {
                        if let Some((_, obj)) = dict.get_first(b"/SubFilter") {
                            if let PdfAtom::Name(n) = &obj.atom {
                                sig_meta.insert(
                                    "signature.subfilter".into(),
                                    String::from_utf8_lossy(&n.decoded).to_string(),
                                );
                            }
                        }
                    }
                    if sig_evidence.len() >= 3 {
                        break;
                    }
                }
            }
        }
        if !sig_evidence.is_empty() {
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "signature_present".into(),
                severity: Severity::Low,
                confidence: Confidence::Strong, // Upgraded: /ByteRange presence is definitive
                title: "Digital signature present".into(),
                description: "Signature dictionaries or ByteRange entries detected.".into(),
                objects: vec!["signature".into()],
                evidence: sig_evidence,
                remediation: Some("Validate signature chain and inspect signed content.".into()),
                meta: sig_meta,

                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }

        let mut dss_evidence = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.get_first(b"/DSS").is_some() || dict.has_name(b"/Type", b"/DSS") {
                    dss_evidence.push(span_to_evidence(entry.full_span, "DSS object"));
                    if dss_evidence.len() >= 3 {
                        break;
                    }
                }
            }
        }
        if !dss_evidence.is_empty() {
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "dss_present".into(),
                severity: Severity::Low,
                confidence: Confidence::Probable,
                impact: None,
                title: "DSS structures present".into(),
                description: "Document Security Store (DSS) entries detected.".into(),
                objects: vec!["dss".into()],
                evidence: dss_evidence,
                remediation: Some("Inspect DSS for embedded validation material.".into()),
                meta: Default::default(),

                reader_impacts: Vec::new(),
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

struct XfaDetector;

impl Detector for XfaDetector {
    fn id(&self) -> &'static str {
        "xfa_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Forms
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.get_first(b"/XFA").is_some() {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "xfa_present".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Strong, // Upgraded: /XFA presence is definitive
                        title: "XFA form present".into(),
                        description: "XFA forms can expand attack surface.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(dict.span, "XFA dict")],
                        remediation: Some("Inspect XFA form data and scripts.".into()),
                        meta: Default::default(),

                        reader_impacts: Vec::new(),
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(findings)
    }
}

struct AcroFormDetector;

impl Detector for AcroFormDetector {
    fn id(&self) -> &'static str {
        "acroform_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Forms
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.get_first(b"/AcroForm").is_some() {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "acroform_present".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Strong, // Upgraded: /AcroForm presence is definitive
                        title: "AcroForm present".into(),
                        description: "Interactive AcroForm dictionaries detected.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(dict.span, "AcroForm dict")],
                        remediation: Some("Inspect form fields and calculation scripts.".into()),
                        meta: Default::default(),

                        reader_impacts: Vec::new(),
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(findings)
    }
}

struct OCGDetector;

impl Detector for OCGDetector {
    fn id(&self) -> &'static str {
        "ocg_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.get_first(b"/OCG").is_some() || dict.get_first(b"/OCProperties").is_some() {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "ocg_present".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "Optional content group present".into(),
                        description: "OCG/OCProperties detected; may influence viewer behaviour."
                            .into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "OCG object")],
                        remediation: Some("Inspect optional content group settings.".into()),
                        meta: Default::default(),

                        reader_impacts: Vec::new(),
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }
        }
        Ok(findings)
    }
}

struct DecoderRiskDetector;

impl Detector for DecoderRiskDetector {
    fn id(&self) -> &'static str {
        "decoder_risk_present"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::StreamsAndFilters
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH | Needs::STREAM_INDEX
    }
    fn cost(&self) -> Cost {
        Cost::Moderate
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let PdfAtom::Stream(st) = &entry.atom {
                let filters = stream_filters(&st.dict);
                if filters.iter().any(|f| f == "/JBIG2Decode" || f == "/JPXDecode") {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "decoder_risk_present".into(),
                        severity: Severity::High,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "High-risk decoder present".into(),
                        description: format!("Stream uses filters: {}", filters.join(", ")),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(st.dict.span, "Stream dict")],
                        remediation: Some("Treat JBIG2/JPX decoding as high risk.".into()),
                        meta: Default::default(),

                        reader_impacts: Vec::new(),
                        action_type: None,
                        action_target: None,
                        action_initiation: None,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }
        }
        Ok(findings)
    }
}

struct DecompressionRatioDetector;

impl Detector for DecompressionRatioDetector {
    fn id(&self) -> &'static str {
        "decompression_ratio_suspicious"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::StreamsAndFilters
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH | Needs::STREAM_DECODE
    }
    fn cost(&self) -> Cost {
        Cost::Expensive
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let PdfAtom::Stream(st) = &entry.atom {
                let filters = stream_filters(&st.dict);
                if filters.is_empty() {
                    continue;
                }
                if let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, st) {
                    if decoded.input_len > 0 {
                        let ratio = decoded.data.len() as f64 / decoded.input_len as f64;
                        if ratio > 100.0 {
                            let mut meta = std::collections::HashMap::new();
                            meta.insert("decode.ratio".into(), format!("{:.1}", ratio));
                            meta.insert("decode.input_len".into(), decoded.input_len.to_string());
                            meta.insert("decode.output_len".into(), decoded.data.len().to_string());
                            if !filters.is_empty() {
                                meta.insert("filters.count".into(), filters.len().to_string());
                                meta.insert("filters.list".into(), filters.join(", "));
                            }
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "decompression_ratio_suspicious".into(),
                                severity: Severity::High,
                                confidence: Confidence::Probable,
                                impact: None,
                                title: "Suspicious decompression ratio".into(),
                                description: format!(
                                    "Decoded output {} bytes from {} input bytes (ratio {:.1}).",
                                    decoded.data.len(),
                                    decoded.input_len,
                                    ratio
                                ),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: vec![span_to_evidence(st.data_span, "Stream data span")],
                                remediation: Some("Inspect stream for decompression bombs.".into()),
                                meta,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

struct HugeImageDetector;

impl Detector for HugeImageDetector {
    fn id(&self) -> &'static str {
        "huge_image_dimensions"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::StreamsAndFilters
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Moderate
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            if let PdfAtom::Stream(st) = &entry.atom {
                if st.dict.has_name(b"/Subtype", b"/Image") {
                    let width = dict_int(&st.dict, b"/Width");
                    let height = dict_int(&st.dict, b"/Height");
                    if let (Some(w), Some(h)) = (width, height) {
                        if w > 10000 || h > 10000 || w.saturating_mul(h) > 10000 * 10000 {
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "huge_image_dimensions".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::Probable,
                                impact: None,
                                title: "Huge image dimensions".into(),
                                description: format!("Image dimensions {}x{}.", w, h),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: vec![span_to_evidence(st.dict.span, "Image dict")],
                                remediation: Some(
                                    "Inspect image payload for resource abuse.".into(),
                                ),
                                meta: Default::default(),

                                reader_impacts: Vec::new(),
                                action_type: None,
                                action_target: None,
                                action_initiation: None,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                            });
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

impl Detector for ObfuscatedNameEncodingDetector {
    fn id(&self) -> &'static str {
        "obfuscated_name_encoding"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::Metadata
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Cheap
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut object_refs = Vec::new();
        let mut matched_names = BTreeSet::new();

        for entry in &ctx.graph.objects {
            if object_has_obfuscated_security_name(&entry.atom, &mut matched_names, 0) {
                object_refs.push(format!("{} {} obj", entry.obj, entry.gen));
            }
        }

        object_refs.sort();
        object_refs.dedup();
        if object_refs.is_empty() {
            return Ok(Vec::new());
        }

        let mut meta = std::collections::HashMap::new();
        meta.insert("obfuscation.name_count".into(), matched_names.len().to_string());
        meta.insert(
            "obfuscation.names".into(),
            matched_names.into_iter().collect::<Vec<_>>().join(","),
        );
        meta.insert("chain.stage".into(), "decode".into());
        meta.insert("chain.capability".into(), "name_obfuscation".into());

        Ok(vec![Finding {
            id: String::new(),
            surface: AttackSurface::Metadata,
            kind: "obfuscated_name_encoding".into(),
            severity: Severity::Low,
            confidence: Confidence::Tentative,
            impact: Some(Impact::Low),
            title: "Obfuscated PDF name encoding".into(),
            description:
                "Security-relevant PDF names use #xx hex encoding, which may indicate obfuscation."
                    .into(),
            objects: object_refs,
            evidence: keyword_evidence(ctx.bytes, b"#", "Hex-encoded name marker", 5),
            remediation: Some(
                "Decode and review action/filter/script-related name tokens before triage conclusions."
                    .into(),
            ),
            meta,
            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            position: None,
            positions: Vec::new(),
        }])
    }
}

impl Detector for PdfStringHexEncodedDetector {
    fn id(&self) -> &'static str {
        "pdf_string_hex_encoded"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::Metadata
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Cheap
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut object_refs = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut sample_previews = BTreeSet::new();

        for entry in &ctx.graph.objects {
            let mut per_object_hit = false;
            collect_hex_string_signals_in_atom(
                ctx,
                &entry.atom,
                0,
                &mut keys,
                &mut sample_previews,
                &mut per_object_hit,
            );
            if per_object_hit {
                object_refs.insert(format!("{} {} obj", entry.obj, entry.gen));
            }
        }

        if object_refs.is_empty() {
            return Ok(Vec::new());
        }

        let mut meta = std::collections::HashMap::new();
        meta.insert("obfuscation.hex_string_count".into(), object_refs.len().to_string());
        meta.insert(
            "obfuscation.hex_string_keys".into(),
            keys.into_iter().collect::<Vec<_>>().join(","),
        );
        meta.insert(
            "obfuscation.hex_string_samples".into(),
            sample_previews.into_iter().take(5).collect::<Vec<_>>().join(" | "),
        );
        meta.insert("chain.stage".into(), "decode".into());
        meta.insert("chain.capability".into(), "string_hex_obfuscation".into());

        Ok(vec![Finding {
            id: String::new(),
            surface: AttackSurface::Metadata,
            kind: "pdf_string_hex_encoded".into(),
            severity: Severity::Low,
            confidence: Confidence::Tentative,
            impact: Some(Impact::Low),
            title: "Hex-encoded PDF string in security context".into(),
            description:
                "Security-relevant string values use PDF hex-literal syntax, which may indicate obfuscation."
                    .into(),
            objects: object_refs.into_iter().collect(),
            evidence: keyword_evidence(ctx.bytes, b"<", "Hex-literal string marker", 3),
            remediation: Some(
                "Review decoded string literals in action/form/annotation contexts and correlate with additional suspicious indicators."
                    .into(),
            ),
            meta,
            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            position: None,
            positions: Vec::new(),
        }])
    }
}

fn collect_hex_string_signals_in_atom(
    ctx: &sis_pdf_core::scan::ScanContext,
    atom: &PdfAtom<'_>,
    depth: usize,
    keys: &mut BTreeSet<String>,
    sample_previews: &mut BTreeSet<String>,
    per_object_hit: &mut bool,
) {
    if depth >= 8 {
        return;
    }

    match atom {
        PdfAtom::Dict(dict) => {
            for (name, value) in &dict.entries {
                let key = String::from_utf8_lossy(&name.decoded).to_string();
                if is_security_relevant_hex_key(&key) {
                    match &value.atom {
                        PdfAtom::Str(sis_pdf_pdf::object::PdfStr::Hex { decoded, .. }) => {
                            *per_object_hit = true;
                            keys.insert(key.clone());
                            sample_previews.insert(preview_ascii(decoded, 80));
                        }
                        PdfAtom::Ref { .. } => {
                            if let Some(resolved) = ctx.graph.resolve_ref(value) {
                                if let PdfAtom::Str(sis_pdf_pdf::object::PdfStr::Hex {
                                    decoded,
                                    ..
                                }) = &resolved.atom
                                {
                                    *per_object_hit = true;
                                    keys.insert(key.clone());
                                    sample_previews.insert(preview_ascii(decoded, 80));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                collect_hex_string_signals_in_atom(
                    ctx,
                    &value.atom,
                    depth + 1,
                    keys,
                    sample_previews,
                    per_object_hit,
                );
            }
        }
        PdfAtom::Array(values) => {
            for value in values {
                collect_hex_string_signals_in_atom(
                    ctx,
                    &value.atom,
                    depth + 1,
                    keys,
                    sample_previews,
                    per_object_hit,
                );
            }
        }
        PdfAtom::Stream(stream) => {
            collect_hex_string_signals_in_atom(
                ctx,
                &PdfAtom::Dict(stream.dict.clone()),
                depth + 1,
                keys,
                sample_previews,
                per_object_hit,
            );
        }
        _ => {}
    }
}

fn is_security_relevant_hex_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "/js" | "/uri" | "/f" | "/v" | "/dv" | "/contents" | "/t"
    )
}

fn object_has_obfuscated_security_name(
    atom: &PdfAtom<'_>,
    matched_names: &mut BTreeSet<String>,
    depth: usize,
) -> bool {
    if depth >= 10 {
        return false;
    }

    match atom {
        PdfAtom::Name(name) => {
            if name_looks_obfuscated(name) && name_is_security_relevant(name) {
                matched_names.insert(String::from_utf8_lossy(&name.decoded).to_string());
                true
            } else {
                false
            }
        }
        PdfAtom::Array(values) => values.iter().any(|value| {
            object_has_obfuscated_security_name(&value.atom, matched_names, depth + 1)
        }),
        PdfAtom::Dict(dict) => {
            let key_hit = dict.entries.iter().any(|(key, value)| {
                let mut hit = false;
                if name_looks_obfuscated(key) && name_is_security_relevant(key) {
                    matched_names.insert(String::from_utf8_lossy(&key.decoded).to_string());
                    hit = true;
                }
                hit || object_has_obfuscated_security_name(&value.atom, matched_names, depth + 1)
            });
            key_hit
        }
        PdfAtom::Stream(stream) => stream.dict.entries.iter().any(|(key, value)| {
            let mut hit = false;
            if name_looks_obfuscated(key) && name_is_security_relevant(key) {
                matched_names.insert(String::from_utf8_lossy(&key.decoded).to_string());
                hit = true;
            }
            hit || object_has_obfuscated_security_name(&value.atom, matched_names, depth + 1)
        }),
        _ => false,
    }
}

fn name_looks_obfuscated(name: &PdfName<'_>) -> bool {
    let raw = name.raw.as_ref();
    let mut i = 0usize;
    while i + 2 < raw.len() {
        if raw[i] == b'#' && hex_value(raw[i + 1]).is_some() && hex_value(raw[i + 2]).is_some() {
            return true;
        }
        i += 1;
    }
    false
}

fn name_is_security_relevant(name: &PdfName<'_>) -> bool {
    let lower = name.decoded.iter().map(|byte| byte.to_ascii_lowercase()).collect::<Vec<u8>>();
    let needles: &[&[u8]] = &[
        b"/javascript",
        b"/js",
        b"/launch",
        b"/uri",
        b"/submitform",
        b"/gotor",
        b"/gotoe",
        b"/openaction",
        b"/aa",
        b"/filter",
        b"/acroform",
        b"/ap",
        b"/s",
        b"/f",
    ];
    needles.iter().any(|needle| lower.windows(needle.len()).any(|window| window == *needle))
}

pub(crate) fn entry_dict<'a>(entry: &'a ObjEntry<'a>) -> Option<&'a PdfDict<'a>> {
    match &entry.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    }
}

fn entry_payload_bytes<'a>(bytes: &'a [u8], entry: &ObjEntry<'a>) -> Option<&'a [u8]> {
    match &entry.atom {
        PdfAtom::Stream(st) => span_bytes(bytes, st.data_span),
        _ => span_bytes(bytes, entry.body_span),
    }
}

fn span_bytes(bytes: &[u8], span: sis_pdf_pdf::span::Span) -> Option<&[u8]> {
    let start = span.start as usize;
    let end = span.end as usize;
    if start >= end || end > bytes.len() {
        return None;
    }
    Some(&bytes[start..end])
}

fn detect_3d_format(data: &[u8]) -> Option<&'static str> {
    if data.len() >= 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x24 {
        return Some("u3d");
    }
    if data.starts_with(b"PRC") {
        return Some("prc");
    }
    None
}

fn detect_media_format(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"ID3") {
        return Some("mp3");
    }
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFB {
        return Some("mp3");
    }
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        return Some("mp4");
    }
    None
}

fn provenance_label(provenance: ObjProvenance) -> String {
    match provenance {
        ObjProvenance::Indirect => "indirect".to_string(),
        ObjProvenance::ObjStm { obj, gen } => format!("objstm:{} {}", obj, gen),
        ObjProvenance::CarvedStream { obj, gen } => format!("carved_stream:{} {}", obj, gen),
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn join_list_sorted(values: &HashSet<String>) -> String {
    let mut list: Vec<String> = values.iter().cloned().collect();
    list.sort();
    list.join(",")
}

fn action_by_s(
    ctx: &sis_pdf_core::scan::ScanContext,
    action: &[u8],
    payload_keys: &[&[u8]],
    kind: &str,
    title: &str,
    action_type: &str,
    initiation: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for entry in &ctx.graph.objects {
        if let Some(dict) = entry_dict(entry) {
            if dict.has_name(b"/S", action) {
                let mut evidence = vec![span_to_evidence(dict.span, "Action dict")];
                let mut meta = std::collections::HashMap::new();
                if let Some(enriched) = payload_from_dict(ctx, dict, payload_keys, "Action payload")
                {
                    evidence.extend(enriched.evidence);
                    meta.extend(enriched.meta);
                }
                let target = action_target_from_meta(&meta);
                annotate_action_meta(&mut meta, action_type, target.as_deref(), initiation);
                if matches!(action_type, "/SubmitForm" | "/URI" | "/GoToR" | "/GoToE") {
                    meta.insert("chain.stage".into(), "egress".into());
                    meta.insert("chain.capability".into(), "action_egress".into());
                    meta.insert("chain.trigger".into(), "action".into());
                    meta.insert(
                        "egress.channel".into(),
                        egress_channel_for_action(action_type).to_string(),
                    );
                    let target_kind =
                        target.as_deref().map(egress_target_kind_from_target).unwrap_or("unknown");
                    meta.insert("egress.target_kind".into(), target_kind.to_string());
                    meta.insert(
                        "egress.user_interaction_required".into(),
                        egress_user_interaction_required(action_type).to_string(),
                    );
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::Actions,
                    kind: kind.into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: title.into(),
                    description: format!(
                        "Action dictionary with /S {}.",
                        String::from_utf8_lossy(action)
                    ),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence,
                    remediation: Some("Review the action target.".into()),
                    meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                    ..Default::default()
                });
            }
        }
    }
    Ok(findings)
}

fn egress_target_kind_from_target(target: &str) -> &'static str {
    let lower = target.trim().to_ascii_lowercase();
    if lower.starts_with("javascript:") {
        return "script_uri";
    }
    if lower.starts_with("data:") {
        return "data_uri";
    }
    if lower.starts_with("file://") {
        return "file_uri";
    }
    if lower.starts_with("\\\\") || lower.starts_with("//") {
        return "unc_path";
    }
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
    {
        return "network_uri";
    }
    "remote_target"
}

pub(crate) fn dict_int(dict: &PdfDict<'_>, key: &[u8]) -> Option<u32> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Int(i) if *i >= 0 => Some(*i as u32),
        _ => None,
    }
}

pub(crate) fn extract_strings_with_span(
    entry: &ObjEntry<'_>,
) -> Vec<(Vec<u8>, sis_pdf_pdf::span::Span)> {
    let mut out = Vec::new();
    match &entry.atom {
        PdfAtom::Str(s) => out.push((string_bytes(s), s_span(s))),
        PdfAtom::Array(arr) => {
            for o in arr {
                if let PdfAtom::Str(s) = &o.atom {
                    out.push((string_bytes(s), s_span(s)));
                }
            }
        }
        PdfAtom::Dict(d) => {
            for (_, v) in &d.entries {
                if let PdfAtom::Str(s) = &v.atom {
                    out.push((string_bytes(s), s_span(s)));
                }
            }
        }
        PdfAtom::Stream(st) => {
            for (_, v) in &st.dict.entries {
                if let PdfAtom::Str(s) = &v.atom {
                    out.push((string_bytes(s), s_span(s)));
                }
            }
        }
        _ => {}
    }
    out
}

pub(crate) struct PayloadInfo {
    pub bytes: Vec<u8>,
    pub kind: String,
    pub ref_chain: String,
    pub origin: Option<sis_pdf_pdf::span::Span>,
    pub filters: Option<String>,
    pub decode_ratio: Option<f64>,
}

pub(crate) struct PayloadResult {
    pub payload: Option<PayloadInfo>,
    pub error: Option<String>,
}

pub(crate) fn resolve_payload(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
) -> PayloadResult {
    let mut visited = HashSet::new();
    resolve_payload_recursive(ctx, obj, 0, &mut visited, Vec::new())
}

const MAX_RESOLVE_DEPTH: usize = 10;
const MAX_ARRAY_ELEMENTS: usize = 1000;

fn resolve_payload_recursive(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
    depth: usize,
    visited: &mut HashSet<(u32, u16)>,
    mut ref_chain: Vec<String>,
) -> PayloadResult {
    if depth > MAX_RESOLVE_DEPTH {
        return PayloadResult {
            payload: None,
            error: Some(format!("max resolution depth {} exceeded", MAX_RESOLVE_DEPTH)),
        };
    }

    match &obj.atom {
        PdfAtom::Str(s) => PayloadResult {
            payload: Some(PayloadInfo {
                bytes: string_bytes(s),
                kind: "string".into(),
                ref_chain: if ref_chain.is_empty() { "-".into() } else { ref_chain.join(" -> ") },
                origin: Some(s_span(s)),
                filters: None,
                decode_ratio: None,
            }),
            error: None,
        },
        PdfAtom::Stream(st) => match ctx.decoded.get_or_decode(ctx.bytes, st) {
            Ok(decoded) => {
                let ratio = if decoded.input_len > 0 {
                    Some(decoded.data.len() as f64 / decoded.input_len as f64)
                } else {
                    None
                };
                PayloadResult {
                    payload: Some(PayloadInfo {
                        bytes: decoded.data,
                        kind: "stream".into(),
                        ref_chain: if ref_chain.is_empty() {
                            "-".into()
                        } else {
                            ref_chain.join(" -> ")
                        },
                        origin: Some(st.data_span),
                        filters: Some(decoded.filters.join(",")),
                        decode_ratio: ratio,
                    }),
                    error: None,
                }
            }
            Err(e) => PayloadResult { payload: None, error: Some(e.to_string()) },
        },
        PdfAtom::Ref { obj: obj_id, gen } => {
            // Cycle detection
            if !visited.insert((*obj_id, *gen)) {
                return PayloadResult {
                    payload: None,
                    error: Some(format!("circular reference detected: {} {} R", obj_id, gen)),
                };
            }

            let entry = match ctx.graph.get_object(*obj_id, *gen) {
                Some(e) => e,
                None => {
                    return PayloadResult {
                        payload: None,
                        error: Some(format!("ref resolution failed: {} {} R", obj_id, gen)),
                    };
                }
            };

            ref_chain.push(format!("{} {} R", obj_id, gen));

            // Create a temporary PdfObj for the resolved entry
            let resolved_obj =
                sis_pdf_pdf::object::PdfObj { span: entry.body_span, atom: entry.atom.clone() };

            resolve_payload_recursive(ctx, &resolved_obj, depth + 1, visited, ref_chain)
        }
        PdfAtom::Array(arr) => {
            // Array payload reconstruction: concatenate all string elements
            if arr.len() > MAX_ARRAY_ELEMENTS {
                return PayloadResult {
                    payload: None,
                    error: Some(format!(
                        "array too large: {} elements (max {})",
                        arr.len(),
                        MAX_ARRAY_ELEMENTS
                    )),
                };
            }

            let mut fragments = Vec::new();
            let mut errors = Vec::new();
            let mut first_origin = None;

            for (idx, elem) in arr.iter().enumerate() {
                let result =
                    resolve_payload_recursive(ctx, elem, depth + 1, visited, ref_chain.clone());

                match result.payload {
                    Some(p) => {
                        if first_origin.is_none() {
                            first_origin = p.origin;
                        }
                        fragments.push(p.bytes);
                    }
                    None => {
                        if let Some(err) = result.error {
                            errors.push(format!("element {}: {}", idx, err));
                        }
                    }
                }
            }

            if fragments.is_empty() {
                return PayloadResult {
                    payload: None,
                    error: Some(format!(
                        "array payload reconstruction failed: {}",
                        if errors.is_empty() {
                            "no resolvable elements".to_string()
                        } else {
                            errors.join("; ")
                        }
                    )),
                };
            }

            let concatenated = fragments.concat();
            PayloadResult {
                payload: Some(PayloadInfo {
                    bytes: concatenated,
                    kind: format!("array[{}]", fragments.len()),
                    ref_chain: if ref_chain.is_empty() {
                        format!("array[{}]", fragments.len())
                    } else {
                        format!("{} -> array[{}]", ref_chain.join(" -> "), fragments.len())
                    },
                    origin: first_origin,
                    filters: None,
                    decode_ratio: None,
                }),
                error: if errors.is_empty() {
                    None
                } else {
                    Some(format!("partial reconstruction: {}", errors.join("; ")))
                },
            }
        }
        _ => PayloadResult {
            payload: None,
            error: Some(format!("unsupported payload type: {:?}", obj.atom)),
        },
    }
}

struct PayloadEnrichment {
    evidence: Vec<sis_pdf_core::model::EvidenceSpan>,
    meta: std::collections::HashMap<String, String>,
}

pub(crate) struct ActionDetails {
    pub evidence: Vec<sis_pdf_core::model::EvidenceSpan>,
    pub meta: std::collections::HashMap<String, String>,
}

pub(crate) fn resolve_action_details(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
) -> Option<ActionDetails> {
    let mut evidence = Vec::new();
    let mut meta = std::collections::HashMap::new();
    let action_obj = match &obj.atom {
        PdfAtom::Dict(_) => obj.clone(),
        PdfAtom::Ref { .. } => {
            let entry = ctx.graph.resolve_ref(obj)?;
            sis_pdf_pdf::object::PdfObj { span: entry.body_span, atom: entry.atom }
        }
        _ => return None,
    };
    if let PdfAtom::Dict(d) = &action_obj.atom {
        if let Some((k, v)) = d.get_first(b"/S") {
            evidence.push(span_to_evidence(k.span, "Action key /S"));
            evidence.push(span_to_evidence(v.span, "Action value"));
            if let PdfAtom::Name(n) = &v.atom {
                meta.insert("action.s".into(), String::from_utf8_lossy(&n.decoded).to_string());
            }
        }
        if let Some((k, v)) = d.get_first(b"/URI") {
            evidence.push(span_to_evidence(k.span, "Action key /URI"));
            evidence.push(span_to_evidence(v.span, "Action URI value"));
            meta.insert("action.target".into(), preview_ascii(&payload_string(v), 120));
        }
        if let Some((k, v)) = d.get_first(b"/F") {
            evidence.push(span_to_evidence(k.span, "Action key /F"));
            evidence.push(span_to_evidence(v.span, "Action file/target"));
            meta.insert("action.target".into(), preview_ascii(&payload_string(v), 120));
        }
        if let Some(s) = meta.get("action.s") {
            let impact = match s.as_str() {
                "/JavaScript" => "JavaScript can execute on open, enabling scripted behaviour.",
                "/Launch" => "Launch actions can invoke external applications or files.",
                "/URI" => "URI actions can open external links, enabling phishing or exfiltration.",
                "/GoToR" => "GoToR can open remote documents or resources.",
                "/SubmitForm" => "SubmitForm can exfiltrate form data to external endpoints.",
                _ => "OpenAction may trigger automated viewer behaviour on open.",
            };
            meta.insert("impact".into(), impact.into());
        }
    }
    Some(ActionDetails { evidence, meta })
}

fn payload_string(obj: &sis_pdf_pdf::object::PdfObj<'_>) -> Vec<u8> {
    match &obj.atom {
        PdfAtom::Str(s) => string_bytes(s),
        PdfAtom::Name(n) => n.decoded.clone(),
        _ => Vec::new(),
    }
}

fn payload_from_dict(
    ctx: &sis_pdf_core::scan::ScanContext,
    dict: &PdfDict<'_>,
    keys: &[&[u8]],
    note: &str,
) -> Option<PayloadEnrichment> {
    for key in keys {
        if let Some((k, v)) = dict.get_first(key) {
            let mut evidence = vec![
                span_to_evidence(k.span, &format!("Key {}", String::from_utf8_lossy(key))),
                span_to_evidence(v.span, note),
            ];
            let mut meta = std::collections::HashMap::new();
            meta.insert("payload.key".into(), String::from_utf8_lossy(key).to_string());
            meta.insert("action.param.source".into(), String::from_utf8_lossy(key).to_string());
            let res = resolve_payload(ctx, v);
            if let Some(err) = res.error {
                meta.insert("payload.error".into(), err);
            }
            if let Some(payload) = res.payload {
                meta.insert("payload.type".into(), payload.kind);
                meta.insert("payload.decoded_len".into(), payload.bytes.len().to_string());
                meta.insert("payload.ref_chain".into(), payload.ref_chain);
                meta.insert("payload.preview".into(), preview_ascii(&payload.bytes, 120));
                meta.insert("payload.decoded_preview".into(), preview_ascii(&payload.bytes, 120));
                let normalised = normalise_injection_payload(&payload.bytes);
                if normalised.decode_layers > 0 {
                    meta.insert("injection.action_param_normalised".into(), "true".into());
                    meta.insert(
                        "injection.decode_layers".into(),
                        normalised.decode_layers.to_string(),
                    );
                    meta.insert(
                        "payload.normalised_preview".into(),
                        preview_ascii(&normalised.bytes, 120),
                    );
                }
                if let Some(origin) = payload.origin {
                    evidence.push(decoded_evidence_span(origin, &payload.bytes, "Decoded payload"));
                }
            }
            return Some(PayloadEnrichment { evidence, meta });
        }
    }
    None
}

#[derive(Clone)]
pub(crate) struct ActionTelemetry {
    pub action_type: String,
    pub action_target: Option<String>,
    pub action_initiation: String,
}

pub(crate) fn annotate_action_meta(
    meta: &mut std::collections::HashMap<String, String>,
    action_type: &str,
    target: Option<&str>,
    initiation: &str,
) -> ActionTelemetry {
    meta.insert("action.type".into(), action_type.to_string());
    let mut recorded_target = None;
    if let Some(t) = target {
        if !t.trim().is_empty() {
            let target_value = shorten_action_target(t);
            meta.insert("action.target".into(), target_value.clone());
            recorded_target = Some(target_value);
        }
    }
    meta.insert("action.initiation".into(), initiation.to_string());
    ActionTelemetry {
        action_type: action_type.to_string(),
        action_target: recorded_target,
        action_initiation: initiation.to_string(),
    }
}

pub(crate) fn action_target_from_meta(
    meta: &std::collections::HashMap<String, String>,
) -> Option<String> {
    meta.get("payload.preview")
        .or_else(|| meta.get("payload.decoded_preview"))
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(shorten_action_target)
}

fn shorten_action_target(value: &str) -> String {
    value.chars().take(256).collect()
}

pub(crate) fn apply_action_telemetry(finding: &mut Finding, telemetry: &ActionTelemetry) {
    finding.action_type = Some(telemetry.action_type.clone());
    finding.action_target = telemetry.action_target.clone();
    finding.action_initiation = Some(telemetry.action_initiation.clone());
}

pub(crate) fn action_type_from_obj(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &PdfObj<'_>,
) -> Option<String> {
    let dict = match &obj.atom {
        PdfAtom::Dict(dict) => dict,
        PdfAtom::Ref { obj: obj_id, gen } => {
            let entry = ctx.graph.get_object(*obj_id, *gen)?;
            match &entry.atom {
                PdfAtom::Dict(dict) => dict,
                _ => return None,
            }
        }
        _ => return None,
    };
    dict.get_first(b"/S").and_then(|(_, value)| match &value.atom {
        PdfAtom::Name(name) => Some(String::from_utf8_lossy(&name.decoded).to_string()),
        _ => None,
    })
}

fn s_span(s: &sis_pdf_pdf::object::PdfStr<'_>) -> sis_pdf_pdf::span::Span {
    match s {
        sis_pdf_pdf::object::PdfStr::Literal { span, .. } => *span,
        sis_pdf_pdf::object::PdfStr::Hex { span, .. } => *span,
    }
}

pub(crate) fn page_has_uri_annot(
    ctx: &sis_pdf_core::scan::ScanContext,
    dict: &PdfDict<'_>,
) -> bool {
    if let Some((_, obj)) = dict.get_first(b"/Annots") {
        match &obj.atom {
            PdfAtom::Array(arr) => arr.iter().any(|o| annot_has_uri(ctx, o)),
            PdfAtom::Ref { .. } => annot_has_uri(ctx, obj),
            _ => false,
        }
    } else {
        false
    }
}

pub(crate) fn annot_has_uri(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
) -> bool {
    let annot_obj = match &obj.atom {
        PdfAtom::Dict(_) => obj.clone(),
        PdfAtom::Ref { .. } => {
            if let Some(entry) = ctx.graph.resolve_ref(obj) {
                sis_pdf_pdf::object::PdfObj { span: entry.body_span, atom: entry.atom }
            } else {
                return false;
            }
        }
        _ => return false,
    };
    if let PdfAtom::Dict(d) = &annot_obj.atom {
        if let Some((_, a)) = d.get_first(b"/A") {
            if let PdfAtom::Dict(ad) = &a.atom {
                return ad.get_first(b"/URI").is_some();
            }
        }
        if let Some((_, aa)) = d.get_first(b"/AA") {
            if let PdfAtom::Dict(aad) = &aa.atom {
                for (_, v) in &aad.entries {
                    if let PdfAtom::Dict(ad) = &v.atom {
                        if ad.get_first(b"/URI").is_some() {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn embedded_filename(dict: &PdfDict<'_>) -> Option<String> {
    if let Some((_, obj)) = dict.get_first(b"/F") {
        if let PdfAtom::Str(s) = &obj.atom {
            return Some(String::from_utf8_lossy(&string_bytes(s)).to_string());
        }
    }
    if let Some((_, obj)) = dict.get_first(b"/UF") {
        if let PdfAtom::Str(s) = &obj.atom {
            return Some(String::from_utf8_lossy(&string_bytes(s)).to_string());
        }
    }
    None
}

fn is_embedded_file_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Type", b"/EmbeddedFile")
        || dict.has_name(b"/Type", b"/Filespec")
        || dict.get_first(b"/EF").is_some()
}

#[derive(Default)]
struct LaunchTargetTracker {
    external: bool,
    embedded: bool,
    target_path: Option<String>,
    embedded_file_hash: Option<String>,
}

impl LaunchTargetTracker {
    fn mark_external(&mut self, path: Option<String>) {
        self.external = true;
        if let Some(name) = path {
            self.set_target_path(name);
        }
    }

    fn mark_embedded(&mut self, path: Option<String>, hash: Option<String>) {
        self.embedded = true;
        if let Some(name) = path {
            self.set_target_path(name);
        }
        if self.embedded_file_hash.is_none() {
            self.embedded_file_hash = hash;
        }
    }

    fn set_target_path(&mut self, path: String) {
        if self.target_path.is_none() {
            self.target_path = Some(path);
        }
    }

    fn target_type(&self) -> &'static str {
        if self.embedded {
            "embedded"
        } else if self.external {
            "external"
        } else {
            "unknown"
        }
    }
}

fn update_launch_targets(
    ctx: &sis_pdf_core::scan::ScanContext,
    value: &PdfObj<'_>,
    tracker: &mut LaunchTargetTracker,
) {
    match &value.atom {
        PdfAtom::Str(s) => {
            let path = String::from_utf8_lossy(&string_bytes(s)).to_string();
            tracker.mark_external(Some(path.clone()));
            if let Some(hash) = find_embedded_hash_by_name(ctx, &path) {
                tracker.mark_embedded(Some(path), Some(hash));
            }
        }
        PdfAtom::Name(n) => {
            let path = String::from_utf8_lossy(&n.decoded).to_string();
            tracker.mark_external(Some(path.clone()));
            if let Some(hash) = find_embedded_hash_by_name(ctx, &path) {
                tracker.mark_embedded(Some(path), Some(hash));
            }
        }
        PdfAtom::Dict(dict) => {
            handle_dict_target(ctx, dict, tracker);
        }
        PdfAtom::Stream(stream) => {
            handle_stream_target(ctx, stream, tracker);
        }
        PdfAtom::Ref { obj, gen } => {
            if let Some(entry) = ctx.graph.get_object(*obj, *gen) {
                match &entry.atom {
                    PdfAtom::Dict(dict) => handle_dict_target(ctx, dict, tracker),
                    PdfAtom::Stream(stream) => handle_stream_target(ctx, stream, tracker),
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn handle_dict_target(
    ctx: &sis_pdf_core::scan::ScanContext,
    dict: &PdfDict<'_>,
    tracker: &mut LaunchTargetTracker,
) {
    let filename = embedded_filename(dict);
    if let Some(name) = filename.clone() {
        tracker.set_target_path(name);
    }
    if is_embedded_file_dict(dict) {
        tracker.mark_embedded(filename, embedded_hash_from_dict(ctx, dict));
    } else if let Some(name) = filename {
        if let Some(hash) = find_embedded_hash_by_name(ctx, &name) {
            tracker.mark_embedded(Some(name), Some(hash));
        }
    }
}

fn handle_stream_target(
    ctx: &sis_pdf_core::scan::ScanContext,
    stream: &PdfStream<'_>,
    tracker: &mut LaunchTargetTracker,
) {
    if is_embedded_file_dict(&stream.dict) {
        tracker
            .mark_embedded(embedded_filename(&stream.dict), embedded_hash_from_stream(ctx, stream));
    }
}

fn find_embedded_hash_by_name(ctx: &sis_pdf_core::scan::ScanContext, name: &str) -> Option<String> {
    for entry in &ctx.graph.objects {
        if let PdfAtom::Stream(st) = &entry.atom {
            if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
                if let Some(filename) = embedded_filename(&st.dict) {
                    if filename == name {
                        if let Some(hash) = embedded_hash_from_stream(ctx, st) {
                            return Some(hash);
                        }
                    }
                }
            }
        }
    }
    None
}

fn embedded_hash_from_stream(
    ctx: &sis_pdf_core::scan::ScanContext,
    stream: &PdfStream<'_>,
) -> Option<String> {
    if !stream.dict.has_name(b"/Type", b"/EmbeddedFile") {
        return None;
    }
    ctx.decoded.get_or_decode(ctx.bytes, stream).ok().map(|decoded| sha256_hex(&decoded.data))
}

fn embedded_hash_from_dict(
    ctx: &sis_pdf_core::scan::ScanContext,
    dict: &PdfDict<'_>,
) -> Option<String> {
    if let Some((_, ef_obj)) = dict.get_first(b"/EF") {
        match &ef_obj.atom {
            PdfAtom::Dict(ef_dict) => {
                for (_, value) in &ef_dict.entries {
                    if let Some(hash) = embedded_hash_from_obj(ctx, value) {
                        return Some(hash);
                    }
                }
            }
            _ => {
                if let Some(hash) = embedded_hash_from_obj(ctx, ef_obj) {
                    return Some(hash);
                }
            }
        }
    }
    None
}

fn embedded_hash_from_obj(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &PdfObj<'_>,
) -> Option<String> {
    match &obj.atom {
        PdfAtom::Stream(stream) => embedded_hash_from_stream(ctx, stream),
        PdfAtom::Ref { obj, gen } => {
            if let Some(entry) = ctx.graph.get_object(*obj, *gen) {
                if let PdfAtom::Stream(stream) = &entry.atom {
                    return embedded_hash_from_stream(ctx, stream);
                }
            }
            None
        }
        _ => None,
    }
}

fn has_double_extension(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    parts.len() >= 3
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn keyword_evidence(
    bytes: &[u8],
    keyword: &[u8],
    note: &str,
    limit: usize,
) -> Vec<sis_pdf_core::model::EvidenceSpan> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + keyword.len() <= bytes.len() {
        if &bytes[i..i + keyword.len()] == keyword {
            out.push(sis_pdf_core::model::EvidenceSpan {
                source: sis_pdf_core::model::EvidenceSource::File,
                offset: i as u64,
                length: keyword.len() as u32,
                origin: None,
                note: Some(note.into()),
            });
            if out.len() >= limit {
                break;
            }
            i += keyword.len();
        } else {
            i += 1;
        }
    }
    out
}

pub(crate) fn zip_encrypted(data: &[u8]) -> bool {
    if data.len() < 8 || !data.starts_with(b"PK\x03\x04") {
        return false;
    }
    let flag = u16::from_le_bytes([data[6], data[7]]);
    (flag & 0x0001) != 0
}

const RAR4_MAGIC: &[u8] = b"Rar!\x1A\x07\x00";
const RAR5_MAGIC: &[u8] = b"Rar!\x1A\x07\x01\x00";

pub(crate) fn is_rar_magic(data: &[u8]) -> bool {
    data.starts_with(RAR4_MAGIC) || data.starts_with(RAR5_MAGIC)
}

pub(crate) fn rar_encrypted(data: &[u8]) -> bool {
    if let Some(flags) = rar_header_flags(data) {
        (flags & 0x0080) != 0
    } else {
        false
    }
}

fn rar_header_flags(data: &[u8]) -> Option<u16> {
    if data.starts_with(RAR4_MAGIC) && data.len() >= 9 {
        Some(u16::from_le_bytes([data[7], data[8]]))
    } else if data.starts_with(RAR5_MAGIC) && data.len() >= 10 {
        Some(u16::from_le_bytes([data[8], data[9]]))
    } else {
        None
    }
}

fn string_bytes(s: &sis_pdf_pdf::object::PdfStr<'_>) -> Vec<u8> {
    match s {
        sis_pdf_pdf::object::PdfStr::Literal { decoded, .. } => decoded.clone(),
        sis_pdf_pdf::object::PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        assess_xref_conflict, classify_embedded_script, data_uri_payload_from_bytes,
        extract_xfa_script_payloads, infer_js_intent, javascript_uri_payload_from_bytes,
        js_present_severity_from_meta, normalise_text_bytes_for_script,
    };
    use sis_pdf_core::model::Severity;
    use sis_pdf_pdf::graph::{Deviation, XrefSectionSummary};
    use sis_pdf_pdf::span::Span;

    #[test]
    fn javascript_uri_payload_strips_scheme() {
        let payload = javascript_uri_payload_from_bytes(b" javascript:confirm(2);");
        assert_eq!(payload, Some(b"confirm(2);".to_vec()));
    }

    #[test]
    fn javascript_uri_payload_is_case_insensitive() {
        let payload = javascript_uri_payload_from_bytes(b"JaVaScRiPt:alert(1)");
        assert_eq!(payload, Some(b"alert(1)".to_vec()));
    }

    #[test]
    fn javascript_uri_payload_returns_none_for_non_js() {
        let payload = javascript_uri_payload_from_bytes(b"http://example.com");
        assert!(payload.is_none());
    }

    #[test]
    fn data_uri_payload_strips_javascript() {
        let payload = data_uri_payload_from_bytes(b"data:text/javascript,alert(1)");
        assert_eq!(payload, Some(b"alert(1)".to_vec()));
    }

    #[test]
    fn data_uri_payload_decodes_base64() {
        let payload =
            data_uri_payload_from_bytes(b"data:application/javascript;base64,YWxlcnQoMSk=");
        assert_eq!(payload, Some(b"alert(1)".to_vec()));
    }

    #[test]
    fn xfa_script_payloads_extract_script_blocks() {
        let xml = b"<xfa:form><xfa:script>confirm(2)</xfa:script></xfa:form>";
        let payloads = extract_xfa_script_payloads(xml);
        assert_eq!(payloads, vec![b"confirm(2)".to_vec()]);
    }

    #[test]
    fn xfa_script_payloads_respect_content_type() {
        let xml = b"<script contentType=\"application/x-javascript\"><![CDATA[alert(1)]]></script>";
        let payloads = extract_xfa_script_payloads(xml);
        assert_eq!(payloads, vec![b"alert(1)".to_vec()]);
    }

    #[test]
    fn normalise_text_bytes_handles_utf16le() {
        let utf16 = b"\xff\xfe\x66\x00\x75\x00\x6e\x00\x63\x00\x74\x00\x69\x00\x6f\x00\x6e\x00";
        let normalised = match normalise_text_bytes_for_script(utf16) {
            Some(bytes) => bytes,
            None => panic!("normalise_text_bytes_for_script should handle UTF-16"),
        };
        assert!(normalised.starts_with(b"function"));
    }

    #[test]
    fn infer_js_intent_marks_user_interaction_for_alert() {
        let signals = std::collections::HashMap::new();
        let intent = infer_js_intent(b"app.alert('XSS from annotation!');", &signals);
        assert_eq!(
            intent,
            Some((
                "user_interaction",
                "JavaScript appears focused on user prompt or social-engineering interaction.",
                "strong",
            ))
        );
    }

    #[test]
    fn infer_js_intent_marks_network_access_for_launchurl() {
        let signals = std::collections::HashMap::new();
        let intent = infer_js_intent(b"app.launchURL('https://example.test')", &signals);
        assert_eq!(
            intent,
            Some((
                "network_access",
                "JavaScript appears to initiate network-capable actions.",
                "strong",
            ))
        );
    }

    #[test]
    fn infer_js_intent_marks_obfuscation_loader_for_eval_chain() {
        let signals = std::collections::HashMap::new();
        let intent = infer_js_intent(b"eval(unescape('%61%6c%65%72%74(1)'))", &signals);
        assert_eq!(
            intent,
            Some((
                "obfuscation_loader",
                "JavaScript contains obfuscation or dynamic execution indicators.",
                "probable",
            ))
        );
    }

    #[test]
    fn js_present_severity_is_high_for_network_intent() {
        let mut meta = std::collections::HashMap::new();
        meta.insert("js.intent.primary".into(), "network_access".into());
        assert_eq!(js_present_severity_from_meta(&meta), Severity::High);
    }

    #[test]
    fn js_present_severity_is_medium_for_user_interaction_intent() {
        let mut meta = std::collections::HashMap::new();
        meta.insert("js.intent.primary".into(), "user_interaction".into());
        assert_eq!(js_present_severity_from_meta(&meta), Severity::Medium);
    }

    #[test]
    fn js_present_severity_is_low_without_risk_metadata() {
        let meta = std::collections::HashMap::new();
        assert_eq!(js_present_severity_from_meta(&meta), Severity::Low);
    }

    #[test]
    fn embedded_script_classifier_marks_batch_from_extension_and_tokens() {
        let payload = b"@echo off\r\necho hello from batch\r\n";
        let assessment = classify_embedded_script(Some("hello.bat"), Some("unknown"), payload)
            .expect("batch payload should classify as script");
        assert_eq!(assessment.family, "cmd");
    }

    #[test]
    fn embedded_script_classifier_marks_powershell_from_extension() {
        let payload = b"Write-Host 'hello from powershell'\n";
        let assessment = classify_embedded_script(Some("hello.ps1"), Some("unknown"), payload)
            .expect("powershell payload should classify as script");
        assert_eq!(assessment.family, "powershell");
    }

    #[test]
    fn xref_conflict_assessment_downgrades_coherent_chain() {
        let sections = vec![
            XrefSectionSummary {
                offset: 200,
                kind: "stream".into(),
                has_trailer: true,
                prev: Some(100),
                trailer_size: Some(122),
                trailer_root: Some("47 0 R".into()),
            },
            XrefSectionSummary {
                offset: 100,
                kind: "stream".into(),
                has_trailer: true,
                prev: None,
                trailer_size: Some(46),
                trailer_root: Some("47 0 R".into()),
            },
        ];
        let assessment = assess_xref_conflict(1_000, &[100, 200], &sections, &[], false);
        assert_eq!(assessment.severity, Severity::Low);
        assert_eq!(assessment.integrity.as_str(), "coherent");
    }

    #[test]
    fn xref_conflict_assessment_marks_broken_prev_chain() {
        let sections = vec![
            XrefSectionSummary {
                offset: 200,
                kind: "stream".into(),
                has_trailer: true,
                prev: Some(999), // missing link
                trailer_size: Some(122),
                trailer_root: Some("47 0 R".into()),
            },
            XrefSectionSummary {
                offset: 100,
                kind: "stream".into(),
                has_trailer: true,
                prev: None,
                trailer_size: Some(46),
                trailer_root: Some("47 0 R".into()),
            },
        ];
        let assessment = assess_xref_conflict(1_000, &[100, 200], &sections, &[], false);
        assert_eq!(assessment.severity, Severity::Medium);
        assert_eq!(assessment.integrity.as_str(), "broken");
    }

    #[test]
    fn xref_conflict_assessment_escalates_cycle_with_deviation() {
        let sections = vec![
            XrefSectionSummary {
                offset: 200,
                kind: "stream".into(),
                has_trailer: true,
                prev: Some(100),
                trailer_size: Some(122),
                trailer_root: Some("47 0 R".into()),
            },
            XrefSectionSummary {
                offset: 100,
                kind: "stream".into(),
                has_trailer: true,
                prev: Some(200), // cycle
                trailer_size: Some(46),
                trailer_root: Some("47 0 R".into()),
            },
        ];
        let deviations = vec![Deviation {
            kind: "xref_trailer_search_invalid".into(),
            span: Span { start: 0, end: 0 },
            note: Some("test".into()),
        }];
        let assessment = assess_xref_conflict(1_000, &[100, 200], &sections, &deviations, false);
        assert_eq!(assessment.severity, Severity::High);
        assert_eq!(assessment.integrity.as_str(), "broken");
    }

    #[test]
    fn contains_html_injection_detects_script_tag() {
        let payload = b"<script>alert(1)</script>";
        assert!(super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn contains_html_injection_detects_img_tag() {
        let payload = b"<img src=x onerror=alert(1)>";
        assert!(super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn contains_html_injection_detects_event_handler() {
        let payload = b"\">'></div><details/open/ontoggle=confirm(1)></details>";
        assert!(super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn contains_html_injection_detects_context_breaking() {
        let payload = b"\"><script>alert(1)</script>";
        assert!(super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn contains_html_injection_detects_svg_tag() {
        let payload = b"<svg onload=alert(1)>";
        assert!(super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn contains_html_injection_detects_iframe_tag() {
        let payload = b"<iframe src=javascript:alert(1)>";
        assert!(super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn contains_html_injection_detects_javascript_protocol() {
        let payload = b"javascript:alert(1)";
        assert!(super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn contains_html_injection_detects_data_uri() {
        let payload = b"data:text/html,<script>alert(1)</script>";
        assert!(super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn contains_html_injection_rejects_document_cookie_without_html_context() {
        let payload = b"confirm(document.cookie)";
        assert!(!super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn contains_html_injection_rejects_window_location_without_html_context() {
        let payload = b"window.location=evil";
        assert!(!super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn contains_html_injection_case_insensitive() {
        let payload = b"<SCRIPT>alert(1)</SCRIPT>";
        assert!(super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn contains_html_injection_rejects_benign_text() {
        let payload = b"Alice";
        assert!(!super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn contains_html_injection_rejects_plain_numbers() {
        let payload = b"12345";
        assert!(!super::contains_html_injection_tokens(payload));
    }

    #[test]
    fn detect_injection_type_identifies_javascript() {
        let payload = b"app.alert('test')";
        let detected = super::detect_injection_type(payload);
        assert_eq!(detected, Some(super::InjectionType::JavaScript));
    }

    #[test]
    fn detect_injection_type_identifies_html() {
        let payload = b"<script>test</script>";
        let detected = super::detect_injection_type(payload);
        assert_eq!(detected, Some(super::InjectionType::Html));
    }

    #[test]
    fn detect_injection_type_identifies_both() {
        let payload = b"<script>eval(alert(1))</script>";
        let detected = super::detect_injection_type(payload);
        assert_eq!(detected, Some(super::InjectionType::Both));
    }

    #[test]
    fn detect_injection_type_identifies_none_for_benign() {
        let payload = b"normal text";
        let detected = super::detect_injection_type(payload);
        assert_eq!(detected, None);
    }
}

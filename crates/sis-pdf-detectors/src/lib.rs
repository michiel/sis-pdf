use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::collections::HashSet;

use crate::encryption_obfuscation::{encryption_meta_from_dict, resolve_encrypt_dict};
use sha2::{Digest, Sha256};
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::{decoded_evidence_span, preview_ascii, EvidenceBuilder};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_core::stream_analysis::{analyse_stream, StreamLimits};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::blob_classify::{classify_blob, BlobKind};
use sis_pdf_pdf::classification::ObjectRole;
use sis_pdf_pdf::decode::stream_filters;
use sis_pdf_pdf::graph::{ObjEntry, ObjProvenance};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStream};
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
pub mod page_tree_anomalies;
pub mod polyglot;
pub mod quantum_risk;
pub mod rich_media_analysis;
pub mod strict;
pub mod supply_chain;
pub mod uri_classification;
pub mod xfa_forms;

#[derive(Clone, Copy)]
pub struct DetectorSettings {
    pub js_ast: bool,
    pub js_sandbox: bool,
}

impl Default for DetectorSettings {
    fn default() -> Self {
        Self {
            js_ast: true,
            js_sandbox: true,
        }
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
        Box::new(linearization::LinearizationDetector),
        Box::new(ObjStmDensityDetector),
        Box::new(objstm_summary::ObjStmSummaryDetector),
        Box::new(OpenActionDetector),
        Box::new(AAPresentDetector),
        Box::new(AAEventDetector),
        Box::new(actions_triggers::ActionTriggerDetector),
        Box::new(JavaScriptDetector {
            enable_ast: settings.js_ast,
        }),
        Box::new(js_polymorphic::JsPolymorphicDetector {
            enable_ast: settings.js_ast,
        }),
        Box::new(evasion_time::TimingEvasionDetector),
        Box::new(evasion_env::EnvProbeDetector),
        Box::new(supply_chain::SupplyChainDetector),
        Box::new(advanced_crypto::AdvancedCryptoDetector),
        Box::new(multi_stage::MultiStageDetector),
        Box::new(content_first::ContentFirstDetector),
        Box::new(quantum_risk::QuantumRiskDetector),
        Box::new(LaunchActionDetector),
        Box::new(GoToRDetector),
        Box::new(UriDetector),
        Box::new(uri_classification::UriPresenceDetector),
        Box::new(uri_classification::UriContentDetector),
        Box::new(SubmitFormDetector),
        Box::new(external_context::ExternalActionContextDetector),
        Box::new(FontMatrixDetector),
        Box::new(font_exploits::FontExploitDetector),
        Box::new(font_external_ref::FontExternalReferenceDetector),
        Box::new(image_analysis::ImageAnalysisDetector),
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
        Box::new(CryptoDetector),
        Box::new(encryption_obfuscation::EncryptionObfuscationDetector),
        Box::new(XfaDetector),
        Box::new(AcroFormDetector),
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
        Box::new(strict::StrictParseDeviationDetector),
        Box::new(ir_graph_static::IrGraphStaticDetector),
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
    sis_pdf_core::report::SandboxSummary {
        enabled: true,
        disabled_reason: None,
    }
}

struct XrefConflictDetector;

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

            let mut meta = std::collections::HashMap::new();
            meta.insert(
                "xref.startxref_count".into(),
                ctx.graph.startxrefs.len().to_string(),
            );
            meta.insert("xref.has_signature".into(), has_signature.to_string());

            // Signed documents with incremental updates are legitimate (multi-author)
            let (severity, description) = if has_signature {
                (
                    Severity::Info,
                    format!(
                        "Found {} startxref offsets in signed document. Likely legitimate multi-author scenario.",
                        ctx.graph.startxrefs.len()
                    )
                )
            } else {
                (
                    Severity::Medium,
                    format!(
                        "Found {} startxref offsets; PDFs with multiple xref sections can hide updates.",
                        ctx.graph.startxrefs.len()
                    )
                )
            };

            let evidence = keyword_evidence(ctx.bytes, b"startxref", "startxref marker", 5);
            Ok(vec![Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "xref_conflict".into(),
                severity,
                confidence: Confidence::Probable,
                title: "Multiple startxref entries".into(),
                description,
                objects: vec!["xref".into()],
                evidence,
                remediation: Some("Validate with a strict parser; inspect each revision.".into()),
                meta,
                yara: None,
                position: None,
                positions: Vec::new(),
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
            Ok(vec![Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "incremental_update_chain".into(),
                severity: Severity::Low,
                confidence: Confidence::Probable,
                title: "Incremental update chain present".into(),
                description: format!(
                    "PDF contains {} startxref markers suggesting incremental updates.",
                    ctx.graph.startxrefs.len()
                ),
                objects: vec!["xref".into()],
                evidence,
                remediation: Some("Review changes between revisions for hidden content.".into()),
                meta: Default::default(),
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
        if !classifications
            .values()
            .any(|c| c.has_role(ObjectRole::EmbeddedFile))
        {
            return Ok(Vec::new());
        }
        let mut findings = Vec::new();

        // Count total shadowing instances across document
        let shadowing_count = ctx
            .graph
            .index
            .iter()
            .filter(|(_, idxs)| idxs.len() > 1)
            .count();

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
        if !classifications
            .values()
            .any(|c| c.has_role(ObjectRole::LaunchTarget))
        {
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
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "open_action_present".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Strong,
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
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "aa_present".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Strong,
                        title: "Additional Actions present".into(),
                        description: "Additional Actions can execute on user events.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence,
                        remediation: Some("Review event actions for unsafe behavior.".into()),
                        meta: Default::default(),
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
                            meta.insert(
                                "aa.event_key".into(),
                                String::from_utf8_lossy(&k.decoded).to_string(),
                            );
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
                            if let Some(value) = aa_event_value(ctx, v) {
                                meta.insert("aa.event_value".into(), value);
                            }
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "aa_event_present".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::Probable,
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

/// Check if a PDF name represents a JavaScript key
/// Matches /JS, /JavaScript, /JScript (case-insensitive, handles hex encoding)
fn is_javascript_key(name: &sis_pdf_pdf::object::PdfName<'_>) -> bool {
    let decoded = &name.decoded;
    // Remove leading slash if present
    let name_str = if decoded.starts_with(b"/") {
        &decoded[1..]
    } else {
        decoded
    };

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
) -> Vec<(
    &'a sis_pdf_pdf::object::PdfName<'a>,
    &'a sis_pdf_pdf::object::PdfObj<'a>,
)> {
    dict.entries
        .iter()
        .filter(|(k, _)| is_javascript_key(k))
        .map(|(k, v)| (k, v))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JsPayloadSource {
    Action,
    Uri,
    DataUri,
    Xfa,
    EmbeddedFile,
}

impl JsPayloadSource {
    fn priority(self) -> u8 {
        match self {
            JsPayloadSource::Action => 0,
            JsPayloadSource::Uri => 1,
            JsPayloadSource::DataUri => 2,
            JsPayloadSource::Xfa => 3,
            JsPayloadSource::EmbeddedFile => 4,
        }
    }

    fn meta_value(self) -> Option<&'static str> {
        match self {
            JsPayloadSource::Action => None,
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
    let matches_prefix = bytes
        .iter()
        .take(prefix.len())
        .zip(prefix.iter())
        .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase());
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
    let matches_prefix = bytes
        .iter()
        .take(prefix.len())
        .zip(prefix.iter())
        .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase());
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
        });
    }

    if let Some((k, v)) = dict.get_first(b"/URI") {
        let res = resolve_payload(ctx, v);
        let Some(mut payload) = res.payload else {
            return out;
        };
        let evidence = vec![
            span_to_evidence(k.span, "Key /URI"),
            span_to_evidence(v.span, "URI value"),
        ];
        if let Some(stripped) = javascript_uri_payload_from_bytes(&payload.bytes) {
            payload.bytes = stripped;
            out.push(JsPayloadCandidate {
                payload,
                evidence,
                key_name: "/URI javascript".into(),
                source: JsPayloadSource::Uri,
            });
        } else if let Some(stripped) = data_uri_payload_from_bytes(&payload.bytes) {
            payload.bytes = stripped;
            out.push(JsPayloadCandidate {
                payload,
                evidence,
                key_name: "/URI data javascript".into(),
                source: JsPayloadSource::DataUri,
            });
        }
    }

    out
}

pub(crate) fn js_payload_candidates_from_entry(
    ctx: &sis_pdf_core::scan::ScanContext,
    entry: &ObjEntry<'_>,
) -> Vec<JsPayloadCandidate> {
    let mut out = Vec::new();
    if let Some(dict) = entry_dict(entry) {
        out.extend(js_payload_candidates_from_action_dict(ctx, dict));
        out.extend(js_payload_candidates_from_xfa(ctx, dict));
    }
    if let PdfAtom::Stream(st) = &entry.atom {
        if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
            out.extend(js_payload_candidates_from_embedded_stream(ctx, entry, st));
        }
    }
    out
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
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn js_payload_candidates_from_embedded_stream(
    ctx: &sis_pdf_core::scan::ScanContext,
    entry: &ObjEntry<'_>,
    stream: &sis_pdf_pdf::object::PdfStream<'_>,
) -> Vec<JsPayloadCandidate> {
    let mut out = Vec::new();
    let payload = resolve_payload(
        ctx,
        &sis_pdf_pdf::object::PdfObj {
            span: entry.body_span,
            atom: entry.atom.clone(),
        },
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
        evidence.push(decoded_evidence_span(
            origin,
            &payload.bytes,
            "Embedded JS payload",
        ));
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
    let slice = if data.len() > max_scan_bytes {
        &data[..max_scan_bytes]
    } else {
        data
    };
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
        &[
            b"function",
            b"eval(",
            b"document.",
            b"window.",
            b"var ",
            b"let ",
            b"const ",
            b"=>",
        ],
    )
}

fn contains_any(data: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|needle| find_subslice(data, needle).is_some())
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
                        meta.insert(
                            "js.multiple_keys_count".into(),
                            js_entries.len().to_string(),
                        );
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
                        meta.insert("payload.type".into(), payload.kind.clone());
                        meta.insert(
                            "payload.decoded_len".into(),
                            payload.bytes.len().to_string(),
                        );
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
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "js_present".into(),
                        severity: Severity::High,
                        confidence: Confidence::Strong,
                        title: "JavaScript present".into(),
                        description: "Inline or referenced JavaScript detected.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence,
                        remediation: Some("Extract and review the JavaScript payload.".into()),
                        meta,
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
            meta.insert(
                "launch.target_type".into(),
                tracker.target_type().to_string(),
            );
            if let Some(hash) = tracker.embedded_file_hash.clone() {
                meta.insert("launch.embedded_file_hash".into(), hash);
            }
            let objects = vec![format!("{} {} obj", entry.obj, entry.gen)];
            let base_meta = meta.clone();
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::Actions,
                kind: "launch_action_present".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Launch action present".into(),
                description: "Action dictionary with /S /Launch.".into(),
                objects: objects.clone(),
                evidence: evidence.clone(),
                remediation: Some("Review the action target.".into()),
                meta: base_meta,
                yara: None,
                position: None,
                positions: Vec::new(),
            });

            if tracker.external {
                let mut extra_meta = meta.clone();
                extra_meta.insert("launch.target_type".into(), "external".into());
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::Actions,
                    kind: "launch_external_program".into(),
                    severity: Severity::High,
                    confidence: Confidence::Probable,
                    title: "Launch action targets external program".into(),
                    description: "Launch action targets an external program or file path.".into(),
                    objects: objects.clone(),
                    evidence: evidence.clone(),
                    remediation: Some("Review the launch target for unsafe execution.".into()),
                    meta: extra_meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }

            if tracker.embedded {
                let mut extra_meta = meta.clone();
                extra_meta.insert("launch.target_type".into(), "embedded".into());
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::Actions,
                    kind: "launch_embedded_file".into(),
                    severity: Severity::High,
                    confidence: Confidence::Probable,
                    title: "Launch action targets embedded file".into(),
                    description: "Launch action targets an embedded file specification.".into(),
                    objects,
                    evidence,
                    remediation: Some("Extract and inspect the embedded target.".into()),
                    meta: extra_meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }
        }
        Ok(findings)
    }
}

struct UriDetector;

impl Detector for UriDetector {
    fn id(&self) -> &'static str {
        "uri_present"
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
        let mut findings = action_by_s(
            ctx,
            b"/URI",
            &[b"/URI"],
            "uri_present",
            "URI action present",
        )?;
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if let Some((k, v)) = dict.get_first(b"/URI") {
                    let mut evidence = vec![
                        span_to_evidence(k.span, "Key /URI"),
                        span_to_evidence(v.span, "URI value"),
                    ];
                    let mut meta = std::collections::HashMap::new();
                    if let Some(enriched) = payload_from_obj(ctx, v, "URI payload") {
                        evidence.extend(enriched.evidence);
                        meta.extend(enriched.meta);
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "uri_present".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Strong,
                        title: "URI present".into(),
                        description: "External URI action detected.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence,
                        remediation: Some("Verify destination URLs.".into()),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });
                }
            }
        }
        findings.extend(uri_findings_from_annots(ctx));
        Ok(findings)
    }
}

fn uri_findings_from_annots(ctx: &sis_pdf_core::scan::ScanContext) -> Vec<Finding> {
    let mut out = Vec::new();
    let annot_parents = sis_pdf_core::page_tree::build_annotation_parent_map(&ctx.graph);
    for entry in &ctx.graph.objects {
        let dict = match entry_dict(entry) {
            Some(d) => d,
            None => continue,
        };
        if !dict.has_name(b"/Subtype", b"/Annot") && !dict.has_name(b"/Type", b"/Annot") {
            continue;
        }
        if let Some((_, a)) = dict.get_first(b"/A") {
            if let Some(f) = uri_finding_from_action(ctx, entry, a, "Annotation /A", &annot_parents)
            {
                out.push(f);
            }
        }
        if let Some((_, aa)) = dict.get_first(b"/AA") {
            if let PdfAtom::Dict(aad) = &aa.atom {
                for (_, v) in &aad.entries {
                    if let Some(f) =
                        uri_finding_from_action(ctx, entry, v, "Annotation /AA", &annot_parents)
                    {
                        out.push(f);
                    }
                }
            }
        }
    }
    out
}

fn uri_finding_from_action(
    ctx: &sis_pdf_core::scan::ScanContext,
    entry: &ObjEntry<'_>,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
    note: &str,
    annot_parents: &std::collections::HashMap<
        sis_pdf_core::graph_walk::ObjRef,
        sis_pdf_core::page_tree::PageRefInfo,
    >,
) -> Option<Finding> {
    let action_obj = match &obj.atom {
        PdfAtom::Dict(_) => obj.clone(),
        PdfAtom::Ref { .. } => {
            let entry = ctx.graph.resolve_ref(obj)?;
            sis_pdf_pdf::object::PdfObj {
                span: entry.body_span,
                atom: entry.atom,
            }
        }
        _ => return None,
    };
    let PdfAtom::Dict(ad) = &action_obj.atom else {
        return None;
    };
    let (k, v) = ad.get_first(b"/URI")?;
    let mut evidence = vec![
        span_to_evidence(action_obj.span, note),
        span_to_evidence(k.span, "Key /URI"),
        span_to_evidence(v.span, "URI value"),
    ];
    let mut meta = std::collections::HashMap::new();
    if let Some(page) = annot_parents.get(&sis_pdf_core::graph_walk::ObjRef {
        obj: entry.obj,
        gen: entry.gen,
    }) {
        meta.insert("page.number".into(), page.number.to_string());
        meta.insert(
            "page.object".into(),
            format!("{} {} obj", page.obj, page.gen),
        );
    }
    if let Some(enriched) = payload_from_obj(ctx, v, "URI payload") {
        evidence.extend(enriched.evidence);
        meta.extend(enriched.meta);
    }
    Some(Finding {
        id: String::new(),
        surface: AttackSurface::Actions,
        kind: "uri_present".into(),
        severity: Severity::Medium,
        confidence: Confidence::Probable,
        title: "URI present".into(),
        description: "Annotation action contains a URI target.".into(),
        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
        evidence,
        remediation: Some("Verify destination URLs.".into()),
        meta,
        yara: None,
        position: None,
        positions: Vec::new(),
    })
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
                    if arr
                        .iter()
                        .any(|o| !matches!(o.atom, PdfAtom::Int(_) | PdfAtom::Real(_)))
                    {
                        let mut meta = std::collections::HashMap::new();
                        meta.insert("fontmatrix.non_numeric".into(), "true".into());
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "fontmatrix_payload_present".into(),
                            severity: Severity::Medium,
                            confidence: Confidence::Probable,
                            title: "Suspicious FontMatrix payload".into(),
                            description: "FontMatrix contains non-numeric entries, suggesting script injection.".into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: vec![span_to_evidence(dict.span, "Font dict")],
                            remediation: Some("Review font dictionaries for injected scripts.".into()),
                            meta,
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

struct SubmitFormDetector;

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
        )
    }
}

struct EmbeddedFileDetector;

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
                    let filename = embedded_filename(&st.dict);
                    if let Some(name) = &filename {
                        meta.insert("embedded.filename".into(), name.clone());
                        meta.insert("filename".into(), name.clone());
                        has_double = has_double_extension(name);
                        if has_double {
                            meta.insert("embedded.double_extension".into(), "true".into());
                        }
                    }
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
                        magic = Some(magic_value);
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
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "embedded_file_present".into(),
                        severity: Severity::High,
                        confidence: Confidence::Probable,
                        title: "Embedded file stream present".into(),
                        description: "Embedded file detected inside PDF.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: evidence.clone(),
                        remediation: Some("Extract and scan the embedded file.".into()),
                        meta: meta.clone(),
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                    });

                    let objects = vec![format!("{} {} obj", entry.obj, entry.gen)];
                    if let Some(magic) = magic.as_deref() {
                        if magic == "pe" {
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "embedded_executable_present".into(),
                                severity: Severity::High,
                                confidence: Confidence::Probable,
                                title: "Embedded executable present".into(),
                                description: "Embedded file appears to be an executable.".into(),
                                objects: objects.clone(),
                                evidence: evidence.clone(),
                                remediation: Some("Extract and scan the executable.".into()),
                                meta: meta.clone(),
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                            });
                        }
                        if magic == "script" {
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "embedded_script_present".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::Probable,
                                title: "Embedded script present".into(),
                                description: "Embedded file appears to be a script.".into(),
                                objects: objects.clone(),
                                evidence: evidence.clone(),
                                remediation: Some("Review the script content.".into()),
                                meta: meta.clone(),
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
                            title: "Embedded archive appears encrypted".into(),
                            description: "Embedded archive indicates encryption flags.".into(),
                            objects: objects.clone(),
                            evidence: evidence.clone(),
                            remediation: Some(
                                "Extract and attempt to inspect archive contents.".into(),
                            ),
                            meta: meta.clone(),
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
                            title: "Embedded file uses double extension".into(),
                            description: "Embedded filename uses multiple extensions.".into(),
                            objects,
                            evidence,
                            remediation: Some(
                                "Treat the file as suspicious and inspect carefully.".into(),
                            ),
                            meta: meta.clone(),
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
                        title: "RichMedia content present".into(),
                        description: "RichMedia annotations or dictionaries detected.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "RichMedia object")],
                        remediation: Some("Inspect 3D or media assets.".into()),
                        meta: Default::default(),
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
                        title: "3D content present".into(),
                        description: "3D content or stream detected (U3D/PRC).".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "3D object")],
                        remediation: Some("Inspect embedded 3D assets.".into()),
                        meta,
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
                        title: "Sound or movie content present".into(),
                        description: "Sound/Movie/Rendition objects detected.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "Sound/Movie object")],
                        remediation: Some("Inspect embedded media objects.".into()),
                        meta,
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
                        title: "File specification present".into(),
                        description: "Filespec or associated files detected.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "Filespec/AF object")],
                        remediation: Some("Inspect file specification targets.".into()),
                        meta: Default::default(),
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
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }

        let mut sig_evidence = Vec::new();
        let mut sig_meta = std::collections::HashMap::new();
        for entry in &ctx.graph.objects {
            if let Some(dict) = entry_dict(entry) {
                if dict.has_name(b"/Type", b"/Sig") || dict.get_first(b"/ByteRange").is_some() {
                    sig_evidence.push(span_to_evidence(entry.full_span, "Signature object"));
                    if sig_meta.get("signature.subfilter").is_none() {
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
                yara: None,
                position: None,
                positions: Vec::new(),
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
                title: "DSS structures present".into(),
                description: "Document Security Store (DSS) entries detected.".into(),
                objects: vec!["dss".into()],
                evidence: dss_evidence,
                remediation: Some("Inspect DSS for embedded validation material.".into()),
                meta: Default::default(),
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
                        title: "Optional content group present".into(),
                        description: "OCG/OCProperties detected; may influence viewer behaviour."
                            .into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "OCG object")],
                        remediation: Some("Inspect optional content group settings.".into()),
                        meta: Default::default(),
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
                if filters
                    .iter()
                    .any(|f| f == "/JBIG2Decode" || f == "/JPXDecode")
                {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "decoder_risk_present".into(),
                        severity: Severity::High,
                        confidence: Confidence::Probable,
                        title: "High-risk decoder present".into(),
                        description: format!("Stream uses filters: {}", filters.join(", ")),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(st.dict.span, "Stream dict")],
                        remediation: Some("Treat JBIG2/JPX decoding as high risk.".into()),
                        meta: Default::default(),
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
                                title: "Huge image dimensions".into(),
                                description: format!("Image dimensions {}x{}.", w, h),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: vec![span_to_evidence(st.dict.span, "Image dict")],
                                remediation: Some(
                                    "Inspect image payload for resource abuse.".into(),
                                ),
                                meta: Default::default(),
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

fn span_bytes<'a>(bytes: &'a [u8], span: sis_pdf_pdf::span::Span) -> Option<&'a [u8]> {
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
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::Actions,
                    kind: kind.into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
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
                });
            }
        }
    }
    Ok(findings)
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
            error: Some(format!(
                "max resolution depth {} exceeded",
                MAX_RESOLVE_DEPTH
            )),
        };
    }

    match &obj.atom {
        PdfAtom::Str(s) => PayloadResult {
            payload: Some(PayloadInfo {
                bytes: string_bytes(s),
                kind: "string".into(),
                ref_chain: if ref_chain.is_empty() {
                    "-".into()
                } else {
                    ref_chain.join(" -> ")
                },
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
            Err(e) => PayloadResult {
                payload: None,
                error: Some(e.to_string()),
            },
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
            let resolved_obj = sis_pdf_pdf::object::PdfObj {
                span: entry.body_span,
                atom: entry.atom.clone(),
            };

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
            sis_pdf_pdf::object::PdfObj {
                span: entry.body_span,
                atom: entry.atom,
            }
        }
        _ => return None,
    };
    if let PdfAtom::Dict(d) = &action_obj.atom {
        if let Some((k, v)) = d.get_first(b"/S") {
            evidence.push(span_to_evidence(k.span, "Action key /S"));
            evidence.push(span_to_evidence(v.span, "Action value"));
            if let PdfAtom::Name(n) = &v.atom {
                meta.insert(
                    "action.s".into(),
                    String::from_utf8_lossy(&n.decoded).to_string(),
                );
            }
        }
        if let Some((k, v)) = d.get_first(b"/URI") {
            evidence.push(span_to_evidence(k.span, "Action key /URI"));
            evidence.push(span_to_evidence(v.span, "Action URI value"));
            meta.insert(
                "action.target".into(),
                preview_ascii(&payload_string(v), 120),
            );
        }
        if let Some((k, v)) = d.get_first(b"/F") {
            evidence.push(span_to_evidence(k.span, "Action key /F"));
            evidence.push(span_to_evidence(v.span, "Action file/target"));
            meta.insert(
                "action.target".into(),
                preview_ascii(&payload_string(v), 120),
            );
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
            meta.insert(
                "payload.key".into(),
                String::from_utf8_lossy(key).to_string(),
            );
            let res = resolve_payload(ctx, v);
            if let Some(err) = res.error {
                meta.insert("payload.error".into(), err);
            }
            if let Some(payload) = res.payload {
                meta.insert("payload.type".into(), payload.kind);
                meta.insert(
                    "payload.decoded_len".into(),
                    payload.bytes.len().to_string(),
                );
                meta.insert("payload.ref_chain".into(), payload.ref_chain);
                meta.insert("payload.preview".into(), preview_ascii(&payload.bytes, 120));
                meta.insert(
                    "payload.decoded_preview".into(),
                    preview_ascii(&payload.bytes, 120),
                );
                if let Some(origin) = payload.origin {
                    evidence.push(decoded_evidence_span(
                        origin,
                        &payload.bytes,
                        "Decoded payload",
                    ));
                }
            }
            return Some(PayloadEnrichment { evidence, meta });
        }
    }
    None
}

fn payload_from_obj(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
    note: &str,
) -> Option<PayloadEnrichment> {
    let mut evidence = vec![span_to_evidence(obj.span, note)];
    let mut meta = std::collections::HashMap::new();
    let res = resolve_payload(ctx, obj);
    if let Some(err) = res.error {
        meta.insert("payload.error".into(), err);
    }
    if let Some(payload) = res.payload {
        meta.insert("payload.type".into(), payload.kind);
        meta.insert(
            "payload.decoded_len".into(),
            payload.bytes.len().to_string(),
        );
        meta.insert("payload.ref_chain".into(), payload.ref_chain);
        meta.insert("payload.preview".into(), preview_ascii(&payload.bytes, 120));
        meta.insert(
            "payload.decoded_preview".into(),
            preview_ascii(&payload.bytes, 120),
        );
        if let Some(origin) = payload.origin {
            evidence.push(decoded_evidence_span(
                origin,
                &payload.bytes,
                "Decoded payload",
            ));
        }
    }
    Some(PayloadEnrichment { evidence, meta })
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
                sis_pdf_pdf::object::PdfObj {
                    span: entry.body_span,
                    atom: entry.atom,
                }
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
        tracker.mark_embedded(
            embedded_filename(&stream.dict),
            embedded_hash_from_stream(ctx, stream),
        );
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
    ctx.decoded
        .get_or_decode(ctx.bytes, stream)
        .ok()
        .map(|decoded| sha256_hex(&decoded.data))
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
        data_uri_payload_from_bytes, extract_xfa_script_payloads,
        javascript_uri_payload_from_bytes, normalise_text_bytes_for_script,
    };

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
        let normalised = normalise_text_bytes_for_script(utf16).unwrap();
        assert!(normalised.starts_with(b"function"));
    }
}

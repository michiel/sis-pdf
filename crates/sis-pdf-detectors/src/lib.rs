use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::{decoded_evidence_span, preview_ascii};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::decode::stream_filters;
use sis_pdf_pdf::graph::ObjEntry;
use sis_pdf_pdf::object::{PdfAtom, PdfDict};
use sha2::{Digest, Sha256};

pub mod js_signals;
pub mod content_phishing;
pub mod strict;

pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(XrefConflictDetector),
        Box::new(IncrementalUpdateDetector),
        Box::new(ObjectIdShadowingDetector),
        Box::new(ObjStmDensityDetector),
        Box::new(OpenActionDetector),
        Box::new(AAPresentDetector),
        Box::new(AAEventDetector),
        Box::new(JavaScriptDetector),
        Box::new(LaunchActionDetector),
        Box::new(GoToRDetector),
        Box::new(UriDetector),
        Box::new(SubmitFormDetector),
        Box::new(FontMatrixDetector),
        Box::new(EmbeddedFileDetector),
        Box::new(RichMediaDetector),
        Box::new(ThreeDDetector),
        Box::new(SoundMovieDetector),
        Box::new(FileSpecDetector),
        Box::new(CryptoDetector),
        Box::new(XfaDetector),
        Box::new(AcroFormDetector),
        Box::new(OCGDetector),
        Box::new(DecoderRiskDetector),
        Box::new(DecompressionRatioDetector),
        Box::new(HugeImageDetector),
        Box::new(content_phishing::ContentPhishingDetector),
        Box::new(content_phishing::ContentDeceptionDetector),
        Box::new(strict::StrictParseDeviationDetector),
    ]
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
            let evidence = keyword_evidence(ctx.bytes, b"startxref", "startxref marker", 5);
            Ok(vec![Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "xref_conflict".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Multiple startxref entries".into(),
                description: format!(
                    "Found {} startxref offsets; PDFs with multiple xref sections can hide updates.",
                    ctx.graph.startxrefs.len()
                ),
                objects: vec!["xref".into()],
                evidence,
                remediation: Some("Validate with a strict parser; inspect each revision.".into()),
                meta: Default::default(),
                yara: None,
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
        let mut findings = Vec::new();
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
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "object_id_shadowing".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "Duplicate object IDs detected".into(),
                    description: format!(
                        "Object {} {} appears {} times; later revisions may shadow earlier content.",
                        obj,
                        gen,
                        idxs.len()
                    ),
                    objects,
                    evidence,
                    remediation: Some("Compare object bodies across revisions.".into()),
                meta: Default::default(),
                yara: None,
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
                        remediation: Some("Validate the action target and disable auto-run.".into()),
                        meta,
                        yara: None,
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
                            });
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

fn aa_event_value(ctx: &sis_pdf_core::scan::ScanContext, obj: &sis_pdf_pdf::object::PdfObj<'_>) -> Option<String> {
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

struct JavaScriptDetector;

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
                let mut js_obj = None;
                if let Some((k, v)) = dict.get_first(b"/JS") {
                    js_obj = Some((k, v));
                }
                if dict.has_name(b"/S", b"/JavaScript") || js_obj.is_some() {
                    let mut evidence = Vec::new();
                    if let Some((k, v)) = js_obj {
                        evidence.push(span_to_evidence(k.span, "JavaScript key /JS"));
                        evidence.push(span_to_evidence(v.span, "JavaScript payload"));
                    } else {
                        evidence.push(span_to_evidence(dict.span, "Action dict"));
                    }
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("payload_key".into(), "/JS".into());
                    meta.insert("js.stream.decoded".into(), "false".into());
                    meta.insert("js.stream.decode_error".into(), "-".into());
                    if let Some((_, v)) = dict.get_first(b"/JS") {
                        let res = resolve_payload(ctx, v);
                        if let Some(err) = res.error {
                            meta.insert("js.stream.decode_error".into(), err);
                        }
                        if let Some(payload) = res.payload {
                            meta.insert("payload.type".into(), payload.kind);
                            meta.insert(
                                "payload.decoded_len".into(),
                                payload.bytes.len().to_string(),
                            );
                            meta.insert("payload.ref_chain".into(), payload.ref_chain);
                            if let Some(filters) = payload.filters {
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
                            let sig = js_signals::extract_js_signals(&payload.bytes);
                            for (k, v) in sig {
                                meta.insert(k, v);
                            }
                            meta.insert("js.stream.decoded".into(), "true".into());
                            meta.insert(
                                "payload.decoded_preview".into(),
                                preview_ascii(&payload.bytes, 120),
                            );
                        }
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
        action_by_s(
            ctx,
            b"/Launch",
            &[b"/F", b"/Win"],
            "launch_action_present",
            "Launch action present",
        )
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
        let mut findings = action_by_s(ctx, b"/URI", &[b"/URI"], "uri_present", "URI action present")?;
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
            if let Some(f) = uri_finding_from_action(ctx, entry, a, "Annotation /A", &annot_parents) {
                out.push(f);
            }
        }
        if let Some((_, aa)) = dict.get_first(b"/AA") {
            if let PdfAtom::Dict(aad) = &aa.atom {
                for (_, v) in &aad.entries {
                    if let Some(f) = uri_finding_from_action(ctx, entry, v, "Annotation /AA", &annot_parents) {
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
    annot_parents: &std::collections::HashMap<sis_pdf_core::graph_walk::ObjRef, sis_pdf_core::page_tree::PageRefInfo>,
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
                    if arr.iter().any(|o| !matches!(o.atom, PdfAtom::Int(_) | PdfAtom::Real(_))) {
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
        action_by_s(ctx, b"/GoToR", &[b"/F"], "gotor_present", "GoToR action present")
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
        for entry in &ctx.graph.objects {
            if let PdfAtom::Stream(st) = &entry.atom {
                if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
                    let mut evidence = vec![
                        span_to_evidence(st.dict.span, "EmbeddedFile dict"),
                        span_to_evidence(st.data_span, "EmbeddedFile stream"),
                    ];
                    let mut meta = std::collections::HashMap::new();
                    if let Some(name) = embedded_filename(&st.dict) {
                        meta.insert("embedded.filename".into(), name.clone());
                        if has_double_extension(&name) {
                            meta.insert("embedded.double_extension".into(), "true".into());
                        }
                    }
                    if let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, st) {
                        let hash = sha256_hex(&decoded.data);
                        let magic = magic_type(&decoded.data);
                        meta.insert("embedded.sha256".into(), hash);
                        meta.insert(
                            "embedded.size".into(),
                            decoded.data.len().to_string(),
                        );
                        let is_zip = magic == "zip";
                        meta.insert("embedded.magic".into(), magic);
                        if is_zip && zip_encrypted(&decoded.data) {
                            meta.insert("embedded.encrypted_container".into(), "true".into());
                        }
                        if decoded.input_len > 0 {
                            let ratio =
                                decoded.data.len() as f64 / decoded.input_len as f64;
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
                        evidence,
                        remediation: Some("Extract and scan the embedded file.".into()),
                        meta,
                        yara: None,
                    });
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
                if dict.get_first(b"/RichMedia").is_some()
                    || dict.has_name(b"/Type", b"/RichMedia")
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
                        meta: Default::default(),
                        yara: None,
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
                        meta: Default::default(),
                        yara: None,
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
        for trailer in &ctx.graph.trailers {
            if trailer.get_first(b"/Encrypt").is_some() {
                encrypt_evidence.push(span_to_evidence(trailer.span, "Trailer /Encrypt"));
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
                confidence: Confidence::Probable,
                title: "Encryption dictionary present".into(),
                description: "Trailer indicates encrypted content via /Encrypt.".into(),
                objects: vec!["trailer".into()],
                evidence: encrypt_evidence,
                remediation: Some("Decrypt with trusted tooling to inspect all objects.".into()),
                meta: Default::default(),
                yara: None,
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
                confidence: Confidence::Probable,
                title: "Digital signature present".into(),
                description: "Signature dictionaries or ByteRange entries detected.".into(),
                objects: vec!["signature".into()],
                evidence: sig_evidence,
                remediation: Some("Validate signature chain and inspect signed content.".into()),
                meta: sig_meta,
                yara: None,
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
                        confidence: Confidence::Probable,
                        title: "XFA form present".into(),
                        description: "XFA forms can expand attack surface.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(dict.span, "XFA dict")],
                        remediation: Some("Inspect XFA form data and scripts.".into()),
                        meta: Default::default(),
                        yara: None,
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
                        confidence: Confidence::Probable,
                        title: "AcroForm present".into(),
                        description: "Interactive AcroForm dictionaries detected.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(dict.span, "AcroForm dict")],
                        remediation: Some("Inspect form fields and calculation scripts.".into()),
                        meta: Default::default(),
                        yara: None,
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
                if dict.get_first(b"/OCG").is_some() || dict.get_first(b"/OCProperties").is_some()
                {
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "ocg_present".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Probable,
                        title: "Optional content group present".into(),
                        description: "OCG/OCProperties detected; may influence viewer behaviour.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(entry.full_span, "OCG object")],
                        remediation: Some("Inspect optional content group settings.".into()),
                        meta: Default::default(),
                        yara: None,
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
                        title: "High-risk decoder present".into(),
                        description: format!("Stream uses filters: {}", filters.join(", ")),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(st.dict.span, "Stream dict")],
                        remediation: Some("Treat JBIG2/JPX decoding as high risk.".into()),
                meta: Default::default(),
                yara: None,
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
                meta: Default::default(),
                yara: None,
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
                                remediation: Some("Inspect image payload for resource abuse.".into()),
                meta: Default::default(),
                yara: None,
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
                    description: format!("Action dictionary with /S {}.", String::from_utf8_lossy(action)),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence,
                    remediation: Some("Review the action target.".into()),
                    meta,
                    yara: None,
                });
            }
        }
    }
    Ok(findings)
}

fn dict_int(dict: &PdfDict<'_>, key: &[u8]) -> Option<u32> {
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

struct PayloadInfo {
    bytes: Vec<u8>,
    kind: String,
    ref_chain: String,
    origin: Option<sis_pdf_pdf::span::Span>,
    filters: Option<String>,
    decode_ratio: Option<f64>,
}

struct PayloadResult {
    payload: Option<PayloadInfo>,
    error: Option<String>,
}

fn resolve_payload(
    ctx: &sis_pdf_core::scan::ScanContext,
    obj: &sis_pdf_pdf::object::PdfObj<'_>,
) -> PayloadResult {
    match &obj.atom {
        PdfAtom::Str(s) => PayloadResult {
            payload: Some(PayloadInfo {
            bytes: string_bytes(s),
            kind: "string".into(),
            ref_chain: "-".into(),
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
                        ref_chain: "-".into(),
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
        PdfAtom::Ref { .. } => {
            let entry = match ctx.graph.resolve_ref(obj) {
                Some(e) => e,
                None => {
                    return PayloadResult {
                        payload: None,
                        error: Some("ref resolution failed".into()),
                    }
                }
            };
            let ref_chain = format!("{} {} R", entry.obj, entry.gen);
            match &entry.atom {
                PdfAtom::Str(s) => PayloadResult {
                    payload: Some(PayloadInfo {
                        bytes: string_bytes(s),
                        kind: "string".into(),
                        ref_chain,
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
                                ref_chain,
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
                _ => PayloadResult {
                    payload: None,
                    error: Some("unsupported payload type".into()),
                },
            }
        }
        _ => PayloadResult {
            payload: None,
            error: Some("unsupported payload type".into()),
        },
    }
}

struct PayloadEnrichment {
    evidence: Vec<sis_pdf_core::model::EvidenceSpan>,
    meta: std::collections::HashMap<String, String>,
}

struct ActionDetails {
    evidence: Vec<sis_pdf_core::model::EvidenceSpan>,
    meta: std::collections::HashMap<String, String>,
}

fn resolve_action_details(
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
                    evidence.push(decoded_evidence_span(origin, &payload.bytes, "Decoded payload"));
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
            evidence.push(decoded_evidence_span(origin, &payload.bytes, "Decoded payload"));
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

fn magic_type(data: &[u8]) -> String {
    if data.starts_with(b"MZ") {
        "pe".into()
    } else if data.starts_with(b"%PDF") {
        "pdf".into()
    } else if data.starts_with(b"PK\x03\x04") {
        "zip".into()
    } else if data.starts_with(b"\x7fELF") {
        "elf".into()
    } else if data.starts_with(b"#!") {
        "script".into()
    } else {
        "unknown".into()
    }
}

fn keyword_evidence(bytes: &[u8], keyword: &[u8], note: &str, limit: usize) -> Vec<sis_pdf_core::model::EvidenceSpan> {
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

fn zip_encrypted(data: &[u8]) -> bool {
    if data.len() < 8 || !data.starts_with(b"PK\x03\x04") {
        return false;
    }
    let flag = u16::from_le_bytes([data[6], data[7]]);
    (flag & 0x0001) != 0
}

fn string_bytes(s: &sis_pdf_pdf::object::PdfStr<'_>) -> Vec<u8> {
    match s {
        sis_pdf_pdf::object::PdfStr::Literal { decoded, .. } => decoded.clone(),
        sis_pdf_pdf::object::PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

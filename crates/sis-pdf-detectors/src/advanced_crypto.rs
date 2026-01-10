use anyhow::Result;

use sis_pdf_core::crypto_analysis::{CryptoAnalyzer, SignatureInfo};
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
use tracing::warn;

use crate::{entry_dict, resolve_payload};

pub struct AdvancedCryptoDetector;

impl Detector for AdvancedCryptoDetector {
    fn id(&self) -> &'static str {
        "advanced_crypto"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::CryptoSignatures
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let analyzer = CryptoAnalyzer;
        if let Some(enc) = trailer_encrypt_dict(ctx) {
            for weak in analyzer.detect_weak_crypto(&enc) {
                let mut meta = std::collections::HashMap::new();
                meta.insert("crypto.issue".into(), weak.issue.clone());
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::CryptoSignatures,
                    kind: "crypto_weak_algo".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "Weak cryptography settings".into(),
                    description: weak.issue,
                    objects: vec!["encrypt".into()],
                    evidence: Vec::new(),
                    remediation: Some("Upgrade encryption algorithm and key length.".into()),
                    meta,
                    yara: None,
        position: None,
        positions: Vec::new(),
                });
            }
        }

        let sigs = extract_signatures(ctx);
        for anomaly in analyzer.analyze_cert_chains(&sigs) {
            let mut meta = std::collections::HashMap::new();
            meta.insert("crypto.issue".into(), anomaly.issue.clone());
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::CryptoSignatures,
                kind: "crypto_cert_anomaly".into(),
                severity: Severity::Low,
                confidence: Confidence::Heuristic,
                title: "Signature chain anomaly".into(),
                description: anomaly.issue,
                objects: vec!["signature".into()],
                evidence: Vec::new(),
                remediation: Some("Validate certificate chain and signature metadata.".into()),
                meta,
                yara: None,
        position: None,
        positions: Vec::new(),
            });
        }

        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else { continue };
            if dict.get_first(b"/JS").is_none() && !dict.has_name(b"/S", b"/JavaScript") {
                continue;
            }
            let Some((_, obj)) = dict.get_first(b"/JS") else { continue };
            let payload = resolve_payload(ctx, obj);
            let Some(info) = payload.payload else { continue };
            if let Some(miner) = analyzer.detect_crypto_mining(&info.bytes) {
                let mut meta = std::collections::HashMap::new();
                meta.insert("crypto.miner_indicator".into(), miner.indicator);
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::CryptoSignatures,
                    kind: "crypto_mining_js".into(),
                    severity: Severity::High,
                    confidence: Confidence::Probable,
                    title: "Cryptomining JavaScript".into(),
                    description: "JavaScript includes cryptomining indicators.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Inspect for cryptomining payloads.".into()),
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

fn trailer_encrypt_dict<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext<'a>,
) -> Option<PdfDict<'a>> {
    if let Some(trailer) = ctx.graph.trailers.last() {
        if let Some((_, enc)) = trailer.get_first(b"/Encrypt") {
            return resolve_dict(&ctx.graph, enc);
        }
    }
    fallback_encrypt_dict(ctx)
}

fn fallback_encrypt_dict<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext<'a>,
) -> Option<PdfDict<'a>> {
    let entry = ctx.graph.objects.iter().find(|entry| {
        entry_dict(entry)
            .map(|d| {
                d.has_name(b"/Filter", b"/Standard")
                    && (d.get_first(b"/V").is_some() || d.get_first(b"/R").is_some())
            })
            .unwrap_or(false)
    })?;
    warn!(
        security = true,
        domain = "pdf.encryption",
        kind = "encrypt_dict_fallback",
        "Using fallback /Encrypt dict from object graph"
    );
    match &entry.atom {
        PdfAtom::Dict(d) => Some(d.clone()),
        PdfAtom::Stream(st) => Some(st.dict.clone()),
        _ => None,
    }
}

fn resolve_dict<'a>(graph: &'a sis_pdf_pdf::ObjectGraph<'a>, obj: &PdfObj<'a>) -> Option<PdfDict<'a>> {
    match &obj.atom {
        PdfAtom::Dict(d) => Some(d.clone()),
        PdfAtom::Stream(st) => Some(st.dict.clone()),
        PdfAtom::Ref { .. } => graph.resolve_ref(obj).and_then(|e| match &e.atom {
            PdfAtom::Dict(d) => Some(d.clone()),
            PdfAtom::Stream(st) => Some(st.dict.clone()),
            _ => None,
        }),
        _ => None,
    }
}

fn extract_signatures(ctx: &sis_pdf_core::scan::ScanContext) -> Vec<SignatureInfo> {
    let mut out = Vec::new();
    for entry in &ctx.graph.objects {
        let Some(dict) = entry_dict(entry) else { continue };
        if dict.has_name(b"/Type", b"/Sig") || dict.get_first(b"/ByteRange").is_some() {
            let filter = dict.get_first(b"/Filter").and_then(|(_, v)| name_string(v));
            let subfilter = dict.get_first(b"/SubFilter").and_then(|(_, v)| name_string(v));
            out.push(SignatureInfo { filter, subfilter });
        }
    }
    out
}

fn name_string(obj: &PdfObj<'_>) -> Option<String> {
    match &obj.atom {
        PdfAtom::Name(n) => Some(String::from_utf8_lossy(&n.decoded).to_string()),
        _ => None,
    }
}

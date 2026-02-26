use anyhow::Result;

use sis_pdf_core::crypto_analysis::{classify_encryption_algorithm, CryptoAnalyzer, SignatureInfo};
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
use tracing::warn;

use crate::{entry_dict, js_payload_candidates_from_entry};

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
        let (fallback_used, fallback_object, enc_dict) = trailer_encrypt_dict(ctx);
        if fallback_used {
            let mut meta = std::collections::HashMap::new();
            meta.insert("encrypt.source".into(), "object_graph_fallback".into());
            if let Some(object_ref) = &fallback_object {
                meta.insert("object.ref".into(), object_ref.clone());
                meta.insert("query.next".into(), format!("object {}", object_ref));
            }
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::CryptoSignatures,
                kind: "encrypt_dict_fallback".into(),
                severity: Severity::Low,
                confidence: Confidence::Probable,
                impact: Some(sis_pdf_core::model::Impact::Low),
                title: "Encryption dictionary recovered via fallback".into(),
                description: "Trailer /Encrypt reference was unavailable; encryption dictionary was recovered from object graph heuristics.".into(),
                objects: fallback_object
                    .as_ref()
                    .map(|object_ref| vec![object_ref.clone()])
                    .unwrap_or_else(|| vec!["encrypt".into()]),
                evidence: Vec::new(),
                remediation: Some("Inspect trailer and encryption dictionary references for tampering.".into()),
                meta,
                yara: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }
        if let Some(enc) = enc_dict {
            let version = dict_int(&enc, b"/V");
            let key_len = dict_int(&enc, b"/Length");
            let revision = dict_int(&enc, b"/R");
            let algorithm = classify_encryption_algorithm(version, key_len);
            for weak in analyzer.detect_weak_crypto(&enc) {
                let mut meta = std::collections::HashMap::new();
                meta.insert("crypto.issue".into(), weak.issue.clone());
                if let Some(algo) = algorithm {
                    meta.insert("crypto.algorithm".into(), algo.into());
                }
                if let Some(len) = key_len {
                    meta.insert("crypto.key_length".into(), len.to_string());
                }
                if let Some(v) = version {
                    meta.insert("crypto.version".into(), v.to_string());
                }
                if let Some(r) = revision {
                    meta.insert("crypto.revision".into(), r.to_string());
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::CryptoSignatures,
                    kind: "crypto_weak_algo".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "Weak cryptography settings".into(),
                    description: weak.issue,
                    objects: vec!["encrypt".into()],
                    evidence: Vec::new(),
                    remediation: Some("Upgrade encryption algorithm and key length.".into()),
                    meta,
                    yara: None,
                    positions: Vec::new(),
                    ..Finding::default()
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
                impact: None,
                title: "Signature chain anomaly".into(),
                description: anomaly.issue,
                objects: vec!["signature".into()],
                evidence: Vec::new(),
                remediation: Some("Validate certificate chain and signature metadata.".into()),
                meta,
                yara: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }

        for entry in &ctx.graph.objects {
            let candidates = js_payload_candidates_from_entry(ctx, entry);
            if candidates.is_empty() {
                continue;
            }
            for candidate in candidates {
                if let Some(miner) = analyzer.detect_crypto_mining(&candidate.payload.bytes) {
                    let mut evidence = candidate.evidence;
                    if evidence.is_empty() {
                        evidence.push(span_to_evidence(entry.full_span, "JavaScript object"));
                    }
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("crypto.miner_indicator".into(), miner.indicator);
                    if let Some(label) = candidate.source.meta_value() {
                        meta.insert("js.source".into(), label.into());
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: AttackSurface::CryptoSignatures,
                        kind: "crypto_mining_js".into(),
                        severity: Severity::High,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "Cryptomining JavaScript".into(),
                        description: "JavaScript includes cryptomining indicators.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence,
                        remediation: Some("Inspect for cryptomining payloads.".into()),
                        meta,
                        yara: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }
            }
        }
        Ok(findings)
    }
}

fn trailer_encrypt_dict<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext<'a>,
) -> (bool, Option<String>, Option<PdfDict<'a>>) {
    if let Some(trailer) = ctx.graph.trailers.last() {
        if let Some((_, enc)) = trailer.get_first(b"/Encrypt") {
            return (false, None, resolve_dict(&ctx.graph, enc));
        }
    }
    fallback_encrypt_dict(ctx)
}

fn fallback_encrypt_dict<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext<'a>,
) -> (bool, Option<String>, Option<PdfDict<'a>>) {
    let entry = ctx.graph.objects.iter().find(|entry| {
        entry_dict(entry)
            .map(|d| {
                d.has_name(b"/Filter", b"/Standard")
                    && (d.get_first(b"/V").is_some() || d.get_first(b"/R").is_some())
            })
            .unwrap_or(false)
    });
    let Some(entry) = entry else {
        return (false, None, None);
    };
    warn!(
        security = true,
        domain = "pdf.encryption",
        kind = "encrypt_dict_fallback",
        "[NON-FATAL][finding:encrypt_dict_fallback] Using fallback /Encrypt dict from object graph"
    );
    let dict = match &entry.atom {
        PdfAtom::Dict(d) => Some(d.clone()),
        PdfAtom::Stream(st) => Some(st.dict.clone()),
        _ => None,
    };
    (true, Some(format!("{} {} obj", entry.obj, entry.gen)), dict)
}

fn resolve_dict<'a>(
    graph: &'a sis_pdf_pdf::ObjectGraph<'a>,
    obj: &PdfObj<'a>,
) -> Option<PdfDict<'a>> {
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
        let Some(dict) = entry_dict(entry) else {
            continue;
        };
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

fn dict_int(dict: &PdfDict<'_>, key: &[u8]) -> Option<u32> {
    dict.get_first(key).and_then(|(_, obj)| match obj.atom {
        PdfAtom::Int(value) => Some(value as u32),
        _ => None,
    })
}

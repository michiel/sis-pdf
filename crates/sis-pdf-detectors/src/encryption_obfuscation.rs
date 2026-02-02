use anyhow::Result;

use sis_pdf_core::crypto_analysis::classify_encryption_algorithm;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::stream_analysis::{
    analyse_stream, StreamAnalysisResult, StreamLimits, STREAM_HIGH_ENTROPY_THRESHOLD,
    STREAM_MIN_BYTES,
};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};

use crate::dict_int;

pub struct EncryptionObfuscationDetector;

impl Detector for EncryptionObfuscationDetector {
    fn id(&self) -> &'static str {
        "encryption_obfuscation"
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
        let timeout = TimeoutChecker::new(std::time::Duration::from_millis(150));
        let limits = StreamLimits::default();

        for trailer in &ctx.graph.trailers {
            if let Some((_, encrypt_obj)) = trailer.get_first(b"/Encrypt") {
                if let Some(dict) = resolve_encrypt_dict(ctx, encrypt_obj) {
                    let mut meta = encryption_meta_from_dict(&dict);
                    if let Some(key_len) = dict_int(&dict, b"/Length") {
                        if key_len < 128 {
                            meta.insert("crypto.key_length".into(), key_len.to_string());
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "encryption_key_short".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::Probable,
                                impact: None,
                                title: "Encryption key length short".into(),
                                description:
                                    "Encryption key length is below recommended threshold.".into(),
                                objects: vec!["trailer".into()],
                                evidence: EvidenceBuilder::new()
                                    .file_offset(
                                        trailer.span.start,
                                        trailer.span.len() as u32,
                                        "Trailer /Encrypt",
                                    )
                                    .build(),
                                remediation: Some("Treat encrypted content as higher risk.".into()),
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
        }

        for entry in &ctx.graph.objects {
            if timeout.check().is_err() {
                break;
            }
            let PdfAtom::Stream(stream) = &entry.atom else {
                continue;
            };
            let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, stream) else {
                continue;
            };
            if decoded.data.len() < STREAM_MIN_BYTES {
                continue;
            }
            let analysis = analyse_stream(&decoded.data, &limits);
            if analysis.entropy >= STREAM_HIGH_ENTROPY_THRESHOLD {
                let meta = stream_entropy_meta(&analysis);
                findings.push(Finding {
                    id: String::new(),
                    surface: AttackSurface::StreamsAndFilters,
                    kind: "stream_high_entropy".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "High entropy stream".into(),
                    description: "Stream entropy exceeds expected threshold.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: EvidenceBuilder::new()
                        .file_offset(
                            stream.dict.span.start,
                            stream.dict.span.len() as u32,
                            "Stream dict",
                        )
                        .file_offset(
                            stream.data_span.start,
                            stream.data_span.len() as u32,
                            "Stream data",
                        )
                        .build(),
                    remediation: Some("Inspect stream content for hidden payloads.".into()),
                    meta: meta.clone(),

                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                    ..Finding::default()
                });

                if stream.dict.has_name(b"/Type", b"/EmbeddedFile")
                    && analysis.magic_type == "unknown"
                {
                    findings.push(Finding {
                        id: String::new(),
                        surface: AttackSurface::EmbeddedFiles,
                        kind: "embedded_encrypted".into(),
                        severity: Severity::Medium,
                        confidence: Confidence::Probable,
                        impact: None,
                        title: "Embedded file appears encrypted".into(),
                        description: "Embedded file has high entropy with unknown magic.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: EvidenceBuilder::new()
                            .file_offset(
                                stream.dict.span.start,
                                stream.dict.span.len() as u32,
                                "EmbeddedFile dict",
                            )
                            .file_offset(
                                stream.data_span.start,
                                stream.data_span.len() as u32,
                                "EmbeddedFile stream",
                            )
                            .build(),
                        remediation: Some(
                            "Attempt to extract and decrypt the embedded file.".into(),
                        ),
                        meta,
                        yara: None,
                        position: None,
                        positions: Vec::new(),
                        ..Finding::default()
                    });
                }
            }
        }

        Ok(findings)
    }
}

fn stream_entropy_meta(
    analysis: &StreamAnalysisResult,
) -> std::collections::HashMap<String, String> {
    let mut meta = std::collections::HashMap::new();
    meta.insert("entropy".into(), format!("{:.3}", analysis.entropy));
    meta.insert("stream.entropy".into(), format!("{:.3}", analysis.entropy));
    meta.insert(
        "entropy_threshold".into(),
        format!("{:.1}", STREAM_HIGH_ENTROPY_THRESHOLD),
    );
    meta.insert(
        "sample_size_bytes".into(),
        analysis.sample_bytes.to_string(),
    );
    meta.insert(
        "stream.sample_size_bytes".into(),
        analysis.sample_bytes.to_string(),
    );
    meta.insert(
        "stream.sample_timed_out".into(),
        analysis.timed_out.to_string(),
    );
    meta.insert("stream.size_bytes".into(), analysis.size_bytes.to_string());
    meta.insert("stream.magic".into(), analysis.magic_type.clone());
    meta.insert("stream.magic_type".into(), analysis.magic_type.clone());
    meta
}

pub(crate) fn resolve_encrypt_dict<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext,
    obj: &'a PdfObj<'a>,
) -> Option<PdfDict<'a>> {
    match &obj.atom {
        PdfAtom::Dict(dict) => Some(dict.clone()),
        PdfAtom::Ref { obj, gen } => {
            ctx.graph
                .get_object(*obj, *gen)
                .and_then(|entry| match &entry.atom {
                    PdfAtom::Dict(dict) => Some(dict.clone()),
                    _ => None,
                })
        }
        _ => None,
    }
}

pub(crate) fn encryption_meta_from_dict(
    dict: &PdfDict<'_>,
) -> std::collections::HashMap<String, String> {
    let mut meta = std::collections::HashMap::new();
    let version = dict_int(dict, b"/V");
    let revision = dict_int(dict, b"/R");
    let key_len = dict_int(dict, b"/Length");

    if let Some(v) = version {
        meta.insert("crypto.version".into(), v.to_string());
    }
    if let Some(r) = revision {
        meta.insert("crypto.revision".into(), r.to_string());
    }
    if let Some(len) = key_len {
        meta.insert("crypto.key_length".into(), len.to_string());
    }
    if let Some((_, obj)) = dict.get_first(b"/Filter") {
        if let PdfAtom::Name(name) = &obj.atom {
            meta.insert(
                "crypto.filter".into(),
                String::from_utf8_lossy(&name.decoded).to_string(),
            );
        }
    }
    if let Some(algorithm) = classify_encryption_algorithm(version, key_len) {
        meta.insert("crypto.algorithm".into(), algorithm.into());
    }
    meta
}

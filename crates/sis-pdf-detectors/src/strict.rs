use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::PdfAtom;

pub struct StrictParseDeviationDetector;

impl Detector for StrictParseDeviationDetector {
    fn id(&self) -> &'static str {
        "strict_parse_deviation"
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
        let mut findings = Vec::new();
        if !ctx.bytes.starts_with(b"%PDF-") {
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "missing_pdf_header".into(),
                severity: Severity::Low,
                confidence: Confidence::Probable,
                title: "Missing PDF header".into(),
                description: "PDF header not found at start of file.".into(),
                objects: vec!["header".into()],
                evidence: vec![sis_pdf_core::model::EvidenceSpan {
                    source: sis_pdf_core::model::EvidenceSource::File,
                    offset: 0,
                    length: 8.min(ctx.bytes.len() as u32),
                    origin: None,
                    note: Some("File start".into()),
                }],
                remediation: Some("Verify file type and parser tolerance.".into()),
                meta: Default::default(),
                yara: None,
            });
        }
        let tail = if ctx.bytes.len() > 1024 {
            &ctx.bytes[ctx.bytes.len() - 1024..]
        } else {
            ctx.bytes
        };
        if !tail.windows(5).any(|w| w == b"%%EOF") {
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "missing_eof_marker".into(),
                severity: Severity::Low,
                confidence: Confidence::Probable,
                title: "Missing EOF marker".into(),
                description: "EOF marker not found near end of file.".into(),
                objects: vec!["eof".into()],
                evidence: vec![sis_pdf_core::model::EvidenceSpan {
                    source: sis_pdf_core::model::EvidenceSource::File,
                    offset: ctx.bytes.len().saturating_sub(1024) as u64,
                    length: tail.len().min(u32::MAX as usize) as u32,
                    origin: None,
                    note: Some("File tail".into()),
                }],
                remediation: Some("Check for truncated or malformed file.".into()),
                meta: Default::default(),
                yara: None,
            });
        }
        for entry in &ctx.graph.objects {
            if let PdfAtom::Stream(st) = &entry.atom {
                if let Some((_, len_obj)) = st.dict.get_first(b"/Length") {
                    if let PdfAtom::Int(i) = len_obj.atom {
                        let declared = i.max(0) as u64;
                        let actual = st.data_span.len();
                        if declared != actual {
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "stream_length_mismatch".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::Probable,
                                title: "Stream length mismatch".into(),
                                description: format!(
                                    "Stream length mismatch: declared {} bytes, actual {} bytes.",
                                    declared, actual
                                ),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: vec![span_to_evidence(st.data_span, "Stream data span")],
                                remediation: Some(
                                    "Inspect stream boundaries and filters for tampering.".into(),
                                ),
                                meta: Default::default(),
                                yara: None,
                            });
                        }
                    }
                }
            }
        }
        if ctx.options.strict {
            for dev in &ctx.graph.deviations {
                let mut description = format!("Strict parser recorded a deviation: {}.", dev.kind);
                if let Some(note) = &dev.note {
                    description.push_str(&format!(" {}", note));
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "strict_parse_deviation".into(),
                    severity: deviation_severity(&dev.kind),
                    confidence: Confidence::Probable,
                    title: format!("Strict parser deviation: {}", dev.kind),
                    description,
                    objects: vec!["parser".into()],
                    evidence: vec![span_to_evidence(dev.span, "Parser deviation")],
                    remediation: Some("Inspect malformed tokens or truncated objects.".into()),
                    meta: Default::default(),
                    yara: None,
                });
            }
        }
        Ok(findings)
    }
}

fn deviation_severity(kind: &str) -> Severity {
    match kind {
        "missing_endobj"
        | "missing_endstream"
        | "invalid_number"
        | "truncated_stream_data" => Severity::Medium,
        _ => Severity::Low,
    }
}

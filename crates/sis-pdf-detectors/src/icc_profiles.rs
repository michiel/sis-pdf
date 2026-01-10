use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfStream};

use crate::entry_dict;

pub struct ICCProfileDetector;

impl Detector for ICCProfileDetector {
    fn id(&self) -> &'static str {
        "icc_profile"
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
            let Some(dict) = entry_dict(entry) else { continue };
            for (_, obj) in &dict.entries {
                if let Some(stream) = icc_stream(ctx, obj) {
                    let raw_len = stream.data_span.len() as usize;
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("icc.raw_len".into(), raw_len.to_string());
                    let evidence = vec![span_to_evidence(stream.data_span, "ICC profile")];
                    if raw_len > 1024 * 1024 {
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "icc_profile_oversized".into(),
                            severity: Severity::Medium,
                            confidence: Confidence::Probable,
                            title: "Oversized ICC profile".into(),
                            description: "ICC profile stream exceeds expected size bounds.".into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: evidence.clone(),
                            remediation: Some("Inspect ICC profile contents for anomalies.".into()),
                            meta: meta.clone(),
                            yara: None,
        position: None,
        positions: Vec::new(),
                        });
                    }
                    if let Some(issue) = icc_header_issue(ctx.bytes, &stream) {
                        meta.insert("icc.header_issue".into(), issue.clone());
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "icc_profile_anomaly".into(),
                            severity: Severity::Medium,
                            confidence: Confidence::Probable,
                            title: "ICC profile header anomaly".into(),
                            description: issue,
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence,
                            remediation: Some("Validate ICC profile header and declared size.".into()),
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

fn icc_stream<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext<'a>,
    obj: &'a sis_pdf_pdf::object::PdfObj<'a>,
) -> Option<PdfStream<'a>> {
    match &obj.atom {
        PdfAtom::Array(arr) => {
            if arr.len() >= 2 {
                if let PdfAtom::Name(name) = &arr[0].atom {
                    if name.decoded.eq_ignore_ascii_case(b"/ICCBased") {
                        return resolve_stream(ctx, &arr[1]);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn resolve_stream<'a>(
    ctx: &'a sis_pdf_core::scan::ScanContext<'a>,
    obj: &'a sis_pdf_pdf::object::PdfObj<'a>,
) -> Option<PdfStream<'a>> {
    match &obj.atom {
        PdfAtom::Stream(st) => Some(st.clone()),
        PdfAtom::Ref { .. } => ctx.graph.resolve_ref(obj).and_then(|e| match &e.atom {
            PdfAtom::Stream(st) => Some(st.clone()),
            _ => None,
        }),
        _ => None,
    }
}

fn icc_header_issue(bytes: &[u8], st: &PdfStream<'_>) -> Option<String> {
    let start = st.data_span.start as usize;
    let end = st.data_span.end.min(bytes.len() as u64) as usize;
    if start + 128 > end {
        return Some("ICC profile header too short".into());
    }
    let slice = &bytes[start..end];
    if slice.len() < 128 {
        return Some("ICC profile header missing".into());
    }
    let declared = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
    if declared > 0 && declared > slice.len() {
        return Some("ICC profile size exceeds stream length".into());
    }
    if slice.len() >= 40 {
        let sig = &slice[36..40];
        if sig != b"acsp" {
            return Some("ICC profile signature missing".into());
        }
    }
    None
}

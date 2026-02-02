use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::decode::stream_filters;
use sis_pdf_pdf::object::{PdfAtom, PdfDict};

pub struct ObjStmSummaryDetector;

impl Detector for ObjStmSummaryDetector {
    fn id(&self) -> &'static str {
        "objstm_embedded_summary"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::ObjectStreams
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
            let st = match &entry.atom {
                PdfAtom::Stream(st) => st,
                _ => continue,
            };
            if !st.dict.has_name(b"/Type", b"/ObjStm") {
                continue;
            }
            let Some(n) = dict_int(&st.dict, b"/N") else {
                continue;
            };
            let Some(first) = dict_int(&st.dict, b"/First") else {
                continue;
            };
            let mut meta = std::collections::HashMap::new();
            meta.insert("objstm.n".into(), n.to_string());
            meta.insert("objstm.first".into(), first.to_string());
            let filters = stream_filters(&st.dict);
            if !filters.is_empty() {
                meta.insert("filters.count".into(), filters.len().to_string());
                meta.insert("filters.list".into(), filters.join(", "));
            }

            let mut severity = Severity::Info;
            let mut confidence = Confidence::Probable;
            let description;
            if let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, st) {
                if decoded.data.len() <= first as usize {
                    severity = Severity::Medium;
                    description = format!(
                        "Decoded ObjStm bytes ({}) shorter than /First ({}) — malformed or unsupported filters.",
                        decoded.data.len(),
                        first
                    );
                    meta.insert("objstm.decoded_len".into(), decoded.data.len().to_string());
                    meta.insert("objstm.table_truncated".into(), "true".into());
                } else {
                    let header = &decoded.data[..first as usize];
                    let tokens = parse_header_tokens(header, n as usize * 2);
                    let parsed = tokens.len() / 2;
                    meta.insert("objstm.parsed_entries".into(), parsed.to_string());
                    if tokens.len() < n as usize * 2 {
                        severity = Severity::Low;
                        description = format!(
                            "ObjStm header table truncated: parsed {} entries of declared {}.",
                            parsed, n
                        );
                        meta.insert("objstm.table_truncated".into(), "true".into());
                    } else {
                        description = format!(
                            "ObjStm declares {} embedded objects; parsed {} header entries.",
                            n, parsed
                        );
                    }
                }
            } else {
                severity = Severity::Low;
                confidence = Confidence::Heuristic;
                description =
                    "ObjStm stream could not be decoded; filters unsupported or budget exceeded."
                        .into();
                meta.insert("objstm.decode_failed".into(), "true".into());
            }

            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "objstm_embedded_summary".into(),
                severity,
                confidence,
                title: "ObjStm embedded object summary".into(),
                description,
                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                evidence: vec![span_to_evidence(st.dict.span, "ObjStm dict")],
                remediation: Some("Inspect embedded objects in deep scans.".into()),
                meta,
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }
        Ok(findings)
    }
}

fn dict_int(dict: &PdfDict<'_>, key: &[u8]) -> Option<u64> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Int(i) if *i >= 0 => Some(*i as u64),
        _ => None,
    }
}

fn parse_header_tokens(bytes: &[u8], max: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() && out.len() < max {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if start == i {
            break;
        }
        if let Ok(v) = std::str::from_utf8(&bytes[start..i]) {
            if let Ok(num) = v.parse::<u64>() {
                out.push(num);
            }
        }
    }
    out
}

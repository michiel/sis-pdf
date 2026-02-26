use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::decode::stream_filters;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfStream};
use sis_pdf_pdf::span::Span;

pub struct ObjStmTortureDetector;

const OBJSTM_TORTURE_THRESHOLD: usize = 8;
const FILTER_SUSPECT_THRESHOLD: usize = 3;

impl Detector for ObjStmTortureDetector {
    fn id(&self) -> &'static str {
        "objstm_torture"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::ObjectStreams
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH | Needs::STREAM_DECODE
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut objstm_count = 0;
        let mut header_mismatches = 0;
        let mut filter_issues = 0;
        let mut total_filters = 0;

        let mut first_span: Option<Span> = None;
        for entry in &ctx.graph.objects {
            let st = match &entry.atom {
                PdfAtom::Stream(st) => st,
                _ => continue,
            };
            if !st.dict.has_name(b"/Type", b"/ObjStm") {
                continue;
            }
            if first_span.is_none() {
                first_span = Some(entry.full_span);
            }
            objstm_count += 1;
            let filters = stream_filters(&st.dict);
            total_filters += filters.len();
            if !filters.is_empty() && filters.len() > FILTER_SUSPECT_THRESHOLD {
                filter_issues += 1;
            }
            if let Some(mismatch) = analyze_objstm_header(ctx, st) {
                if mismatch {
                    header_mismatches += 1;
                }
            }
        }

        if objstm_count >= OBJSTM_TORTURE_THRESHOLD || header_mismatches > 0 || filter_issues > 0 {
            let mut meta = HashMap::new();
            meta.insert("objstm.count".into(), objstm_count.to_string());
            meta.insert("objstm.header_mismatches".into(), header_mismatches.to_string());
            meta.insert("objstm.filter_issues".into(), filter_issues.to_string());
            meta.insert("objstm.total_filters".into(), total_filters.to_string());

            let severity = if objstm_count >= OBJSTM_TORTURE_THRESHOLD || header_mismatches >= 2 {
                Severity::Medium
            } else {
                Severity::Low
            };

            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "objstm.torture".into(),
                severity,
                confidence: Confidence::Probable,
                impact: Impact::Medium,
                title: "ObjStm torture detected".into(),
                description: "Document contains an unusually large number of object streams with mismatched headers or suspicious filters."
                    .into(),
                objects: vec!["objstm".into()],
                evidence: vec![span_to_evidence(
                    first_span.unwrap_or_else(|| Span { start: 0, end: 0 }),
                    "ObjStm overview",
                )],
                remediation: Some("Review ObjStm chains for tampering or obfuscation.".into()),
                meta,
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                positions: Vec::new(),
            });
        }

        Ok(findings)
    }
}

fn analyze_objstm_header(
    ctx: &sis_pdf_core::scan::ScanContext,
    stream: &PdfStream<'_>,
) -> Option<bool> {
    let dict = &stream.dict;
    let n = dict_int(dict, b"/N")?;
    let first = dict_int(dict, b"/First")?;
    if let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, stream) {
        if decoded.data.len() <= first as usize {
            return Some(false);
        }
        let header = &decoded.data[..first as usize];
        let tokens = parse_header_tokens(header, (n * 2) as usize);
        let parsed = tokens.len() / 2;
        return Some(parsed != n as usize);
    }
    Some(false)
}

fn dict_int(dict: &PdfDict<'_>, key: &[u8]) -> Option<u64> {
    let (_, obj) = dict.get_first(key)?;
    match &obj.atom {
        PdfAtom::Int(i) if *i >= 0 => Some(*i as u64),
        _ => None,
    }
}

fn parse_header_tokens(bytes: &[u8], max: usize) -> Vec<usize> {
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
            if let Ok(num) = v.parse::<usize>() {
                out.push(num);
            }
        }
    }
    out
}

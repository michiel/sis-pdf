use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::PdfAtom;
use std::collections::BTreeMap;
use tracing::warn;

use crate::{js_payload_candidates_from_entry, JsPayloadSource};

pub struct StrictParseDeviationDetector;

const DEVIATION_CLUSTER_THRESHOLD: usize = 50;

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
        let header_offset = find_first(ctx.bytes, b"%PDF-");
        if header_offset.is_none() || !ctx.bytes.starts_with(b"%PDF-") {
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "missing_pdf_header".into(),
                severity: Severity::Low,
                confidence: Confidence::Probable,
                impact: None,
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

                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        }
        if let Some(off) = header_offset {
            if off > 0 {
                let mut meta = std::collections::HashMap::new();
                meta.insert("header.offset".into(), off.to_string());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "header_offset_unusual".into(),
                    severity: if off > 1024 {
                        Severity::Medium
                    } else {
                        Severity::Low
                    },
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "PDF header offset unusual".into(),
                    description: format!(
                        "PDF header found at offset {} (expected at start of file).",
                        off
                    ),
                    objects: vec!["header".into()],
                    evidence: vec![sis_pdf_core::model::EvidenceSpan {
                        source: sis_pdf_core::model::EvidenceSource::File,
                        offset: off as u64,
                        length: 5,
                        origin: None,
                        note: Some("PDF header".into()),
                    }],
                    remediation: Some("Inspect for polyglot or header-tolerant evasion.".into()),
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
        let tail = if ctx.bytes.len() > 1024 {
            &ctx.bytes[ctx.bytes.len() - 1024..]
        } else {
            ctx.bytes
        };
        let eof_offset = find_last(ctx.bytes, b"%%EOF");
        if eof_offset.is_none() {
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "missing_eof_marker".into(),
                severity: Severity::Low,
                confidence: Confidence::Strong, // Upgraded: %%EOF presence is definitive check
                impact: None,
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

                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            });
        } else if let Some(off) = eof_offset {
            let distance = ctx.bytes.len().saturating_sub(off + 5);
            if distance > 1024 {
                let mut meta = std::collections::HashMap::new();
                meta.insert("eof.offset".into(), off.to_string());
                meta.insert("eof.distance_to_end".into(), distance.to_string());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "eof_offset_unusual".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "EOF marker far from file end".into(),
                    description: format!(
                        "EOF marker found at offset {}, which is {} bytes from file end.",
                        off, distance
                    ),
                    objects: vec!["eof".into()],
                    evidence: vec![sis_pdf_core::model::EvidenceSpan {
                        source: sis_pdf_core::model::EvidenceSource::File,
                        offset: off as u64,
                        length: 5,
                        origin: None,
                        note: Some("EOF marker".into()),
                    }],
                    remediation: Some("Inspect for incremental updates or trailing data.".into()),
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
        for entry in &ctx.graph.objects {
            if let PdfAtom::Stream(st) = &entry.atom {
                if let Some((_, len_obj)) = st.dict.get_first(b"/Length") {
                    if let PdfAtom::Int(i) = len_obj.atom {
                        let declared = i.max(0) as u64;
                        let actual = st.data_span.len();
                        if declared != actual {
                            let tolerance = (declared as i64 - actual as i64).unsigned_abs();
                            let mut meta = std::collections::HashMap::new();
                            meta.insert("stream.declared_length".into(), declared.to_string());
                            meta.insert("stream.actual_length".into(), actual.to_string());
                            meta.insert("stream.tolerance".into(), tolerance.to_string());

                            // ±10 bytes is common due to whitespace differences
                            let (severity, description) = if tolerance <= 10 {
                                (
                                    Severity::Low,
                                    format!(
                                        "Stream length mismatch within tolerance: declared {} bytes, actual {} bytes (diff {}).",
                                        declared, actual, tolerance
                                    )
                                )
                            } else {
                                (
                                    Severity::Medium,
                                    format!(
                                        "Stream length mismatch: declared {} bytes, actual {} bytes (diff {}).",
                                        declared, actual, tolerance
                                    )
                                )
                            };

                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "stream_length_mismatch".into(),
                                severity,
                                confidence: Confidence::Probable,
                                impact: None,
                                title: "Stream length mismatch".into(),
                                description,
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: vec![span_to_evidence(st.data_span, "Stream data span")],
                                remediation: Some(
                                    "Inspect stream boundaries and filters for tampering.".into(),
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
            }
        }
        if ctx.options.strict {
            if ctx.graph.deviations.len() > DEVIATION_CLUSTER_THRESHOLD {
                warn!(
                    security = true,
                    domain = "pdf.parser",
                    kind = "parser_deviation_cluster",
                    deviation_count = ctx.graph.deviations.len(),
                    "Deviation cluster detected"
                );
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "parser_deviation_cluster".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
            impact: None,
                    title: "High deviation count".into(),
                    description: format!(
                        "Strict parser recorded {} deviations, indicating potential parser confusion.",
                        ctx.graph.deviations.len()
                    ),
                    objects: vec!["parser".into()],
                    evidence: Vec::new(),
                    remediation: Some("Treat as evasion attempt; inspect malformed structure.".into()),
                    meta: Default::default(),

            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,                    yara: None,
        position: None,
        positions: Vec::new(),
                });
            }
            let mut action_object = None;
            for entry in &ctx.graph.objects {
                if let Some(dict) = crate::entry_dict(entry) {
                    let has_hidden_js = js_payload_candidates_from_entry(ctx, entry)
                        .iter()
                        .any(|candidate| candidate.source != JsPayloadSource::Action);
                    if has_hidden_js
                        || dict.has_name(b"/S", b"/JavaScript")
                        || dict.get_first(b"/JS").is_some()
                        || dict.get_first(b"/Action").is_some()
                        || dict.get_first(b"/OpenAction").is_some()
                    {
                        action_object = Some(entry);
                        break;
                    }
                }
            }
            if action_object.is_some() && !ctx.graph.deviations.is_empty() {
                warn!(
                    security = true,
                    domain = "pdf.parser",
                    kind = "deviations_in_action_context",
                    deviation_count = ctx.graph.deviations.len(),
                    "Deviations present in JS/Action context"
                );
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "parser_deviation_in_action_context".into(),
                    severity: Severity::High,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "Parser deviations with action context".into(),
                    description:
                        "Parser deviations present alongside JavaScript or Action objects.".into(),
                    objects: vec!["parser".into()],
                    evidence: Vec::new(),
                    remediation: Some(
                        "Validate with alternate parser and inspect action payloads.".into(),
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
            if ctx.options.strict_summary {
                if !ctx.graph.deviations.is_empty() {
                    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
                    for dev in &ctx.graph.deviations {
                        *counts.entry(dev.kind.clone()).or_insert(0) += 1;
                    }
                    let mut top: Vec<(String, usize)> =
                        counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
                    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                    let top_list = top
                        .iter()
                        .take(10)
                        .map(|(k, v)| format!("{}:{}", k, v))
                        .collect::<Vec<_>>();
                    let mut meta = std::collections::HashMap::new();
                    meta.insert(
                        "parser.deviation_total".into(),
                        ctx.graph.deviations.len().to_string(),
                    );
                    meta.insert("parser.deviation_unique".into(), counts.len().to_string());
                    if !top_list.is_empty() {
                        meta.insert("parser.deviation_top".into(), top_list.join(","));
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "strict_parse_deviation_summary".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Heuristic,
                        impact: None,
                        title: "Strict parser deviation summary".into(),
                        description: "Strict parser deviations summarised by kind.".into(),
                        objects: vec!["parser".into()],
                        evidence: Vec::new(),
                        remediation: Some(
                            "Inspect deviation kinds with the highest counts.".into(),
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
            } else {
                for dev in &ctx.graph.deviations {
                    let mut description =
                        format!("Strict parser recorded a deviation: {}.", dev.kind);
                    if let Some(note) = &dev.note {
                        description.push_str(&format!(" {}", note));
                    }
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "strict_parse_deviation".into(),
                        severity: deviation_severity(&dev.kind),
                        confidence: Confidence::Probable,
                        impact: None,
                        title: format!("Strict parser deviation: {}", dev.kind),
                        description,
                        objects: vec!["parser".into()],
                        evidence: vec![span_to_evidence(dev.span, "Parser deviation")],
                        remediation: Some("Inspect malformed tokens or truncated objects.".into()),
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

fn deviation_severity(kind: &str) -> Severity {
    match kind {
        "missing_endobj" | "missing_endstream" | "invalid_number" | "truncated_stream_data" => {
            Severity::Medium
        }
        _ => Severity::Low,
    }
}

fn find_first(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let mut i = haystack.len().saturating_sub(needle.len());
    loop {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    None
}

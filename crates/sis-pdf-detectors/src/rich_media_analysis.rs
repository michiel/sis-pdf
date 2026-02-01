use anyhow::Result;

use std::collections::HashMap;
use std::time::Duration;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::rich_media::{
    analyze_swf, swf_compression_label, swf_magic, SWF_DECODE_TIMEOUT_MS, SWF_DECOMPRESSED_LIMIT,
    SWF_DECOMPRESSION_RATIO_LIMIT,
};
use sis_pdf_core::stream_analysis::{analyse_stream, StreamLimits};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::object::{PdfAtom, PdfDict};

use crate::entry_dict;

pub struct RichMediaContentDetector;

impl Detector for RichMediaContentDetector {
    fn id(&self) -> &'static str {
        "rich_media_content"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::RichMedia3D
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let timeout = TimeoutChecker::new(Duration::from_millis(100));
        let has_rich_media = ctx
            .graph
            .objects
            .iter()
            .any(|entry| entry_dict(entry).map_or(false, |dict| is_rich_media_dict(dict)));
        if !has_rich_media {
            return Ok(findings);
        }
        for entry in &ctx.graph.objects {
            if timeout.check().is_err() {
                break;
            }
            let PdfAtom::Stream(stream) = &entry.atom else {
                continue;
            };
            if let Some(dict) = entry_dict(entry) {
                if !is_rich_media_dict(dict) {
                    continue;
                }
            }
            let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, stream) else {
                continue;
            };
            if !swf_magic(&decoded.data) {
                continue;
            }
            let mut decode_timeout =
                TimeoutChecker::new(Duration::from_millis(SWF_DECODE_TIMEOUT_MS));
            let Some(analysis) = analyze_swf(&decoded.data, &mut decode_timeout) else {
                continue;
            };
            if analysis.decompressed_body_len >= SWF_DECOMPRESSED_LIMIT {
                continue;
            }
            let ratio = analysis.decompressed_body_len as f64 / analysis.compressed_len as f64;
            if ratio > SWF_DECOMPRESSION_RATIO_LIMIT {
                continue;
            }
            let mut meta = HashMap::new();
            insert_stream_analysis_meta(&mut meta, &decoded.data);
            meta.insert(
                "swf.magic".into(),
                String::from_utf8_lossy(&decoded.data[..3]).into(),
            );
            meta.insert("swf.size".into(), decoded.data.len().to_string());
            meta.insert("media_type".into(), "swf".into());
            meta.insert(
                "swf.decompressed_bytes".into(),
                analysis.decompressed_body_len.to_string(),
            );
            meta.insert("swf.decompression_ratio".into(), format!("{:.2}", ratio));
            meta.insert("swf.version".into(), analysis.header.version.to_string());
            meta.insert(
                "swf.declared_length".into(),
                analysis.header.file_length.to_string(),
            );
            meta.insert(
                "swf.compression".into(),
                swf_compression_label(analysis.header.compression).to_string(),
            );
            if let Some(rate) = analysis.header.frame_rate {
                meta.insert("swf.frame_rate".into(), format!("{:.2}", rate));
            }
            if let Some(count) = analysis.header.frame_count {
                meta.insert("swf.frame_count".into(), count.to_string());
            }
            let evidence = EvidenceBuilder::new()
                .file_offset(
                    stream.dict.span.start,
                    stream.dict.span.len() as u32,
                    "RichMedia dict",
                )
                .file_offset(
                    stream.data_span.start,
                    stream.data_span.len() as u32,
                    "RichMedia stream",
                )
                .build();
            let action_evidence = evidence.clone();
            findings.push(Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "swf_embedded".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                impact: None,
                title: "SWF content embedded".into(),
                description: "Stream data matches SWF magic header.".into(),
                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                evidence: evidence.clone(),
                remediation: Some("Extract and inspect the SWF payload.".into()),
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
            if !analysis.action_scan.action_tags.is_empty() {
                let mut action_meta = meta.clone();
                action_meta.insert(
                    "swf.action_tag_count".into(),
                    analysis.action_scan.action_tags.len().to_string(),
                );
                action_meta.insert(
                    "swf.tags_scanned".into(),
                    analysis.action_scan.tags_scanned.to_string(),
                );
                action_meta.insert(
                    "swf.action_tags".into(),
                    encode_list(&analysis.action_scan.action_tags),
                );
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "swf_actionscript_detected".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "SWF ActionScript tags detected".into(),
                    description:
                        "SWF stream contains ActionScript tags (DoAction/DoInitAction/DoABC)."
                            .into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: action_evidence,
                    remediation: Some("Review the ActionScript tags for malicious logic.".into()),
                    meta: action_meta,

                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                    ..Finding::default()
                });
            }
        }
        Ok(findings)
    }
}

fn insert_stream_analysis_meta(meta: &mut HashMap<String, String>, data: &[u8]) {
    let analysis = analyse_stream(data, &StreamLimits::default());
    meta.insert("stream.magic_type".into(), analysis.magic_type);
    meta.insert("stream.entropy".into(), format!("{:.2}", analysis.entropy));
    meta.insert("stream.blake3".into(), analysis.blake3);
    meta.insert("size_bytes".into(), analysis.size_bytes.to_string());
}

fn is_rich_media_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Type", b"/RichMedia")
        || dict.has_name(b"/Subtype", b"/RichMedia")
        || dict.has_name(b"/Subtype", b"/Flash")
        || dict.get_first(b"/RichMedia").is_some()
}

fn encode_list(values: &[String]) -> String {
    let escaped: Vec<String> = values
        .iter()
        .map(|value| {
            format!(
                "\"{}\"",
                value
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', " ")
                    .replace('\r', " ")
            )
        })
        .collect();
    format!("[{}]", escaped.join(","))
}

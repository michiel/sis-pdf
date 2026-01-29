use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::object::PdfAtom;
use sis_pdf_pdf::swf::{parse_swf_header, SwfCompression};

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
        Cost::Cheap
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let timeout = TimeoutChecker::new(std::time::Duration::from_millis(100));
        for entry in &ctx.graph.objects {
            if timeout.check().is_err() {
                break;
            }
            let PdfAtom::Stream(stream) = &entry.atom else {
                continue;
            };
            if let Some(dict) = entry_dict(entry) {
                if !dict.has_name(b"/Type", b"/RichMedia")
                    && !dict.has_name(b"/Subtype", b"/RichMedia")
                    && !dict.has_name(b"/Subtype", b"/Flash")
                    && dict.get_first(b"/RichMedia").is_none()
                {
                    continue;
                }
            }
            let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, stream) else {
                continue;
            };
            if swf_magic(&decoded.data) {
                let mut meta = std::collections::HashMap::new();
                meta.insert(
                    "swf.magic".into(),
                    String::from_utf8_lossy(&decoded.data[..3]).into(),
                );
                meta.insert("swf.size".into(), decoded.data.len().to_string());
                if let Some(header) = parse_swf_header(&decoded.data) {
                    meta.insert("swf.version".into(), header.version.to_string());
                    meta.insert("swf.declared_length".into(), header.file_length.to_string());
                    meta.insert(
                        "swf.compression".into(),
                        swf_compression_label(header.compression),
                    );
                    if let Some(rate) = header.frame_rate {
                        meta.insert("swf.frame_rate".into(), format!("{:.2}", rate));
                    }
                    if let Some(count) = header.frame_count {
                        meta.insert("swf.frame_count".into(), count.to_string());
                    }
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
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "swf_embedded".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "SWF content embedded".into(),
                    description: "Stream data matches SWF magic header.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence,
                    remediation: Some("Extract and inspect the SWF payload.".into()),
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

fn swf_magic(data: &[u8]) -> bool {
    matches!(data.get(0..3), Some(b"FWS") | Some(b"CWS") | Some(b"ZWS"))
}

fn swf_compression_label(compression: SwfCompression) -> String {
    match compression {
        SwfCompression::None => "none",
        SwfCompression::Zlib => "zlib",
        SwfCompression::Lzma => "lzma",
    }
    .to_string()
}

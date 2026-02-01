use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{
    AttackSurface, Confidence, EvidenceSource, EvidenceSpan, Finding, Severity,
};

pub struct PolyglotDetector;

impl Detector for PolyglotDetector {
    fn id(&self) -> &'static str {
        "polyglot_signature_conflict"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::FileStructure
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Cheap
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let summary = analyze_polyglot_signatures(ctx.bytes);
        if summary.pdf_header_offset.is_none() {
            return Ok(Vec::new());
        }
        if summary.hits.is_empty() {
            return Ok(Vec::new());
        }

        let pdf_offset = summary.pdf_header_offset.unwrap_or(0);
        let pdf_at_zero = summary.pdf_header_at_zero;

        let non_pdf_at_zero = summary.hits.iter().any(|h| h.offset == 0);
        let strong_conflict = non_pdf_at_zero && pdf_offset > 0;

        let severity = if strong_conflict {
            Severity::Medium
        } else {
            Severity::Low
        };
        let confidence = if strong_conflict {
            Confidence::Probable
        } else {
            Confidence::Heuristic
        };

        let mut evidence = Vec::new();
        evidence.push(EvidenceSpan {
            source: EvidenceSource::File,
            offset: pdf_offset as u64,
            length: 5,
            origin: None,
            note: Some("PDF header".into()),
        });
        for hit in summary.hits.iter().take(8) {
            evidence.push(EvidenceSpan {
                source: EvidenceSource::File,
                offset: hit.offset as u64,
                length: hit.length as u32,
                origin: None,
                note: Some(format!("Magic {}", hit.label)),
            });
        }

        let sig_list = summary
            .hits
            .iter()
            .take(12)
            .map(|h| format!("{}@{}", h.label, h.offset))
            .collect::<Vec<_>>()
            .join(", ");
        let mut meta = std::collections::HashMap::new();
        meta.insert("polyglot.pdf_header_offset".into(), pdf_offset.to_string());
        meta.insert(
            "polyglot.pdf_header_at_zero".into(),
            pdf_at_zero.to_string(),
        );
        meta.insert("polyglot.signatures".into(), sig_list.clone());

        Ok(vec![Finding {
            id: String::new(),
            surface: self.surface(),
            kind: "polyglot_signature_conflict".into(),
            severity,
            confidence,
            title: "Polyglot signature conflict".into(),
            description: format!(
                "Detected conflicting magic signatures with PDF header at offset {}. Signatures: {}.",
                pdf_offset, sig_list
            ),
            objects: vec!["file_header".into()],
            evidence,
            remediation: Some(
                "Validate file type by content and block mixed-format files in the PDF pipeline."
                    .into(),
            ),
            meta,
            yara: None,
            position: None,
            positions: Vec::new(),
        ..Finding::default()
        }])
    }
}

#[derive(Debug, Clone)]
pub struct PolyglotMagicHit {
    pub label: &'static str,
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone)]
pub struct PolyglotSignatureSummary {
    pub hits: Vec<PolyglotMagicHit>,
    pub pdf_header_offset: Option<usize>,
    pub pdf_header_at_zero: bool,
}

pub fn analyze_polyglot_signatures(bytes: &[u8]) -> PolyglotSignatureSummary {
    if bytes.is_empty() {
        return PolyglotSignatureSummary {
            hits: Vec::new(),
            pdf_header_offset: None,
            pdf_header_at_zero: false,
        };
    }

    let head_len = 4096.min(bytes.len());
    let tail_len = 4096.min(bytes.len());
    let head = &bytes[..head_len];
    let tail = &bytes[bytes.len().saturating_sub(tail_len)..];

    let pdf_offsets = find_all(head, b"%PDF-");
    let pdf_offset = pdf_offsets.first().copied();
    let pdf_at_zero = matches!(pdf_offset, Some(0));

    let mut hits = Vec::new();
    let sigs = magic_signatures();
    for sig in sigs {
        if sig.offset_zero {
            if bytes.starts_with(sig.bytes) {
                hits.push(MagicHit::new(sig.label, 0, sig.bytes.len(), "offset0"));
            }
            continue;
        }
        for off in find_all(head, sig.bytes) {
            hits.push(MagicHit::new(sig.label, off, sig.bytes.len(), "head"));
        }
        for off in find_all(tail, sig.bytes) {
            let abs = bytes.len().saturating_sub(tail.len()).saturating_add(off);
            hits.push(MagicHit::new(sig.label, abs, sig.bytes.len(), "tail"));
        }
        if sig.case_insensitive {
            for off in find_all_ascii_case_insensitive(head, sig.bytes) {
                hits.push(MagicHit::new(sig.label, off, sig.bytes.len(), "head-ci"));
            }
            for off in find_all_ascii_case_insensitive(tail, sig.bytes) {
                let abs = bytes.len().saturating_sub(tail.len()).saturating_add(off);
                hits.push(MagicHit::new(sig.label, abs, sig.bytes.len(), "tail-ci"));
            }
        }
    }

    hits.retain(|h| !h.label.eq_ignore_ascii_case("PDF"));
    hits.sort_by(|a, b| (a.offset, a.label).cmp(&(b.offset, b.label)));
    hits.dedup_by(|a, b| a.offset == b.offset && a.label == b.label);

    let hits = hits
        .into_iter()
        .map(|hit| PolyglotMagicHit {
            label: hit.label,
            offset: hit.offset,
            length: hit.length,
        })
        .collect::<Vec<_>>();

    PolyglotSignatureSummary {
        hits,
        pdf_header_offset: pdf_offset,
        pdf_header_at_zero: pdf_at_zero,
    }
}

struct MagicSig {
    label: &'static str,
    bytes: &'static [u8],
    offset_zero: bool,
    case_insensitive: bool,
}

struct MagicHit {
    label: &'static str,
    offset: usize,
    length: usize,
    _region: &'static str,
}

impl MagicHit {
    fn new(label: &'static str, offset: usize, length: usize, region: &'static str) -> Self {
        Self {
            label,
            offset,
            length,
            _region: region,
        }
    }
}

fn magic_signatures() -> Vec<MagicSig> {
    vec![
        MagicSig {
            label: "PNG",
            bytes: b"\x89PNG\r\n\x1a\n",
            offset_zero: true,
            case_insensitive: false,
        },
        MagicSig {
            label: "JPG",
            bytes: b"\xFF\xD8\xFF",
            offset_zero: true,
            case_insensitive: false,
        },
        MagicSig {
            label: "GIF",
            bytes: b"GIF87a",
            offset_zero: true,
            case_insensitive: false,
        },
        MagicSig {
            label: "GIF",
            bytes: b"GIF89a",
            offset_zero: true,
            case_insensitive: false,
        },
        MagicSig {
            label: "ZIP",
            bytes: b"PK\x03\x04",
            offset_zero: false,
            case_insensitive: false,
        },
        MagicSig {
            label: "ZIP",
            bytes: b"PK\x05\x06",
            offset_zero: false,
            case_insensitive: false,
        },
        MagicSig {
            label: "ZIP",
            bytes: b"PK\x07\x08",
            offset_zero: false,
            case_insensitive: false,
        },
        MagicSig {
            label: "MZ",
            bytes: b"MZ",
            offset_zero: true,
            case_insensitive: false,
        },
        MagicSig {
            label: "HTML",
            bytes: b"<!doctype html",
            offset_zero: false,
            case_insensitive: true,
        },
        MagicSig {
            label: "HTML",
            bytes: b"<html",
            offset_zero: false,
            case_insensitive: true,
        },
        MagicSig {
            label: "HTA",
            bytes: b"<hta:application",
            offset_zero: false,
            case_insensitive: true,
        },
    ]
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
            i += needle.len();
        } else {
            i += 1;
        }
    }
    out
}

fn find_all_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let needle_lower: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
    let mut i = 0usize;
    while i + needle_lower.len() <= haystack.len() {
        let mut matched = true;
        for (j, nb) in needle_lower.iter().enumerate() {
            if haystack[i + j].to_ascii_lowercase() != *nb {
                matched = false;
                break;
            }
        }
        if matched {
            out.push(i);
            i += needle_lower.len();
        } else {
            i += 1;
        }
    }
    out
}

use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::canonical::canonical_filter_chain;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::filter_allowlist::default_filter_allowlist;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::object::PdfAtom;

pub struct FilterChainAnomalyDetector;

impl Detector for FilterChainAnomalyDetector {
    fn id(&self) -> &'static str {
        "filter_chain_anomaly"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::StreamsAndFilters
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
        let allowlist = ctx
            .options
            .filter_allowlist
            .as_ref()
            .cloned()
            .unwrap_or_else(default_filter_allowlist);
        let strict = ctx.options.filter_allowlist_strict;
        for &idx in &ctx.canonical_view().indices {
            let entry = &ctx.graph.objects[idx];
            if timeout.check().is_err() {
                break;
            }
            let PdfAtom::Stream(stream) = &entry.atom else {
                continue;
            };
            let normalised = canonical_filter_chain(stream);
            if normalised.is_empty() {
                continue;
            }
            let allowlist_match = is_allowlisted_chain(&normalised, &allowlist);
            let image_with_compression = has_image_with_compression(&normalised);
            let mut meta = std::collections::HashMap::new();
            meta.insert("stream.filter_chain".into(), normalised.join(" -> "));
            meta.insert("stream.filter_depth".into(), normalised.len().to_string());
            meta.insert("filters".into(), format_filter_list(&normalised));
            meta.insert("filter_count".into(), normalised.len().to_string());
            meta.insert("allowlist_match".into(), allowlist_match.to_string());
            let evidence = EvidenceBuilder::new()
                .file_offset(
                    stream.dict.span.start,
                    stream.dict.span.len() as u32,
                    "Stream dict",
                )
                .build();

            if let Some(violation) =
                unusual_violation(allowlist_match, &normalised, strict, image_with_compression)
            {
                let mut meta = meta.clone();
                meta.insert("violation_type".into(), violation.to_string());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "filter_chain_unusual".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "Unusual filter chain".into(),
                    description: "Filter chain uses uncommon or unexpected combinations.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: evidence.clone(),
                    remediation: Some("Inspect stream decoding for obfuscation.".into()),
                    meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                    ..Finding::default()
                });
            }

            if let Some(violation) = invalid_order_reason(&normalised) {
                let mut meta = meta.clone();
                meta.insert("violation_type".into(), violation.to_string());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "filter_order_invalid".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "Invalid filter order".into(),
                    description: "Filter order violates PDF decoding rules.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: evidence.clone(),
                    remediation: Some("Review filter order for obfuscation.".into()),
                    meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                    ..Finding::default()
                });
            }

            if has_duplicate_filters(&normalised) {
                let mut meta = meta.clone();
                meta.insert("violation_type".into(), "duplicate_filters".to_string());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "filter_combination_unusual".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Probable,
                    impact: None,
                    title: "Repeated filters in chain".into(),
                    description: "Filter chain repeats the same filter multiple times.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: evidence.clone(),
                    remediation: Some("Inspect for redundant or obfuscated decoding.".into()),
                    meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                    ..Finding::default()
                });
            }
            if is_jbig2_obfuscation(&normalised) {
                let mut meta = meta.clone();
                meta.insert("violation_type".into(), "jbig2_obfuscation".to_string());
                meta.insert("jbig2.cves".into(), "CVE-2021-30860,CVE-2022-38171".into());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "filter_chain_jbig2_obfuscation".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
            impact: None,
                    title: "JBIG2 filter chain obfuscation".into(),
                    description: "JBIG2 payloads wrapped with ASCII/Flate layers match known CVE obfuscations.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: evidence.clone(),
                    remediation: Some("Decode payloads carefully to expose JBIG2 segments.".into()),
                    meta,
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

fn unusual_violation(
    allowlist_match: bool,
    filters: &[String],
    strict: bool,
    image_with_compression: bool,
) -> Option<&'static str> {
    if strict && !filters.is_empty() {
        return Some("strict_mode");
    }
    if has_unknown_filter(filters) {
        return Some("unknown_filter");
    }
    if image_with_compression {
        return Some("image_with_compression");
    }
    if !allowlist_match {
        return Some("allowlist_miss");
    }
    None
}

fn invalid_order_reason(filters: &[String]) -> Option<&'static str> {
    for (idx, f) in filters.iter().enumerate() {
        if is_ascii_filter(f) && idx != 0 {
            return Some("ascii_after_binary");
        }
    }
    for (idx, f) in filters.iter().enumerate() {
        if f == "Crypt" && idx != 0 {
            return Some("crypt_not_outermost");
        }
    }
    None
}

fn has_duplicate_filters(filters: &[String]) -> bool {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in filters {
        *counts.entry(f.as_str()).or_insert(0) += 1;
    }
    counts.values().any(|v| *v > 1)
}

fn is_ascii_filter(filter: &str) -> bool {
    matches!(filter, "ASCIIHEXDECODE" | "ASCII85DECODE")
}

fn format_filter_list(filters: &[String]) -> String {
    let mut out = String::from("[");
    for (idx, filter) in filters.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push('"');
        out.push_str(filter);
        out.push('"');
    }
    out.push(']');
    out
}

fn is_jbig2_obfuscation(filters: &[String]) -> bool {
    filters.iter().any(|f| f == "JBIG2DECODE") && filters.iter().any(|f| is_ascii_filter(f))
}

const KNOWN_FILTERS: &[&str] = &[
    "FlateDecode",
    "DCTDecode",
    "JPXDecode",
    "LZWDecode",
    "ASCII85Decode",
    "ASCIIHexDecode",
    "RunLengthDecode",
    "CCITTFaxDecode",
    "JBIG2Decode",
    "Crypt",
];

fn is_allowlisted_chain(filters: &[String], allowlist: &[Vec<String>]) -> bool {
    if filters.is_empty() {
        return true;
    }
    if filters.iter().any(|f| !KNOWN_FILTERS.contains(&f.as_str())) {
        return false;
    }
    allowlist.iter().any(|allowed| {
        if allowed.len() != filters.len() {
            return false;
        }
        allowed
            .iter()
            .zip(filters.iter())
            .all(|(a, f)| *a == f.as_str())
    })
}

fn has_unknown_filter(filters: &[String]) -> bool {
    filters.iter().any(|f| !KNOWN_FILTERS.contains(&f.as_str()))
}

fn has_image_with_compression(filters: &[String]) -> bool {
    let has_image = filters.iter().any(|f| IMAGE_FILTERS.contains(&f.as_str()));
    let has_compression = filters
        .iter()
        .any(|f| COMPRESSION_FILTERS.contains(&f.as_str()));
    has_image && has_compression
}

const IMAGE_FILTERS: &[&str] = &["DCTDecode", "JPXDecode", "JBIG2Decode", "CCITTFaxDecode"];
const COMPRESSION_FILTERS: &[&str] = &["FlateDecode", "LZWDecode", "RunLengthDecode"];

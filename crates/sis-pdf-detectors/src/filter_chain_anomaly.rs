use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::canonical::canonical_filter_chain;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::evidence::EvidenceBuilder;
use sis_pdf_core::filter_allowlist::default_filter_allowlist;
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, FindingBuilder, Impact, Severity};
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
            let mut meta: HashMap<String, String> = std::collections::HashMap::new();
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
                let violation_meta = {
                    let mut dup = meta.clone();
                    dup.insert("violation_type".into(), violation.to_string());
                    dup
                };
                findings.push(
                    FindingBuilder::template(
                        self.surface(),
                        "filter_chain_unusual",
                        Severity::Low,
                        Confidence::Probable,
                        "Unusual filter chain",
                        "Filter chain uses uncommon or unexpected combinations.",
                    )
                    .objects(vec![format!("{} {} obj", entry.obj, entry.gen)])
                    .evidence(evidence.clone())
                    .remediation("Inspect stream decoding for obfuscation.")
                    .extend_meta(violation_meta.into_iter())
                    .build(),
                );
            }

            if let Some(violation) = invalid_order_reason(&normalised) {
                let violation_meta = {
                    let mut dup = meta.clone();
                    dup.insert("violation_type".into(), violation.to_string());
                    dup
                };
                findings.push(
                    FindingBuilder::template(
                        self.surface(),
                        "filter_order_invalid",
                        Severity::Medium,
                        Confidence::Probable,
                        "Invalid filter order",
                        "Filter order violates PDF decoding rules.",
                    )
                    .objects(vec![format!("{} {} obj", entry.obj, entry.gen)])
                    .evidence(evidence.clone())
                    .remediation("Review filter order for obfuscation.")
                    .extend_meta(violation_meta.into_iter())
                    .build(),
                );
            }

            if has_duplicate_filters(&normalised) {
                let violation_meta = {
                    let mut dup = meta.clone();
                    dup.insert("violation_type".into(), "duplicate_filters".to_string());
                    dup
                };
                findings.push(
                    FindingBuilder::template(
                        self.surface(),
                        "filter_combination_unusual",
                        Severity::Low,
                        Confidence::Probable,
                        "Repeated filters in chain",
                        "Filter chain repeats the same filter multiple times.",
                    )
                    .objects(vec![format!("{} {} obj", entry.obj, entry.gen)])
                    .evidence(evidence.clone())
                    .remediation("Inspect for redundant or obfuscated decoding.")
                    .extend_meta(violation_meta.into_iter())
                    .build(),
                );
            }

            if is_jbig2_obfuscation(&normalised) {
                let violation_meta = {
                    let mut dup = meta.clone();
                    dup.insert("violation_type".into(), "jbig2_obfuscation".to_string());
                    dup.insert("jbig2.cves".into(), "CVE-2021-30860,CVE-2022-38171".into());
                    dup.insert("cve".into(), "CVE-2021-30860,CVE-2022-38171".into());
                    dup.insert(
                        "attack_surface".into(),
                        "Image codecs / filter obfuscation".into(),
                    );
                    dup
                };
                findings.push(
                    FindingBuilder::template(
                        self.surface(),
                        "filter_chain_jbig2_obfuscation",
                        Severity::High,
                        Confidence::Probable,
                        "JBIG2 filter chain obfuscation",
                        "JBIG2 payloads wrapped with ASCII/Flate layers match known CVE obfuscations.",
                    )
                    .impact(Impact::High)
                    .objects(vec![format!("{} {} obj", entry.obj, entry.gen)])
                    .evidence(evidence.clone())
                    .remediation("Decode payloads carefully to expose JBIG2 segments.")
                    .extend_meta(violation_meta.into_iter())
                    .build(),
                );
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
    "FLATEDECODE",
    "DCTDECODE",
    "JPXDECODE",
    "LZWDECODE",
    "ASCII85DECODE",
    "ASCIIHEXDECODE",
    "RUNLENGTHDECODE",
    "CCITTFAXDECODE",
    "JBIG2DECODE",
    "CRYPT",
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

const IMAGE_FILTERS: &[&str] = &["DCTDECODE", "JPXDECODE", "JBIG2DECODE", "CCITTFAXDECODE"];
const COMPRESSION_FILTERS: &[&str] = &["FLATEDECODE", "LZWDECODE", "RUNLENGTHDECODE"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jbig2_obfuscation_detects_ascii_wrapper() {
        let filters = vec![
            "ASCIIHEXDECODE".into(),
            "FlateDecode".into(),
            "JBIG2DECODE".into(),
        ];
        assert!(is_jbig2_obfuscation(&filters));
    }

    #[test]
    fn jbig2_obfuscation_requires_both_filters() {
        let filters = vec!["FlateDecode".into(), "JBIG2Decode".into()];
        assert!(!is_jbig2_obfuscation(&filters));
    }
}

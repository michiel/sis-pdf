use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfStream};
use std::collections::BTreeSet;

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
        Needs::OBJECT_GRAPH | Needs::STREAM_DECODE
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut seen_stream_spans = BTreeSet::new();
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            for (_, obj) in &dict.entries {
                if let Some(stream) = icc_stream(ctx, obj) {
                    let span_key = (stream.data_span.start, stream.data_span.end);
                    if !seen_stream_spans.insert(span_key) {
                        continue;
                    }
                    let raw_len = stream.data_span.len() as usize;
                    let decoded_profile = ctx.decoded.get_or_decode(ctx.bytes, &stream).ok();
                    let decoded_len = decoded_profile
                        .as_ref()
                        .map(|decoded| decoded.data.len())
                        .unwrap_or(raw_len);
                    let n_value = extract_n_value(&stream);
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("icc.raw_len".into(), raw_len.to_string());
                    meta.insert("icc.decoded_len".into(), decoded_len.to_string());
                    let evidence = vec![span_to_evidence(stream.data_span, "ICC profile")];
                    if decoded_len > 1024 * 1024 {
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "icc_profile_oversized".into(),
                            severity: Severity::Medium,
                            confidence: Confidence::Probable,
                            impact: Impact::Unknown,
                            title: "Oversized ICC profile".into(),
                            description: format!(
                                "ICC profile decoded to {} bytes, exceeding the expected size bound (1048576 bytes).",
                                decoded_len
                            ),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: evidence.clone(),
                            remediation: Some(
                                "Drop or replace the profile with a compact, standards-compliant ICC profile and re-encode the stream."
                                    .into(),
                            ),
                            meta: meta.clone(),
                            action_type: None,
                            action_target: None,
                            action_initiation: None,
                            yara: None,
                            positions: Vec::new(),
                        });
                    }
                    let validation = if let Some(decoded) = decoded_profile.as_ref() {
                        validate_icc_profile(decoded.data.as_slice(), n_value)
                    } else {
                        IccValidation {
                            issues: vec![IccIssue::new(
                                "decode_failed",
                                "ICC profile stream could not be decoded for validation",
                            )],
                            declared_size: None,
                            tag_count: None,
                        }
                    };
                    if !validation.issues.is_empty() {
                        let issue_codes = validation
                            .issues
                            .iter()
                            .map(|issue| issue.code)
                            .collect::<Vec<_>>()
                            .join(",");
                        let issue_messages = validation
                            .issues
                            .iter()
                            .map(|issue| issue.message.as_str())
                            .collect::<Vec<_>>();
                        meta.insert("icc.issue_codes".into(), issue_codes);
                        meta.insert("icc.issue_count".into(), validation.issues.len().to_string());
                        if let Some(declared_size) = validation.declared_size {
                            meta.insert("icc.declared_size".into(), declared_size.to_string());
                        }
                        if let Some(tag_count) = validation.tag_count {
                            meta.insert("icc.tag_count".into(), tag_count.to_string());
                        }
                        let description = format!(
                            "Decoded ICC profile failed {} validation check(s): {}.",
                            validation.issues.len(),
                            issue_messages.join("; ")
                        );
                        let remediation = remediation_for_icc_issues(validation.issues.as_slice());
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "icc_profile_anomaly".into(),
                            severity: Severity::Medium,
                            confidence: Confidence::Probable,
                            impact: Impact::Unknown,
                            title: "ICC profile header anomaly".into(),
                            description,
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence,
                            remediation: Some(remediation),
                            meta,
                            action_type: None,
                            action_target: None,
                            action_initiation: None,
                            yara: None,
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

#[derive(Clone)]
struct IccIssue {
    code: &'static str,
    message: String,
}

impl IccIssue {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

struct IccValidation {
    issues: Vec<IccIssue>,
    declared_size: Option<usize>,
    tag_count: Option<usize>,
}

fn validate_icc_profile(decoded: &[u8], n_value: Option<u32>) -> IccValidation {
    let mut issues = Vec::new();
    if decoded.len() < 128 {
        issues.push(IccIssue::new(
            "header_too_short",
            "ICC profile header is shorter than 128 bytes",
        ));
        return IccValidation { issues, declared_size: None, tag_count: None };
    }
    if decoded.len() < 132 {
        issues.push(IccIssue::new(
            "tag_count_missing",
            "ICC profile is too short to include a tag count",
        ));
        return IccValidation { issues, declared_size: None, tag_count: None };
    }

    let declared_size =
        u32::from_be_bytes([decoded[0], decoded[1], decoded[2], decoded[3]]) as usize;
    if declared_size == 0 {
        issues.push(IccIssue::new("declared_size_zero", "ICC profile declared size is zero"));
    }
    if declared_size > 0 && declared_size < 132 {
        issues.push(IccIssue::new(
            "declared_size_too_small",
            format!(
                "ICC declared size {} is smaller than mandatory header/tag-count region",
                declared_size
            ),
        ));
    }
    if declared_size > decoded.len() {
        issues.push(IccIssue::new(
            "declared_size_exceeds_decoded",
            format!("ICC declared size {} exceeds decoded length {}", declared_size, decoded.len()),
        ));
    }

    let sig = &decoded[36..40];
    if sig != b"acsp" {
        issues.push(IccIssue::new(
            "signature_missing",
            "ICC profile signature at offset 36 is not 'acsp'",
        ));
    }

    let tag_count =
        u32::from_be_bytes([decoded[128], decoded[129], decoded[130], decoded[131]]) as usize;
    let declared_bound =
        if declared_size > 0 { declared_size.min(decoded.len()) } else { decoded.len() };
    let table_end = 132usize.checked_add(tag_count.saturating_mul(12));
    if table_end.is_none() || table_end.unwrap_or(usize::MAX) > declared_bound {
        issues.push(IccIssue::new(
            "tag_table_out_of_bounds",
            format!("ICC tag table end exceeds profile bounds (tag_count={tag_count})"),
        ));
    }

    let mut ranges = Vec::new();
    let available_entries = (decoded.len().saturating_sub(132)) / 12;
    let parsed_entries = tag_count.min(available_entries);
    for idx in 0..parsed_entries {
        let base = 132 + idx * 12;
        let offset = u32::from_be_bytes([
            decoded[base + 4],
            decoded[base + 5],
            decoded[base + 6],
            decoded[base + 7],
        ]) as usize;
        let size = u32::from_be_bytes([
            decoded[base + 8],
            decoded[base + 9],
            decoded[base + 10],
            decoded[base + 11],
        ]) as usize;
        if size == 0 {
            continue;
        }
        let Some(end) = offset.checked_add(size) else {
            issues.push(IccIssue::new(
                "tag_entry_overflow",
                format!("ICC tag entry {} offset+size overflows usize", idx),
            ));
            continue;
        };
        if offset < 128 || end > declared_bound {
            issues.push(IccIssue::new(
                "tag_entry_out_of_bounds",
                format!(
                    "ICC tag entry {} points outside profile bounds (offset={}, size={}, bound={})",
                    idx, offset, size, declared_bound
                ),
            ));
            continue;
        }
        ranges.push((offset, end));
    }

    ranges.sort_unstable_by_key(|range| range.0);
    for pair in ranges.windows(2) {
        let left = pair[0];
        let right = pair[1];
        if right.0 < left.1 {
            issues.push(IccIssue::new(
                "tag_overlap",
                format!(
                    "ICC tag data ranges overlap ({}..{} and {}..{})",
                    left.0, left.1, right.0, right.1
                ),
            ));
            break;
        }
    }

    if let Some(n) = n_value {
        if !matches!(n, 1 | 3 | 4) {
            issues.push(IccIssue::new(
                "n_invalid",
                format!("ICC /N value {} is outside common component counts (1,3,4)", n),
            ));
        }
        if let Some(expected_n) = expected_components_from_header(decoded) {
            if expected_n != n {
                issues.push(IccIssue::new(
                    "n_header_mismatch",
                    format!(
                        "ICC /N value {} conflicts with header colour space component count {}",
                        n, expected_n
                    ),
                ));
            }
        }
    }

    IccValidation { issues, declared_size: Some(declared_size), tag_count: Some(tag_count) }
}

fn extract_n_value(stream: &PdfStream<'_>) -> Option<u32> {
    let (_, n_obj) = stream.dict.get_first(b"/N")?;
    match &n_obj.atom {
        PdfAtom::Int(value) => (*value >= 0).then_some(*value as u32),
        PdfAtom::Real(value) => (*value >= 0.0).then_some(*value as u32),
        _ => None,
    }
}

fn expected_components_from_header(decoded: &[u8]) -> Option<u32> {
    if decoded.len() < 20 {
        return None;
    }
    match &decoded[16..20] {
        b"GRAY" => Some(1),
        b"RGB " => Some(3),
        b"CMYK" => Some(4),
        _ => None,
    }
}

fn remediation_for_icc_issues(issues: &[IccIssue]) -> String {
    let issue_codes = issues.iter().map(|issue| issue.code).collect::<Vec<_>>().join(", ");
    format!(
        "Address detected ICC validation issues ({issue_codes}): re-encode or replace the profile, ensure declared size and tag offsets stay within decoded bounds, and align /N with the ICC header colour space."
    )
}

#[cfg(test)]
mod tests {
    use super::validate_icc_profile;

    fn valid_icc_rgb_profile() -> Vec<u8> {
        let mut data = vec![0u8; 160];
        data[0..4].copy_from_slice(&(160u32.to_be_bytes()));
        data[16..20].copy_from_slice(b"RGB ");
        data[36..40].copy_from_slice(b"acsp");
        data[128..132].copy_from_slice(&(1u32.to_be_bytes()));
        data[132..136].copy_from_slice(b"desc");
        data[136..140].copy_from_slice(&(144u32.to_be_bytes()));
        data[140..144].copy_from_slice(&(16u32.to_be_bytes()));
        data
    }

    #[test]
    fn valid_icc_profile_has_no_issues() {
        let data = valid_icc_rgb_profile();
        let result = validate_icc_profile(&data, Some(3));
        assert!(result.issues.is_empty());
    }

    #[test]
    fn malformed_icc_profile_reports_specific_issue_codes() {
        let mut data = valid_icc_rgb_profile();
        data[0..4].copy_from_slice(&(220u32.to_be_bytes()));
        data[36..40].copy_from_slice(b"zzzz");
        let result = validate_icc_profile(&data, Some(1));
        let codes = result.issues.iter().map(|issue| issue.code).collect::<Vec<_>>();
        assert!(codes.contains(&"declared_size_exceeds_decoded"));
        assert!(codes.contains(&"signature_missing"));
        assert!(codes.contains(&"n_header_mismatch"));
    }
}

use sis_pdf_pdf::graph::XrefSectionSummary;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj};
use sis_pdf_pdf::{parse_pdf, ParseOptions};

use crate::scan::ScanContext;

#[derive(Debug, Clone)]
pub struct SignatureRevisionSnapshot {
    pub object_ref: String,
    pub byte_range: [u64; 4],
    pub signed_segments: [(u64, u64); 2],
    pub covered_end: u64,
    pub nearest_startxref: Option<u64>,
    pub state_parseable: bool,
    pub state_object_count: usize,
    pub state_parse_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RevisionContentExtraction {
    pub signatures: Vec<SignatureRevisionSnapshot>,
    pub prev_chain_valid: bool,
    pub prev_chain_errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PrevChainValidation {
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct ByteRangeValidation {
    byte_range: [u64; 4],
    segments: [(u64, u64); 2],
    covered_end: u64,
}

pub fn extract_revision_content(ctx: &ScanContext<'_>) -> RevisionContentExtraction {
    let prev_chain =
        validate_prev_chain(ctx.bytes.len(), &ctx.graph.xref_sections, &ctx.graph.startxrefs);
    let mut signatures = Vec::new();

    for entry in &ctx.graph.objects {
        let Some(dict) = entry_dict(entry) else {
            continue;
        };
        if !is_signature_dict(&dict) {
            continue;
        }
        let object_ref = format!("{} {} obj", entry.obj, entry.gen);
        let Some((_, byte_range_obj)) = dict.get_first(b"/ByteRange") else {
            continue;
        };
        let parsed = parse_byte_range(byte_range_obj, ctx.bytes.len());
        let snapshot = match parsed {
            Ok(validated) => {
                let nearest_startxref =
                    nearest_startxref(ctx.graph.startxrefs.as_slice(), validated.covered_end);
                let slice_end = usize::try_from(validated.covered_end).unwrap_or(ctx.bytes.len());
                let (state_parseable, state_object_count, state_parse_error) =
                    parse_revision_slice(ctx, slice_end);
                SignatureRevisionSnapshot {
                    object_ref,
                    byte_range: validated.byte_range,
                    signed_segments: validated.segments,
                    covered_end: validated.covered_end,
                    nearest_startxref,
                    state_parseable,
                    state_object_count,
                    state_parse_error,
                }
            }
            Err(err) => SignatureRevisionSnapshot {
                object_ref,
                byte_range: [0, 0, 0, 0],
                signed_segments: [(0, 0), (0, 0)],
                covered_end: 0,
                nearest_startxref: None,
                state_parseable: false,
                state_object_count: 0,
                state_parse_error: Some(err),
            },
        };
        signatures.push(snapshot);
    }

    signatures.sort_by(|left, right| left.covered_end.cmp(&right.covered_end));
    RevisionContentExtraction {
        signatures,
        prev_chain_valid: prev_chain.valid,
        prev_chain_errors: prev_chain.errors,
    }
}

pub fn validate_prev_chain(
    bytes_len: usize,
    sections: &[XrefSectionSummary],
    startxrefs: &[u64],
) -> PrevChainValidation {
    let mut errors = Vec::new();
    if sections.is_empty() {
        return PrevChainValidation { valid: true, errors };
    }
    let mut seen = std::collections::BTreeSet::new();
    for section in sections {
        if section.offset as usize >= bytes_len {
            errors.push(format!(
                "xref offset {} is out of bounds (len {})",
                section.offset, bytes_len
            ));
        }
        if !seen.insert(section.offset) {
            errors.push(format!("duplicate xref section offset {}", section.offset));
        }
    }

    for idx in 0..sections.len() {
        let expected_prev =
            if idx + 1 < sections.len() { Some(sections[idx + 1].offset) } else { None };
        let actual_prev = sections[idx].prev;
        if actual_prev != expected_prev {
            errors.push(format!(
                "xref /Prev mismatch at section {}: expected {:?}, observed {:?}",
                sections[idx].offset, expected_prev, actual_prev
            ));
        }
    }

    if let Some(last_startxref) = startxrefs.iter().max().copied() {
        let head = sections[0].offset;
        if head != last_startxref {
            errors.push(format!(
                "xref chain head {} does not match latest startxref {}",
                head, last_startxref
            ));
        }
    }

    PrevChainValidation { valid: errors.is_empty(), errors }
}

fn parse_revision_slice(ctx: &ScanContext<'_>, slice_end: usize) -> (bool, usize, Option<String>) {
    if slice_end == 0 || slice_end > ctx.bytes.len() {
        return (false, 0, Some("covered byte range end is invalid".into()));
    }
    let slice = &ctx.bytes[..slice_end];
    let parse_options = ParseOptions {
        recover_xref: ctx.options.recover_xref,
        deep: ctx.options.deep,
        strict: ctx.options.strict,
        max_objstm_bytes: ctx.options.max_decode_bytes,
        max_objects: ctx.options.max_objects,
        max_objstm_total_bytes: ctx.options.max_total_decoded_bytes,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };
    match parse_pdf(slice, parse_options) {
        Ok(graph) => (true, graph.objects.len(), None),
        Err(err) => (false, 0, Some(err.to_string())),
    }
}

fn parse_byte_range(obj: &PdfObj<'_>, bytes_len: usize) -> Result<ByteRangeValidation, String> {
    let PdfAtom::Array(items) = &obj.atom else {
        return Err("/ByteRange is not an array".into());
    };
    if items.len() != 4 {
        return Err(format!("/ByteRange expected 4 integers, got {}", items.len()));
    }
    let mut values = [0u64; 4];
    for (idx, item) in items.iter().enumerate() {
        let PdfAtom::Int(value) = item.atom else {
            return Err(format!("/ByteRange entry {} is not an integer", idx));
        };
        if value < 0 {
            return Err(format!("/ByteRange entry {} is negative", idx));
        }
        values[idx] = value as u64;
    }

    let first_start = values[0];
    let first_len = values[1];
    let second_start = values[2];
    let second_len = values[3];
    let first_end = first_start
        .checked_add(first_len)
        .ok_or_else(|| "first /ByteRange segment overflows u64".to_string())?;
    let second_end = second_start
        .checked_add(second_len)
        .ok_or_else(|| "second /ByteRange segment overflows u64".to_string())?;
    if first_end > bytes_len as u64 || second_end > bytes_len as u64 {
        return Err(format!(
            "/ByteRange segment out of bounds (first_end={}, second_end={}, file_len={})",
            first_end, second_end, bytes_len
        ));
    }
    if first_start > second_start {
        return Err("/ByteRange segments are not ordered".into());
    }
    if first_end > second_start {
        return Err("/ByteRange segments overlap".into());
    }

    Ok(ByteRangeValidation {
        byte_range: values,
        segments: [(first_start, first_end), (second_start, second_end)],
        covered_end: first_end.max(second_end),
    })
}

fn nearest_startxref(startxrefs: &[u64], covered_end: u64) -> Option<u64> {
    startxrefs.iter().copied().filter(|offset| *offset <= covered_end).max()
}

fn is_signature_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/Type", b"/Sig") || dict.get_first(b"/ByteRange").is_some()
}

fn entry_dict<'a>(entry: &'a sis_pdf_pdf::graph::ObjEntry<'a>) -> Option<PdfDict<'a>> {
    match &entry.atom {
        PdfAtom::Dict(dict) => Some(dict.clone()),
        PdfAtom::Stream(stream) => Some(stream.dict.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_scan_options() -> crate::scan::ScanOptions {
        crate::scan::ScanOptions {
            deep: false,
            max_decode_bytes: 32 * 1024 * 1024,
            max_total_decoded_bytes: 256 * 1024 * 1024,
            recover_xref: true,
            parallel: false,
            batch_parallel: false,
            diff_parser: false,
            max_objects: 500_000,
            max_recursion_depth: 64,
            fast: false,
            focus_trigger: None,
            yara_scope: None,
            focus_depth: 0,
            strict: false,
            strict_summary: false,
            ir: false,
            ml_config: None,
            font_analysis: crate::scan::FontAnalysisOptions::default(),
            image_analysis: crate::scan::ImageAnalysisOptions::default(),
            filter_allowlist: None,
            filter_allowlist_strict: false,
            profile: false,
            profile_format: crate::scan::ProfileFormat::Text,
            group_chains: true,
            correlation: crate::scan::CorrelationOptions::default(),
        }
    }

    fn parse_ctx<'a>(bytes: &'a [u8]) -> crate::scan::ScanContext<'a> {
        let graph = parse_pdf(
            bytes,
            ParseOptions {
                recover_xref: true,
                deep: false,
                strict: false,
                max_objstm_bytes: 32 * 1024 * 1024,
                max_objects: 500_000,
                max_objstm_total_bytes: 256 * 1024 * 1024,
                carve_stream_objects: false,
                max_carved_objects: 0,
                max_carved_bytes: 0,
            },
        )
        .expect("parse test pdf");
        crate::scan::ScanContext::new(bytes, graph, default_scan_options())
    }

    fn build_signature_pdf(byte_range: &str) -> Vec<u8> {
        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n");
        let objects = [
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n"
                .to_string(),
            format!(
                "5 0 obj\n<< /Type /Sig /ByteRange [{}] /Contents <00112233> >>\nendobj\n",
                byte_range
            ),
        ];
        let mut offsets = [0usize; 6];
        for object in &objects {
            let header = object.as_bytes()[0];
            let obj_id = if header == b'1' {
                1
            } else if header == b'2' {
                2
            } else if header == b'3' {
                3
            } else {
                5
            };
            offsets[obj_id] = pdf.len();
            pdf.extend_from_slice(object.as_bytes());
        }
        let start_xref = pdf.len();
        pdf.extend_from_slice(b"xref\n0 6\n");
        pdf.extend_from_slice(b"0000000000 65535 f \n");
        for offset in offsets.iter().skip(1) {
            if *offset == 0 {
                pdf.extend_from_slice(b"0000000000 00000 f \n");
            } else {
                let line = format!("{offset:010} 00000 n \n");
                pdf.extend_from_slice(line.as_bytes());
            }
        }
        pdf.extend_from_slice(b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n");
        pdf.extend_from_slice(start_xref.to_string().as_bytes());
        pdf.extend_from_slice(b"\n%%EOF\n");
        pdf
    }

    #[test]
    fn extractor_accepts_valid_signature_byte_range() {
        let bytes = build_signature_pdf("0 80 120 20");
        let ctx = parse_ctx(&bytes);
        let extraction = extract_revision_content(&ctx);
        assert!(extraction.prev_chain_valid, "{:?}", extraction.prev_chain_errors);
        assert_eq!(extraction.signatures.len(), 1);
        let sig = &extraction.signatures[0];
        assert_eq!(sig.byte_range, [0, 80, 120, 20]);
        assert_eq!(sig.covered_end, 140);
        assert!(sig.state_parseable);
        assert!(sig.state_object_count > 0);
    }

    #[test]
    fn extractor_rejects_out_of_bounds_byte_range() {
        let bytes = build_signature_pdf("0 80 999999 20");
        let ctx = parse_ctx(&bytes);
        let extraction = extract_revision_content(&ctx);
        assert_eq!(extraction.signatures.len(), 1);
        let sig = &extraction.signatures[0];
        assert!(!sig.state_parseable);
        assert!(sig
            .state_parse_error
            .as_ref()
            .map(|error| error.contains("out of bounds"))
            .unwrap_or(false));
    }

    #[test]
    fn prev_chain_validator_reports_mismatch() {
        let sections = vec![
            XrefSectionSummary {
                offset: 100,
                kind: "table".into(),
                has_trailer: true,
                prev: Some(40),
                trailer_size: Some(6),
                trailer_root: Some("1 0 R".into()),
            },
            XrefSectionSummary {
                offset: 60,
                kind: "table".into(),
                has_trailer: true,
                prev: None,
                trailer_size: Some(6),
                trailer_root: Some("1 0 R".into()),
            },
        ];
        let validation = validate_prev_chain(1_000, &sections, &[100]);
        assert!(!validation.valid);
        assert!(validation.errors.iter().any(|error| error.contains("/Prev mismatch")));
    }
}

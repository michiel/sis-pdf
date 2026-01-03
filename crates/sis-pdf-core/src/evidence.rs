use crate::model::{EvidenceSource, EvidenceSpan};
use sis_pdf_pdf::span::Span;

pub fn decoded_evidence_span(origin: Span, bytes: &[u8], note: &str) -> EvidenceSpan {
    let preview = preview_ascii(bytes, 80);
    EvidenceSpan {
        source: EvidenceSource::Decoded,
        offset: 0,
        length: bytes.len().min(u32::MAX as usize) as u32,
        origin: Some(origin),
        note: Some(format!("{} preview={}", note, preview)),
    }
}

pub fn preview_ascii(data: &[u8], max_len: usize) -> String {
    let mut out = String::new();
    for &b in data.iter().take(max_len) {
        if b.is_ascii_graphic() || b == b' ' {
            out.push(b as char);
        } else {
            out.push('.');
        }
    }
    out
}

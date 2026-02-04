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

#[derive(Default)]
pub struct EvidenceBuilder {
    spans: Vec<EvidenceSpan>,
}

impl EvidenceBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn file_offset(mut self, offset: u64, length: u32, note: &str) -> Self {
        self.spans.push(EvidenceSpan {
            source: EvidenceSource::File,
            offset,
            length,
            origin: None,
            note: Some(note.to_string()),
        });
        self
    }

    pub fn object_ref(mut self, obj: u32, gen: u16) -> Self {
        self.spans.push(EvidenceSpan {
            source: EvidenceSource::File,
            offset: 0,
            length: 0,
            origin: None,
            note: Some(format!("Object {} {} R", obj, gen)),
        });
        self
    }

    pub fn decoded_payload(mut self, origin: Span, bytes: &[u8], note: &str) -> Self {
        self.spans.push(decoded_evidence_span(origin, bytes, note));
        self
    }

    pub fn hash(mut self, name: &str, value: &str) -> Self {
        self.spans.push(EvidenceSpan {
            source: EvidenceSource::File,
            offset: 0,
            length: 0,
            origin: None,
            note: Some(format!("{}={}", name, value)),
        });
        self
    }

    pub fn build(self) -> Vec<EvidenceSpan> {
        self.spans
    }
}

#[cfg(test)]
mod tests {
    use super::EvidenceBuilder;

    #[test]
    fn builder_collects_spans() {
        let spans = EvidenceBuilder::new()
            .file_offset(10, 4, "test")
            .object_ref(1, 0)
            .hash("hash.blake3", "abc")
            .build();
        assert_eq!(spans.len(), 3);
    }
}

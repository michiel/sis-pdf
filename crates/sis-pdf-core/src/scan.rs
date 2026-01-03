use std::collections::HashMap;
use std::sync::Mutex;

use sis_pdf_pdf::decode::{decode_stream, DecodedStream};
use sis_pdf_pdf::object::PdfStream;
use sis_pdf_pdf::span::Span;
use sis_pdf_pdf::ObjectGraph;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub deep: bool,
    pub max_decode_bytes: usize,
    pub max_total_decoded_bytes: usize,
    pub recover_xref: bool,
    pub parallel: bool,
    pub diff_parser: bool,
    pub max_objects: usize,
    pub max_recursion_depth: usize,
    pub fast: bool,
    pub focus_trigger: Option<String>,
    pub yara_scope: Option<String>,
    pub focus_depth: usize,
    pub strict: bool,
}

pub struct ScanContext<'a> {
    pub bytes: &'a [u8],
    pub graph: ObjectGraph<'a>,
    pub decoded: DecodedCache,
    pub options: ScanOptions,
}

#[derive(Debug)]
pub struct DecodedCache {
    max_decode_bytes: usize,
    max_total_decoded_bytes: usize,
    cache: Mutex<HashMap<(u64, u64), DecodedStream>>,
    total_decoded: Mutex<usize>,
}

impl DecodedCache {
    pub fn new(max_decode_bytes: usize, max_total_decoded_bytes: usize) -> Self {
        Self {
            max_decode_bytes,
            max_total_decoded_bytes,
            cache: Mutex::new(HashMap::new()),
            total_decoded: Mutex::new(0),
        }
    }

    pub fn get_or_decode(
        &self,
        bytes: &[u8],
        stream: &PdfStream<'_>,
    ) -> anyhow::Result<DecodedStream> {
        let key = (stream.data_span.start, stream.data_span.end);
        if let Some(v) = self.cache.lock().ok().and_then(|c| c.get(&key).cloned()) {
            return Ok(v);
        }
        let decoded = decode_stream(bytes, stream, self.max_decode_bytes)?;
        if let Ok(mut total) = self.total_decoded.lock() {
            if *total + decoded.data.len() > self.max_total_decoded_bytes {
                return Err(anyhow::anyhow!("total decoded bytes budget exceeded"));
            }
            *total += decoded.data.len();
        }
        if let Ok(mut c) = self.cache.lock() {
            c.insert(key, decoded.clone());
        }
        Ok(decoded)
    }
}

pub fn span_to_evidence(span: Span, note: &str) -> crate::model::EvidenceSpan {
    crate::model::EvidenceSpan {
        source: crate::model::EvidenceSource::File,
        offset: span.start,
        length: span.len().min(u64::from(u32::MAX)) as u32,
        origin: None,
        note: Some(note.to_string()),
    }
}

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    pub batch_parallel: bool,
    pub diff_parser: bool,
    pub max_objects: usize,
    pub max_recursion_depth: usize,
    pub fast: bool,
    pub focus_trigger: Option<String>,
    pub yara_scope: Option<String>,
    pub focus_depth: usize,
    pub strict: bool,
    pub ir: bool,
    pub ml_config: Option<crate::ml::MlConfig>,
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
    total_decoded: AtomicUsize,
}

impl DecodedCache {
    pub fn new(max_decode_bytes: usize, max_total_decoded_bytes: usize) -> Self {
        Self {
            max_decode_bytes,
            max_total_decoded_bytes,
            cache: Mutex::new(HashMap::new()),
            total_decoded: AtomicUsize::new(0),
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
        let reservation = self.reserve_budget(self.max_decode_bytes)?;
        let decoded = decode_stream(bytes, stream, self.max_decode_bytes)?;
        reservation.commit(decoded.data.len(), self.max_total_decoded_bytes, &self.total_decoded)?;
        if let Ok(mut c) = self.cache.lock() {
            c.insert(key, decoded.clone());
        }
        Ok(decoded)
    }

    fn reserve_budget(&self, amount: usize) -> anyhow::Result<BudgetReservation<'_>> {
        if self.max_total_decoded_bytes == 0 {
            return Ok(BudgetReservation {
                reserved: 0,
                committed: true,
                total: &self.total_decoded,
            });
        }
        let mut current = self.total_decoded.load(Ordering::SeqCst);
        loop {
            let next = current.saturating_add(amount);
            if next > self.max_total_decoded_bytes {
                eprintln!(
                    "security_boundary: decode budget exceeded (current={} reserve={} limit={})",
                    current, amount, self.max_total_decoded_bytes
                );
                return Err(anyhow::anyhow!("total decoded bytes budget exceeded"));
            }
            match self.total_decoded.compare_exchange(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Ok(BudgetReservation {
                        reserved: amount,
                        committed: false,
                        total: &self.total_decoded,
                    });
                }
                Err(updated) => current = updated,
            }
        }
    }
}

struct BudgetReservation<'a> {
    reserved: usize,
    committed: bool,
    total: &'a AtomicUsize,
}

impl<'a> BudgetReservation<'a> {
    fn commit(
        mut self,
        actual: usize,
        limit: usize,
        total: &AtomicUsize,
    ) -> anyhow::Result<()> {
        if self.reserved > 0 {
            total.fetch_sub(self.reserved, Ordering::SeqCst);
        }
        if limit > 0 {
            let current = total.fetch_add(actual, Ordering::SeqCst) + actual;
            if current > limit {
                eprintln!(
                    "security_boundary: decode budget exceeded after decode (total={} limit={})",
                    current, limit
                );
                return Err(anyhow::anyhow!("total decoded bytes budget exceeded"));
            }
        }
        self.committed = true;
        Ok(())
    }
}

impl Drop for BudgetReservation<'_> {
    fn drop(&mut self) {
        if !self.committed && self.reserved > 0 {
            self.total.fetch_sub(self.reserved, Ordering::SeqCst);
        }
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

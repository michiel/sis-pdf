use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use sis_pdf_pdf::classification::ClassificationMap;
use sis_pdf_pdf::decode::{
    decode_stream, decode_stream_with_meta, DecodeLimits, DecodeServiceResult, DecodedStream,
};
use sis_pdf_pdf::object::PdfStream;
use sis_pdf_pdf::span::Span;
use sis_pdf_pdf::typed_graph::TypedGraph;
use sis_pdf_pdf::ObjectGraph;
use tracing::{debug, trace, warn, Level};

use crate::canonical::CanonicalView;
use crate::security_log::{SecurityDomain, SecurityEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileFormat {
    Text,
    Json,
}

impl Default for ProfileFormat {
    fn default() -> Self {
        Self::Text
    }
}

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
    pub strict_summary: bool,
    pub ir: bool,
    pub ml_config: Option<crate::ml::MlConfig>,
    pub font_analysis: FontAnalysisOptions,
    pub image_analysis: ImageAnalysisOptions,
    pub filter_allowlist: Option<Vec<Vec<String>>>,
    pub filter_allowlist_strict: bool,
    pub profile: bool,
    pub profile_format: ProfileFormat,
    pub group_chains: bool,
    pub correlation: CorrelationOptions,
}

#[derive(Debug, Clone)]
pub struct FontAnalysisOptions {
    pub enabled: bool,
    pub dynamic_enabled: bool,
    pub dynamic_timeout_ms: u64,
    pub max_fonts: usize,
    pub signature_matching_enabled: bool,
    pub signature_directory: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImageAnalysisOptions {
    pub enabled: bool,
    pub dynamic_enabled: bool,
    pub max_pixels: u64,
    pub max_decode_bytes: usize,
    pub timeout_ms: u64,
    pub total_budget_ms: u64,
    pub skip_threshold: usize,
    pub max_header_bytes: usize,
    pub max_dimension: u32,
    pub max_xfa_decode_bytes: usize,
    pub max_filter_chain_depth: usize,
}

impl Default for ImageAnalysisOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            dynamic_enabled: true,
            max_pixels: 100_000_000,
            max_decode_bytes: 256 * 1024 * 1024,
            timeout_ms: 250,
            total_budget_ms: 5_000,
            skip_threshold: 50,
            max_header_bytes: 4096,
            max_dimension: 10_000,
            max_xfa_decode_bytes: 8 * 1024 * 1024,
            max_filter_chain_depth: 8,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CorrelationOptions {
    pub enabled: bool,
    pub launch_obfuscated_enabled: bool,
    pub action_chain_malicious_enabled: bool,
    pub xfa_data_exfiltration_enabled: bool,
    pub encrypted_payload_delivery_enabled: bool,
    pub obfuscated_payload_enabled: bool,
    pub high_entropy_threshold: f64,
    pub action_chain_depth_threshold: usize,
    pub xfa_sensitive_field_threshold: usize,
}

impl Default for CorrelationOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            launch_obfuscated_enabled: true,
            action_chain_malicious_enabled: true,
            xfa_data_exfiltration_enabled: true,
            encrypted_payload_delivery_enabled: true,
            obfuscated_payload_enabled: true,
            high_entropy_threshold: 7.5,
            action_chain_depth_threshold: 3,
            xfa_sensitive_field_threshold: 1,
        }
    }
}

impl Default for FontAnalysisOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            dynamic_enabled: false,
            dynamic_timeout_ms: 120,
            max_fonts: 256,
            signature_matching_enabled: true,
            signature_directory: None,
        }
    }
}

pub struct ScanContext<'a> {
    pub bytes: &'a [u8],
    pub graph: ObjectGraph<'a>,
    pub decoded: DecodedCache,
    pub options: ScanOptions,

    // Lazy-initialized graph infrastructure (Sprint 4)
    classifications: OnceLock<ClassificationMap>,
    canonical_view: OnceLock<CanonicalView>,
}

impl<'a> ScanContext<'a> {
    /// Creates a new ScanContext
    pub fn new(bytes: &'a [u8], graph: ObjectGraph<'a>, options: ScanOptions) -> Self {
        Self {
            bytes,
            graph,
            decoded: DecodedCache::new(options.max_decode_bytes, options.max_total_decoded_bytes),
            options,
            classifications: OnceLock::new(),
            canonical_view: OnceLock::new(),
        }
    }

    /// Gets or creates the classification map
    ///
    /// This is lazily initialized on first access. Classifications identify object
    /// types (Catalog, Page, Action, etc.) and roles (JsContainer, UriTarget, etc.)
    /// for all objects in the document.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let classifications = ctx.classifications();
    /// if let Some(classified) = classifications.get(&(obj, gen)) {
    ///     if classified.has_role(ObjectRole::JsContainer) {
    ///         // This object contains JavaScript
    ///     }
    /// }
    /// ```
    pub fn classifications(&self) -> &ClassificationMap {
        self.classifications
            .get_or_init(|| self.graph.classify_objects())
    }

    pub fn canonical_view(&self) -> &CanonicalView {
        self.canonical_view
            .get_or_init(|| CanonicalView::build(&self.graph))
    }

    pub fn decode_stream_with_meta(&self, stream: &PdfStream<'_>) -> DecodeServiceResult {
        let limits = DecodeLimits {
            max_decoded_bytes: self.options.max_decode_bytes,
            ..DecodeLimits::default()
        };
        decode_stream_with_meta(self.bytes, stream, limits)
    }

    /// Builds a typed graph
    ///
    /// Creates a typed graph with semantic edge information (OpenAction, JavaScriptPayload,
    /// UriTarget, etc.) with forward/reverse indices for efficient traversal.
    ///
    /// Note: This is not cached due to lifetime constraints. Detectors should call this
    /// once and reuse the result.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let typed_graph = ctx.build_typed_graph();
    ///
    /// // Find all JavaScript sources
    /// let js_sources = typed_graph.path_finder().find_javascript_sources();
    ///
    /// // Find action chains
    /// let chains = typed_graph.path_finder().find_all_action_chains();
    /// for chain in chains {
    ///     if chain.is_multi_stage() && chain.involves_js {
    ///         eprintln!("Multi-stage JS attack detected!");
    ///     }
    /// }
    /// ```
    pub fn build_typed_graph(&'a self) -> TypedGraph<'a> {
        let classifications = self.classifications();
        TypedGraph::build(&self.graph, classifications)
    }
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
        trace!(
            data_start = stream.data_span.start,
            data_end = stream.data_span.end,
            "Decoding stream"
        );
        let key = (stream.data_span.start, stream.data_span.end);
        if let Some(v) = self.cache.lock().ok().and_then(|c| c.get(&key).cloned()) {
            debug!(
                data_start = stream.data_span.start,
                data_end = stream.data_span.end,
                "Decoded stream cache hit"
            );
            return Ok(v);
        }
        let reservation = self.reserve_budget(self.max_decode_bytes)?;
        let decoded = decode_stream(bytes, stream, self.max_decode_bytes)?;
        reservation.commit(
            decoded.data.len(),
            self.max_total_decoded_bytes,
            &self.total_decoded,
        )?;
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
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::PdfStructure,
                    severity: crate::model::Severity::Medium,
                    kind: "decode_budget_exceeded",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Decode budget exceeded",
                }
                .emit();
                warn!(
                    current = current,
                    reserve = amount,
                    limit = self.max_total_decoded_bytes,
                    "Decode budget exceeded"
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
    fn commit(mut self, actual: usize, limit: usize, total: &AtomicUsize) -> anyhow::Result<()> {
        if self.reserved > 0 {
            total.fetch_sub(self.reserved, Ordering::SeqCst);
        }
        if limit > 0 {
            let current = total.fetch_add(actual, Ordering::SeqCst) + actual;
            if current > limit {
                SecurityEvent {
                    level: Level::WARN,
                    domain: SecurityDomain::PdfStructure,
                    severity: crate::model::Severity::Medium,
                    kind: "decode_budget_exceeded_post",
                    policy: None,
                    object_id: None,
                    object_type: None,
                    vector: None,
                    technique: None,
                    confidence: None,
                    message: "Decode budget exceeded after decode",
                }
                .emit();
                warn!(
                    total = current,
                    limit = limit,
                    "Decode budget exceeded after decode"
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

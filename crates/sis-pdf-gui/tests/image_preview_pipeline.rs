use sis_pdf_gui::image_preview::{
    build_preview_for_object, ImagePreviewOutcome, ImagePreviewStage, PreviewLimits,
};
use sis_pdf_gui::preview_cache::PreviewCache;
use std::time::Instant;

#[test]
fn preview_pipeline_mixed_filter_fixture_records_prefix_path() {
    let encoded_asciihex_jpeg_markers = b"FFD8FFD9>";
    let pdf =
        build_single_image_pdf(Some("[/ASCIIHexDecode /DCTDecode]"), encoded_asciihex_jpeg_markers);

    let start = Instant::now();
    let result = build_preview_for_object(&pdf, 2, 0, PreviewLimits::default())
        .expect("object preview should run for image stream");
    let elapsed = start.elapsed().as_millis() as u64;

    assert!(elapsed < 250, "mixed-filter preview should stay fast, got {elapsed} ms");
    let has_prefix_ready = result.statuses.iter().any(|status| {
        status.stage == ImagePreviewStage::PrefixDecode
            && status.outcome == ImagePreviewOutcome::Ready
    });
    let has_raw_early_success = result.source_used.as_deref() == Some("raw");
    assert!(
        has_prefix_ready || has_raw_early_success,
        "expected prefix decode ready or early raw success, statuses={:?}, source_used={:?}",
        result.statuses,
        result.source_used
    );
}

#[test]
fn preview_pipeline_large_source_fixture_skips_on_budget() {
    let oversized = vec![b'A'; 1024];
    let pdf = build_single_image_pdf(None, &oversized);
    let limits = PreviewLimits { max_source_bytes: 64, ..PreviewLimits::default() };
    let result =
        build_preview_for_object(&pdf, 2, 0, limits).expect("object preview should return result");

    assert_eq!(result.summary, "Unavailable: raw stream exceeded preview source budget");
    let budget_status = result
        .statuses
        .iter()
        .find(|status| status.stage == ImagePreviewStage::RawProbe)
        .expect("raw probe status should be present");
    assert_eq!(budget_status.outcome, ImagePreviewOutcome::SkippedBudget);
    assert_eq!(budget_status.input_bytes, Some(oversized.len()));
}

#[test]
fn preview_pipeline_cache_reopen_uses_cached_result() {
    let payload = b"FFD8FFD9>";
    let pdf = build_single_image_pdf(Some("[/ASCIIHexDecode /DCTDecode]"), payload);
    let first = build_preview_for_object(&pdf, 2, 0, PreviewLimits::default())
        .expect("initial preview build should succeed");

    let mut cache = PreviewCache::new(4, 1024 * 1024);
    let cached_size = preview_build_result_size(&first);
    cache.insert((2u32, 0u16), first.clone(), cached_size);

    let reopen_start = Instant::now();
    let reopened =
        cache.get_cloned(&(2u32, 0u16)).expect("cached preview should be available on reopen");
    let reopen_elapsed = reopen_start.elapsed().as_millis() as u64;

    assert!(reopen_elapsed < 30, "cached reopen should be fast, got {reopen_elapsed} ms");
    assert_eq!(reopened.summary, first.summary);
    assert_eq!(reopened.statuses.len(), first.statuses.len());
}

#[test]
fn preview_pipeline_first_decode_latency_budget() {
    let payload = b"FFD8FFD9>";
    let pdf = build_single_image_pdf(Some("[/ASCIIHexDecode /DCTDecode]"), payload);
    let start = Instant::now();
    let result = build_preview_for_object(&pdf, 2, 0, PreviewLimits::default())
        .expect("preview should run for image object");
    let elapsed = start.elapsed().as_millis() as u64;

    assert!(elapsed < 150, "first preview decode should meet budget (<150ms), got {elapsed} ms");
    assert!(!result.statuses.is_empty(), "first decode should emit stage statuses for diagnostics");
}

#[test]
fn preview_pipeline_cache_hit_p95_latency_budget() {
    let payload = b"FFD8FFD9>";
    let pdf = build_single_image_pdf(Some("[/ASCIIHexDecode /DCTDecode]"), payload);
    let built = build_preview_for_object(&pdf, 2, 0, PreviewLimits::default())
        .expect("initial preview build should succeed");
    let mut cache = PreviewCache::new(4, 1024 * 1024);
    cache.insert((2u32, 0u16), built.clone(), preview_build_result_size(&built));

    let mut samples_us = Vec::with_capacity(200);
    for _ in 0..200 {
        let start = Instant::now();
        let hit = cache.get_cloned(&(2u32, 0u16));
        let elapsed_us = start.elapsed().as_micros() as u64;
        assert!(hit.is_some(), "cache hit should return a preview result");
        samples_us.push(elapsed_us);
    }
    samples_us.sort_unstable();
    let idx_95 = ((samples_us.len() as f64) * 0.95).floor() as usize;
    let p95_us = samples_us[idx_95.min(samples_us.len() - 1)];
    assert!(p95_us < 30_000, "cache-hit p95 should meet budget (<30ms), got {} us", p95_us);
}

#[test]
fn preview_pipeline_deferred_only_filter_records_unsupported_prefix() {
    let payload = b"not-a-jpeg";
    let pdf = build_single_image_pdf(Some("/DCTDecode"), payload);
    let result = build_preview_for_object(&pdf, 2, 0, PreviewLimits::default())
        .expect("preview should run for image object");

    let has_prefix_unsupported = result.statuses.iter().any(|status| {
        status.stage == ImagePreviewStage::PrefixDecode
            && status.outcome == ImagePreviewOutcome::Unsupported
    });
    let has_raw_early_success = result.source_used.as_deref() == Some("raw");
    assert!(
        has_prefix_unsupported || has_raw_early_success,
        "expected unsupported prefix decode or early raw success, statuses={:?}, source_used={:?}",
        result.statuses,
        result.source_used
    );
}

#[test]
fn preview_pipeline_non_stream_object_returns_none() {
    let pdf = build_catalog_only_pdf();
    let result = build_preview_for_object(&pdf, 1, 0, PreviewLimits::default());
    assert!(result.is_none(), "non-stream object should not produce preview result");
}

#[test]
fn preview_pipeline_missing_object_returns_none() {
    let pdf = build_catalog_only_pdf();
    let result = build_preview_for_object(&pdf, 999, 0, PreviewLimits::default());
    assert!(result.is_none(), "missing object id should not produce preview result");
}

#[test]
fn preview_pipeline_missing_generation_returns_none() {
    let pdf = build_single_image_pdf(None, b"abc");
    let result = build_preview_for_object(&pdf, 2, 9, PreviewLimits::default());
    assert!(result.is_none(), "missing generation should not produce preview result");
}

#[test]
fn preview_pipeline_invalid_pdf_bytes_returns_none() {
    let invalid = b"not-a-pdf";
    let result = build_preview_for_object(invalid, 2, 0, PreviewLimits::default());
    assert!(result.is_none(), "invalid PDF bytes should fail closed without preview");
}

#[test]
fn preview_pipeline_repeat_build_is_stable() {
    let payload = b"FFD8FFD9>";
    let pdf = build_single_image_pdf(Some("[/ASCIIHexDecode /DCTDecode]"), payload);
    let first = build_preview_for_object(&pdf, 2, 0, PreviewLimits::default())
        .expect("first preview build should succeed");
    let second = build_preview_for_object(&pdf, 2, 0, PreviewLimits::default())
        .expect("second preview build should succeed");

    assert_eq!(first.summary, second.summary);
    assert_eq!(first.source_used, second.source_used);
    let first_stages: Vec<_> =
        first.statuses.iter().map(|status| (status.stage, status.outcome)).collect();
    let second_stages: Vec<_> =
        second.statuses.iter().map(|status| (status.stage, status.outcome)).collect();
    assert_eq!(
        first_stages, second_stages,
        "preview pipeline should be deterministic across repeat builds"
    );
}

#[test]
fn preview_pipeline_cache_steady_state_respects_byte_budget() {
    let mut cache = PreviewCache::new(2, 4_000);
    for idx in 0..5u32 {
        let payload = format!("FFD8FFD9{:02X}>", idx);
        let pdf = build_single_image_pdf(Some("[/ASCIIHexDecode /DCTDecode]"), payload.as_bytes());
        let built = build_preview_for_object(&pdf, 2, 0, PreviewLimits::default())
            .expect("preview build should succeed for cache test");
        let size = preview_build_result_size(&built);
        cache.insert((idx, 0u16), built, size);
        assert!(
            cache.total_bytes() <= cache.max_total_bytes(),
            "cache should stay within configured byte budget after insertion {}",
            idx
        );
    }
}

fn preview_build_result_size(result: &sis_pdf_gui::image_preview::PreviewBuildResult) -> usize {
    let mut size = result.summary.len();
    size = size.saturating_add(result.source_used.as_ref().map(|s| s.len()).unwrap_or(0));
    if let Some((_, _, rgba)) = &result.preview {
        size = size.saturating_add(rgba.len());
    }
    for status in &result.statuses {
        size = size
            .saturating_add(status.detail.len())
            .saturating_add(status.source.as_ref().map(|s| s.len()).unwrap_or(0));
    }
    size.max(1)
}

fn build_single_image_pdf(filter_expr: Option<&str>, stream_payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut offsets: Vec<usize> = vec![0];
    bytes.extend_from_slice(b"%PDF-1.4\n");

    offsets.push(bytes.len());
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");

    offsets.push(bytes.len());
    let filter_fragment = filter_expr.map(|value| format!(" /Filter {value}")).unwrap_or_default();
    let image_obj = format!(
        "2 0 obj\n<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceRGB /BitsPerComponent 8{filter_fragment} /Length {} >>\nstream\n",
        stream_payload.len()
    );
    bytes.extend_from_slice(image_obj.as_bytes());
    bytes.extend_from_slice(stream_payload);
    bytes.extend_from_slice(b"\nendstream\nendobj\n");

    let xref_offset = bytes.len();
    bytes.extend_from_slice(b"xref\n0 3\n");
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        let line = format!("{:010} 00000 n \n", offset);
        bytes.extend_from_slice(line.as_bytes());
    }
    let trailer = format!("trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF");
    bytes.extend_from_slice(trailer.as_bytes());
    bytes
}

fn build_catalog_only_pdf() -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut offsets: Vec<usize> = vec![0];
    bytes.extend_from_slice(b"%PDF-1.4\n");

    offsets.push(bytes.len());
    bytes.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");

    let xref_offset = bytes.len();
    bytes.extend_from_slice(b"xref\n0 2\n");
    bytes.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        let line = format!("{:010} 00000 n \n", offset);
        bytes.extend_from_slice(line.as_bytes());
    }
    let trailer = format!("trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF");
    bytes.extend_from_slice(trailer.as_bytes());
    bytes
}

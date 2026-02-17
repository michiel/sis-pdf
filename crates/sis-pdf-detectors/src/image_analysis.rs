use anyhow::Result;
use std::collections::HashMap;

use image_analysis::{ImageDynamicOptions, ImageFinding as AnalysisFinding, ImageStaticOptions};
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfStream};

pub struct ImageAnalysisDetector;

impl Detector for ImageAnalysisDetector {
    fn id(&self) -> &'static str {
        "image_analysis"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::Images
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let options = &ctx.options.image_analysis;
        if !options.enabled {
            return Ok(findings);
        }

        let static_opts = ImageStaticOptions {
            max_header_bytes: options.max_header_bytes,
            max_dimension: options.max_dimension,
            max_pixels: options.max_pixels,
            max_xfa_decode_bytes: options.max_xfa_decode_bytes,
            max_filter_chain_depth: options.max_filter_chain_depth,
        };
        let static_result =
            image_analysis::static_analysis::analyze_static_images(&ctx.graph, &static_opts);
        findings.extend(map_findings(ctx, static_result.findings, false));

        if ctx.options.deep && options.dynamic_enabled {
            let dynamic_opts = ImageDynamicOptions {
                max_pixels: options.max_pixels,
                max_decode_bytes: options.max_decode_bytes,
                timeout_ms: options.timeout_ms,
                total_budget_ms: options.total_budget_ms,
                skip_threshold: options.skip_threshold,
            };
            let dynamic_result =
                image_analysis::dynamic::analyze_dynamic_images(&ctx.graph, &dynamic_opts);
            findings.extend(map_findings(ctx, dynamic_result.findings, true));
        }

        Ok(findings)
    }
}

fn map_findings(
    ctx: &sis_pdf_core::scan::ScanContext,
    src: Vec<AnalysisFinding>,
    dynamic: bool,
) -> Vec<Finding> {
    src.into_iter().filter_map(|finding| map_finding(ctx, &finding, dynamic)).collect()
}

fn map_finding(
    ctx: &sis_pdf_core::scan::ScanContext,
    finding: &AnalysisFinding,
    dynamic: bool,
) -> Option<Finding> {
    let entry = ctx.graph.get_object(finding.obj, finding.gen);
    let mut meta: HashMap<String, String> =
        finding.meta.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    if dynamic {
        meta.insert("image.dynamic".into(), "true".into());
    }
    meta.insert("payload.type".into(), "image".into());
    if meta.get("image.xfa").map(|v| v == "true").unwrap_or(false) {
        meta.insert("payload.source".into(), "xfa".into());
    } else {
        meta.insert("payload.source".into(), "xobject".into());
    }
    if let Some(filters) = meta.get("image.filters") {
        meta.insert("stream.filters".into(), filters.clone());
    }
    if let Some(format) = payload_format(&meta) {
        meta.insert("payload.format".into(), format.clone());
        if is_risky_format(&format) {
            meta.insert("payload.risky".into(), "true".into());
        }
    }
    if let Some(summary) = payload_summary(&meta) {
        meta.insert("payload.summary".into(), summary);
    }

    let object_label = format!("{} {} obj", finding.obj, finding.gen);
    let evidence = match entry {
        Some(entry) => match &entry.atom {
            PdfAtom::Stream(PdfStream { data_span, .. }) => {
                vec![span_to_evidence(*data_span, "Image stream")]
            }
            _ => vec![span_to_evidence(entry.body_span, "Image object")],
        },
        None => Vec::new(),
    };

    let (severity, confidence, title, description, remediation) =
        image_finding_summary(&finding.kind, &meta);
    let impact = image_finding_impact(&finding.kind);

    Some(Finding {
        id: String::new(),
        surface: AttackSurface::Images,
        kind: finding.kind.clone(),
        severity,
        confidence,
        title,
        description,
        impact,
        objects: vec![object_label],
        evidence,
        remediation: Some(remediation),
        meta,
        yara: None,
        position: None,
        positions: Vec::new(),
        ..Finding::default()
    })
}

fn payload_format(meta: &HashMap<String, String>) -> Option<String> {
    let filters = meta
        .get("image.filters")
        .map(|v| v.split(',').map(|s| s.trim()).collect::<Vec<_>>())
        .unwrap_or_default();
    if filters.contains(&"JBIG2Decode") {
        return Some("JBIG2".into());
    }
    if filters.contains(&"JPXDecode") {
        return Some("JPX".into());
    }
    if filters.contains(&"CCITTFaxDecode") {
        return Some("CCITT".into());
    }
    if filters.iter().any(|f| *f == "DCTDecode" || *f == "DCT") {
        return Some("JPEG".into());
    }
    if meta.get("image.header.png").map(|v| v == "true").unwrap_or(false) {
        return Some("PNG".into());
    }
    if meta.get("image.header.tiff").map(|v| v == "true").unwrap_or(false) {
        return Some("TIFF".into());
    }
    None
}

fn payload_summary(meta: &HashMap<String, String>) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(format) = meta.get("payload.format") {
        parts.push(format!("format={format}"));
    }
    if let Some(width) = meta.get("image.width") {
        if let Some(height) = meta.get("image.height") {
            parts.push(format!("dimensions={}x{}", width, height));
        }
    }
    if let Some(filters) = meta.get("image.filters") {
        parts.push(format!("filters={filters}"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn is_risky_format(format: &str) -> bool {
    matches!(format, "JBIG2" | "JPX" | "CCITT")
}

fn image_finding_summary(
    kind: &str,
    _meta: &HashMap<String, String>,
) -> (Severity, Confidence, String, String, String) {
    match kind {
        "image.jbig2_present" => (
            Severity::Low,
            Confidence::Probable,
            "JBIG2 image present".into(),
            "PDF contains JBIG2-compressed image data, which increases decoder attack surface."
                .into(),
            "Review JBIG2 image payloads and decoder behaviour.".into(),
        ),
        "image.jpx_present" => (
            Severity::Low,
            Confidence::Probable,
            "JPEG2000 image present".into(),
            "PDF contains JPEG2000-compressed image data, which increases decoder attack surface."
                .into(),
            "Review JPX image payloads and decoder behaviour.".into(),
        ),
        "image.ccitt_present" => (
            Severity::Low,
            Confidence::Probable,
            "CCITT image present".into(),
            "PDF contains CCITT-compressed image data, which increases decoder attack surface."
                .into(),
            "Review CCITT image payloads and decoder behaviour.".into(),
        ),
        "image.multiple_filters" => (
            Severity::Low,
            Confidence::Probable,
            "Image uses multiple filters".into(),
            "Image stream uses a filter chain, which can hide malicious payloads.".into(),
            "Inspect filter chain and decoded image data.".into(),
        ),
        "image.extreme_dimensions" => (
            Severity::Medium,
            Confidence::Probable,
            "Image dimensions exceed limits".into(),
            "Image dimensions exceed configured safety limits.".into(),
            "Inspect image payload for resource abuse.".into(),
        ),
        "image.pixel_count_excessive" => (
            Severity::Medium,
            Confidence::Probable,
            "Image pixel count exceeds limits".into(),
            "Image pixel count exceeds configured safety limits.".into(),
            "Inspect image payload for resource abuse.".into(),
        ),
        "image.suspect_strip_dimensions" => (
            Severity::Medium,
            Confidence::Probable,
            "Image has suspect strip dimensions".into(),
            "Image dimensions indicate thin strip patterns that may hide payloads.".into(),
            "Inspect image payload for obfuscated content.".into(),
        ),
        "image.zero_click_jbig2" => (
            Severity::High,
            Confidence::Strong,
            "Zero-click JBIG2 payload".into(),
            "JBIG2 stream uses extreme strip dimensions (CVE-2021-30860) that mimic zero-click payloads."
                .into(),
            "Treat as a high-risk zero-click JBIG2 vector and isolate the payload.".into(),
        ),
        "image.decode_too_large" => (
            Severity::Low,
            Confidence::Probable,
            "Image decode skipped due to size".into(),
            "Image exceeds configured decode limits and was not decoded.".into(),
            "Adjust image decode limits or review payload manually.".into(),
        ),
        "image.decode_skipped" => (
            Severity::Info,
            Confidence::Probable,
            "Image decode skipped".into(),
            "Image decode was skipped due to format or policy limits.".into(),
            "Review image payloads and decoder configuration.".into(),
        ),
        "image.decode_failed" => (
            Severity::Medium,
            Confidence::Probable,
            "Image decode failed".into(),
            "Image stream failed to decode, indicating malformed or unsupported data.".into(),
            "Inspect image data for corruption or exploit-like structure.".into(),
        ),
        "image.jbig2_malformed" => (
            Severity::High,
            Confidence::Strong,
            "JBIG2 decode failed".into(),
            "JBIG2 image data failed to decode, which may indicate exploit-like content.".into(),
            "Inspect JBIG2 payload and decoder paths.".into(),
        ),
        "image.jpx_malformed" => (
            Severity::High,
            Confidence::Strong,
            "JPEG2000 decode failed".into(),
            "JPEG2000 image data failed to decode, which may indicate exploit-like content.".into(),
            "Inspect JPX payload and decoder paths.".into(),
        ),
        "image.jpeg_malformed" => (
            Severity::Medium,
            Confidence::Probable,
            "JPEG decode failed".into(),
            "JPEG image data failed to decode, indicating malformed or suspicious data.".into(),
            "Inspect JPEG payload and decoder paths.".into(),
        ),
        "image.ccitt_malformed" => (
            Severity::Medium,
            Confidence::Probable,
            "CCITT decode failed".into(),
            "CCITT image data failed to decode, indicating malformed or suspicious data.".into(),
            "Inspect CCITT payload and decoder paths.".into(),
        ),
        "image.xfa_decode_failed" => (
            Severity::Medium,
            Confidence::Probable,
            "XFA image decode failed".into(),
            "Image embedded in XFA content failed to decode.".into(),
            "Inspect XFA image payloads for malformed data.".into(),
        ),
        "image.xfa_image_present" => (
            Severity::Info,
            Confidence::Probable,
            "XFA image present".into(),
            "XFA content embeds image data.".into(),
            "Review embedded images in XFA forms.".into(),
        ),
        "image.colour_space_invalid" => (
            Severity::Medium,
            Confidence::Strong,
            "Invalid colour space".into(),
            "Image colour space is malformed, unresolved, or violates the PDF specification."
                .into(),
            "Inspect image colour space structure for evasion or malformed data.".into(),
        ),
        "image.bpc_anomalous" => (
            Severity::Low,
            Confidence::Strong,
            "Anomalous bits per component".into(),
            "Image BitsPerComponent value is not a standard value (1, 2, 4, 8, or 16).".into(),
            "Inspect image parameters for malformed or crafted values.".into(),
        ),
        "image.pixel_buffer_overflow" => (
            Severity::Medium,
            Confidence::Certain,
            "Image pixel buffer overflow".into(),
            "Image dimensions and colour depth would produce a pixel buffer exceeding safe limits."
                .into(),
            "Inspect image for resource exhaustion or denial of service attempt.".into(),
        ),
        "image.pixel_data_size_mismatch" => (
            Severity::Medium,
            Confidence::Probable,
            "Image stream size mismatch".into(),
            "Decoded stream length does not match the expected pixel data size for the declared dimensions."
                .into(),
            "Inspect image stream for hidden data, truncation, or metadata inconsistency.".into(),
        ),
        "image.indexed_palette_short" => (
            Severity::Low,
            Confidence::Strong,
            "Indexed palette too short".into(),
            "Indexed colour space palette has fewer bytes than required by the declared hival."
                .into(),
            "Inspect palette data for truncation or crafted values.".into(),
        ),
        "image.decode_array_invalid" => (
            Severity::Low,
            Confidence::Strong,
            "Invalid decode array".into(),
            "Image /Decode array has incorrect length for the colour space.".into(),
            "Inspect decode parameters for malformed or crafted values.".into(),
        ),
        other => (
            Severity::Low,
            Confidence::Probable,
            format!("Image analysis finding: {other}"),
            "Image analysis recorded a noteworthy condition.".into(),
            "Review image payloads and related findings.".into(),
        ),
    }
}

fn image_finding_impact(kind: &str) -> Option<Impact> {
    match kind {
        "image.zero_click_jbig2" => Some(Impact::High),
        _ => None,
    }
}

use anyhow::Result;

use sis_pdf_core::content_index::build_content_index;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfObj};

use crate::{entry_dict, extract_strings_with_span, page_has_uri_annot};

pub struct ContentPhishingDetector;

impl Detector for ContentPhishingDetector {
    fn id(&self) -> &'static str {
        "content_phishing"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::ContentPhishing
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH | Needs::STREAM_DECODE
    }
    fn cost(&self) -> Cost {
        Cost::Moderate
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        const KEYWORDS: &[(&[u8], &str)] = &[
            (b"invoice", "invoice"),
            (b"secure", "secure"),
            (b"view document", "view document"),
            (b"account", "account"),
            (b"verify", "verify"),
        ];
        let mut has_keyword = false;
        let mut matched_keywords: Vec<String> = Vec::new();
        let mut evidence = Vec::new();
        for entry in &ctx.graph.objects {
            for (bytes, span) in extract_strings_with_span(entry) {
                let lower = bytes.to_ascii_lowercase();
                let mut matches = matched_keyword_labels(&lower, KEYWORDS);
                if !matches.is_empty() {
                    has_keyword = true;
                    for label in matches.drain(..) {
                        if !matched_keywords.contains(&label) {
                            matched_keywords.push(label);
                        }
                    }
                    if let Some(first) = matched_keywords.first() {
                        evidence.push(span_to_evidence(
                            span,
                            &format!("Phishing-like keyword: {}", first),
                        ));
                    } else {
                        evidence.push(span_to_evidence(span, "Phishing-like keyword"));
                    }
                    break;
                }
            }
            if has_keyword {
                break;
            }
        }
        if !has_keyword {
            let html = detect_html_payload(ctx);
            return Ok(html.into_iter().collect());
        }
        if let Some((uri_value, uri_span)) = first_external_uri(ctx) {
            let mut meta = std::collections::HashMap::new();
            if !matched_keywords.is_empty() {
                meta.insert("content.phishing_keywords".into(), matched_keywords.join(","));
                // Keep legacy singular key for explainability and existing consumers.
                meta.insert("keyword".into(), matched_keywords[0].clone());
            }
            meta.insert("content.phishing_external_uri".into(), uri_value.clone());
            evidence.push(span_to_evidence(
                uri_span,
                &format!("External URI target: {}", uri_note_value(&uri_value)),
            ));
            return Ok(vec![Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "content_phishing".into(),
                severity: Severity::Medium,
                confidence: Confidence::Heuristic,
                impact: None,
                title: "Potential phishing content".into(),
                description: "Detected phishing-like keywords alongside external URI actions."
                    .into(),
                objects: vec!["content".into()],
                evidence,
                remediation: Some("Manually review page content and links.".into()),
                meta,

                reader_impacts: Vec::new(),
                action_type: None,
                action_target: None,
                action_initiation: None,
                yara: None,
                position: None,
                positions: Vec::new(),
            }]);
        }
        let mut out = Vec::new();
        if let Some(html) = detect_html_payload(ctx) {
            out.push(html);
        }
        Ok(out)
    }
}

fn first_external_uri(
    ctx: &sis_pdf_core::scan::ScanContext,
) -> Option<(String, sis_pdf_pdf::span::Span)> {
    for entry in &ctx.graph.objects {
        let Some(dict) = entry_dict(entry) else {
            continue;
        };
        let Some((_, uri_obj)) = dict.get_first(b"/URI") else {
            continue;
        };
        if let Some(uri) = uri_string_from_obj(ctx, uri_obj) {
            let lower = uri.to_ascii_lowercase();
            if lower.starts_with("http://")
                || lower.starts_with("https://")
                || lower.starts_with("mailto:")
                || lower.starts_with("ftp://")
            {
                return Some((uri, uri_obj.span));
            }
        }
    }
    None
}

fn uri_string_from_obj(ctx: &sis_pdf_core::scan::ScanContext, obj: &PdfObj<'_>) -> Option<String> {
    match &obj.atom {
        PdfAtom::Str(s) => Some(String::from_utf8_lossy(&pdf_string_bytes(s)).to_string()),
        PdfAtom::Name(name) => Some(String::from_utf8_lossy(&name.decoded).to_string()),
        PdfAtom::Ref { .. } => {
            let resolved = ctx.graph.resolve_ref(obj)?;
            uri_string_from_obj(ctx, &PdfObj { span: resolved.body_span, atom: resolved.atom })
        }
        _ => None,
    }
}

fn pdf_string_bytes(s: &sis_pdf_pdf::object::PdfStr<'_>) -> Vec<u8> {
    match s {
        sis_pdf_pdf::object::PdfStr::Literal { decoded, .. } => decoded.clone(),
        sis_pdf_pdf::object::PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

fn uri_note_value(uri: &str) -> String {
    const MAX_LEN: usize = 120;
    if uri.chars().count() <= MAX_LEN {
        return uri.to_string();
    }
    let truncated = uri.chars().take(MAX_LEN).collect::<String>();
    format!("{truncated}...")
}

fn matched_keyword_labels(haystack: &[u8], keywords: &[(&[u8], &str)]) -> Vec<String> {
    keywords
        .iter()
        .filter_map(|(needle, label)| {
            if haystack.windows(needle.len()).any(|window| window == *needle) {
                Some((*label).to_string())
            } else {
                None
            }
        })
        .collect()
}

fn detect_html_payload(ctx: &sis_pdf_core::scan::ScanContext) -> Option<Finding> {
    let patterns: &[&[u8]] = &[b"<script", b"<iframe", b"javascript:", b"<svg", b"onerror=", b"onload="];
    for entry in &ctx.graph.objects {
        for (bytes, span) in extract_strings_with_span(entry) {
            let lower = bytes.to_ascii_lowercase();
            if patterns.iter().any(|p| lower.windows(p.len()).any(|w| w == *p)) {
                return Some(Finding {
                    id: String::new(),
                    surface: AttackSurface::ContentPhishing,
                    kind: "content_html_payload".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Heuristic,
                    impact: None,
                    title: "HTML-like payload in content".into(),
                    description: "Content contains HTML or javascript-like sequences.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(span, "HTML-like content")],
                    remediation: Some("Review rendered text for embedded scripts or links.".into()),
                    meta: Default::default(),

                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }
        }
    }
    for entry in &ctx.graph.objects {
        let PdfAtom::Stream(stream) = &entry.atom else {
            continue;
        };
        let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, stream) else {
            continue;
        };
        let Some(marker) = detect_rendered_script_lure(&decoded.data) else {
            continue;
        };
        let mut meta = std::collections::HashMap::new();
        meta.insert("content.pattern".into(), marker.to_string());
        meta.insert("content.source".into(), "decoded_stream_text".into());
        return Some(Finding {
            id: String::new(),
            surface: AttackSurface::ContentPhishing,
            kind: "content_html_payload".into(),
            severity: Severity::Low,
            confidence: Confidence::Heuristic,
            impact: None,
            title: "HTML-like payload in content".into(),
            description:
                "Decoded stream text contains script/HTML-like sequences rendered via text operators."
                    .into(),
            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
            evidence: vec![span_to_evidence(stream.data_span, "Decoded content stream text")],
            remediation: Some(
                "Review rendered text for social-engineering lures that mimic executable HTML/JavaScript."
                    .into(),
            ),
            meta,
            reader_impacts: Vec::new(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            position: None,
            positions: Vec::new(),
        });
    }
    None
}

fn detect_rendered_script_lure(bytes: &[u8]) -> Option<&'static str> {
    let lower = bytes.to_ascii_lowercase();
    const MARKERS: &[&[u8]] =
        &[b"<script", b"<iframe", b"javascript:", b"<svg", b"onerror=", b"onload="];
    for marker in MARKERS {
        let mut cursor = 0usize;
        while cursor < lower.len() {
            let Some(rel) = lower[cursor..].windows(marker.len()).position(|w| w == *marker) else {
                break;
            };
            let marker_pos = cursor + rel;
            let has_tj_nearby = has_text_operator_context(&lower, marker_pos);
            if has_tj_nearby {
                return std::str::from_utf8(marker).ok();
            }
            cursor = marker_pos.saturating_add(1);
        }
    }
    None
}

fn has_text_operator_context(lower: &[u8], marker_pos: usize) -> bool {
    let context_start = marker_pos.saturating_sub(192);
    let context_end = (marker_pos + 256).min(lower.len());
    let context = &lower[context_start..context_end];
    if !(context.contains(&b'(') && context.contains(&b')')) {
        return false;
    }
    context.windows(2).any(|window| window == b"tj")
        || context.windows(3).any(|window| window == b" ' " || window == b" \" ")
}

pub struct ContentDeceptionDetector;

impl Detector for ContentDeceptionDetector {
    fn id(&self) -> &'static str {
        "content_deception"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::ContentPhishing
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH | Needs::STREAM_DECODE
    }
    fn cost(&self) -> Cost {
        Cost::Moderate
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let pages = build_content_index(ctx);
        for page in pages {
            let page_entry = ctx.graph.get_object(page.obj, page.gen);
            let Some(entry) = page_entry else { continue };
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            let evidence = vec![span_to_evidence(entry.full_span, "Page object")];
            let has_image = !page.image_points.is_empty();
            let has_text = !page.text_points.is_empty();
            let coord = first_coord(&page).map(|(x, y)| format!("x={:.2} y={:.2}", x, y));

            if has_image && !has_text {
                let mut meta = std::collections::HashMap::new();
                meta.insert("page.number".into(), page.page_number.to_string());
                if let Some(c) = &coord {
                    meta.insert("content.coord".into(), c.clone());
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "content_image_only_page".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Heuristic,
                    impact: None,
                    title: "Image-only page".into(),
                    description: "Page content contains images without detectable text.".into(),
                    objects: vec![format!("{} {} obj", page.obj, page.gen)],
                    evidence: evidence.clone(),
                    remediation: Some("Review for deceptive overlays or lures.".into()),
                    meta,
                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }
            if page.invisible_text {
                let mut meta = std::collections::HashMap::new();
                meta.insert("page.number".into(), page.page_number.to_string());
                if let Some(c) = &coord {
                    meta.insert("content.coord".into(), c.clone());
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "content_invisible_text".into(),
                    severity: Severity::Low,
                    confidence: Confidence::Heuristic,
                    impact: None,
                    title: "Invisible text rendering".into(),
                    description: "Content stream suggests invisible text rendering mode.".into(),
                    objects: vec![format!("{} {} obj", page.obj, page.gen)],
                    evidence: evidence.clone(),
                    remediation: Some("Inspect for hidden text or overlays.".into()),
                    meta,
                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }
            if has_image && page_has_uri_annot(ctx, dict) {
                let mut meta = std::collections::HashMap::new();
                meta.insert("page.number".into(), page.page_number.to_string());
                if let Some(c) = &coord {
                    meta.insert("content.coord".into(), c.clone());
                }
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "content_overlay_link".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Heuristic,
                    impact: None,
                    title: "Potential overlay link".into(),
                    description: "Page combines image content with URI annotations.".into(),
                    objects: vec![format!("{} {} obj", page.obj, page.gen)],
                    evidence,
                    remediation: Some("Inspect annotation overlays and link targets.".into()),
                    meta,
                    reader_impacts: Vec::new(),
                    action_type: None,
                    action_target: None,
                    action_initiation: None,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }
        }
        Ok(findings)
    }
}

fn first_coord(page: &sis_pdf_core::content_index::PageContent) -> Option<(f32, f32)> {
    if let Some(p) = page.image_points.first() {
        return Some(*p);
    }
    page.text_points.first().copied()
}

#[cfg(test)]
mod tests {
    use super::{detect_rendered_script_lure, uri_note_value};

    #[test]
    fn uri_note_value_truncates_long_values() {
        let value = format!("https://example.com/{}", "a".repeat(200));
        let note = uri_note_value(&value);
        assert!(note.ends_with("..."));
        assert!(note.len() <= 123);
    }

    #[test]
    fn uri_note_value_keeps_short_values() {
        let value = "https://example.com/reset";
        assert_eq!(uri_note_value(value), value);
    }

    #[test]
    fn rendered_script_lure_detects_script_tag_in_text_operator_context() {
        let data = b"BT (XSS Payload: <script>alert('x')</script>) Tj ET";
        assert_eq!(detect_rendered_script_lure(data), Some("<script"));
    }

    #[test]
    fn rendered_script_lure_detects_javascript_uri_in_text_operator_context() {
        let data = b"BT (Click javascript:alert(1) now) Tj ET";
        assert_eq!(detect_rendered_script_lure(data), Some("javascript:"));
    }

    #[test]
    fn rendered_script_lure_ignores_marker_without_text_operator_context() {
        let data = b"<< /Subtype /XML /Note <script>alert(1)</script> >>";
        assert_eq!(detect_rendered_script_lure(data), None);
    }
}

#[cfg(test)]
mod keyword_tests {
    use super::matched_keyword_labels;

    #[test]
    fn matched_keyword_labels_collects_expected_tokens() {
        let keywords: &[(&[u8], &str)] =
            &[(b"invoice", "invoice"), (b"verify", "verify"), (b"secure", "secure")];
        let labels = matched_keyword_labels(b"please verify this invoice now", keywords);
        assert!(labels.contains(&"invoice".to_string()));
        assert!(labels.contains(&"verify".to_string()));
        assert!(!labels.contains(&"secure".to_string()));
    }
}

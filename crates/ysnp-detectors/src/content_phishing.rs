use anyhow::Result;

use ysnp_core::content_index::build_content_index;
use ysnp_core::detect::{Cost, Detector, Needs};
use ysnp_core::model::{AttackSurface, Confidence, Finding, Severity};
use ysnp_core::scan::span_to_evidence;

use crate::{
    extract_strings_with_span, page_has_uri_annot,
    entry_dict,
};

pub struct ContentPhishingDetector;

impl Detector for ContentPhishingDetector {
    fn id(&self) -> &'static str {
        "content_phishing"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::ContentPhishing
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }
    fn cost(&self) -> Cost {
        Cost::Moderate
    }
    fn run(&self, ctx: &ysnp_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let keywords: &[&[u8]] = &[b"invoice", b"secure", b"view document", b"account", b"verify"];
        let mut has_keyword = false;
        let mut evidence = Vec::new();
        for entry in &ctx.graph.objects {
            for (bytes, span) in extract_strings_with_span(entry) {
                let lower = bytes.to_ascii_lowercase();
                if keywords
                    .iter()
                    .any(|k| lower.windows(k.len()).any(|w| w == *k))
                {
                    has_keyword = true;
                    evidence.push(span_to_evidence(span, "Phishing-like keyword"));
                    break;
                }
            }
            if has_keyword {
                break;
            }
        }
        if !has_keyword {
            return Ok(Vec::new());
        }
        let has_uri = ctx.graph.objects.iter().any(|e| {
            if let Some(dict) = entry_dict(e) {
                dict.get_first(b"/URI").is_some()
            } else {
                false
            }
        });
        if has_uri {
            return Ok(vec![Finding {
                id: String::new(),
                surface: self.surface(),
                kind: "content_phishing".into(),
                severity: Severity::Medium,
                confidence: Confidence::Heuristic,
                title: "Potential phishing content".into(),
                description:
                    "Detected phishing-like keywords alongside external URI actions.".into(),
                objects: vec!["content".into()],
                evidence,
                remediation: Some("Manually review page content and links.".into()),
                meta: Default::default(),
                yara: None,
            }]);
        }
        Ok(Vec::new())
    }
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
    fn run(&self, ctx: &ysnp_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let pages = build_content_index(ctx);
        for page in pages {
            let page_entry = ctx.graph.get_object(page.obj, page.gen);
            let Some(entry) = page_entry else { continue };
            let Some(dict) = entry_dict(entry) else { continue };
            let evidence = vec![span_to_evidence(entry.full_span, "Page object")];
            let has_image = !page.image_points.is_empty();
            let has_text = !page.text_points.is_empty();
            let coord = first_coord(&page)
                .map(|(x, y)| format!("x={:.2} y={:.2}", x, y));

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
                    title: "Image-only page".into(),
                    description: "Page content contains images without detectable text.".into(),
                    objects: vec![format!("{} {} obj", page.obj, page.gen)],
                    evidence: evidence.clone(),
                    remediation: Some("Review for deceptive overlays or lures.".into()),
                    meta,
                    yara: None,
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
                    title: "Invisible text rendering".into(),
                    description: "Content stream suggests invisible text rendering mode.".into(),
                    objects: vec![format!("{} {} obj", page.obj, page.gen)],
                    evidence: evidence.clone(),
                    remediation: Some("Inspect for hidden text or overlays.".into()),
                    meta,
                    yara: None,
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
                    title: "Potential overlay link".into(),
                    description: "Page combines image content with URI annotations.".into(),
                    objects: vec![format!("{} {} obj", page.obj, page.gen)],
                    evidence,
                    remediation: Some("Inspect annotation overlays and link targets.".into()),
                    meta,
                    yara: None,
                });
            }
        }
        Ok(findings)
    }
}

fn first_coord(page: &ysnp_core::content_index::PageContent) -> Option<(f32, f32)> {
    if let Some(p) = page.image_points.first() {
        return Some(*p);
    }
    page.text_points.first().copied()
}

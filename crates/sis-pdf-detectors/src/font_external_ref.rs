use anyhow::Result;
use std::collections::HashSet;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfDict};
use sis_pdf_pdf::typed_graph::EdgeType;

use crate::entry_dict;

pub struct FontExternalReferenceDetector;

impl Detector for FontExternalReferenceDetector {
    fn id(&self) -> &'static str {
        "font_external_reference"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::StreamsAndFilters
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH | Needs::STREAM_INDEX
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Build typed graph to find external actions
        let typed_graph = ctx.build_typed_graph();

        // Find all objects with external references
        let mut external_objects = HashSet::new();
        for edge in &typed_graph.edges {
            match &edge.edge_type {
                EdgeType::UriTarget | EdgeType::LaunchTarget | EdgeType::GoToRTarget => {
                    external_objects.insert(edge.src);
                }
                _ => {}
            }
        }

        if external_objects.is_empty() {
            return Ok(findings);
        }

        // Find font dictionaries that reference external objects
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else {
                continue;
            };

            // Check if this is a font descriptor or font dictionary
            let is_font_related = is_font_dict(dict) || is_font_descriptor(dict);
            if !is_font_related {
                continue;
            }

            // Check if any values in the dictionary point to external objects
            let mut referenced_external = Vec::new();
            for font_key in [
                b"/FontFile" as &[u8],
                b"/FontFile2",
                b"/FontFile3",
                b"/URI",
                b"/F",
                b"/UF",
            ] {
                // Check if the referenced object has external references
                if let Some((_, obj_ref)) = dict.get_first(font_key) {
                    if let PdfAtom::Ref { obj, gen } = &obj_ref.atom {
                        if external_objects.contains(&(*obj, *gen)) {
                            referenced_external.push((
                                String::from_utf8_lossy(font_key).to_string(),
                                (*obj, *gen),
                            ));
                        }
                    }
                }
            }

            // Also check for /FS key with /URL value (file specification)
            if let Some((_, fs_obj)) = dict.get_first(b"/FS") {
                if let PdfAtom::Name(name) = &fs_obj.atom {
                    if name.raw.as_ref() == b"/URL" {
                        referenced_external
                            .push(("/FS /URL".to_string(), (entry.obj, entry.gen)));
                    }
                }
            }

            if !referenced_external.is_empty() {
                let mut meta = std::collections::HashMap::new();
                meta.insert(
                    "font.object_id".into(),
                    format!("{} {} obj", entry.obj, entry.gen),
                );
                meta.insert(
                    "font.external_ref_count".into(),
                    referenced_external.len().to_string(),
                );

                let ref_keys: Vec<String> =
                    referenced_external.iter().map(|(k, _)| k.clone()).collect();
                meta.insert("font.external_ref_keys".into(), ref_keys.join(", "));

                let ref_objects: Vec<String> = referenced_external
                    .iter()
                    .map(|(_, (obj, gen))| format!("{} {} obj", obj, gen))
                    .collect();

                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "font.external_reference".into(),
                    severity: Severity::High,
                    confidence: Confidence::Probable,
                    title: "Font with external reference detected".into(),
                    description: format!(
                        "Font dictionary contains references to external resources ({}). \
                         This could allow attackers to load malicious fonts from external sources.",
                        ref_keys.join(", ")
                    ),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)]
                        .into_iter()
                        .chain(ref_objects)
                        .collect(),
                    evidence: vec![span_to_evidence(entry.full_span, "Font with external ref")],
                    remediation: Some(
                        "Remove external font references or validate that external fonts are from trusted sources only.".into(),
                    ),
                    meta,
                    yara: None,
                    position: None,
                    positions: Vec::new(),
                });
            }
        }

        Ok(findings)
    }
}

/// Check if a dictionary appears to be a font dictionary
fn is_font_dict(dict: &PdfDict) -> bool {
    dict.entries
        .iter()
        .any(|(k, v)| {
            k.raw.as_ref() == b"/Type"
                && matches!(&v.atom, PdfAtom::Name(n) if n.raw.as_ref() == b"/Font")
        })
        || dict.entries.iter().any(|(k, _)| {
            k.raw.as_ref() == b"/BaseFont"
                || k.raw.as_ref() == b"/FontDescriptor"
                || k.raw.as_ref() == b"/ToUnicode"
        })
}

/// Check if a dictionary appears to be a font descriptor
fn is_font_descriptor(dict: &PdfDict) -> bool {
    dict.entries.iter().any(|(k, _)| {
        k.raw.as_ref() == b"/FontFile"
            || k.raw.as_ref() == b"/FontFile2"
            || k.raw.as_ref() == b"/FontFile3"
            || k.raw.as_ref() == b"/FontName"
            || k.raw.as_ref() == b"/FontBBox"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sis_pdf_pdf::object::PdfName;

    #[test]
    fn test_is_font_dict() {
        let mut dict = PdfDict::new();
        assert!(!is_font_dict(&dict));

        dict.entries.push((
            PdfName::from("/Type"),
            PdfAtom::Name(PdfName::from("/Font")),
        ));
        assert!(is_font_dict(&dict));
    }

    #[test]
    fn test_is_font_descriptor() {
        let mut dict = PdfDict::new();
        assert!(!is_font_descriptor(&dict));

        dict.entries
            .push((PdfName::from("/FontFile"), PdfAtom::Null));
        assert!(is_font_descriptor(&dict));
    }
}

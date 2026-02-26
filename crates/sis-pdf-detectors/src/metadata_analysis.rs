use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::object::{PdfAtom, PdfObj};

pub struct MetadataAnalysisDetector;

impl Detector for MetadataAnalysisDetector {
    fn id(&self) -> &'static str {
        "metadata_analysis"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::Metadata
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Cheap
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Analyze /Info dictionary
        if let Some(trailer) = ctx.graph.trailers.last() {
            if let Some((_, info_obj)) = trailer.get_first(b"/Info") {
                analyze_info_dict(ctx, info_obj, &mut findings);
            }
        }

        // Analyze XMP metadata
        analyze_xmp_metadata(ctx, &mut findings);

        Ok(findings)
    }
}

fn analyze_info_dict(
    ctx: &sis_pdf_core::scan::ScanContext,
    info_obj: &PdfObj,
    findings: &mut Vec<Finding>,
) {
    let info_dict = match resolve_to_dict(&ctx.graph, info_obj) {
        Some(dict) => dict,
        None => return,
    };

    let mut meta = HashMap::new();
    let mut suspicious_keys = Vec::new();

    // Check for suspiciously large /Info dict
    let info_size = info_dict.entries.len();
    if info_size > 20 {
        meta.insert("info.key_count".into(), info_size.to_string());
        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::Metadata,
            kind: "info_dict_oversized".into(),
            severity: Severity::Low,
            confidence: Confidence::Probable,
            impact: Impact::Unknown,
            title: "Oversized Info dictionary".into(),
            description: format!(
                "/Info dictionary contains {} keys (normal: 5-10). May hide data.",
                info_size
            ),
            objects: vec!["info".into()],
            evidence: vec![span_to_evidence(info_dict.span, "Info dictionary")],
            remediation: Some("Inspect unusual metadata keys for steganography.".into()),
            meta: meta.clone(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            positions: Vec::new(),
        });
    }

    // Check for suspicious Producer/Creator values
    if let Some((_, producer)) = info_dict.get_first(b"/Producer") {
        if let PdfAtom::Str(s) = &producer.atom {
            let bytes = crate::string_bytes(s);
            let producer_str = String::from_utf8_lossy(&bytes);
            if is_suspicious_producer(&producer_str) {
                suspicious_keys.push(format!("Producer: {}", producer_str));
            }
            meta.insert("info.producer".into(), producer_str.to_string());
        }
    }

    if let Some((_, creator)) = info_dict.get_first(b"/Creator") {
        if let PdfAtom::Str(s) = &creator.atom {
            let bytes = crate::string_bytes(s);
            let creator_str = String::from_utf8_lossy(&bytes);
            if is_suspicious_creator(&creator_str) {
                suspicious_keys.push(format!("Creator: {}", creator_str));
            }
            meta.insert("info.creator".into(), creator_str.to_string());
        }
    }

    // Check for unusual keys (not standard PDF keys)
    let standard_keys: Vec<&[u8]> = vec![
        b"/Title",
        b"/Author",
        b"/Subject",
        b"/Keywords",
        b"/Creator",
        b"/Producer",
        b"/CreationDate",
        b"/ModDate",
        b"/Trapped",
    ];

    for (key, _) in &info_dict.entries {
        if !standard_keys.contains(&key.decoded.as_slice()) {
            let key_str = String::from_utf8_lossy(&key.decoded);
            suspicious_keys.push(format!("Unusual key: {}", key_str));
        }
    }

    if !suspicious_keys.is_empty() {
        meta.insert("info.suspicious_keys_count".into(), suspicious_keys.len().to_string());
        meta.insert("info.suspicious_keys".into(), suspicious_keys.join("; "));

        findings.push(Finding {
            id: String::new(),
            surface: AttackSurface::Metadata,
            kind: "info_dict_suspicious".into(),
            severity: Severity::Low,
            confidence: Confidence::Probable,
            impact: Impact::Unknown,
            title: "Suspicious Info dictionary content".into(),
            description: format!(
                "/Info dictionary contains suspicious values or unusual keys: {}",
                suspicious_keys.join(", ")
            ),
            objects: vec!["info".into()],
            evidence: vec![span_to_evidence(info_dict.span, "Info dictionary")],
            remediation: Some("Inspect metadata for malware signatures or steganography.".into()),
            meta,
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
            positions: Vec::new(),
        });
    }
}

fn analyze_xmp_metadata(ctx: &sis_pdf_core::scan::ScanContext, findings: &mut Vec<Finding>) {
    // Find Metadata stream in catalog
    let catalog = ctx
        .graph
        .trailers
        .last()
        .and_then(|t| t.get_first(b"/Root"))
        .and_then(|(_, root)| resolve_to_dict(&ctx.graph, root));

    if let Some(catalog) = catalog {
        if let Some((_, metadata_obj)) = catalog.get_first(b"/Metadata") {
            if let Some(entry) = ctx.graph.resolve_ref(metadata_obj) {
                if let PdfAtom::Stream(st) = &entry.atom {
                    let mut meta = HashMap::new();
                    meta.insert("xmp.size".into(), st.data_span.len().to_string());

                    // Check for excessively large XMP
                    if st.data_span.len() > 100_000 {
                        findings.push(Finding {
                            id: String::new(),
                            surface: AttackSurface::Metadata,
                            kind: "xmp_oversized".into(),
                            severity: Severity::Low,
                            confidence: Confidence::Strong,
            impact: Impact::Unknown,
                            title: "Oversized XMP metadata".into(),
                            description: format!(
                                "XMP metadata stream is {} bytes (normal: <10KB). May hide embedded data.",
                                st.data_span.len()
                            ),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: vec![span_to_evidence(st.data_span, "XMP metadata stream")],
                            remediation: Some("Inspect XMP content for steganography.".into()),
                            meta,
                            yara: None,
                            positions: Vec::new(),
                        ..Finding::default()
                        });
                    }

                    // Basic XMP content analysis (if decodable)
                    // Note: Full XMP parsing would require XML parsing, keeping this simple
                }
            }
        }
    }
}

fn is_suspicious_producer(s: &str) -> bool {
    let suspicious_patterns = ["user", "admin", "test", "unknown", "null", "script"];

    let lower = s.to_lowercase();
    suspicious_patterns.iter().any(|p| lower.contains(p))
}

fn is_suspicious_creator(s: &str) -> bool {
    let suspicious_patterns =
        ["script", "python", "perl", "ruby", "php", "powershell", "cmd", "bash", "unknown", "null"];

    let lower = s.to_lowercase();
    suspicious_patterns.iter().any(|p| lower.contains(p))
}

fn resolve_to_dict<'a>(
    graph: &'a sis_pdf_pdf::ObjectGraph<'a>,
    obj: &PdfObj<'a>,
) -> Option<sis_pdf_pdf::object::PdfDict<'a>> {
    match &obj.atom {
        PdfAtom::Dict(d) => Some(d.clone()),
        PdfAtom::Stream(st) => Some(st.dict.clone()),
        PdfAtom::Ref { .. } => graph.resolve_ref(obj).and_then(|e| match &e.atom {
            PdfAtom::Dict(d) => Some(d.clone()),
            PdfAtom::Stream(st) => Some(st.dict.clone()),
            _ => None,
        }),
        _ => None,
    }
}

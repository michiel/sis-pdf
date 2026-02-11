use anyhow::Result;
use sha2::{Digest, Sha256};
use sis_pdf_core::canonical::canonical_filter_chain;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_core::timeout::TimeoutChecker;
use sis_pdf_pdf::content::parse_content_ops;
use sis_pdf_pdf::object::PdfAtom;

use crate::entry_dict;

pub struct ParserDivergenceDetector;

impl Detector for ParserDivergenceDetector {
    fn id(&self) -> &'static str {
        "parser_divergence"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::FileStructure
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH | Needs::STREAM_DECODE
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let timeout = TimeoutChecker::new(std::time::Duration::from_millis(150));
        let mut findings = Vec::new();
        let mut duplicate_objects = Vec::new();
        let mut content_anomaly_objects = Vec::new();
        let mut divergence_reasons = Vec::new();

        let mut groups: std::collections::HashMap<String, Vec<StreamProfile>> =
            std::collections::HashMap::new();
        for entry in &ctx.graph.objects {
            let PdfAtom::Stream(stream) = &entry.atom else {
                continue;
            };
            let start = stream.data_span.start as usize;
            let end = stream.data_span.end as usize;
            if start >= end || end > ctx.bytes.len() {
                continue;
            }
            let mut hasher = Sha256::new();
            hasher.update(&ctx.bytes[start..end]);
            let hash = format!("{:x}", hasher.finalize());
            let filters = canonical_filter_chain(stream);
            groups.entry(hash).or_default().push(StreamProfile {
                object_ref: format!("{} {} obj", entry.obj, entry.gen),
                span: stream.data_span,
                filters: if filters.is_empty() { "none".into() } else { filters.join(" -> ") },
            });
        }

        for (hash, profiles) in &groups {
            if profiles.len() < 2 {
                continue;
            }
            let unique_filters = profiles
                .iter()
                .map(|profile| profile.filters.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            if unique_filters.len() < 2 {
                continue;
            }
            let mut objects =
                profiles.iter().map(|profile| profile.object_ref.clone()).collect::<Vec<_>>();
            objects.sort();
            objects.dedup();
            duplicate_objects.extend(objects.iter().cloned());
            let mut meta = std::collections::HashMap::new();
            meta.insert("stream.hash".into(), hash.clone());
            meta.insert("stream.duplicate_count".into(), profiles.len().to_string());
            meta.insert("stream.unique_filter_count".into(), unique_filters.len().to_string());
            meta.insert(
                "stream.filter_chains".into(),
                unique_filters.into_iter().collect::<Vec<_>>().join(" | "),
            );
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::StreamsAndFilters,
                kind: "duplicate_stream_filters".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                impact: Some(Impact::Medium),
                title: "Duplicate stream payload with divergent filters".into(),
                description:
                    "Identical stream payload bytes are present under different filter chains, which can trigger parser-specific decoding behaviour."
                        .into(),
                objects,
                evidence: profiles
                    .iter()
                    .map(|profile| span_to_evidence(profile.span, "Duplicate stream payload"))
                    .collect(),
                remediation: Some(
                    "Normalise and decode duplicate payload streams across multiple parser profiles before trust decisions."
                        .into(),
                ),
                meta,
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }

        if !duplicate_objects.is_empty() {
            divergence_reasons.push("duplicate_stream_filters".to_string());
        }

        for entry in &ctx.graph.objects {
            if timeout.check().is_err() {
                break;
            }
            let PdfAtom::Stream(stream) = &entry.atom else {
                continue;
            };
            let Some(dict) = entry_dict(entry) else {
                continue;
            };
            let likely_content_stream = dict.get_first(b"/Length").is_some()
                && (dict.get_first(b"/Filter").is_none() || dict.get_first(b"/Type").is_none());
            if !likely_content_stream {
                continue;
            }
            let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, stream) else {
                continue;
            };
            let ops = parse_content_ops(&decoded.data);
            if ops.is_empty() {
                continue;
            }
            let mut unknown_ops = 0usize;
            let mut arity_mismatches = 0usize;
            let mut samples = Vec::new();
            for op in &ops {
                if !is_known_content_operator(op.op.as_str()) {
                    unknown_ops += 1;
                    if samples.len() < 8 {
                        samples.push(format!("unknown:{}", op.op));
                    }
                }
                if let Some(expected) = expected_operand_count(op.op.as_str()) {
                    if op.operands.len() != expected {
                        arity_mismatches += 1;
                        if samples.len() < 8 {
                            samples.push(format!("arity:{}={}", op.op, op.operands.len()));
                        }
                    }
                }
            }
            if unknown_ops == 0 && arity_mismatches == 0 {
                continue;
            }
            let object_ref = format!("{} {} obj", entry.obj, entry.gen);
            content_anomaly_objects.push(object_ref.clone());
            let mut meta = std::collections::HashMap::new();
            meta.insert("content.op_count".into(), ops.len().to_string());
            meta.insert("content.unknown_ops".into(), unknown_ops.to_string());
            meta.insert("content.arity_mismatches".into(), arity_mismatches.to_string());
            if !samples.is_empty() {
                meta.insert("content.samples".into(), samples.join(", "));
            }
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::FileStructure,
                kind: "content_stream_anomaly".into(),
                severity: if unknown_ops + arity_mismatches >= 3 {
                    Severity::Medium
                } else {
                    Severity::Low
                },
                confidence: Confidence::Probable,
                impact: Some(Impact::Low),
                title: "Content stream syntax anomaly".into(),
                description:
                    "Decoded content stream contains unknown operators or suspicious operand counts that can yield parser-dependent rendering."
                        .into(),
                objects: vec![object_ref],
                evidence: vec![span_to_evidence(stream.data_span, "Decoded content stream")],
                remediation: Some(
                    "Validate content stream syntax and compare rendering behaviour across strict and permissive parser modes."
                        .into(),
                ),
                meta,
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }

        if !content_anomaly_objects.is_empty() {
            divergence_reasons.push("content_stream_anomaly".to_string());
        }
        if ctx.graph.deviations.iter().any(|dev| dev.kind.starts_with("xref_")) {
            divergence_reasons.push("xref_deviation_present".to_string());
        }
        if has_linearization_signal(ctx) {
            divergence_reasons.push("linearization_integrity_signal".to_string());
        }

        let mut divergence_score = 0u32;
        if divergence_reasons.iter().any(|reason| reason == "duplicate_stream_filters") {
            divergence_score += 2;
        }
        if divergence_reasons.iter().any(|reason| reason == "content_stream_anomaly") {
            divergence_score += 2;
        }
        if divergence_reasons.iter().any(|reason| reason == "xref_deviation_present") {
            divergence_score += 1;
        }
        if divergence_reasons.iter().any(|reason| reason == "linearization_integrity_signal") {
            divergence_score += 1;
        }
        if divergence_score >= 3 {
            let mut objects = duplicate_objects;
            objects.extend(content_anomaly_objects);
            objects.sort();
            objects.dedup();
            let (severity, confidence) = if divergence_score >= 5 {
                (Severity::High, Confidence::Strong)
            } else if divergence_score >= 4 {
                (Severity::Medium, Confidence::Strong)
            } else {
                (Severity::Medium, Confidence::Probable)
            };
            let mut meta = std::collections::HashMap::new();
            meta.insert("parser_divergence.score".into(), divergence_score.to_string());
            meta.insert("parser_divergence.reasons".into(), divergence_reasons.join(","));
            findings.push(Finding {
                id: String::new(),
                surface: AttackSurface::FileStructure,
                kind: "parser_divergence_risk".into(),
                severity,
                confidence,
                impact: Some(Impact::High),
                title: "Parser divergence risk".into(),
                description:
                    "Multiple divergence indicators suggest the PDF may render differently across readers or parser strictness levels."
                        .into(),
                objects,
                evidence: Vec::new(),
                remediation: Some(
                    "Replay analysis with multiple parser profiles and treat inconsistent render paths as high-risk evasion."
                        .into(),
                ),
                meta,
                yara: None,
                position: None,
                positions: Vec::new(),
                ..Finding::default()
            });
        }

        Ok(findings)
    }
}

#[derive(Clone)]
struct StreamProfile {
    object_ref: String,
    span: sis_pdf_pdf::span::Span,
    filters: String,
}

fn has_linearization_signal(ctx: &sis_pdf_core::scan::ScanContext<'_>) -> bool {
    ctx.graph
        .objects
        .iter()
        .filter_map(entry_dict)
        .any(|dict| dict.get_first(b"/Linearized").is_some())
}

fn is_known_content_operator(operator: &str) -> bool {
    matches!(
        operator,
        "q" | "Q"
            | "cm"
            | "w"
            | "J"
            | "j"
            | "M"
            | "d"
            | "ri"
            | "i"
            | "gs"
            | "m"
            | "l"
            | "c"
            | "v"
            | "y"
            | "h"
            | "re"
            | "S"
            | "s"
            | "f"
            | "F"
            | "f*"
            | "B"
            | "B*"
            | "b"
            | "b*"
            | "n"
            | "W"
            | "W*"
            | "BT"
            | "ET"
            | "Tc"
            | "Tw"
            | "Tz"
            | "TL"
            | "Tf"
            | "Tr"
            | "Ts"
            | "Td"
            | "TD"
            | "Tm"
            | "T*"
            | "Tj"
            | "TJ"
            | "'"
            | "\""
            | "CS"
            | "cs"
            | "SC"
            | "SCN"
            | "sc"
            | "scn"
            | "G"
            | "g"
            | "RG"
            | "rg"
            | "K"
            | "k"
            | "sh"
            | "Do"
            | "MP"
            | "DP"
            | "BMC"
            | "BDC"
            | "EMC"
            | "BX"
            | "EX"
    )
}

fn expected_operand_count(operator: &str) -> Option<usize> {
    match operator {
        "q" | "Q" | "h" | "S" | "s" | "f" | "F" | "f*" | "B" | "B*" | "b" | "b*" | "n" | "W"
        | "W*" | "BT" | "ET" | "T*" | "TJ" | "'" | "\"" => Some(0),
        "m" | "l" => Some(2),
        "v" | "y" => Some(4),
        "c" => Some(6),
        "re" => Some(4),
        "cm" => Some(6),
        "Tf" => Some(2),
        "Td" | "TD" => Some(2),
        "Tm" => Some(6),
        "Tj" => Some(1),
        "Do" => Some(1),
        _ => None,
    }
}

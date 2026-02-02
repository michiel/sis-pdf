use std::collections::{HashMap, HashSet};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::graph_walk::ObjRef;
use sis_pdf_core::model::{
    AttackSurface, Confidence, EvidenceSource, EvidenceSpan, Finding, Severity,
};
use sis_pdf_core::page_tree::build_page_tree;
use sis_pdf_core::scan::{span_to_evidence, ScanContext};
use sis_pdf_pdf::content::{parse_content_ops, ContentOp, ContentOperand};
use sis_pdf_pdf::graph::ObjEntry;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStream};

struct StreamCandidate<'a> {
    stream: PdfStream<'a>,
    obj_ref: ObjRef,
}

pub struct VectorGraphicsDetector;

impl Detector for VectorGraphicsDetector {
    fn id(&self) -> &'static str {
        "vector_graphics_anomaly"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::Images
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH | Needs::PAGE_CONTENT | Needs::STREAM_DECODE
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &ScanContext) -> anyhow::Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let tree = build_page_tree(&ctx.graph);
        for page in &tree.pages {
            let page_ref = ObjRef {
                obj: page.obj,
                gen: page.gen,
            };
            let entry = ctx.graph.get_object(page.obj, page.gen);
            let dict = entry.and_then(entry_dict);
            if let Some(dict) = dict {
                let streams = collect_page_streams(ctx, dict, page_ref);
                for candidate in streams {
                    if let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, &candidate.stream) {
                        let ops = parse_content_ops(&decoded.data);
                        let stats = summarize_ops(&ops);
                        if let Some(signal) = stats.should_report() {
                            let mut meta = HashMap::new();
                            meta.insert(
                                "vector.operator_count".into(),
                                stats.total_ops.to_string(),
                            );
                            meta.insert(
                                "vector.path_operator_count".into(),
                                stats.path_ops.to_string(),
                            );
                            meta.insert(
                                "vector.path_ratio".into(),
                                format!("{:.2}", stats.path_ratio()),
                            );
                            meta.insert(
                                "vector.small_rectangles".into(),
                                stats.small_rect_count.to_string(),
                            );
                            if !stats.color_spaces.is_empty() {
                                let joined = stats.color_spaces.iter().cloned().collect::<Vec<_>>();
                                meta.insert("vector.color_spaces".into(), joined.join(","));
                            }
                            meta.insert("vector.page_number".into(), page.number.to_string());
                            meta.insert(
                                "vector.stream.object".into(),
                                format!("{} {} obj", candidate.obj_ref.obj, candidate.obj_ref.gen),
                            );
                            let evidence = stats
                                .candidate_op
                                .as_ref()
                                .map(|op| evidence_for_op(op, &candidate.stream))
                                .unwrap_or_else(|| {
                                    span_to_evidence(
                                        candidate.stream.data_span,
                                        "Vector content stream",
                                    )
                                });
                            findings.push(Finding {
                                id: String::new(),
                                surface: AttackSurface::Images,
                                kind: "vector_graphics_anomaly".into(),
                                severity: signal.severity,
                                confidence: Confidence::Probable,
                                impact: None,
                                title: "Suspicious vector content stream".into(),
                                description: format!(
                                    "Page {} stream uses {} path operators (ratio {:.2}) and {}.",
                                    page.number,
                                    stats.path_ops,
                                    stats.path_ratio(),
                                    signal.reason
                                ),
                                objects: vec![format!(
                                    "{} {} obj",
                                    candidate.obj_ref.obj, candidate.obj_ref.gen
                                )],
                                evidence: vec![evidence],
                                remediation: Some(
                                    "Review the content stream and verify the vector usage.".into(),
                                ),
                                meta,
                                position: None,
                                positions: vec![format!("page:{}", page.number)],
                                yara: None,
                                reader_impacts: Vec::new(),
                                action_type: None,
                                action_target: None,
                                action_initiation: None,
                            });
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

fn entry_dict<'a>(entry: &'a ObjEntry<'a>) -> Option<&'a PdfDict<'a>> {
    match &entry.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    }
}

fn collect_page_streams<'a>(
    ctx: &ScanContext<'a>,
    dict: &PdfDict<'a>,
    page_ref: ObjRef,
) -> Vec<StreamCandidate<'a>> {
    let mut out = Vec::new();
    if let Some((_, obj)) = dict.get_first(b"/Contents") {
        match &obj.atom {
            PdfAtom::Stream(st) => out.push(StreamCandidate {
                stream: st.clone(),
                obj_ref: page_ref,
            }),
            PdfAtom::Array(arr) => {
                for o in arr {
                    if let Some(candidate) = resolve_stream(ctx, o, page_ref) {
                        out.push(candidate);
                    }
                }
            }
            _ => {
                if let Some(candidate) = resolve_stream(ctx, obj, page_ref) {
                    out.push(candidate);
                }
            }
        }
    }
    out
}

fn resolve_stream<'a>(
    ctx: &ScanContext<'a>,
    obj: &PdfObj<'a>,
    fallback: ObjRef,
) -> Option<StreamCandidate<'a>> {
    match &obj.atom {
        PdfAtom::Stream(st) => Some(StreamCandidate {
            stream: st.clone(),
            obj_ref: fallback,
        }),
        PdfAtom::Ref { obj, gen } => {
            ctx.graph
                .get_object(*obj, *gen)
                .and_then(|entry| match &entry.atom {
                    PdfAtom::Stream(st) => Some(StreamCandidate {
                        stream: st.clone(),
                        obj_ref: ObjRef {
                            obj: *obj,
                            gen: *gen,
                        },
                    }),
                    _ => None,
                })
        }
        _ => None,
    }
}

struct VectorStats {
    total_ops: usize,
    path_ops: usize,
    small_rect_count: usize,
    color_spaces: HashSet<String>,
    candidate_op: Option<ContentOp>,
}

struct VectorSignal {
    severity: Severity,
    reason: &'static str,
}

impl VectorStats {
    fn path_ratio(&self) -> f32 {
        if self.total_ops == 0 {
            0.0
        } else {
            self.path_ops as f32 / self.total_ops as f32
        }
    }

    fn should_report(&self) -> Option<VectorSignal> {
        if self.total_ops < 20 {
            return None;
        }
        let ratio = self.path_ratio();
        if self.path_ops >= 250 && ratio > 0.6 {
            let severity = if self.path_ops >= 500 {
                Severity::High
            } else {
                Severity::Medium
            };
            return Some(VectorSignal {
                severity,
                reason: "heavy density of path operators",
            });
        }
        if self.small_rect_count >= 6 {
            return Some(VectorSignal {
                severity: Severity::Medium,
                reason: "repeated tiny rectangles or clipping paths",
            });
        }
        let has_spot_color = self.color_spaces.iter().any(|space| {
            let lower = space.to_ascii_lowercase();
            lower.contains("spot") || lower.contains("separation") || lower.contains("indexed")
        });
        if has_spot_color && self.path_ops >= 80 {
            return Some(VectorSignal {
                severity: Severity::Medium,
                reason: "spot/indexed colors used with vector paths",
            });
        }
        None
    }
}

fn summarize_ops(ops: &[ContentOp]) -> VectorStats {
    let mut stats = VectorStats {
        total_ops: 0,
        path_ops: 0,
        small_rect_count: 0,
        color_spaces: HashSet::new(),
        candidate_op: None,
    };
    for op in ops {
        stats.total_ops += 1;
        if is_path_operator(&op.op) {
            stats.path_ops += 1;
            if stats.candidate_op.is_none() {
                stats.candidate_op = Some(op.clone());
            }
        }
        if op.op == "re" {
            if let Some(area) = rect_area(&op.operands) {
                if area > 0.0 && area < 400.0 {
                    stats.small_rect_count += 1;
                    if stats.candidate_op.is_none() {
                        stats.candidate_op = Some(op.clone());
                    }
                }
            }
        }
        if let Some(space) = color_space_name(op) {
            stats.color_spaces.insert(space);
        }
    }
    stats
}

fn is_path_operator(op: &str) -> bool {
    matches!(
        op,
        "m" | "l"
            | "c"
            | "v"
            | "y"
            | "h"
            | "re"
            | "S"
            | "s"
            | "f"
            | "F"
            | "B"
            | "B*"
            | "b"
            | "b*"
            | "n"
    )
}

fn rect_area(operands: &[ContentOperand]) -> Option<f32> {
    let nums = operands
        .iter()
        .filter_map(|o| match o {
            ContentOperand::Number(n) => Some(*n),
            _ => None,
        })
        .collect::<Vec<_>>();
    if nums.len() < 4 {
        return None;
    }
    let width = nums[2].abs();
    let height = nums[3].abs();
    Some(width * height)
}

fn color_space_name(op: &ContentOp) -> Option<String> {
    match op.op.as_str() {
        "CS" | "cs" | "SC" | "sc" => op.operands.get(0).and_then(|operand| match operand {
            ContentOperand::Name(name) => Some(name.clone()),
            _ => None,
        }),
        "SCN" | "scn" => op.operands.get(0).and_then(|operand| match operand {
            ContentOperand::Name(name) => Some(name.clone()),
            _ => None,
        }),
        _ => None,
    }
}

fn evidence_for_op(op: &ContentOp, stream: &PdfStream) -> EvidenceSpan {
    let length = op.span.end.saturating_sub(op.span.start) as u32;
    EvidenceSpan {
        source: EvidenceSource::Decoded,
        offset: op.span.start,
        length: length.max(1),
        origin: Some(stream.data_span),
        note: Some(format!("Vector operator {}", op.op)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sis_pdf_pdf::content::ContentOperand;

    fn make_op(op: &str, operands: Vec<ContentOperand>) -> ContentOp {
        ContentOp {
            op: op.to_string(),
            operands,
            span: sis_pdf_pdf::span::Span { start: 0, end: 1 },
        }
    }

    #[test]
    fn path_density_triggers() {
        let mut ops = Vec::new();
        for _ in 0..130 {
            ops.push(make_op("m", vec![]));
            ops.push(make_op("l", vec![]));
        }
        let stats = summarize_ops(&ops);
        assert!(stats.should_report().is_some());
    }

    #[test]
    fn spot_color_triggers() {
        let mut ops = Vec::new();
        for _ in 0..90 {
            ops.push(make_op("m", vec![]));
        }
        ops.push(make_op("cs", vec![ContentOperand::Name("SpotRed".into())]));
        let stats = summarize_ops(&ops);
        let signal = stats.should_report();
        assert!(signal.is_some());
        assert_eq!(
            signal.unwrap().reason,
            "spot/indexed colors used with vector paths"
        );
    }
}

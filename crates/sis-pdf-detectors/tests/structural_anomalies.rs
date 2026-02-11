mod common;

use std::borrow::Cow;
use std::collections::HashMap;

use common::default_scan_opts;
use sis_pdf_core::detect::Detector;
use sis_pdf_core::scan::ScanContext;
use sis_pdf_detectors::strict::StrictParseDeviationDetector;
use sis_pdf_detectors::structural_anomalies::StructuralAnomaliesDetector;
use sis_pdf_pdf::graph::{Deviation, ObjEntry, ObjProvenance, ObjectGraph, XrefSectionSummary};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfName, PdfObj, PdfStream};
use sis_pdf_pdf::span::Span;

fn leak_bytes(data: Vec<u8>) -> &'static [u8] {
    let boxed = data.into_boxed_slice();
    Box::leak(boxed)
}

fn pdf_name(name: &'static str) -> PdfName<'static> {
    PdfName {
        span: Span { start: 0, end: name.len() as u64 },
        raw: Cow::Borrowed(name.as_bytes()),
        decoded: name.as_bytes().to_vec(),
    }
}

fn pdf_ref(obj: u32, gen: u16) -> PdfObj<'static> {
    PdfObj { span: Span { start: 0, end: 0 }, atom: PdfAtom::Ref { obj, gen } }
}

fn pdf_int(value: i64) -> PdfObj<'static> {
    PdfObj { span: Span { start: 0, end: 0 }, atom: PdfAtom::Int(value) }
}
fn build_context(
    bytes: &'static [u8],
    objects: Vec<ObjEntry<'static>>,
    trailers: Vec<sis_pdf_pdf::object::PdfDict<'static>>,
    startxrefs: Vec<u64>,
) -> ScanContext<'static> {
    build_context_with_xref(bytes, objects, trailers, startxrefs, Vec::new(), Vec::new())
}

fn build_context_with_xref(
    bytes: &'static [u8],
    objects: Vec<ObjEntry<'static>>,
    trailers: Vec<sis_pdf_pdf::object::PdfDict<'static>>,
    startxrefs: Vec<u64>,
    xref_sections: Vec<XrefSectionSummary>,
    deviations: Vec<Deviation>,
) -> ScanContext<'static> {
    let mut index: HashMap<(u32, u16), Vec<usize>> = HashMap::new();
    for (idx, entry) in objects.iter().enumerate() {
        index.entry((entry.obj, entry.gen)).or_default().push(idx);
    }
    let graph = ObjectGraph {
        bytes,
        objects,
        index,
        trailers,
        startxrefs,
        xref_sections,
        deviations,
        telemetry_events: Vec::new(),
    };
    ScanContext::new(bytes, graph, default_scan_opts())
}

#[test]
fn trailer_and_xref_anomalies_detected() {
    let bytes = leak_bytes(vec![0u8; 10]);
    let trailer = PdfDict {
        span: Span { start: 0, end: 0 },
        entries: vec![(
            pdf_name("/Size"),
            PdfObj { span: Span { start: 0, end: 0 }, atom: PdfAtom::Int(5) },
        )],
    };
    let ctx = build_context(bytes, Vec::new(), vec![trailer], vec![20]);
    let detector = StructuralAnomaliesDetector;
    let findings = detector.run(&ctx).expect("detector should run");
    assert!(
        findings.iter().any(|f| f.kind == "pdf.trailer_inconsistent"),
        "Expected trailer inconsistency finding"
    );
    assert!(
        findings.iter().any(|f| f.kind == "xref_start_offset_oob"),
        "Expected startxref OOB finding"
    );
}

#[test]
fn strict_detector_flags_missing_length_and_ascii85() {
    let data = b"secretdata";
    let bytes = leak_bytes(data.to_vec());

    let stream_dict = PdfDict {
        span: Span { start: 0, end: 0 },
        entries: vec![(
            pdf_name("/Filter"),
            PdfObj {
                span: Span { start: 0, end: 0 },
                atom: PdfAtom::Name(pdf_name("ASCII85Decode")),
            },
        )],
    };

    let stream =
        PdfStream { dict: stream_dict, data_span: Span { start: 0, end: data.len() as u64 } };

    let entry = ObjEntry {
        obj: 1,
        gen: 0,
        atom: PdfAtom::Stream(stream),
        header_span: Span { start: 0, end: 0 },
        body_span: Span { start: 0, end: data.len() as u64 },
        full_span: Span { start: 0, end: data.len() as u64 },
        provenance: ObjProvenance::Indirect,
    };

    let trailer = PdfDict { span: Span { start: 0, end: 0 }, entries: Vec::new() };

    let ctx = build_context(bytes, vec![entry], vec![trailer], vec![0]);
    let detector = StrictParseDeviationDetector;
    let findings = detector.run(&ctx).expect("strict detector should run");
    assert!(
        findings.iter().any(|f| f.kind == "stream_missing_length"),
        "Missing length should produce finding"
    );
    assert!(
        findings.iter().any(|f| f.kind == "stream_ascii85_missing_eod"),
        "ASCII85 missing EOD should produce finding"
    );
    assert!(
        findings.iter().any(|f| f.kind == "stream.obfuscated_concealment"),
        "Combined obfuscation finding should be emitted"
    );
}

#[test]
fn trailer_size_noncanonical_detected_with_sparse_object_ids() {
    let bytes = leak_bytes(vec![0u8; 16]);
    let objects = vec![
        ObjEntry {
            obj: 4,
            gen: 0,
            atom: PdfAtom::Null,
            header_span: Span { start: 0, end: 0 },
            body_span: Span { start: 0, end: 0 },
            full_span: Span { start: 0, end: 0 },
            provenance: ObjProvenance::Indirect,
        },
        ObjEntry {
            obj: 11,
            gen: 0,
            atom: PdfAtom::Null,
            header_span: Span { start: 0, end: 0 },
            body_span: Span { start: 0, end: 0 },
            full_span: Span { start: 0, end: 0 },
            provenance: ObjProvenance::Indirect,
        },
    ];
    let trailer = PdfDict {
        span: Span { start: 0, end: 0 },
        entries: vec![(
            pdf_name("/Size"),
            PdfObj { span: Span { start: 0, end: 0 }, atom: PdfAtom::Int(2) },
        )],
    };
    let ctx = build_context(bytes, objects, vec![trailer], vec![0]);
    let detector = StructuralAnomaliesDetector;
    let findings = detector.run(&ctx).expect("detector should run");

    assert!(
        findings.iter().any(|f| f.kind == "pdf.trailer_size_noncanonical"),
        "Expected canonical trailer /Size mismatch finding"
    );
    assert!(
        !findings.iter().any(|f| f.kind == "pdf.trailer_inconsistent"),
        "Object-count mismatch finding should not trigger when /Size equals parsed count"
    );
}

#[test]
fn emits_trailer_root_conflict_with_evasion_metadata() {
    let bytes = leak_bytes(b"%PDF-1.7\n/Root 1 0 R\n/Root 9 0 R\n".to_vec());
    let xref_sections = vec![
        XrefSectionSummary {
            offset: 100,
            kind: "table".into(),
            has_trailer: true,
            prev: None,
            trailer_size: Some(12),
            trailer_root: Some("1 0 R".into()),
        },
        XrefSectionSummary {
            offset: 200,
            kind: "table".into(),
            has_trailer: true,
            prev: Some(100),
            trailer_size: Some(12),
            trailer_root: Some("9 0 R".into()),
        },
    ];
    let ctx = build_context_with_xref(
        bytes,
        Vec::new(),
        Vec::new(),
        vec![100, 200],
        xref_sections,
        Vec::new(),
    );
    let detector = StructuralAnomaliesDetector;
    let findings = detector.run(&ctx).expect("detector should run");
    let finding = findings
        .iter()
        .find(|finding| finding.kind == "trailer_root_conflict")
        .expect("expected trailer_root_conflict");
    assert_eq!(finding.meta.get("evasion.trailer_root_conflict").map(String::as_str), Some("true"));
}

#[test]
fn emits_xref_phantom_entries_from_xref_deviations() {
    let bytes = leak_bytes(b"%PDF-1.7\nxref\n".to_vec());
    let deviations = vec![Deviation {
        kind: "xref_trailer_search_invalid".into(),
        span: Span { start: 0, end: 4 },
        note: Some("invalid trailer".into()),
    }];
    let ctx =
        build_context_with_xref(bytes, Vec::new(), Vec::new(), vec![0], Vec::new(), deviations);
    let detector = StructuralAnomaliesDetector;
    let findings = detector.run(&ctx).expect("detector should run");
    let finding = findings
        .iter()
        .find(|finding| finding.kind == "xref_phantom_entries")
        .expect("expected xref_phantom_entries");
    assert_eq!(finding.meta.get("evasion.xref_phantom_entries").map(String::as_str), Some("true"));
}

#[test]
fn emits_null_object_density_when_ratio_is_high() {
    let bytes = leak_bytes(vec![0u8; 32]);
    let mut objects = Vec::new();
    for obj in 1..=10 {
        let atom = if obj <= 7 { PdfAtom::Null } else { PdfAtom::Int(obj as i64) };
        objects.push(ObjEntry {
            obj,
            gen: 0,
            atom,
            header_span: Span { start: 0, end: 0 },
            body_span: Span { start: 0, end: 0 },
            full_span: Span { start: 0, end: 0 },
            provenance: ObjProvenance::Indirect,
        });
    }
    let ctx = build_context(bytes, objects, Vec::new(), vec![0]);
    let detector = StructuralAnomaliesDetector;
    let findings = detector.run(&ctx).expect("detector should run");
    let finding = findings
        .iter()
        .find(|finding| finding.kind == "null_object_density")
        .expect("expected null_object_density");
    assert_eq!(finding.meta.get("evasion.null_object_density").map(String::as_str), Some("true"));
}

#[test]
fn emits_empty_objstm_padding_for_sparse_object_streams() {
    let bytes = leak_bytes(b"%PDF-1.7\n/ObjStm\n".to_vec());
    let objstm_dict = PdfDict {
        span: Span { start: 0, end: 0 },
        entries: vec![
            (
                pdf_name("/Type"),
                PdfObj {
                    span: Span { start: 0, end: 0 },
                    atom: PdfAtom::Name(pdf_name("/ObjStm")),
                },
            ),
            (pdf_name("/N"), pdf_int(9)),
        ],
    };
    let objstm = ObjEntry {
        obj: 20,
        gen: 0,
        atom: PdfAtom::Stream(PdfStream {
            dict: objstm_dict,
            data_span: Span { start: 0, end: 8 },
        }),
        header_span: Span { start: 0, end: 0 },
        body_span: Span { start: 0, end: 0 },
        full_span: Span { start: 0, end: 0 },
        provenance: ObjProvenance::Indirect,
    };
    let ctx = build_context(bytes, vec![objstm], Vec::new(), vec![0]);
    let detector = StructuralAnomaliesDetector;
    let findings = detector.run(&ctx).expect("detector should run");
    let finding = findings
        .iter()
        .find(|finding| finding.kind == "empty_objstm_padding")
        .expect("expected empty_objstm_padding");
    assert_eq!(finding.meta.get("evasion.empty_objstm_padding").map(String::as_str), Some("true"));
}

#[test]
fn emits_structural_decoy_objects_when_unreachable_cluster_exists() {
    let bytes = leak_bytes(vec![0u8; 64]);
    let mut objects = vec![
        ObjEntry {
            obj: 1,
            gen: 0,
            atom: PdfAtom::Dict(PdfDict {
                span: Span { start: 0, end: 0 },
                entries: vec![
                    (
                        pdf_name("/Type"),
                        PdfObj {
                            span: Span { start: 0, end: 0 },
                            atom: PdfAtom::Name(pdf_name("/Catalog")),
                        },
                    ),
                    (pdf_name("/Pages"), pdf_ref(2, 0)),
                ],
            }),
            header_span: Span { start: 0, end: 0 },
            body_span: Span { start: 0, end: 0 },
            full_span: Span { start: 0, end: 0 },
            provenance: ObjProvenance::Indirect,
        },
        ObjEntry {
            obj: 2,
            gen: 0,
            atom: PdfAtom::Dict(PdfDict {
                span: Span { start: 0, end: 0 },
                entries: vec![
                    (
                        pdf_name("/Type"),
                        PdfObj {
                            span: Span { start: 0, end: 0 },
                            atom: PdfAtom::Name(pdf_name("/Pages")),
                        },
                    ),
                    (
                        pdf_name("/Kids"),
                        PdfObj {
                            span: Span { start: 0, end: 0 },
                            atom: PdfAtom::Array(vec![pdf_ref(3, 0)]),
                        },
                    ),
                ],
            }),
            header_span: Span { start: 0, end: 0 },
            body_span: Span { start: 0, end: 0 },
            full_span: Span { start: 0, end: 0 },
            provenance: ObjProvenance::Indirect,
        },
        ObjEntry {
            obj: 3,
            gen: 0,
            atom: PdfAtom::Dict(PdfDict {
                span: Span { start: 0, end: 0 },
                entries: vec![(
                    pdf_name("/Type"),
                    PdfObj {
                        span: Span { start: 0, end: 0 },
                        atom: PdfAtom::Name(pdf_name("/Page")),
                    },
                )],
            }),
            header_span: Span { start: 0, end: 0 },
            body_span: Span { start: 0, end: 0 },
            full_span: Span { start: 0, end: 0 },
            provenance: ObjProvenance::Indirect,
        },
    ];
    for obj in 10..=16 {
        objects.push(ObjEntry {
            obj,
            gen: 0,
            atom: PdfAtom::Dict(PdfDict {
                span: Span { start: 0, end: 0 },
                entries: vec![(
                    pdf_name("/Type"),
                    PdfObj {
                        span: Span { start: 0, end: 0 },
                        atom: PdfAtom::Name(pdf_name("/XObject")),
                    },
                )],
            }),
            header_span: Span { start: 0, end: 0 },
            body_span: Span { start: 0, end: 0 },
            full_span: Span { start: 0, end: 0 },
            provenance: ObjProvenance::Indirect,
        });
    }
    let trailer = PdfDict {
        span: Span { start: 0, end: 0 },
        entries: vec![(pdf_name("/Root"), pdf_ref(1, 0))],
    };
    let ctx = build_context(bytes, objects, vec![trailer], vec![0]);
    let detector = StructuralAnomaliesDetector;
    let findings = detector.run(&ctx).expect("detector should run");
    let finding = findings
        .iter()
        .find(|finding| finding.kind == "structural_decoy_objects")
        .expect("expected structural_decoy_objects");
    assert_eq!(
        finding.meta.get("evasion.structural_decoy_objects").map(String::as_str),
        Some("true")
    );
}

#[test]
fn emits_structural_decoy_scan_limited_when_object_cap_exceeded() {
    let bytes = leak_bytes(vec![0u8; 16]);
    let mut objects = Vec::new();
    for obj in 1..=10_001u32 {
        objects.push(ObjEntry {
            obj,
            gen: 0,
            atom: PdfAtom::Dict(PdfDict {
                span: Span { start: 0, end: 0 },
                entries: vec![(
                    pdf_name("/Type"),
                    PdfObj {
                        span: Span { start: 0, end: 0 },
                        atom: PdfAtom::Name(pdf_name("/XObject")),
                    },
                )],
            }),
            header_span: Span { start: 0, end: 0 },
            body_span: Span { start: 0, end: 0 },
            full_span: Span { start: 0, end: 0 },
            provenance: ObjProvenance::Indirect,
        });
    }
    let ctx = build_context(bytes, objects, Vec::new(), vec![0]);
    let detector = StructuralAnomaliesDetector;
    let findings = detector.run(&ctx).expect("detector should run");
    let finding = findings
        .iter()
        .find(|finding| finding.kind == "structural_decoy_objects_scan_limited")
        .expect("expected structural_decoy_objects_scan_limited");
    assert_eq!(
        finding.meta.get("evasion.decoy_scan_skip_reason").map(String::as_str),
        Some("object_count_cap")
    );
}

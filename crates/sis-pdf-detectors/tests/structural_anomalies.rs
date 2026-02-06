mod common;

use std::borrow::Cow;
use std::collections::HashMap;

use common::default_scan_opts;
use sis_pdf_core::detect::Detector;
use sis_pdf_core::scan::ScanContext;
use sis_pdf_detectors::strict::StrictParseDeviationDetector;
use sis_pdf_detectors::structural_anomalies::StructuralAnomaliesDetector;
use sis_pdf_pdf::graph::{ObjEntry, ObjProvenance, ObjectGraph};
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
fn build_context(
    bytes: &'static [u8],
    objects: Vec<ObjEntry<'static>>,
    trailers: Vec<sis_pdf_pdf::object::PdfDict<'static>>,
    startxrefs: Vec<u64>,
) -> ScanContext<'static> {
    let mut index: HashMap<(u32, u16), Vec<usize>> = HashMap::new();
    for (idx, entry) in objects.iter().enumerate() {
        index.entry((entry.obj, entry.gen)).or_default().push(idx);
    }
    let graph = ObjectGraph { bytes, objects, index, trailers, startxrefs, deviations: Vec::new() };
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

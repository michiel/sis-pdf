mod common;

use std::borrow::Cow;
use std::collections::HashMap;

use common::default_scan_opts;
use sis_pdf_core::detect::Detector;
use sis_pdf_core::scan::ScanContext;
use sis_pdf_detectors::advanced_crypto::AdvancedCryptoDetector;
use sis_pdf_pdf::graph::{ObjEntry, ObjProvenance, ObjectGraph};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfName, PdfObj};
use sis_pdf_pdf::span::Span;

fn pdf_name(name: &'static str) -> PdfName<'static> {
    PdfName {
        span: Span { start: 0, end: name.len() as u64 },
        raw: Cow::Borrowed(name.as_bytes()),
        decoded: name.as_bytes().to_vec(),
    }
}

fn dict_entry(name: &'static str, atom: PdfAtom<'static>) -> (PdfName<'static>, PdfObj<'static>) {
    (pdf_name(name), PdfObj { span: Span { start: 0, end: 0 }, atom })
}

#[test]
fn emits_encrypt_dict_fallback_finding() {
    let encrypt_dict = PdfDict {
        span: Span { start: 10, end: 50 },
        entries: vec![
            dict_entry("/Filter", PdfAtom::Name(pdf_name("/Standard"))),
            dict_entry("/V", PdfAtom::Int(4)),
            dict_entry("/R", PdfAtom::Int(4)),
            dict_entry("/Length", PdfAtom::Int(128)),
        ],
    };
    let entry = ObjEntry {
        obj: 9,
        gen: 0,
        atom: PdfAtom::Dict(encrypt_dict),
        header_span: Span { start: 0, end: 0 },
        body_span: Span { start: 10, end: 50 },
        full_span: Span { start: 0, end: 50 },
        provenance: ObjProvenance::Indirect,
    };
    let mut index = HashMap::new();
    index.insert((9, 0), vec![0]);
    let graph = ObjectGraph {
        bytes: b"%PDF-1.7\n",
        objects: vec![entry],
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        xref_sections: Vec::new(),
        deviations: Vec::new(),
        telemetry_events: Vec::new(),
    };
    let ctx = ScanContext::new(b"%PDF-1.7\n", graph, default_scan_opts());
    let detector = AdvancedCryptoDetector;
    let findings = detector.run(&ctx).expect("advanced crypto detector should run");
    assert!(findings.iter().any(|finding| finding.kind == "encrypt_dict_fallback"));
}

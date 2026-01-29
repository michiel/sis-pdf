use std::borrow::Cow;
use std::collections::HashMap;

use image_analysis::dynamic::analyze_dynamic_images;
use image_analysis::{ImageDynamicOptions, ImageFinding};
use sis_pdf_pdf::graph::{ObjEntry, ObjProvenance, ObjectGraph};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfName, PdfObj, PdfStream};
use sis_pdf_pdf::span::Span;

fn zero_span() -> Span {
    Span { start: 0, end: 0 }
}

fn pdf_name(name: &'static str) -> PdfName<'static> {
    PdfName {
        span: zero_span(),
        raw: Cow::Owned(name.as_bytes().to_vec()),
        decoded: name.as_bytes().to_vec(),
    }
}

fn pdf_obj_name(name: &'static str) -> PdfObj<'static> {
    PdfObj {
        span: zero_span(),
        atom: PdfAtom::Name(pdf_name(name)),
    }
}

fn pdf_obj_int(value: i64) -> PdfObj<'static> {
    PdfObj {
        span: zero_span(),
        atom: PdfAtom::Int(value),
    }
}

fn make_image_entry(
    obj_id: u32,
    start: usize,
    len: usize,
    width: u32,
    height: u32,
    filter: &'static str,
) -> ObjEntry<'static> {
    let dict = PdfDict {
        span: zero_span(),
        entries: vec![
            (pdf_name("/Type"), pdf_obj_name("/XObject")),
            (pdf_name("/Subtype"), pdf_obj_name("/Image")),
            (pdf_name("/Width"), pdf_obj_int(width as i64)),
            (pdf_name("/Height"), pdf_obj_int(height as i64)),
            (
                pdf_name("/Filter"),
                PdfObj {
                    span: zero_span(),
                    atom: PdfAtom::Name(pdf_name(filter)),
                },
            ),
        ],
    };

    let stream = PdfStream {
        dict,
        data_span: Span {
            start: start as u64,
            end: (start + len) as u64,
        },
    };

    ObjEntry {
        obj: obj_id,
        gen: 0,
        atom: PdfAtom::Stream(stream),
        header_span: zero_span(),
        body_span: zero_span(),
        full_span: zero_span(),
        provenance: ObjProvenance::Indirect,
    }
}

fn append_image_entries(
    data: &mut Vec<u8>,
    count: usize,
    sample: &[u8],
) -> (Vec<ObjEntry<'static>>, HashMap<(u32, u16), Vec<usize>>) {
    let mut objects = Vec::new();
    let mut index = HashMap::new();
    for i in 0..count {
        let start = data.len();
        data.extend_from_slice(sample);
        let entry = make_image_entry((i + 1) as u32, start, sample.len(), 100, 100, "/DCTDecode");
        index.insert((entry.obj, entry.gen), vec![objects.len()]);
        objects.push(entry);
    }
    (objects, index)
}

fn find_skip_reason(findings: &[ImageFinding], reason: &str) -> bool {
    findings.iter().any(|f| {
        f.kind == "image.decode_skipped"
            && f.meta
                .get("image.decode_skipped")
                .map(|v| v == reason)
                .unwrap_or(false)
    })
}

#[test]
fn timeout_enforced() {
    let mut bytes = Vec::new();
    let (objects, index) = append_image_entries(&mut bytes, 1, b"jpegdata");
    let graph = ObjectGraph {
        bytes: bytes.as_slice(),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        deviations: Vec::new(),
    };
    let opts = ImageDynamicOptions {
        max_pixels: 1_000_000,
        max_decode_bytes: 1024,
        timeout_ms: 1,
        total_budget_ms: 10,
        skip_threshold: 10,
    };

    let result = analyze_dynamic_images(&graph, &opts);
    assert!(
        find_skip_reason(&result.findings, "timeout"),
        "expected timeout skip"
    );
}

#[test]
fn total_budget_enforced() {
    let mut bytes = Vec::new();
    let (objects, index) = append_image_entries(&mut bytes, 3, b"jpegdata");
    let graph = ObjectGraph {
        bytes: bytes.as_slice(),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        deviations: Vec::new(),
    };
    let opts = ImageDynamicOptions {
        max_pixels: 1_000_000,
        max_decode_bytes: 1024,
        timeout_ms: 1_000,
        total_budget_ms: 2,
        skip_threshold: 10,
    };

    let result = analyze_dynamic_images(&graph, &opts);
    assert!(
        find_skip_reason(&result.findings, "budget_exceeded"),
        "expected budget skip"
    );
}

#[test]
fn skip_threshold_enforced() {
    let images = 60;
    let mut bytes = Vec::new();
    let (objects, index) = append_image_entries(&mut bytes, images, b"jpegdata");
    let graph = ObjectGraph {
        bytes: bytes.as_slice(),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        deviations: Vec::new(),
    };
    let opts = ImageDynamicOptions {
        max_pixels: 1_000_000,
        max_decode_bytes: 1024,
        timeout_ms: 1_000,
        total_budget_ms: 10_000,
        skip_threshold: 50,
    };

    let result = analyze_dynamic_images(&graph, &opts);
    assert_eq!(result.findings.len(), 1);
    let finding = &result.findings[0];
    assert_eq!(finding.kind, "image.decode_skipped");
    assert_eq!(
        finding.meta.get("image.decode_skipped").map(String::as_str),
        Some("too_many_images")
    );
    assert_eq!(
        finding
            .meta
            .get("image.count")
            .and_then(|v: &String| v.parse::<usize>().ok()),
        Some(images)
    );
}

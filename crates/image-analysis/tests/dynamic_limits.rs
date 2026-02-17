use std::borrow::Cow;
use std::collections::HashMap;

use image_analysis::dynamic::analyze_dynamic_images;
use image_analysis::{ImageDynamicOptions, ImageFinding};
#[cfg(feature = "png")]
use png::Encoder;
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
    PdfObj { span: zero_span(), atom: PdfAtom::Name(pdf_name(name)) }
}

fn pdf_obj_int(value: i64) -> PdfObj<'static> {
    PdfObj { span: zero_span(), atom: PdfAtom::Int(value) }
}

fn make_image_entry(
    obj_id: u32,
    start: usize,
    len: usize,
    width: u32,
    height: u32,
    filter: Option<&'static str>,
) -> ObjEntry<'static> {
    let mut entries = vec![
        (pdf_name("/Type"), pdf_obj_name("/XObject")),
        (pdf_name("/Subtype"), pdf_obj_name("/Image")),
        (pdf_name("/Width"), pdf_obj_int(width as i64)),
        (pdf_name("/Height"), pdf_obj_int(height as i64)),
        (pdf_name("/ColorSpace"), pdf_obj_name("/DeviceGray")),
        (pdf_name("/BitsPerComponent"), pdf_obj_int(8)),
    ];
    if let Some(filter_name) = filter {
        entries.push((
            pdf_name("/Filter"),
            PdfObj { span: zero_span(), atom: PdfAtom::Name(pdf_name(filter_name)) },
        ));
    }

    let dict = PdfDict { span: zero_span(), entries };

    let stream =
        PdfStream { dict, data_span: Span { start: start as u64, end: (start + len) as u64 } };

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
    width: u32,
    height: u32,
    filter: Option<&'static str>,
) -> (Vec<ObjEntry<'static>>, HashMap<(u32, u16), Vec<usize>>) {
    let mut objects = Vec::new();
    let mut index = HashMap::new();
    for i in 0..count {
        let start = data.len();
        data.extend_from_slice(sample);
        let entry = make_image_entry((i + 1) as u32, start, sample.len(), width, height, filter);
        index.insert((entry.obj, entry.gen), vec![objects.len()]);
        objects.push(entry);
    }
    (objects, index)
}

fn find_skip_reason(findings: &[ImageFinding], reason: &str) -> bool {
    findings.iter().any(|f| {
        f.kind == "image.decode_skipped"
            && f.meta.get("image.decode_skipped").map(|v| v == reason).unwrap_or(false)
    })
}

#[cfg(feature = "png")]
fn build_png_sample() -> Vec<u8> {
    let mut buf = Vec::new();
    let mut encoder = Encoder::new(&mut buf, 1, 1);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().expect("png header");
    writer.write_image_data(&[0, 0, 0, 0]).expect("png data");
    drop(writer);
    buf
}

const MALFORMED_JPEG: &[u8] = b"\xff\xd8\xff\x00\x00\x01\x02";

fn build_jpeg_with_app1(payload: &[u8]) -> Vec<u8> {
    let max_payload = (u16::MAX as usize).saturating_sub(2);
    let payload_len = payload.len().min(max_payload);
    let seg_len = (payload_len + 2) as u16;
    let mut out = Vec::with_capacity(payload_len + 8);
    out.extend_from_slice(&[0xFF, 0xD8]); // SOI
    out.extend_from_slice(&[0xFF, 0xE1]); // APP1
    out.extend_from_slice(&seg_len.to_be_bytes());
    out.extend_from_slice(&payload[..payload_len]);
    out.extend_from_slice(&[0xFF, 0xD9]); // EOI
    out
}

#[test]
fn timeout_enforced() {
    let mut bytes = Vec::new();
    let (objects, index) =
        append_image_entries(&mut bytes, 1, b"jpegdata", 100, 100, Some("/DCTDecode"));
    let graph = ObjectGraph {
        bytes: bytes.as_slice(),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        xref_sections: Vec::new(),
        deviations: Vec::new(),
        telemetry_events: Vec::new(),
    };
    let opts = ImageDynamicOptions {
        max_pixels: 1_000_000,
        max_decode_bytes: 1024,
        timeout_ms: 1,
        total_budget_ms: 10,
        skip_threshold: 10,
    };

    let result = analyze_dynamic_images(&graph, &opts);
    assert!(find_skip_reason(&result.findings, "timeout"), "expected timeout skip");
}

#[test]
fn total_budget_enforced() {
    let mut bytes = Vec::new();
    let (objects, index) =
        append_image_entries(&mut bytes, 3, b"jpegdata", 100, 100, Some("/DCTDecode"));
    let graph = ObjectGraph {
        bytes: bytes.as_slice(),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        xref_sections: Vec::new(),
        deviations: Vec::new(),
        telemetry_events: Vec::new(),
    };
    let opts = ImageDynamicOptions {
        max_pixels: 1_000_000,
        max_decode_bytes: 1024,
        timeout_ms: 1_000,
        total_budget_ms: 2,
        skip_threshold: 10,
    };

    let result = analyze_dynamic_images(&graph, &opts);
    assert!(find_skip_reason(&result.findings, "budget_exceeded"), "expected budget skip");
}

#[test]
fn skip_threshold_enforced() {
    let images = 60;
    let mut bytes = Vec::new();
    let (objects, index) =
        append_image_entries(&mut bytes, images, b"jpegdata", 100, 100, Some("/DCTDecode"));
    let graph = ObjectGraph {
        bytes: bytes.as_slice(),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        xref_sections: Vec::new(),
        deviations: Vec::new(),
        telemetry_events: Vec::new(),
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
        finding.meta.get("image.count").and_then(|v: &String| v.parse::<usize>().ok()),
        Some(images)
    );
}

#[test]
fn size_limit_enforced() {
    let mut bytes = Vec::new();
    let (objects, index) =
        append_image_entries(&mut bytes, 1, b"jpegdata", 200, 200, Some("/DCTDecode"));
    let graph = ObjectGraph {
        bytes: bytes.as_slice(),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        xref_sections: Vec::new(),
        deviations: Vec::new(),
        telemetry_events: Vec::new(),
    };

    let opts = ImageDynamicOptions {
        max_pixels: 2_000,
        max_decode_bytes: 16 * 1024,
        timeout_ms: 1_000,
        total_budget_ms: 10_000,
        skip_threshold: 50,
    };

    let result = analyze_dynamic_images(&graph, &opts);
    assert!(result.findings.iter().any(|f| f.kind == "image.decode_too_large"));
    assert!(result.findings.iter().any(|f| {
        f.kind == "image.decode_too_large"
            && f.meta.get("image.decode_too_large").map(|v| v == "true").unwrap_or(false)
    }));
}

#[cfg(feature = "jpeg")]
#[test]
fn malformed_jpeg_detected() {
    let mut bytes = Vec::new();
    let (objects, index) =
        append_image_entries(&mut bytes, 1, MALFORMED_JPEG, 10, 10, Some("/DCTDecode"));
    let graph = ObjectGraph {
        bytes: bytes.as_slice(),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        xref_sections: Vec::new(),
        deviations: Vec::new(),
        telemetry_events: Vec::new(),
    };

    let opts = ImageDynamicOptions {
        max_pixels: 1_000_000,
        max_decode_bytes: 16 * 1024,
        timeout_ms: 1_000,
        total_budget_ms: 10_000,
        skip_threshold: 50,
    };

    let result = analyze_dynamic_images(&graph, &opts);
    assert!(result.findings.iter().any(|f| f.kind == "image.jpeg_malformed"));
}

#[cfg(feature = "png")]
#[test]
fn png_decode_success_no_findings() {
    let mut bytes = Vec::new();
    let png_data = build_png_sample();
    let (objects, index) = append_image_entries(&mut bytes, 1, &png_data, 1, 1, None);
    let graph = ObjectGraph {
        bytes: bytes.as_slice(),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        xref_sections: Vec::new(),
        deviations: Vec::new(),
        telemetry_events: Vec::new(),
    };

    let opts = ImageDynamicOptions {
        max_pixels: 1_000_000,
        max_decode_bytes: 64 * 1024,
        timeout_ms: 1_000,
        total_budget_ms: 10_000,
        skip_threshold: 50,
    };

    let result = analyze_dynamic_images(&graph, &opts);
    assert!(result.findings.is_empty());
}

#[test]
fn raw_pixel_size_mismatch_detected() {
    let mut bytes = Vec::new();
    // Width=2, Height=2, DeviceGray defaults to BPC=8 => expected 4 bytes. Provide 3.
    let sample = [1u8, 2u8, 3u8];
    let (objects, index) = append_image_entries(&mut bytes, 1, &sample, 2, 2, None);
    let graph = ObjectGraph {
        bytes: bytes.as_slice(),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        xref_sections: Vec::new(),
        deviations: Vec::new(),
        telemetry_events: Vec::new(),
    };
    let opts = ImageDynamicOptions {
        max_pixels: 1_000_000,
        max_decode_bytes: 64 * 1024,
        timeout_ms: 1_000,
        total_budget_ms: 10_000,
        skip_threshold: 50,
    };
    let result = analyze_dynamic_images(&graph, &opts);
    assert!(result.findings.iter().any(|f| {
        f.kind == "image.pixel_data_size_mismatch"
            && f.meta.get("image.expected_bytes").map(|v| v == "4").unwrap_or(false)
            && f.meta.get("image.actual_bytes").map(|v| v == "3").unwrap_or(false)
            && f.meta
                .get("image.size_check_basis")
                .map(|v| v == "decoded_raw_pixels")
                .unwrap_or(false)
    }));
}

#[test]
fn metadata_oversized_detected() {
    let mut bytes = Vec::new();
    let mut payload = b"Exif\0\0".to_vec();
    payload.extend(vec![b'A'; 40 * 1024]);
    let jpeg = build_jpeg_with_app1(&payload);
    let (objects, index) = append_image_entries(&mut bytes, 1, &jpeg, 64, 64, Some("/DCTDecode"));
    let graph = ObjectGraph {
        bytes: bytes.as_slice(),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        xref_sections: Vec::new(),
        deviations: Vec::new(),
        telemetry_events: Vec::new(),
    };
    let opts = ImageDynamicOptions {
        max_pixels: 1_000_000,
        max_decode_bytes: 256 * 1024,
        timeout_ms: 1_000,
        total_budget_ms: 10_000,
        skip_threshold: 50,
    };
    let result = analyze_dynamic_images(&graph, &opts);
    assert!(result.findings.iter().any(|f| f.kind == "image.metadata_oversized"));
}

#[test]
fn metadata_scriptable_content_detected() {
    let mut bytes = Vec::new();
    let payload = b"<?xpacket><script>alert(1)</script>".to_vec();
    let jpeg = build_jpeg_with_app1(&payload);
    let (objects, index) = append_image_entries(&mut bytes, 1, &jpeg, 64, 64, Some("/DCTDecode"));
    let graph = ObjectGraph {
        bytes: bytes.as_slice(),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        xref_sections: Vec::new(),
        deviations: Vec::new(),
        telemetry_events: Vec::new(),
    };
    let opts = ImageDynamicOptions {
        max_pixels: 1_000_000,
        max_decode_bytes: 256 * 1024,
        timeout_ms: 1_000,
        total_budget_ms: 10_000,
        skip_threshold: 50,
    };
    let result = analyze_dynamic_images(&graph, &opts);
    assert!(
        result.findings.iter().any(|f| f.kind == "image.metadata_scriptable_content"),
        "expected scriptable metadata finding, got {:?}",
        result.findings.iter().map(|f| f.kind.clone()).collect::<Vec<_>>()
    );
}

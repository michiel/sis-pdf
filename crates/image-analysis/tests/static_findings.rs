use std::borrow::Cow;
use std::collections::HashMap;

use image_analysis::static_analysis::analyze_static_images;
use image_analysis::ImageStaticOptions;
use sis_pdf_pdf::graph::{ObjEntry, ObjProvenance, ObjectGraph};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfName, PdfObj, PdfStr, PdfStream};
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

fn pdf_obj_bool(value: bool) -> PdfObj<'static> {
    PdfObj { span: zero_span(), atom: PdfAtom::Bool(value) }
}

fn pdf_obj_array(items: Vec<PdfObj<'static>>) -> PdfObj<'static> {
    PdfObj { span: zero_span(), atom: PdfAtom::Array(items) }
}

fn make_image_stream(dict_entries: Vec<(PdfName<'static>, PdfObj<'static>)>) -> PdfStream<'static> {
    let mut entries = vec![
        (pdf_name("/Type"), pdf_obj_name("/XObject")),
        (pdf_name("/Subtype"), pdf_obj_name("/Image")),
    ];
    entries.extend(dict_entries);
    PdfStream { dict: PdfDict { span: zero_span(), entries }, data_span: zero_span() }
}

fn make_graph(objects: Vec<ObjEntry<'static>>) -> (Vec<u8>, ObjectGraph<'static>) {
    let mut index = HashMap::new();
    for (i, entry) in objects.iter().enumerate() {
        index.insert((entry.obj, entry.gen), vec![i]);
    }
    let bytes = Vec::new();
    let graph = ObjectGraph {
        bytes: Box::leak(bytes.into_boxed_slice()),
        objects,
        index,
        trailers: Vec::new(),
        startxrefs: Vec::new(),
        xref_sections: Vec::new(),
        deviations: Vec::new(),
        telemetry_events: Vec::new(),
    };
    (Vec::new(), graph)
}

fn make_entry(obj: u32, stream: PdfStream<'static>) -> ObjEntry<'static> {
    ObjEntry {
        obj,
        gen: 0,
        atom: PdfAtom::Stream(stream),
        header_span: zero_span(),
        body_span: zero_span(),
        full_span: zero_span(),
        provenance: ObjProvenance::Indirect,
    }
}

fn default_opts() -> ImageStaticOptions {
    ImageStaticOptions::default()
}

#[test]
fn colour_space_invalid_detected() {
    // Image with [/ICCBased] (missing stream ref)
    let cs_array =
        PdfObj { span: zero_span(), atom: PdfAtom::Array(vec![pdf_obj_name("/ICCBased")]) };
    let stream = make_image_stream(vec![
        (pdf_name("/Width"), pdf_obj_int(10)),
        (pdf_name("/Height"), pdf_obj_int(10)),
        (pdf_name("/ColorSpace"), cs_array),
    ]);
    let entry = make_entry(1, stream);
    let (_, graph) = make_graph(vec![entry]);

    let result = analyze_static_images(&graph, &default_opts());
    assert!(
        result.findings.iter().any(|f| f.kind == "image.colour_space_invalid"),
        "expected colour_space_invalid finding, got: {:?}",
        result.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
}

#[test]
fn bpc_anomalous_detected() {
    let stream = make_image_stream(vec![
        (pdf_name("/Width"), pdf_obj_int(10)),
        (pdf_name("/Height"), pdf_obj_int(10)),
        (pdf_name("/BitsPerComponent"), pdf_obj_int(7)),
        (pdf_name("/ColorSpace"), pdf_obj_name("/DeviceGray")),
    ]);
    let entry = make_entry(1, stream);
    let (_, graph) = make_graph(vec![entry]);

    let result = analyze_static_images(&graph, &default_opts());
    assert!(
        result.findings.iter().any(|f| f.kind == "image.bpc_anomalous"),
        "expected bpc_anomalous finding"
    );
}

#[test]
fn pixel_buffer_overflow_detected() {
    let stream = make_image_stream(vec![
        (pdf_name("/Width"), pdf_obj_int(100_000)),
        (pdf_name("/Height"), pdf_obj_int(100_000)),
        (pdf_name("/BitsPerComponent"), pdf_obj_int(8)),
        (pdf_name("/ColorSpace"), pdf_obj_name("/DeviceRGB")),
    ]);
    let entry = make_entry(1, stream);
    let (_, graph) = make_graph(vec![entry]);

    let result = analyze_static_images(&graph, &default_opts());
    assert!(
        result.findings.iter().any(|f| f.kind == "image.pixel_buffer_overflow"),
        "expected pixel_buffer_overflow finding"
    );
}

#[test]
fn indexed_palette_short_detected() {
    // Indexed with DeviceRGB base, hival=1 (needs 6 bytes), but palette is 3 bytes
    let palette_bytes = vec![255, 0, 0]; // only 1 entry, need 2
    let palette_str = PdfObj {
        span: zero_span(),
        atom: PdfAtom::Str(PdfStr::Literal {
            span: zero_span(),
            raw: Cow::Owned(palette_bytes.clone()),
            decoded: palette_bytes,
        }),
    };
    let cs_array = PdfObj {
        span: zero_span(),
        atom: PdfAtom::Array(vec![
            pdf_obj_name("/Indexed"),
            pdf_obj_name("/DeviceRGB"),
            pdf_obj_int(1),
            palette_str,
        ]),
    };
    let stream = make_image_stream(vec![
        (pdf_name("/Width"), pdf_obj_int(10)),
        (pdf_name("/Height"), pdf_obj_int(10)),
        (pdf_name("/BitsPerComponent"), pdf_obj_int(8)),
        (pdf_name("/ColorSpace"), cs_array),
    ]);
    let entry = make_entry(1, stream);
    let (_, graph) = make_graph(vec![entry]);

    let result = analyze_static_images(&graph, &default_opts());
    assert!(
        result.findings.iter().any(|f| f.kind == "image.indexed_palette_short"),
        "expected indexed_palette_short finding, got: {:?}",
        result.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
}

#[test]
fn decode_array_invalid_detected() {
    // DeviceGray expects /Decode [min max] (2 elements), give 4
    let decode_arr = PdfObj {
        span: zero_span(),
        atom: PdfAtom::Array(vec![
            PdfObj { span: zero_span(), atom: PdfAtom::Real(0.0) },
            PdfObj { span: zero_span(), atom: PdfAtom::Real(1.0) },
            PdfObj { span: zero_span(), atom: PdfAtom::Real(0.0) },
            PdfObj { span: zero_span(), atom: PdfAtom::Real(1.0) },
        ]),
    };
    let stream = make_image_stream(vec![
        (pdf_name("/Width"), pdf_obj_int(10)),
        (pdf_name("/Height"), pdf_obj_int(10)),
        (pdf_name("/BitsPerComponent"), pdf_obj_int(8)),
        (pdf_name("/ColorSpace"), pdf_obj_name("/DeviceGray")),
        (pdf_name("/Decode"), decode_arr),
    ]);
    let entry = make_entry(1, stream);
    let (_, graph) = make_graph(vec![entry]);

    let result = analyze_static_images(&graph, &default_opts());
    assert!(
        result.findings.iter().any(|f| f.kind == "image.decode_array_invalid"),
        "expected decode_array_invalid finding, got: {:?}",
        result.findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
}

#[test]
fn decode_array_non_numeric_detected() {
    let decode_arr = PdfObj {
        span: zero_span(),
        atom: PdfAtom::Array(vec![
            PdfObj { span: zero_span(), atom: PdfAtom::Real(0.0) },
            PdfObj { span: zero_span(), atom: PdfAtom::Name(pdf_name("/NotNumeric")) },
        ]),
    };
    let stream = make_image_stream(vec![
        (pdf_name("/Width"), pdf_obj_int(10)),
        (pdf_name("/Height"), pdf_obj_int(10)),
        (pdf_name("/BitsPerComponent"), pdf_obj_int(8)),
        (pdf_name("/ColorSpace"), pdf_obj_name("/DeviceGray")),
        (pdf_name("/Decode"), decode_arr),
    ]);
    let entry = make_entry(1, stream);
    let (_, graph) = make_graph(vec![entry]);

    let result = analyze_static_images(&graph, &default_opts());
    assert!(
        result.findings.iter().any(|f| {
            f.kind == "image.decode_array_invalid"
                && f.meta
                    .get("image.decode_array_issue")
                    .map(|issue| issue.starts_with("non_numeric_entry_at_index_"))
                    .unwrap_or(false)
        }),
        "expected decode_array_invalid for non-numeric entry"
    );
}

#[test]
fn valid_image_produces_no_new_findings() {
    // A normal DeviceRGB image should not trigger any of the new findings
    let stream = make_image_stream(vec![
        (pdf_name("/Width"), pdf_obj_int(100)),
        (pdf_name("/Height"), pdf_obj_int(100)),
        (pdf_name("/BitsPerComponent"), pdf_obj_int(8)),
        (pdf_name("/ColorSpace"), pdf_obj_name("/DeviceRGB")),
    ]);
    let entry = make_entry(1, stream);
    let (_, graph) = make_graph(vec![entry]);

    let result = analyze_static_images(&graph, &default_opts());
    let new_kinds = [
        "image.colour_space_invalid",
        "image.bpc_anomalous",
        "image.pixel_buffer_overflow",
        "image.indexed_palette_short",
        "image.decode_array_invalid",
    ];
    for kind in &new_kinds {
        assert!(!result.findings.iter().any(|f| f.kind == *kind), "unexpected finding: {}", kind);
    }
}

#[test]
fn structure_filter_chain_inconsistent_detected() {
    let stream = make_image_stream(vec![
        (pdf_name("/Width"), pdf_obj_int(16)),
        (pdf_name("/Height"), pdf_obj_int(16)),
        (pdf_name("/BitsPerComponent"), pdf_obj_int(8)),
        (pdf_name("/ColorSpace"), pdf_obj_name("/DeviceGray")),
        (
            pdf_name("/Filter"),
            pdf_obj_array(vec![pdf_obj_name("/FlateDecode"), pdf_obj_name("/ASCII85Decode")]),
        ),
        (pdf_name("/DecodeParms"), pdf_obj_name("/UnexpectedDecodeParms")),
    ]);
    let entry = make_entry(1, stream);
    let (_, graph) = make_graph(vec![entry]);
    let result = analyze_static_images(&graph, &default_opts());
    assert!(result.findings.iter().any(|f| f.kind == "image.structure_filter_chain_inconsistent"));
}

#[test]
fn structure_mask_inconsistent_detected() {
    let stream = make_image_stream(vec![
        (pdf_name("/Width"), pdf_obj_int(10)),
        (pdf_name("/Height"), pdf_obj_int(10)),
        (pdf_name("/BitsPerComponent"), pdf_obj_int(1)),
        (pdf_name("/ImageMask"), pdf_obj_bool(true)),
        (pdf_name("/SMask"), pdf_obj_int(9)),
    ]);
    let entry = make_entry(1, stream);
    let (_, graph) = make_graph(vec![entry]);
    let result = analyze_static_images(&graph, &default_opts());
    assert!(result.findings.iter().any(|f| f.kind == "image.structure_mask_inconsistent"));
}

#[test]
fn structure_geometry_improbable_detected() {
    let stream = make_image_stream(vec![
        (pdf_name("/Width"), pdf_obj_int(10_000_000)),
        (pdf_name("/Height"), pdf_obj_int(1)),
        (pdf_name("/BitsPerComponent"), pdf_obj_int(8)),
        (pdf_name("/ColorSpace"), pdf_obj_name("/DeviceGray")),
    ]);
    let entry = make_entry(1, stream);
    let (_, graph) = make_graph(vec![entry]);
    let result = analyze_static_images(&graph, &default_opts());
    assert!(result.findings.iter().any(|f| f.kind == "image.structure_geometry_improbable"));
}

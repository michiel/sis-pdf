use sis_pdf_pdf::typed_graph::EdgeType;
use sis_pdf_pdf::{parse_pdf, ParseOptions};

#[test]
fn typed_graph_extracts_resource_font_and_xobject_edges() {
    let pdf_bytes = b"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /Resources 4 0 R >>
endobj
4 0 obj
<< /Font << /F1 5 0 R >> /XObject << /Im1 6 0 R >> >>
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
6 0 obj
<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceGray /Length 1 >>
stream
\x00
endstream
endobj
xref
0 7
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000186 00000 n
0000000260 00000 n
0000000333 00000 n
trailer
<< /Size 7 /Root 1 0 R >>
startxref
470
%%EOF";

    let options = ParseOptions {
        recover_xref: true,
        deep: false,
        strict: false,
        max_objstm_bytes: 1024 * 1024,
        max_objects: 10_000,
        max_objstm_total_bytes: 10 * 1024 * 1024,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };
    let graph = parse_pdf(pdf_bytes, options).expect("parse pdf");
    let classifications = graph.classify_objects();
    let typed = sis_pdf_pdf::typed_graph::TypedGraph::build(&graph, &classifications);

    assert!(typed.edges.iter().any(|edge| {
        edge.src == (3, 0)
            && edge.dst == (5, 0)
            && matches!(edge.edge_type, EdgeType::FontReference)
    }));
    assert!(typed.edges.iter().any(|edge| {
        edge.src == (3, 0)
            && edge.dst == (6, 0)
            && matches!(edge.edge_type, EdgeType::XObjectReference)
    }));
}

fn build_pdf(objects: &[String], size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = vec![0usize; size];
    for object in objects {
        let id = object
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        if id < offsets.len() {
            offsets[id] = out.len();
        }
        out.extend_from_slice(object.as_bytes());
    }
    let startxref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", size).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n", size).as_bytes(),
    );
    out.extend_from_slice(startxref.to_string().as_bytes());
    out.extend_from_slice(b"\n%%EOF\n");
    out
}

fn parse_options() -> ParseOptions {
    ParseOptions {
        recover_xref: true,
        deep: false,
        strict: false,
        max_objstm_bytes: 1024 * 1024,
        max_objects: 10_000,
        max_objstm_total_bytes: 10 * 1024 * 1024,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    }
}

#[test]
fn typed_graph_extracts_next_action_and_uri_target_edges() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n".to_string(),
        "4 0 obj\n<< /Type /Action /S /URI /URI 7 0 R /Next [5 0 R 6 0 R] >>\nendobj\n".to_string(),
        "5 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert(1)) >>\nendobj\n".to_string(),
        "6 0 obj\n<< /Type /Action /S /Launch /F 8 0 R >>\nendobj\n".to_string(),
        "7 0 obj\n(https://example.test/payload)\nendobj\n".to_string(),
        "8 0 obj\n(target.exe)\nendobj\n".to_string(),
    ];
    let bytes = build_pdf(&objects, 9);
    let graph = parse_pdf(&bytes, parse_options()).expect("parse pdf");
    let classifications = graph.classify_objects();
    let typed = sis_pdf_pdf::typed_graph::TypedGraph::build(&graph, &classifications);

    assert!(typed.edges.iter().any(|edge| {
        edge.src == (4, 0) && edge.dst == (7, 0) && matches!(edge.edge_type, EdgeType::UriTarget)
    }));
    assert!(typed.edges.iter().any(|edge| {
        edge.src == (4, 0) && edge.dst == (5, 0) && matches!(edge.edge_type, EdgeType::NextAction)
    }));
    assert!(typed.edges.iter().any(|edge| {
        edge.src == (4, 0) && edge.dst == (6, 0) && matches!(edge.edge_type, EdgeType::NextAction)
    }));
}

#[test]
fn typed_graph_extracts_page_and_form_field_aa_edges() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /AA << /O 4 0 R >> >>\nendobj\n".to_string(),
        "4 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('p')) >>\nendobj\n".to_string(),
        "5 0 obj\n<< /FT /Tx /AA << /K 6 0 R >> >>\nendobj\n".to_string(),
        "6 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('f')) >>\nendobj\n".to_string(),
    ];
    let bytes = build_pdf(&objects, 7);
    let graph = parse_pdf(&bytes, parse_options()).expect("parse pdf");
    let classifications = graph.classify_objects();
    let typed = sis_pdf_pdf::typed_graph::TypedGraph::build(&graph, &classifications);

    assert!(typed.edges.iter().any(|edge| {
        edge.src == (3, 0)
            && edge.dst == (4, 0)
            && matches!(&edge.edge_type, EdgeType::PageAction { event } if event == "/O")
    }));
    assert!(typed.edges.iter().any(|edge| {
        edge.src == (5, 0)
            && edge.dst == (6, 0)
            && matches!(&edge.edge_type, EdgeType::FormFieldAction { event } if event == "/K")
    }));
}

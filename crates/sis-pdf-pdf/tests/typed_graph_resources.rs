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

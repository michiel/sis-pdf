use sis_pdf_core::org::OrgGraph;
use sis_pdf_pdf::{parse_pdf, ParseOptions};

#[test]
fn org_builds_reference_edges() {
    let bytes = b"%PDF-1.7\n1 0 obj\n<< /A 2 0 R >>\nendobj\n2 0 obj\n(hi)\nendobj\n%%EOF";
    let graph = parse_pdf(
        bytes,
        ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 5_000_000,
            max_objects: 500_000,
            max_objstm_total_bytes: 256 * 1024 * 1024,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        },
    )
    .expect("parse pdf");
    let org = OrgGraph::from_object_graph(&graph);
    let edges = org.edge_index();
    assert!(!edges.is_empty());
}

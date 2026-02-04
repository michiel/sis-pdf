use sis_pdf_pdf::classification::{ClassificationStats, ObjectRole, PdfObjectType};
use sis_pdf_pdf::{parse_pdf, ParseOptions};

#[test]
fn test_classify_simple_pdf() {
    // Minimal PDF with catalog and page
    let pdf_bytes = b"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
184
%%EOF";

    let options = ParseOptions {
        recover_xref: false,
        deep: false,
        strict: false,
        max_objstm_bytes: 1024 * 1024,
        max_objects: 10000,
        max_objstm_total_bytes: 10 * 1024 * 1024,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };

    let graph = parse_pdf(pdf_bytes, options).expect("Failed to parse PDF");
    let classifications = graph.classify_objects();

    // Should have 3 objects
    assert_eq!(classifications.len(), 3);

    // Object 1 should be Catalog
    let catalog = classifications.get(&(1, 0)).expect("Catalog not found");
    assert_eq!(catalog.obj_type, PdfObjectType::Catalog);
    assert!(catalog.obj_type.is_container());

    // Object 2 should be Pages
    let pages = classifications.get(&(2, 0)).expect("Pages not found");
    assert_eq!(pages.obj_type, PdfObjectType::Pages);
    assert!(pages.obj_type.is_container());

    // Object 3 should be Page
    let page = classifications.get(&(3, 0)).expect("Page not found");
    assert_eq!(page.obj_type, PdfObjectType::Page);
    assert!(page.obj_type.is_container());
}

#[test]
fn test_classify_javascript_action() {
    // PDF with JavaScript action
    let pdf_bytes = b"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<< /S /JavaScript /JS (app.alert('Hello');) >>
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000074 00000 n
0000000131 00000 n
0000000200 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
260
%%EOF";

    let options = ParseOptions {
        recover_xref: false,
        deep: false,
        strict: false,
        max_objstm_bytes: 1024 * 1024,
        max_objects: 10000,
        max_objstm_total_bytes: 10 * 1024 * 1024,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };

    let graph = parse_pdf(pdf_bytes, options).expect("Failed to parse PDF");
    let classifications = graph.classify_objects();

    // Object 4 should be Action
    let action = classifications.get(&(4, 0)).expect("Action not found");
    assert_eq!(action.obj_type, PdfObjectType::Action);
    assert!(action.is_executable());

    // Should have JsContainer role
    assert!(action.has_role(ObjectRole::JsContainer));
    assert!(action.is_suspicious());
}

#[test]
fn test_classification_stats() {
    let pdf_bytes = b"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<< /S /JavaScript /JS (app.alert('Hello');) >>
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000074 00000 n
0000000131 00000 n
0000000200 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
260
%%EOF";

    let options = ParseOptions {
        recover_xref: false,
        deep: false,
        strict: false,
        max_objstm_bytes: 1024 * 1024,
        max_objects: 10000,
        max_objstm_total_bytes: 10 * 1024 * 1024,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };

    let graph = parse_pdf(pdf_bytes, options).expect("Failed to parse PDF");
    let classifications = graph.classify_objects();
    let stats = ClassificationStats::from_classifications(&classifications);

    assert_eq!(stats.total_objects, 4);
    assert_eq!(stats.executable_objects, 1); // The JavaScript action
    assert_eq!(stats.suspicious_objects, 1); // The JavaScript action

    // Should have 1 Catalog, 1 Pages, 1 Page, 1 Action
    assert_eq!(*stats.by_type.get(&PdfObjectType::Catalog).unwrap(), 1);
    assert_eq!(*stats.by_type.get(&PdfObjectType::Pages).unwrap(), 1);
    assert_eq!(*stats.by_type.get(&PdfObjectType::Page).unwrap(), 1);
    assert_eq!(*stats.by_type.get(&PdfObjectType::Action).unwrap(), 1);

    // Should have 1 JsContainer role
    assert_eq!(*stats.by_role.get(&ObjectRole::JsContainer).unwrap(), 1);
}

#[test]
fn test_classify_uri_action() {
    let pdf_bytes = b"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>
endobj
4 0 obj
<< /Type /Annot /Subtype /Link /Rect [0 0 100 100] /A 5 0 R >>
endobj
5 0 obj
<< /S /URI /URI (http://example.com) >>
endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000201 00000 n
0000000279 00000 n
trailer
<< /Size 6 /Root 1 0 R >>
startxref
331
%%EOF";

    let options = ParseOptions {
        recover_xref: false,
        deep: false,
        strict: false,
        max_objstm_bytes: 1024 * 1024,
        max_objects: 10000,
        max_objstm_total_bytes: 10 * 1024 * 1024,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };

    let graph = parse_pdf(pdf_bytes, options).expect("Failed to parse PDF");
    let classifications = graph.classify_objects();

    // Object 4 should be Annotation
    let annot = classifications.get(&(4, 0)).expect("Annotation not found");
    assert_eq!(annot.obj_type, PdfObjectType::Annotation);
    assert!(annot.has_role(ObjectRole::ActionTarget)); // Has /A

    // Object 5 should be Action with UriTarget role
    let uri_action = classifications.get(&(5, 0)).expect("URI action not found");
    assert_eq!(uri_action.obj_type, PdfObjectType::Action);
    assert!(uri_action.has_role(ObjectRole::UriTarget));
}

#[test]
fn test_classify_embedded_file() {
    let pdf_bytes = b"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 4 0 R >> >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<< >>
endobj
5 0 obj
<< /Type /Filespec /F (test.txt) /EF << /F 6 0 R >> >>
endobj
6 0 obj
<< /Type /EmbeddedFile /Length 5 >>
stream
hello
endstream
endobj
xref
0 7
0000000000 65535 f
0000000009 00000 n
0000000095 00000 n
0000000152 00000 n
0000000221 00000 n
0000000240 00000 n
0000000304 00000 n
trailer
<< /Size 7 /Root 1 0 R >>
startxref
380
%%EOF";

    let options = ParseOptions {
        recover_xref: false,
        deep: false,
        strict: false,
        max_objstm_bytes: 1024 * 1024,
        max_objects: 10000,
        max_objstm_total_bytes: 10 * 1024 * 1024,
        carve_stream_objects: false,
        max_carved_objects: 0,
        max_carved_bytes: 0,
    };

    let graph = parse_pdf(pdf_bytes, options).expect("Failed to parse PDF");
    let classifications = graph.classify_objects();

    // Object 5 should have EmbeddedFile role
    let filespec = classifications.get(&(5, 0)).expect("Filespec not found");
    assert!(filespec.has_role(ObjectRole::EmbeddedFile));

    // Object 6 should be Stream
    let embedded = classifications.get(&(6, 0)).expect("Embedded file not found");
    assert_eq!(embedded.obj_type, PdfObjectType::Stream);
}

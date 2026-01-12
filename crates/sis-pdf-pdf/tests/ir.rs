use sis_pdf_pdf::ir::{ir_for_graph, IrOptions};
use sis_pdf_pdf::{parse_pdf, ParseOptions};

#[test]
fn ir_emits_nested_dict_paths() {
    let bytes = b"%PDF-1.7\n1 0 obj\n<< /Type /Page /OpenAction << /S /JavaScript /JS 5 0 R >> >>\nendobj\n5 0 obj\n(alert)\nendobj\n%%EOF";
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
    let ir = ir_for_graph(&graph.objects, &IrOptions::default());
    let mut found_openaction = false;
    let mut found_openaction_s = false;
    for obj in ir {
        for line in obj.lines {
            if line.path == "/OpenAction" && line.value_type == "dict" {
                found_openaction = true;
            }
            if line.path == "/OpenAction/S" && line.value_type == "name" {
                found_openaction_s = true;
            }
        }
    }
    assert!(found_openaction);
    assert!(found_openaction_s);
}

#[test]
fn ir_string_preview_truncates_on_char_boundary() {
    let bytes = b"%PDF-1.7\n1 0 obj\n(A\xc3\xa9B)\nendobj\n%%EOF";
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
    let mut opts = IrOptions::default();
    opts.max_string_len = 2;
    let ir = ir_for_graph(&graph.objects, &opts);
    let mut found = false;
    for obj in ir {
        for line in obj.lines {
            if line.value_type == "str" {
                found = true;
                assert_eq!(
                    line.value,
                    "len_bytes=4 hex=41c3 ascii=A\\xc3 truncated=true"
                );
            }
        }
    }
    assert!(found);
}

#![no_main]

use libfuzzer_sys::fuzz_target;
use sis_pdf_core::page_tree::build_page_tree;

fuzz_target!(|data: &[u8]| {
    let graph = match sis_pdf_pdf::parse_pdf(
        data,
        sis_pdf_pdf::ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 1_000_000,
            max_objects: 20_000,
            max_objstm_total_bytes: 5_000_000,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        },
    ) {
        Ok(graph) => graph,
        Err(_) => return,
    };

    let tree = build_page_tree(&graph);
    for page in tree.pages {
        let _ = graph.get_object(page.obj, page.gen);
    }
});

#![no_main]

use libfuzzer_sys::fuzz_target;
use sis_pdf_core::event_graph::{build_event_graph, EventGraphOptions};
use sis_pdf_core::event_projection::build_stream_exec_summaries;

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

    let classifications = graph.classify_objects();
    let typed_graph = sis_pdf_pdf::typed_graph::TypedGraph::build(&graph, &classifications);
    let event_graph = build_event_graph(
        &typed_graph,
        &[],
        EventGraphOptions { include_type3_exec: true, ..EventGraphOptions::default() },
    );
    let _ = build_stream_exec_summaries(data, &graph, &event_graph);
});

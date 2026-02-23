#![no_main]

use libfuzzer_sys::fuzz_target;
use sis_pdf_pdf::content_summary::summarise_stream;

fuzz_target!(|data: &[u8]| {
    // Exercise summarise_stream directly over raw bytes as the decoded stream body.
    // No ObjectGraph or Resources: this exercises the operator-parsing and anomaly-detection
    // paths with no external dependencies.
    let graph = sis_pdf_pdf::graph::ObjectGraph {
        bytes: b"",
        objects: vec![],
        index: std::collections::HashMap::new(),
        trailers: vec![],
        startxrefs: vec![],
        xref_sections: vec![],
        deviations: vec![],
        telemetry_events: vec![],
    };

    let summary = summarise_stream(
        data,
        false,
        (1, 0),
        None,
        0,
        None,
        &graph,
    );

    // Exercise all output paths to ensure none panic on arbitrary input.
    let _ = sis_pdf_pdf::content_summary::summary_to_text(&summary);
    let _ = sis_pdf_pdf::content_summary::summary_to_json(&summary);
    let graph_data = sis_pdf_pdf::content_summary::build_content_graph(&summary);
    let _ = sis_pdf_pdf::content_summary::content_graph_to_dot(&graph_data, "fuzz");
    let _ = sis_pdf_pdf::content_summary::content_graph_to_json(&graph_data);
});

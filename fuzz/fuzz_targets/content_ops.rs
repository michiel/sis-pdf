#![no_main]

use libfuzzer_sys::fuzz_target;
use sis_pdf_pdf::content::parse_content_ops;

fuzz_target!(|data: &[u8]| {
    let _ = parse_content_ops(data);

    let graph = match sis_pdf_pdf::parse_pdf(
        data,
        sis_pdf_pdf::ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 1_000_000,
            max_objects: 10_000,
            max_objstm_total_bytes: 5_000_000,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        },
    ) {
        Ok(graph) => graph,
        Err(_) => return,
    };

    for entry in &graph.objects {
        if let sis_pdf_pdf::object::PdfAtom::Stream(stream) = &entry.atom {
            let Ok(decoded) = sis_pdf_pdf::decode::decode_stream(data, stream, 256 * 1024) else {
                continue;
            };
            let _ = parse_content_ops(&decoded.data);
        }
    }
});

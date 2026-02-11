mod common;
use common::default_scan_opts;

use sis_pdf_detectors::default_detectors;

fn build_minimal_js_pdf(js_payload: &str) -> Vec<u8> {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");
    let objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n".to_string(),
        format!("5 0 obj\n<< /S /JavaScript /JS ({}) >>\nendobj\n", js_payload),
    ];
    let mut offsets = [0usize; 6];
    for object in &objects {
        let header = object.as_bytes()[0];
        let obj_id = if header == b'1' {
            1
        } else if header == b'2' {
            2
        } else if header == b'3' {
            3
        } else {
            5
        };
        offsets[obj_id] = pdf.len();
        pdf.extend_from_slice(object.as_bytes());
    }
    let start_xref = pdf.len();
    pdf.extend_from_slice(b"xref\n0 6\n");
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        if *offset == 0 {
            pdf.extend_from_slice(b"0000000000 00000 f \n");
        } else {
            let line = format!("{offset:010} 00000 n \n");
            pdf.extend_from_slice(line.as_bytes());
        }
    }
    pdf.extend_from_slice(b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n");
    pdf.extend_from_slice(start_xref.to_string().as_bytes());
    pdf.extend_from_slice(b"\n%%EOF\n");
    pdf
}

#[test]
fn emits_jsfuck_finding() {
    let payload = "[]+[]+(![]+[])[+[]]+([][[]]+[])[+!![]]+(![]+[])[!![]+!![]]+(!![]+[])[+[]]";
    let bytes = build_minimal_js_pdf(payload);
    let detectors = default_detectors();

    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(report.findings.iter().any(|f| f.kind == "js_jsfuck_encoding"));
}

#[test]
fn emits_jjencode_finding() {
    let payload = "$=~[];$={___:++$,$$$$:(![]+\"\")[$],$_:++$,$$_:(![]+\"\")[$],$_$_:++$,$_$$:([]+\"\")[$],$$_$:++$,$$$:({}+\"\")[$],$__:++$,$_$:++$,$$__:({}+\"\")[$],$$_$_:++$,$$$_:++$,$$$$_:++$,$__:++$};";
    let bytes = build_minimal_js_pdf(payload);
    let detectors = default_detectors();

    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(report.findings.iter().any(|f| f.kind == "js_jjencode_encoding"));
}

#[test]
fn emits_aaencode_finding() {
    let payload =
        "(function(){ var x = '＠＠｀ω´＠＠＾＾＠＠'; return this.constructor('return 1')(); })();";
    let bytes = build_minimal_js_pdf(payload);
    let detectors = default_detectors();

    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(report.findings.iter().any(|f| f.kind == "js_aaencode_encoding"));
}

#[test]
fn emits_heap_grooming_finding() {
    let payload =
        include_str!("../../js-analysis/tests/fixtures/modern_heap/cve_2023_21608_sanitised.js");
    let bytes = build_minimal_js_pdf(payload);
    let detectors = default_detectors();

    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(report.findings.iter().any(|f| f.kind == "js_heap_grooming"));
}

#[test]
fn emits_lfh_priming_finding() {
    let payload = r#"
        var pool = [];
        for (var i = 0; i < 64; i++) { pool.push(new ArrayBuffer(0x400)); }
        for (var j = 0; j < pool.length; j++) { pool[j] = null; }
        var target = new DataView(new ArrayBuffer(0x400));
    "#;
    let bytes = build_minimal_js_pdf(payload);
    let detectors = default_detectors();

    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(report.findings.iter().any(|f| f.kind == "js_lfh_priming"));
}

#[test]
fn emits_rop_and_info_leak_findings() {
    let payload =
        include_str!("../../js-analysis/tests/fixtures/modern_heap/cve_2023_26369_sanitised.js");
    let bytes = build_minimal_js_pdf(payload);
    let detectors = default_detectors();

    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan");

    assert!(report.findings.iter().any(|f| f.kind == "js_rop_chain_construction"));
    assert!(report.findings.iter().any(|f| f.kind == "js_info_leak_primitive"));
}

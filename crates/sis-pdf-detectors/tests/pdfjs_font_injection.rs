mod common;

use common::default_scan_opts;
use sis_pdf_detectors::default_detectors;

fn build_pdf_with_objects(objects: &[&str]) -> Vec<u8> {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = vec![0usize; objects.len() + 1];
    for object in objects {
        let obj_num = object
            .split_whitespace()
            .next()
            .and_then(|token| token.parse::<usize>().ok())
            .expect("object number");
        if obj_num < offsets.len() {
            offsets[obj_num] = pdf.len();
        }
        pdf.extend_from_slice(object.as_bytes());
    }
    let start_xref = pdf.len();
    let size = offsets.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", size).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        if *offset == 0 {
            pdf.extend_from_slice(b"0000000000 00000 f \n");
        } else {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n", size).as_bytes(),
    );
    pdf.extend_from_slice(start_xref.to_string().as_bytes());
    pdf.extend_from_slice(b"\n%%EOF\n");
    pdf
}

fn base_objects(font_object: &str) -> Vec<String> {
    vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 200 200] >>\nendobj\n".to_string(),
        font_object.to_string(),
    ]
}

fn find_pdfjs_finding<'a>(
    report: &'a sis_pdf_core::report::Report,
    subsignal: &str,
) -> Option<&'a sis_pdf_core::model::Finding> {
    report.findings.iter().find(|finding| {
        finding.kind == "pdfjs_font_injection"
            && finding.meta.get("pdfjs.subsignal").map(String::as_str) == Some(subsignal)
    })
}

#[test]
fn detects_pdfjs_fontmatrix_injection_signal() {
    let font =
        "4 0 obj\n<< /Type /Font /Subtype /Type1 /FontMatrix [0 0 1 1 (evil) 0] >>\nendobj\n";
    let objects = base_objects(font);
    let refs = objects.iter().map(String::as_str).collect::<Vec<_>>();
    let bytes = build_pdf_with_objects(&refs);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    let finding = find_pdfjs_finding(&report, "fontmatrix_non_numeric")
        .expect("expected fontmatrix_non_numeric");
    assert_eq!(finding.meta.get("pdfjs.affected_versions").map(String::as_str), Some("<4.2.67"));
    assert!(!finding.reader_impacts.is_empty());
}

#[test]
fn detects_pdfjs_fontbbox_injection_signal() {
    let font = "4 0 obj\n<< /Type /Font /Subtype /Type1 /FontBBox [0 0 100 (bbox)] >>\nendobj\n";
    let objects = base_objects(font);
    let refs = objects.iter().map(String::as_str).collect::<Vec<_>>();
    let bytes = build_pdf_with_objects(&refs);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(find_pdfjs_finding(&report, "fontbbox_non_numeric").is_some());
}

#[test]
fn detects_pdfjs_encoding_string_value_signal() {
    let font = "4 0 obj\n<< /Type /Font /Subtype /Type1 /Encoding << /Differences [0 /A (payload)] >> >>\nendobj\n";
    let objects = base_objects(font);
    let refs = objects.iter().map(String::as_str).collect::<Vec<_>>();
    let bytes = build_pdf_with_objects(&refs);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(find_pdfjs_finding(&report, "encoding_string_values").is_some());
}

#[test]
fn detects_pdfjs_cmap_script_token_signal() {
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 200 200] >>\nendobj\n",
        "4 0 obj\n<< /Type /Font /Subtype /Type0 /DescendantFonts [5 0 R] >>\nendobj\n",
        "5 0 obj\n<< /Type /CMap /Length 27 >>\nstream\nbegincmap\napp.alert(1)\nendcmap\nendstream\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(find_pdfjs_finding(&report, "cmap_script_tokens").is_some());
}

#[test]
fn benign_type1_font_does_not_trigger_pdfjs_font_injection() {
    let font = "4 0 obj\n<< /Type /Font /Subtype /Type1 /FontMatrix [0.001 0 0 0.001 0 0] /FontBBox [0 0 500 700] /Encoding /WinAnsiEncoding >>\nendobj\n";
    let objects = base_objects(font);
    let refs = objects.iter().map(String::as_str).collect::<Vec<_>>();
    let bytes = build_pdf_with_objects(&refs);
    let report = sis_pdf_core::runner::run_scan_with_detectors(
        &bytes,
        default_scan_opts(),
        &default_detectors(),
    )
    .expect("scan");
    assert!(!report.findings.iter().any(|finding| finding.kind == "pdfjs_font_injection"));
}

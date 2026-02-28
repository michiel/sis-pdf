mod common;

use common::default_scan_opts;
use sis_pdf_core::model::{Confidence, Severity};
use sis_pdf_detectors::default_detectors;

fn build_pdf_with_link_annotation(uri: &str) -> Vec<u8> {
    let uri_escaped = uri.replace('(', "\\(").replace(')', "\\)");
    let objects = vec![
        format!(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        ),
        format!(
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
        ),
        format!(
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>\nendobj\n"
        ),
        format!(
            "4 0 obj\n<< /Type /Annot /Subtype /Link /Rect [10 10 200 30] /A << /S /URI /URI ({}) >> >>\nendobj\n",
            uri_escaped
        ),
    ];
    build_pdf_with_objects(&objects)
}

fn build_pdf_with_two_annotations_same_t(t_value: &str) -> Vec<u8> {
    let t_escaped = t_value.replace('(', "\\(").replace(')', "\\)");
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        format!(
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R 5 0 R] >>\nendobj\n"
        ),
        format!(
            "4 0 obj\n<< /Type /Annot /Subtype /Text /Rect [10 10 100 30] /T ({}) /Contents (First annotation) >>\nendobj\n",
            t_escaped
        ),
        format!(
            "5 0 obj\n<< /Type /Annot /Subtype /Text /Rect [110 10 200 30] /T ({}) /Contents (Second annotation) >>\nendobj\n",
            t_escaped
        ),
    ];
    build_pdf_with_objects(&objects)
}

fn build_pdf_with_text_annotation(t_field: &str, contents: &str) -> Vec<u8> {
    let t_escaped = t_field.replace('(', "\\(").replace(')', "\\)");
    let contents_escaped = contents.replace('(', "\\(").replace(')', "\\)");
    let objects = vec![
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>\nendobj\n".to_string(),
        format!(
            "4 0 obj\n<< /Type /Annot /Subtype /Text /Rect [10 10 200 30] /T ({}) /Contents ({}) >>\nendobj\n",
            t_escaped, contents_escaped
        ),
    ];
    build_pdf_with_objects(&objects)
}

fn build_pdf_with_objects(objects: &[String]) -> Vec<u8> {
    let mut pdf = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");
    let max_obj = objects.len() + 1;
    let mut offsets = vec![0usize; max_obj];
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

fn scan(bytes: &[u8]) -> sis_pdf_core::report::Report {
    sis_pdf_core::runner::run_scan_with_detectors(bytes, default_scan_opts(), &default_detectors())
        .expect("scan")
}

// --- A1: URI dangerous scheme findings ---

#[test]
fn javascript_uri_emits_dedicated_high_finding() {
    let bytes = build_pdf_with_link_annotation("javascript:confirm(1)");
    let report = scan(&bytes);

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "uri_javascript_scheme")
        .expect("uri_javascript_scheme finding should be emitted");

    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Strong);
    assert_eq!(finding.meta.get("uri.classification").map(String::as_str), Some("javascript"));
    assert!(finding.meta.contains_key("uri.target"));
    assert!(finding.meta.contains_key("uri.scheme"));
}

#[test]
fn file_uri_emits_dedicated_high_finding() {
    let bytes = build_pdf_with_link_annotation("file:///C:/Windows/system32/calc.exe");
    let report = scan(&bytes);

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "uri_file_scheme")
        .expect("uri_file_scheme finding should be emitted");

    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Strong);
    assert_eq!(finding.meta.get("uri.classification").map(String::as_str), Some("file"));
}

#[test]
fn data_html_uri_emits_dedicated_high_finding() {
    let bytes = build_pdf_with_link_annotation("data:text/html,<script>alert(2);</script>");
    let report = scan(&bytes);

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "uri_data_html_scheme")
        .expect("uri_data_html_scheme finding should be emitted");

    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Strong);
    assert_eq!(finding.meta.get("uri.classification").map(String::as_str), Some("data"));
}

#[test]
fn start_command_uri_emits_dedicated_high_probable_finding() {
    let bytes = build_pdf_with_link_annotation("START C:/Windows/system32/calc.exe");
    let report = scan(&bytes);

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "uri_command_injection")
        .expect("uri_command_injection finding should be emitted");

    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Probable);
    assert_eq!(finding.meta.get("uri.classification").map(String::as_str), Some("command"));
}

#[test]
fn benign_https_uri_does_not_emit_scheme_finding() {
    let bytes = build_pdf_with_link_annotation("https://example.com/page");
    let report = scan(&bytes);

    let scheme_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind.as_str(),
                "uri_javascript_scheme"
                    | "uri_file_scheme"
                    | "uri_data_html_scheme"
                    | "uri_command_injection"
            )
        })
        .collect();

    assert!(
        scheme_findings.is_empty(),
        "benign https URI should not produce any uri_*_scheme findings, got: {:?}",
        scheme_findings.iter().map(|f| &f.kind).collect::<Vec<_>>()
    );
}

#[test]
fn annotation_action_chain_also_fires_alongside_scheme_finding() {
    let bytes = build_pdf_with_link_annotation("javascript:confirm(1)");
    let report = scan(&bytes);

    assert!(
        report.findings.iter().any(|f| f.kind == "annotation_action_chain"),
        "annotation_action_chain should still fire alongside uri_javascript_scheme"
    );
    assert!(
        report.findings.iter().any(|f| f.kind == "uri_javascript_scheme"),
        "uri_javascript_scheme should also fire"
    );
}

// --- C1: Annotation field HTML injection ---

#[test]
fn html_in_annotation_t_field_emits_finding() {
    let bytes =
        build_pdf_with_text_annotation("\">'><details open ontoggle=confirm(3)>", "Normal content");
    let report = scan(&bytes);

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "annotation_field_html_injection")
        .expect("annotation_field_html_injection should be emitted for /T XSS");

    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.confidence, Confidence::Probable);
    assert_eq!(finding.meta.get("annot.field").map(String::as_str), Some("/T"));
}

#[test]
fn html_in_annotation_contents_field_emits_finding() {
    let bytes = build_pdf_with_text_annotation("Normal title", "<script>alert(1)</script>");
    let report = scan(&bytes);

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "annotation_field_html_injection")
        .expect("annotation_field_html_injection should be emitted for /Contents XSS");

    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.confidence, Confidence::Probable);
}

#[test]
fn plain_text_annotation_fields_do_not_emit_finding() {
    let bytes = build_pdf_with_text_annotation(
        "Review comment",
        "This is a normal annotation with text content.",
    );
    let report = scan(&bytes);

    assert!(
        report.findings.iter().all(|f| f.kind != "annotation_field_html_injection"),
        "plain text annotation fields should not trigger injection finding"
    );
}

// --- EXT-02: uri.scheme metadata on annotation_action_chain ---

#[test]
fn annotation_chain_http_uri_includes_uri_scheme_metadata() {
    let bytes = build_pdf_with_link_annotation("https://example.com/page");
    let report = scan(&bytes);

    let chain = report
        .findings
        .iter()
        .find(|f| f.kind == "annotation_action_chain")
        .expect("annotation_action_chain should fire");

    assert_eq!(
        chain.meta.get("uri.scheme").map(String::as_str),
        Some("https"),
        "annotation_action_chain for https URI should have uri.scheme=https"
    );
}

#[test]
fn annotation_chain_javascript_uri_includes_uri_scheme_metadata() {
    let bytes = build_pdf_with_link_annotation("javascript:confirm(1)");
    let report = scan(&bytes);

    let chain = report
        .findings
        .iter()
        .find(|f| f.kind == "annotation_action_chain")
        .expect("annotation_action_chain should fire");

    assert_eq!(
        chain.meta.get("uri.scheme").map(String::as_str),
        Some("javascript"),
        "annotation_action_chain for javascript: URI should have uri.scheme=javascript"
    );
}

// --- EXT-06: Annotation /T field spoofing detection ---

#[test]
fn duplicate_t_field_on_same_page_emits_collision_finding() {
    let bytes = build_pdf_with_two_annotations_same_t("shared-identifier");
    let report = scan(&bytes);
    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "annotation_t_field_collision")
        .expect("annotation_t_field_collision should be emitted when two annotations share /T");
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(finding.confidence, Confidence::Probable);
    assert!(
        finding.meta.get("collision.t_value").map(String::as_str) == Some("shared-identifier"),
        "collision.t_value should be the shared identifier"
    );
    assert!(finding.meta.contains_key("collision.page"), "collision.page should be set");
    assert!(
        finding.meta.contains_key("collision.refs"),
        "collision.refs should list the colliding object refs"
    );
}

#[test]
fn distinct_t_fields_do_not_emit_collision_finding() {
    let bytes = build_pdf_with_text_annotation("unique-id-1", "Normal annotation");
    let report = scan(&bytes);
    assert!(
        report.findings.iter().all(|f| f.kind != "annotation_t_field_collision"),
        "a single annotation with a unique /T should not emit a collision finding"
    );
}

// --- EXT-08: Structured URI classification finding ---

#[test]
fn javascript_uri_emits_uri_classification_summary_finding() {
    let bytes = build_pdf_with_link_annotation("javascript:confirm(1)");
    let report = scan(&bytes);
    let summary = report
        .findings
        .iter()
        .find(|f| f.kind == "uri_classification_summary")
        .expect("uri_classification_summary should be emitted for javascript: URI");
    assert_eq!(summary.severity, Severity::Info);
    assert_eq!(summary.confidence, Confidence::Strong);
    assert_eq!(summary.meta.get("uri.scheme").map(String::as_str), Some("javascript"));
    assert_eq!(summary.meta.get("uri.is_javascript_uri").map(String::as_str), Some("true"));
}

#[test]
fn benign_https_uri_does_not_emit_uri_classification_summary() {
    let bytes = build_pdf_with_link_annotation("https://example.com/page");
    let report = scan(&bytes);
    assert!(
        report.findings.iter().all(|f| f.kind != "uri_classification_summary"),
        "plain https URI with no risk signals should not emit classification summary"
    );
}

#[test]
fn ip_address_uri_emits_uri_classification_summary() {
    let bytes = build_pdf_with_link_annotation("http://192.168.1.1/payload");
    let report = scan(&bytes);
    assert!(
        report.findings.iter().any(|f| f.kind == "uri_classification_summary"),
        "IP-address URI should emit uri_classification_summary"
    );
}

// --- EXT-04: Multi-encoding annotation field scanning ---

#[test]
fn percent_encoded_xss_in_annotation_t_field_emits_finding() {
    // %3C = '<', %3E = '>', %2F = '/' → <script>
    let bytes =
        build_pdf_with_text_annotation("%3Cscript%3Ealert%281%29%3C%2Fscript%3E", "Normal content");
    let report = scan(&bytes);
    assert!(
        report.findings.iter().any(|f| f.kind == "annotation_field_html_injection"),
        "percent-encoded XSS in /T should be detected"
    );
}

#[test]
fn html_entity_encoded_xss_in_annotation_contents_emits_finding() {
    // &lt;script&gt; → <script>
    let bytes =
        build_pdf_with_text_annotation("Normal title", "&lt;script&gt;alert(1)&lt;/script&gt;");
    let report = scan(&bytes);
    assert!(
        report.findings.iter().any(|f| f.kind == "annotation_field_html_injection"),
        "HTML entity-encoded XSS in /Contents should be detected"
    );
}

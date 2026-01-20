use sis_pdf_core::scan::{FontAnalysisOptions, ProfileFormat, ScanOptions};

fn opts() -> ScanOptions {
    ScanOptions {
        deep: true,
        max_decode_bytes: 8 * 1024 * 1024,
        max_total_decoded_bytes: 64 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
        batch_parallel: false,
        diff_parser: false,
        max_objects: 100_000,
        max_recursion_depth: 64,
        fast: false,
        focus_trigger: None,
        focus_depth: 0,
        yara_scope: None,
        strict: false,
        strict_summary: false,
        ir: false,
        ml_config: None,
        font_analysis: FontAnalysisOptions::default(),
        image_analysis: sis_pdf_core::scan::ImageAnalysisOptions::default(),
        filter_allowlist: None,
        filter_allowlist_strict: false,
        profile: false,
        profile_format: ProfileFormat::Text,
        group_chains: true,
    }
}

#[test]
fn findings_schema_validation() {
    let schema = load_findings_schema();
    let compiled = jsonschema::JSONSchema::compile(&schema).expect("compile findings schema");
    let fixtures = [
        "tests/fixtures/embedded/embedded_exe_cve_2018_4990.pdf",
        "tests/fixtures/actions/launch_cve_2010_1240.pdf",
        "tests/fixtures/xfa/xfa_submit_sensitive.pdf",
        "tests/fixtures/media/swf_cve_2011_0611.pdf",
        "tests/fixtures/encryption/high_entropy_stream.pdf",
        "tests/fixtures/filters/filter_unusual_chain.pdf",
    ];

    for fixture in fixtures {
        let bytes = std::fs::read(fixture_path(fixture)).expect("fixture read");
        let detectors = sis_pdf_detectors::default_detectors();
        let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, opts(), &detectors)
            .expect("scan should succeed");

        for finding in &report.findings {
            assert!(!finding.kind.is_empty());
            assert!(!finding.title.is_empty());
            assert!(!finding.description.is_empty());
            assert!(!finding.objects.is_empty());
            for span in &finding.evidence {
                assert!(span.length <= u32::MAX);
            }
            let value = serde_json::to_value(finding).expect("finding serialise");
            let obj = value.as_object().expect("finding json object");
            for key in ["kind", "title", "description", "severity", "confidence", "objects"] {
                assert!(obj.contains_key(key), "missing key {}", key);
            }
            let validation = compiled.validate(&value);
            if let Err(errors) = validation {
                let messages: Vec<String> = errors.map(|err| err.to_string()).collect();
                panic!(
                    "finding schema validation failed: {}",
                    messages.join("; ")
                );
            }
        }
    }
}

#[test]
fn findings_jsonl_schema_validation() {
    let schema = load_findings_schema();
    let compiled = jsonschema::JSONSchema::compile(&schema).expect("compile findings schema");
    let fixtures = [
        "tests/fixtures/embedded/embedded_exe_cve_2018_4990.pdf",
        "tests/fixtures/actions/launch_cve_2010_1240.pdf",
        "tests/fixtures/xfa/xfa_submit_sensitive.pdf",
        "tests/fixtures/media/swf_cve_2011_0611.pdf",
        "tests/fixtures/encryption/high_entropy_stream.pdf",
        "tests/fixtures/filters/filter_unusual_chain.pdf",
    ];

    for fixture in fixtures {
        let bytes = std::fs::read(fixture_path(fixture)).expect("fixture read");
        let detectors = sis_pdf_detectors::default_detectors();
        let report = sis_pdf_core::runner::run_scan_with_detectors(&bytes, opts(), &detectors)
            .expect("scan should succeed")
            .with_input_path(Some(fixture.to_string()));
        let mut buffer = Vec::new();
        sis_pdf_core::report::write_jsonl_findings(&report, &mut buffer)
            .expect("write jsonl");
        let output = String::from_utf8(buffer).expect("utf8 jsonl");
        for line in output.lines() {
            let record: serde_json::Value =
                serde_json::from_str(line).expect("parse jsonl line");
            if let Some(finding) = record.get("finding") {
                let validation = compiled.validate(finding);
                if let Err(errors) = validation {
                    let messages: Vec<String> = errors.map(|err| err.to_string()).collect();
                    panic!(
                        "finding jsonl schema validation failed: {}",
                        messages.join("; ")
                    );
                }
            }
        }
    }
}

fn fixture_path(rel: &str) -> std::path::PathBuf {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    root.join(rel)
}

fn load_findings_schema() -> serde_json::Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../docs/findings-schema.json");
    let bytes = std::fs::read(path).expect("read findings schema");
    serde_json::from_slice(&bytes).expect("parse findings schema")
}

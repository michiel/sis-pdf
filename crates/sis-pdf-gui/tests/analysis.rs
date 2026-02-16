use sis_pdf_gui::analysis::{analyze, AnalysisError};
use sis_pdf_gui::query::{execute_query, parse_query, Query, QueryOutput};

#[test]
fn rejects_oversized_file() {
    let big = vec![0u8; 50 * 1024 * 1024 + 1];
    let result = analyze(&big, "too_big.pdf");
    assert!(result.is_err());
    match result.unwrap_err() {
        AnalysisError::FileTooLarge { size, limit } => {
            assert_eq!(size, 50 * 1024 * 1024 + 1);
            assert_eq!(limit, 50 * 1024 * 1024);
        }
        other => panic!("Expected FileTooLarge, got: {:?}", other),
    }
}

#[test]
fn analyzes_fixture_with_findings() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    assert_eq!(result.file_name, "launch_action.pdf");
    assert_eq!(result.file_size, bytes.len());
    assert!(!result.report.findings.is_empty(), "launch_action.pdf should produce findings");
}

#[test]
fn analyzes_clean_pdf() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/clean-google-docs-basic.pdf");
    let result = analyze(bytes, "clean.pdf").expect("analysis should succeed");
    assert_eq!(result.file_name, "clean.pdf");
    // Clean PDF should still produce a report
    let _ = result.report.summary.total;
}

#[test]
fn analyzes_minimal_synthetic_pdf() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF";
    let result = analyze(pdf, "minimal.pdf").expect("analysis should succeed");
    assert_eq!(result.file_size, pdf.len());
}

// --- ObjectData tests ---

#[test]
fn object_data_has_objects() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    assert!(!result.object_data.objects.is_empty(), "ObjectData should contain objects");
}

#[test]
fn object_data_count_matches_structural() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    // ObjectData.objects contains unique objects (deduplicated by obj/gen).
    // StructuralSummary.object_count comes from the scanner which may count differently
    // (e.g. including ObjStm expansion). Both should be non-zero.
    assert!(result.object_data.objects.len() > 0);
    if let Some(ref structural) = result.report.structural_summary {
        assert!(structural.object_count > 0);
    }
}

#[test]
fn object_data_has_catalog() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    let has_catalog = result.object_data.objects.iter().any(|o| o.obj_type == "catalog");
    assert!(has_catalog, "ObjectData should contain a Catalog object");
}

#[test]
fn object_data_has_references() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    let has_refs = result.object_data.objects.iter().any(|o| !o.references_from.is_empty());
    assert!(has_refs, "At least some objects should have outgoing references");
}

#[test]
fn object_data_reverse_references_populated() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    let has_reverse = result.object_data.objects.iter().any(|o| !o.references_to.is_empty());
    assert!(has_reverse, "At least some objects should have incoming references");
}

#[test]
fn object_data_index_consistent() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    for (i, obj) in result.object_data.objects.iter().enumerate() {
        let key = (obj.obj, obj.gen);
        let idx = result.object_data.index.get(&key);
        assert!(idx.is_some(), "Object {} {} should be in index", obj.obj, obj.gen);
        assert_eq!(*idx.expect("checked above"), i, "Index should point to correct position");
    }
}

#[test]
fn finding_objects_exist_in_object_data() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    for finding in &result.report.findings {
        for obj_str in &finding.objects {
            // Parse "N M R" format
            let parts: Vec<&str> = obj_str.split_whitespace().collect();
            if parts.len() >= 2 {
                if let (Ok(obj), Ok(gen)) = (parts[0].parse::<u32>(), parts[1].parse::<u16>()) {
                    assert!(
                        result.object_data.index.contains_key(&(obj, gen)),
                        "Finding {} references object {} {} which should exist in ObjectData",
                        finding.id,
                        obj,
                        gen
                    );
                }
            }
        }
    }
}

#[test]
fn minimal_pdf_object_data() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF";
    let result = analyze(pdf, "minimal.pdf").expect("analysis should succeed");
    assert_eq!(result.object_data.objects.len(), 1, "Minimal PDF has one object");
    assert_eq!(result.object_data.objects[0].obj_type, "catalog");
    assert_eq!(result.object_data.objects[0].obj, 1);
    assert_eq!(result.object_data.objects[0].gen, 0);
}

// --- M2: Bytes retention tests ---

#[test]
fn analysis_result_retains_bytes() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    assert_eq!(result.bytes.len(), result.file_size, "Stored bytes should match file_size");
    assert_eq!(result.bytes.len(), bytes.len(), "Stored bytes should match input length");
    assert_eq!(&result.bytes[..5], b"%PDF-", "Stored bytes should start with PDF header");
}

#[test]
fn minimal_pdf_retains_bytes() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF";
    let result = analyze(pdf, "minimal.pdf").expect("analysis should succeed");
    assert_eq!(result.bytes.len(), pdf.len());
    assert_eq!(&result.bytes, &pdf[..]);
}

#[test]
fn object_data_stream_raw_populated_for_streams() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/clean-google-docs-basic.pdf");
    let result = analyze(bytes, "clean.pdf").expect("analysis should succeed");
    let stream_objects: Vec<_> =
        result.object_data.objects.iter().filter(|o| o.has_stream).collect();
    if !stream_objects.is_empty() {
        // At least some stream objects should have stream_raw populated
        let has_raw = stream_objects.iter().any(|o| o.stream_raw.is_some());
        assert!(has_raw, "Stream objects should have stream_raw populated when decodable");
    }
}

#[test]
fn stream_raw_contains_decoded_bytes() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/clean-google-docs-basic.pdf");
    let result = analyze(bytes, "clean.pdf").expect("analysis should succeed");
    for obj in &result.object_data.objects {
        if let Some(ref raw) = obj.stream_raw {
            assert!(!raw.is_empty(), "stream_raw should not be empty when present");
            // If stream_text is also set, its content should match a prefix of stream_raw
            if let Some(ref text) = obj.stream_text {
                let raw_as_text = std::str::from_utf8(raw);
                if let Ok(raw_text) = raw_as_text {
                    assert!(
                        raw_text.starts_with(&text[..text.len().min(100)]),
                        "stream_text should be a prefix of stream_raw as UTF-8"
                    );
                }
            }
        }
    }
}

// --- M2: Query parser and executor tests ---

#[test]
fn query_parser_metadata() {
    assert_eq!(parse_query("pages").unwrap(), Query::Pages);
    assert_eq!(parse_query("objects").unwrap(), Query::Objects);
    assert_eq!(parse_query("filesize").unwrap(), Query::FileSize);
    assert_eq!(parse_query("version").unwrap(), Query::Version);
    assert_eq!(parse_query("creator").unwrap(), Query::Creator);
    assert_eq!(parse_query("producer").unwrap(), Query::Producer);
    assert_eq!(parse_query("title").unwrap(), Query::Title);
    assert_eq!(parse_query("encrypted").unwrap(), Query::Encrypted);
}

#[test]
fn query_parser_parametric() {
    assert_eq!(parse_query("object 1").unwrap(), Query::Object { obj: 1, gen: 0 });
    assert_eq!(parse_query("obj 5 0").unwrap(), Query::Object { obj: 5, gen: 0 });
    assert_eq!(parse_query("ref 5 0").unwrap(), Query::Ref { obj: 5, gen: 0 });
    assert_eq!(parse_query("stream 8").unwrap(), Query::Stream { obj: 8, gen: 0 });
    assert_eq!(parse_query("goto 3 1").unwrap(), Query::Goto { obj: 3, gen: 1 });
}

#[test]
fn query_executor_findings_count() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    let query = parse_query("findings.count").unwrap();
    let output = execute_query(&query, &result);
    match output {
        QueryOutput::Text(text) => {
            let count: usize = text.parse().expect("findings.count should return a number");
            assert_eq!(count, result.report.findings.len());
        }
        _ => panic!("Expected Text output from findings.count"),
    }
}

#[test]
fn query_executor_object_lookup() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");

    // Find the catalog object number
    let catalog = result.object_data.objects.iter().find(|o| o.obj_type == "catalog");
    assert!(catalog.is_some(), "Should have a catalog object");
    let catalog = catalog.unwrap();

    let query = parse_query(&format!("object {}", catalog.obj)).unwrap();
    let output = execute_query(&query, &result);
    match output {
        QueryOutput::Text(text) => {
            assert!(
                text.contains("catalog"),
                "Object query should mention the type; got: {}",
                text
            );
        }
        _ => panic!("Expected Text output from object query"),
    }
}

#[test]
fn query_executor_object_not_found() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF";
    let result = analyze(pdf, "minimal.pdf").expect("analysis should succeed");
    let query = parse_query("object 999").unwrap();
    let output = execute_query(&query, &result);
    match output {
        QueryOutput::Error(msg) => {
            assert!(msg.contains("not found"), "Should report object not found");
        }
        _ => panic!("Expected Error output for missing object"),
    }
}

#[test]
fn query_executor_version() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF";
    let result = analyze(pdf, "minimal.pdf").expect("analysis should succeed");
    let query = parse_query("version").unwrap();
    let output = execute_query(&query, &result);
    match output {
        QueryOutput::Text(text) => {
            assert!(text.contains("1.4"), "Version should contain 1.4; got: {}", text);
        }
        _ => panic!("Expected Text output from version query"),
    }
}

#[test]
fn query_executor_filesize() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF";
    let result = analyze(pdf, "minimal.pdf").expect("analysis should succeed");
    let query = parse_query("filesize").unwrap();
    let output = execute_query(&query, &result);
    match output {
        QueryOutput::Text(text) => {
            assert!(
                text.contains(&pdf.len().to_string()),
                "filesize should contain actual size; got: {}",
                text
            );
        }
        _ => panic!("Expected Text output from filesize query"),
    }
}

#[test]
fn query_executor_navigation() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF";
    let result = analyze(pdf, "minimal.pdf").expect("analysis should succeed");
    let query = parse_query("goto 1").unwrap();
    let output = execute_query(&query, &result);
    match output {
        QueryOutput::Navigation { obj, gen } => {
            assert_eq!(obj, 1);
            assert_eq!(gen, 0);
        }
        _ => panic!("Expected Navigation output from goto query"),
    }
}

#[test]
fn query_executor_objects_list() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    let query = parse_query("objects.list").unwrap();
    let output = execute_query(&query, &result);
    match output {
        QueryOutput::Table { headers, rows } => {
            assert!(headers.contains(&"Obj".to_string()));
            assert!(headers.contains(&"Type".to_string()));
            assert_eq!(rows.len(), result.object_data.objects.len());
        }
        _ => panic!("Expected Table output from objects.list"),
    }
}

#[test]
fn query_executor_ref() {
    let bytes = include_bytes!("../../sis-pdf-core/tests/fixtures/launch_action.pdf");
    let result = analyze(bytes, "launch_action.pdf").expect("analysis should succeed");
    // Use the catalog object which should have references
    let catalog = result.object_data.objects.iter().find(|o| o.obj_type == "catalog").unwrap();
    let query = parse_query(&format!("ref {}", catalog.obj)).unwrap();
    let output = execute_query(&query, &result);
    match output {
        QueryOutput::Text(text) => {
            assert!(text.contains("References"), "ref query should show references; got: {}", text);
        }
        _ => panic!("Expected Text output from ref query"),
    }
}

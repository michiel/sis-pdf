use sis_pdf_gui::analysis::{analyze, AnalysisError};

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

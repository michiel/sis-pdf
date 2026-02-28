//! Integration tests for the `sis` CLI binary.
//!
//! These tests invoke the compiled binary directly via `std::process::Command`.
//! Run with: `cargo test -p sis-pdf --test cli_integration`

use std::process::Command;

fn sis_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sis")
}

fn cve_fixture() -> &'static str {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf"
    )
}

#[test]
fn json_output_is_valid() {
    let out = Command::new(sis_bin())
        .args(["scan", cve_fixture(), "--json"])
        .output()
        .expect("failed to run sis");
    assert!(out.status.success(), "exit code: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is not valid JSON");
    assert!(
        json.get("findings").is_some_and(|f| f.is_array()),
        "missing 'findings' array in output"
    );
    assert_eq!(
        json.get("type").and_then(|t| t.as_str()),
        Some("report"),
        "expected type=report in JSON output"
    );
}

#[test]
fn jsonl_findings_output_is_valid() {
    let out = Command::new(sis_bin())
        .args(["scan", cve_fixture(), "--jsonl-findings"])
        .output()
        .expect("failed to run sis");
    assert!(out.status.success(), "exit code: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut found_line = false;
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let json: serde_json::Value =
            serde_json::from_str(line).expect("JSONL line is not valid JSON");
        // Each line is a {"finding": {...}, "path": "..."} entry
        assert!(
            json.get("finding").is_some() || json.get("id").is_some(),
            "JSONL line missing 'finding' or 'id': {}",
            line
        );
        found_line = true;
    }
    assert!(found_line, "no JSONL lines found in output");
}

#[test]
fn sarif_output_is_valid() {
    let out = Command::new(sis_bin())
        .args(["scan", cve_fixture(), "--sarif"])
        .output()
        .expect("failed to run sis");
    assert!(out.status.success(), "exit code: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("SARIF output is not valid JSON");
    assert!(json.get("$schema").is_some(), "missing '$schema' in SARIF output");
    assert!(json.get("runs").is_some(), "missing 'runs' in SARIF output");
}

#[test]
fn missing_file_exits_nonzero() {
    let out = Command::new(sis_bin())
        .args(["scan", "missing_file_pdf_nonexistent_12345.pdf"])
        .output()
        .expect("failed to run sis");
    assert!(!out.status.success(), "expected non-zero exit code for missing file");
    // stderr or stdout should contain some error indication
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stderr.is_empty() || !stdout.is_empty(),
        "expected error output for missing file"
    );
}

#[test]
fn query_pages_is_integer() {
    let out = Command::new(sis_bin())
        .args(["query", cve_fixture(), "pages"])
        .output()
        .expect("failed to run sis");
    assert!(out.status.success(), "exit code: {}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim();
    assert!(
        trimmed.parse::<u64>().is_ok(),
        "expected integer page count, got: {:?}",
        trimmed
    );
}

#[test]
fn fast_deep_conflict_error() {
    let out = Command::new(sis_bin())
        .args(["scan", cve_fixture(), "--fast", "--deep"])
        .output()
        .expect("failed to run sis");
    assert!(!out.status.success(), "expected non-zero exit for --fast --deep conflict");
}

// TODO: diff_identical_inputs test
//
// This test would verify that `sis diff <jsonl1> <jsonl2>` exits 0 when both
// inputs are identical. Setting it up requires generating two JSONL files via
// `sis scan <cve_fixture> --format jsonl` and writing them to temporary paths,
// then invoking `sis diff`. Deferred for now due to temp-file coordination
// complexity in a no-std-process integration test context.
// Tracked as a follow-up task.

#[test]
fn correlate_findings_clusters_by_kind() {
    // Write a synthetic 3-line JSONL: two matching font.cmap_range_overlap findings
    // from different files, plus one embedded_file_present finding.
    let jsonl = concat!(
        r#"{"path":"a.pdf","finding":{"kind":"font.cmap_range_overlap","severity":"Medium","confidence":"Strong"}}"#,
        "\n",
        r#"{"path":"b.pdf","finding":{"kind":"font.cmap_range_overlap","severity":"Medium","confidence":"Strong"}}"#,
        "\n",
        r#"{"path":"c.pdf","finding":{"kind":"embedded_file_present","severity":"Low","confidence":"Probable"}}"#,
        "\n"
    );
    let dir = std::env::temp_dir();
    let input_path = dir.join("sis_test_correlate_findings.jsonl");
    std::fs::write(&input_path, jsonl).expect("write temp JSONL");

    let out = Command::new(sis_bin())
        .args(["correlate", "findings", "--input", input_path.to_str().unwrap()])
        .output()
        .expect("failed to run sis correlate findings");

    let _ = std::fs::remove_file(&input_path);

    assert!(out.status.success(), "exit code: {}\nstderr: {}", out.status, String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout is not valid JSON");

    assert_eq!(
        json.get("type").and_then(|t| t.as_str()),
        Some("findings_clusters"),
        "expected type=findings_clusters"
    );

    let clusters = json.get("clusters").and_then(|c| c.as_array()).expect("missing clusters array");
    let font_cluster = clusters
        .iter()
        .find(|c| c.get("kind").and_then(|k| k.as_str()) == Some("font.cmap_range_overlap"))
        .expect("expected cluster for font.cmap_range_overlap");

    let count = font_cluster.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
    assert!(count >= 2, "expected count >= 2 for font.cmap_range_overlap cluster, got {}", count);
}

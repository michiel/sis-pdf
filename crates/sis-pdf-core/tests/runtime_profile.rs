use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn profile_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join("performance-data")
        .join("profile-launch-cve.json")
}

#[test]
fn profile_json_honours_slo() {
    let path = profile_path();
    let contents =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("Failed to read {}", path.display()));
    let json: Value = serde_json::from_str(&contents).expect("valid profile JSON");

    let phases = json["phases"].as_array().expect("phases array");
    let parse_phase = phases
        .iter()
        .find(|phase| phase["name"].as_str() == Some("parse"))
        .expect("parse phase missing");
    let detection_phase = phases
        .iter()
        .find(|phase| phase["name"].as_str() == Some("detection"))
        .expect("detection phase missing");

    let parse_ms = parse_phase["duration_ms"].as_u64().expect("parse duration");
    let detection_ms = detection_phase["duration_ms"].as_u64().expect("detection duration");
    assert!(parse_ms < 10, "parse duration {}ms exceeds 10ms", parse_ms);
    assert!(detection_ms < 50, "detection duration {}ms exceeds 50ms", detection_ms);

    let detectors = json["detectors"].as_array().expect("detectors array");
    assert!(!detectors.is_empty(), "expected at least one detector in profile");
}

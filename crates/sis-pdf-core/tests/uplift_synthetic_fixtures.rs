use sis_pdf_core::chain_synth::synthesise_chains;
use sis_pdf_core::model::{
    AttackSurface, Confidence, Finding, Impact, ReaderImpact, ReaderProfile, Severity,
};
use std::collections::{HashMap, HashSet};

#[derive(serde::Deserialize)]
struct FixtureDoc {
    findings: Vec<FixtureFinding>,
}

#[derive(serde::Deserialize)]
struct FixtureFinding {
    id: String,
    kind: String,
    surface: String,
    severity: String,
    confidence: String,
    objects: Vec<String>,
    #[serde(default)]
    positions: Vec<String>,
    #[serde(default)]
    meta: HashMap<String, String>,
    #[serde(default)]
    reader_impacts: Vec<FixtureReaderImpact>,
}

#[derive(serde::Deserialize)]
struct FixtureReaderImpact {
    profile: String,
    surface: String,
    severity: String,
    impact: String,
}

fn load_fixture(path: &str) -> Vec<Finding> {
    let raw = std::fs::read_to_string(path).expect("fixture should be readable");
    let doc: FixtureDoc = serde_json::from_str(&raw).expect("fixture should parse");
    doc.findings
        .into_iter()
        .map(|fixture| Finding {
            id: fixture.id,
            surface: parse_surface(&fixture.surface),
            kind: fixture.kind,
            severity: parse_severity(&fixture.severity),
            confidence: parse_confidence(&fixture.confidence),
            impact: None,
            title: "fixture".to_string(),
            description: "fixture".to_string(),
            objects: fixture.objects,
            evidence: Vec::new(),
            remediation: None,
            position: None,
            positions: fixture.positions,
            meta: fixture.meta,
            reader_impacts: fixture.reader_impacts.into_iter().map(to_reader_impact).collect(),
            action_type: None,
            action_target: None,
            action_initiation: None,
            yara: None,
        })
        .collect()
}

fn to_reader_impact(value: FixtureReaderImpact) -> ReaderImpact {
    ReaderImpact {
        profile: parse_profile(&value.profile),
        surface: parse_surface(&value.surface),
        severity: parse_severity(&value.severity),
        impact: parse_impact(&value.impact),
        note: None,
    }
}

fn parse_surface(value: &str) -> AttackSurface {
    match value {
        "FileStructure" => AttackSurface::FileStructure,
        "XRefTrailer" => AttackSurface::XRefTrailer,
        "ObjectStreams" => AttackSurface::ObjectStreams,
        "StreamsAndFilters" => AttackSurface::StreamsAndFilters,
        "Actions" => AttackSurface::Actions,
        "JavaScript" => AttackSurface::JavaScript,
        "Forms" => AttackSurface::Forms,
        "EmbeddedFiles" => AttackSurface::EmbeddedFiles,
        "RichMedia3D" => AttackSurface::RichMedia3D,
        "Images" => AttackSurface::Images,
        "CryptoSignatures" => AttackSurface::CryptoSignatures,
        "Metadata" => AttackSurface::Metadata,
        "ContentPhishing" => AttackSurface::ContentPhishing,
        _ => AttackSurface::FileStructure,
    }
}

fn parse_profile(value: &str) -> ReaderProfile {
    match value {
        "Acrobat" => ReaderProfile::Acrobat,
        "Pdfium" => ReaderProfile::Pdfium,
        "Preview" => ReaderProfile::Preview,
        _ => ReaderProfile::Acrobat,
    }
}

fn parse_severity(value: &str) -> Severity {
    match value {
        "Info" => Severity::Info,
        "Low" => Severity::Low,
        "Medium" => Severity::Medium,
        "High" => Severity::High,
        "Critical" => Severity::Critical,
        _ => Severity::Info,
    }
}

fn parse_confidence(value: &str) -> Confidence {
    match value {
        "Certain" => Confidence::Certain,
        "Strong" => Confidence::Strong,
        "Probable" => Confidence::Probable,
        "Tentative" => Confidence::Tentative,
        "Weak" => Confidence::Weak,
        "Heuristic" => Confidence::Heuristic,
        _ => Confidence::Heuristic,
    }
}

fn parse_impact(value: &str) -> Impact {
    match value {
        "Critical" => Impact::Critical,
        "High" => Impact::High,
        "Medium" => Impact::Medium,
        "Low" => Impact::Low,
        "None" => Impact::None,
        _ => Impact::None,
    }
}

#[test]
fn synthetic_complex_distributed_fragmented_fixture_stays_connected() {
    let findings = load_fixture("tests/fixtures/uplift/complex_distributed_fragmented_chain.json");
    let (chains, _) = synthesise_chains(&findings, true);

    let stages = findings
        .iter()
        .filter_map(|finding| finding.meta.get("chain.stage").cloned())
        .collect::<HashSet<_>>();
    assert!(stages.contains("decode"));
    assert!(stages.contains("render"));
    assert!(stages.contains("execute"));
    assert!(
        chains.iter().any(|chain| chain.nodes.len() >= 2),
        "expected distributed chain with at least two node anchors"
    );
    assert!(
        chains.iter().any(|chain| {
            chain.notes.contains_key("exploit.outcomes")
                && chain.narrative.contains("Likely outcomes:")
                && chain.narrative.contains("Payload scatter evidence:")
        }),
        "expected exploit outcomes and scatter context in chain narrative"
    );
}

#[test]
fn synthetic_revision_shadow_fixture_preserves_revision_context() {
    let findings = load_fixture("tests/fixtures/uplift/revision_shadow_chain.json");
    let (chains, _) = synthesise_chains(&findings, true);

    assert!(findings.iter().any(|finding| finding.kind == "revision_annotations_changed"));
    assert!(findings.iter().any(|finding| finding.kind == "revision_anomaly_scoring"));
    assert!(findings.iter().any(|finding| finding.meta.get("revision.total").is_some()));
    assert!(
        chains.iter().any(|chain| !chain.narrative.trim().is_empty()),
        "expected non-empty narratives for revision-shadow fixture"
    );
}

#[test]
fn synthetic_multi_reader_divergence_fixture_aggregates_reader_risk() {
    let findings = load_fixture("tests/fixtures/uplift/multi_reader_divergence_chain.json");
    let (chains, _) = synthesise_chains(&findings, true);

    let expected = HashMap::from([
        ("acrobat".to_string(), "High".to_string()),
        ("pdfium".to_string(), "Medium".to_string()),
        ("preview".to_string(), "Low".to_string()),
    ]);
    assert!(
        chains.iter().any(|chain| chain.reader_risk == expected),
        "expected aggregated reader-risk divergence in chain output"
    );
}

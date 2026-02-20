use sis_pdf_core::report::Report;

#[test]
fn report_v1_fixture_defaults_chain_schema_and_additive_chain_fields() {
    let raw = include_str!("fixtures/report_v1_chain_schema.json");
    let report: Report = serde_json::from_str(raw).expect("fixture should deserialise");
    assert_eq!(report.chain_schema_version, 0);
    assert_eq!(report.chains.len(), 1);
    let chain = &report.chains[0];
    assert!(chain.group_id.is_none());
    assert_eq!(chain.group_count, 0);
    assert!(chain.group_members.is_empty());
    assert!(chain.nodes.is_empty());
    assert!(chain.edges.is_empty());
    assert!(chain.confirmed_stages.is_empty());
    assert!(chain.inferred_stages.is_empty());
    assert_eq!(chain.chain_completeness, 0.0);
    assert!(chain.reader_risk.is_empty());
    assert!(chain.narrative.is_empty());
    assert!(chain.finding_criticality.is_empty());
    assert!(chain.active_mitigations.is_empty());
    assert!(chain.required_conditions.is_empty());
    assert!(chain.unmet_conditions.is_empty());
}

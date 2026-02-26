use anyhow::Result;
use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::revision_timeline::{build_revision_timeline, DEFAULT_MAX_REVISIONS};
use sis_pdf_core::scan::span_to_evidence;

pub struct RevisionForensicsDetector;

impl Detector for RevisionForensicsDetector {
    fn id(&self) -> &'static str {
        "revision_forensics"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::FileStructure
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Moderate
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let timeline = build_revision_timeline(ctx, DEFAULT_MAX_REVISIONS);
        if timeline.revisions.len() <= 1 {
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();
        let base_meta = build_base_meta(&timeline);

        let page_refs = collect_refs(&timeline, |record| &record.page_content_changed_refs);
        if !page_refs.is_empty() {
            let mut meta = base_meta.clone();
            let revisions = collect_revisions_matching(&timeline, |record| {
                !record.page_content_changed_refs.is_empty()
            });
            meta.insert("revision.changed_pages_count".into(), page_refs.len().to_string());
            meta.insert("revision.changed_pages_refs".into(), list_preview(&page_refs, 16));
            meta.insert("revision.changed_revisions".into(), list_numbers(&revisions));
            findings.push(build_finding(
                ctx,
                "revision_page_content_changed",
                Severity::High,
                Confidence::Probable,
                Some(Impact::High),
                "Revision page content changed",
                "Page/content objects changed across revisions, indicating likely visual content modification.",
                &page_refs,
                "Diff changed page content streams across revisions and validate whether post-update rendering is expected.",
                meta,
            ));
        }

        let annotation_added_refs = collect_refs(&timeline, |record| &record.annotation_added_refs);
        let annotation_modified_refs =
            collect_refs(&timeline, |record| &record.annotation_modified_refs);
        if !annotation_added_refs.is_empty() || !annotation_modified_refs.is_empty() {
            let mut meta = base_meta.clone();
            let revisions = collect_revisions_matching(&timeline, |record| {
                !record.annotation_added_refs.is_empty()
                    || !record.annotation_modified_refs.is_empty()
            });
            meta.insert(
                "revision.annotations_added_count".into(),
                annotation_added_refs.len().to_string(),
            );
            meta.insert(
                "revision.annotations_modified_count".into(),
                annotation_modified_refs.len().to_string(),
            );
            if !annotation_added_refs.is_empty() {
                meta.insert(
                    "revision.annotations_added_refs".into(),
                    list_preview(&annotation_added_refs, 16),
                );
            }
            if !annotation_modified_refs.is_empty() {
                meta.insert(
                    "revision.annotations_modified_refs".into(),
                    list_preview(&annotation_modified_refs, 16),
                );
            }
            meta.insert("revision.changed_revisions".into(), list_numbers(&revisions));
            let mut objects = annotation_added_refs.clone();
            objects.extend(annotation_modified_refs.clone());
            objects.sort();
            objects.dedup();
            findings.push(build_finding(
                ctx,
                "revision_annotations_changed",
                Severity::Medium,
                Confidence::Probable,
                Some(Impact::Medium),
                "Revision annotations changed",
                "Annotations were added or modified across revisions, which can alter user-visible overlays and interaction points.",
                &objects,
                "Review annotation deltas between revisions, especially post-signature updates with appearance streams.",
                meta,
            ));
        }

        let catalog_refs = collect_refs(&timeline, |record| &record.catalog_changed_refs);
        if !catalog_refs.is_empty() {
            let mut meta = base_meta.clone();
            let revisions = collect_revisions_matching(&timeline, |record| {
                !record.catalog_changed_refs.is_empty()
            });
            meta.insert("revision.catalog_changed".into(), "true".into());
            meta.insert("revision.catalog_changed_refs".into(), list_preview(&catalog_refs, 16));
            meta.insert("revision.changed_revisions".into(), list_numbers(&revisions));
            findings.push(build_finding(
                ctx,
                "revision_catalog_changed",
                Severity::High,
                Confidence::Strong,
                Some(Impact::High),
                "Revision catalog changed",
                "Document catalog/root structures changed across revisions, indicating behaviour-level document mutation.",
                &catalog_refs,
                "Audit catalog-level changes (/Root, /OpenAction, name trees, and page tree links) between revisions.",
                meta,
            ));
        }

        if let Some(max_record) =
            timeline.revisions.iter().max_by_key(|record| record.anomaly_score)
        {
            if max_record.anomaly_score >= 4 {
                let mut meta = base_meta;
                meta.insert(
                    "revision.anomaly.max_score".into(),
                    max_record.anomaly_score.to_string(),
                );
                meta.insert(
                    "revision.anomaly.max_revision".into(),
                    max_record.revision.to_string(),
                );
                if !max_record.anomaly_reasons.is_empty() {
                    meta.insert(
                        "revision.anomaly.reasons".into(),
                        max_record.anomaly_reasons.join(","),
                    );
                }
                let scores = timeline
                    .revisions
                    .iter()
                    .map(|record| format!("r{}={}", record.revision, record.anomaly_score))
                    .collect::<Vec<_>>();
                meta.insert("revision.anomaly.timeline".into(), scores.join(", "));

                let (severity, confidence) = if max_record.anomaly_score >= 9 {
                    (Severity::High, Confidence::Strong)
                } else if max_record.anomaly_score >= 6 {
                    (Severity::Medium, Confidence::Probable)
                } else {
                    (Severity::Low, Confidence::Tentative)
                };
                let mut objects = max_record.objects_modified_refs.clone();
                objects.extend(max_record.objects_added_refs.clone());
                objects.sort();
                objects.dedup();
                findings.push(build_finding(
                    ctx,
                    "revision_anomaly_scoring",
                    severity,
                    confidence,
                    Some(Impact::Medium),
                    "Revision anomaly scoring",
                    "Revision-level anomaly scoring indicates unusual structural or behavioural change patterns in incremental updates.",
                    &objects,
                    "Inspect high-scoring revisions first and compare changed objects against expected editing workflows.",
                    meta,
                ));
            }
        }

        Ok(findings)
    }
}

fn build_base_meta(
    timeline: &sis_pdf_core::revision_timeline::RevisionTimeline,
) -> std::collections::HashMap<String, String> {
    let mut meta = std::collections::HashMap::new();
    meta.insert("revision.total".into(), timeline.total_revisions.to_string());
    meta.insert("revision.analysed".into(), timeline.revisions.len().to_string());
    meta.insert("revision.capped".into(), timeline.capped.to_string());
    meta.insert("revision.skipped".into(), timeline.skipped_revisions.to_string());
    meta.insert("revision.prev_chain_valid".into(), timeline.prev_chain_valid.to_string());
    if !timeline.prev_chain_errors.is_empty() {
        meta.insert("revision.prev_chain_errors".into(), timeline.prev_chain_errors.join(" | "));
    }
    if !timeline.signature_boundaries.is_empty() {
        meta.insert(
            "revision.signature_boundaries".into(),
            timeline.signature_boundaries.iter().map(u64::to_string).collect::<Vec<_>>().join(","),
        );
    }
    meta
}

fn collect_refs<F>(
    timeline: &sis_pdf_core::revision_timeline::RevisionTimeline,
    extract: F,
) -> Vec<String>
where
    F: Fn(&sis_pdf_core::revision_timeline::RevisionRecord) -> &Vec<String>,
{
    let mut refs = Vec::new();
    for record in &timeline.revisions {
        for object_ref in extract(record) {
            if !refs.contains(object_ref) {
                refs.push(object_ref.clone());
            }
        }
    }
    refs
}

fn collect_revisions_matching<F>(
    timeline: &sis_pdf_core::revision_timeline::RevisionTimeline,
    predicate: F,
) -> Vec<usize>
where
    F: Fn(&sis_pdf_core::revision_timeline::RevisionRecord) -> bool,
{
    timeline
        .revisions
        .iter()
        .filter(|record| predicate(record))
        .map(|record| record.revision)
        .collect::<Vec<_>>()
}

fn list_preview(values: &[String], max_items: usize) -> String {
    if values.len() <= max_items {
        return values.join(", ");
    }
    let shown = values.iter().take(max_items).cloned().collect::<Vec<_>>().join(", ");
    format!("{shown} (+{} more)", values.len() - max_items)
}

fn list_numbers(values: &[usize]) -> String {
    values.iter().map(usize::to_string).collect::<Vec<_>>().join(",")
}

fn build_finding(
    ctx: &sis_pdf_core::scan::ScanContext<'_>,
    kind: &str,
    severity: Severity,
    confidence: Confidence,
    impact: Option<Impact>,
    title: &str,
    description: &str,
    object_refs: &[String],
    remediation: &str,
    meta: std::collections::HashMap<String, String>,
) -> Finding {
    Finding {
        id: String::new(),
        surface: AttackSurface::FileStructure,
        kind: kind.into(),
        severity,
        confidence,
        impact,
        title: title.into(),
        description: description.into(),
        objects: object_refs.to_vec(),
        evidence: object_refs
            .iter()
            .filter_map(|object_ref| parse_obj_ref(object_ref))
            .filter_map(|(obj, generation)| ctx.graph.get_object(obj, generation))
            .map(|entry| span_to_evidence(entry.full_span, "Revision-changed object"))
            .collect(),
        remediation: Some(remediation.into()),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    }
}

fn parse_obj_ref(value: &str) -> Option<(u32, u16)> {
    let mut parts = value.split_whitespace();
    let obj = parts.next()?.parse::<u32>().ok()?;
    let generation = parts.next()?.parse::<u16>().ok()?;
    Some((obj, generation))
}

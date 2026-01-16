use std::collections::{BTreeSet, HashSet};

use anyhow::Result;

use crate::model::{AttackSurface, Finding, Severity};
use crate::report::{Report, TemporalSignalSummary};
use crate::scan::{ScanContext, ScanOptions};
use sis_pdf_pdf::{parse_pdf, ParseOptions};

pub struct VersionedScan<'a> {
    pub label: String,
    pub bytes: &'a [u8],
    pub report: Report,
    pub context: ScanContext<'a>,
}

pub fn build_versioned_scans<'a>(
    bytes: &'a [u8],
    opts: &ScanOptions,
    detectors: &[Box<dyn crate::detect::Detector>],
) -> Result<Vec<VersionedScan<'a>>> {
    let graph = parse_pdf(
        bytes,
        ParseOptions {
            recover_xref: opts.recover_xref,
            deep: opts.deep,
            strict: opts.strict,
            max_objstm_bytes: opts.max_decode_bytes,
            max_objects: opts.max_objects,
            max_objstm_total_bytes: opts.max_total_decoded_bytes,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        },
    )?;
    let mut startxrefs = graph.startxrefs.clone();
    startxrefs.sort_unstable();
    startxrefs.dedup();
    let slices = build_version_slices(bytes, &startxrefs);

    let mut scans = Vec::new();
    for (idx, slice) in slices.into_iter().enumerate() {
        let label = format!("v{}", idx + 1);
        let report = crate::runner::run_scan_with_detectors(slice, opts.clone(), detectors)?;
        let context = ScanContext::new(
            slice,
            parse_pdf(
                slice,
                ParseOptions {
                    recover_xref: opts.recover_xref,
                    deep: opts.deep,
                    strict: opts.strict,
                    max_objstm_bytes: opts.max_decode_bytes,
                    max_objects: opts.max_objects,
                    max_objstm_total_bytes: opts.max_total_decoded_bytes,
                    carve_stream_objects: false,
                    max_carved_objects: 0,
                    max_carved_bytes: 0,
                },
            )?,
            opts.clone(),
        );
        scans.push(VersionedScan {
            label,
            bytes: slice,
            report,
            context,
        });
    }

    Ok(scans)
}

pub fn build_temporal_signal_summary(reports: &[VersionedScan<'_>]) -> TemporalSignalSummary {
    let revisions = reports.len();
    let mut new_attack_surfaces: BTreeSet<String> = BTreeSet::new();
    let mut new_findings: BTreeSet<String> = BTreeSet::new();
    let mut removed_findings: BTreeSet<String> = BTreeSet::new();
    let mut structural_deltas: Vec<String> = Vec::new();
    let mut new_high_severity = 0usize;

    let mut seen_kinds: HashSet<String> = HashSet::new();
    let mut seen_surfaces: HashSet<AttackSurface> = HashSet::new();
    let mut seen_high_kinds: HashSet<String> = HashSet::new();
    let mut prev_kinds: Option<HashSet<String>> = None;

    for (idx, scan) in reports.iter().enumerate() {
        let label = &scan.label;
        let findings = &scan.report.findings;
        let current_kinds: HashSet<String> = findings.iter().map(|f| f.kind.clone()).collect();
        let current_surfaces: HashSet<AttackSurface> = findings.iter().map(|f| f.surface).collect();

        if let Some(prev) = prev_kinds.as_ref() {
            for kind in prev.difference(&current_kinds) {
                removed_findings.insert(format!("{}: {}", label, kind));
            }
        }

        for kind in current_kinds.difference(&seen_kinds) {
            new_findings.insert(format!("{}: {}", label, kind));
        }

        for surface in current_surfaces.difference(&seen_surfaces) {
            new_attack_surfaces.insert(format!("{:?}", surface));
        }

        if idx > 0 {
            for finding in findings.iter().filter(|f| is_high_severity(f)) {
                if seen_high_kinds.insert(finding.kind.clone()) {
                    new_high_severity += 1;
                }
            }
        } else {
            for finding in findings.iter().filter(|f| is_high_severity(f)) {
                seen_high_kinds.insert(finding.kind.clone());
            }
        }

        if idx > 0 {
            let prev_report = &reports[idx - 1].report;
            add_structural_deltas(label, prev_report, &scan.report, &mut structural_deltas);
        }

        seen_kinds.extend(current_kinds.into_iter());
        seen_surfaces.extend(current_surfaces.into_iter());
        prev_kinds = Some(findings.iter().map(|f| f.kind.clone()).collect());
    }

    TemporalSignalSummary {
        revisions,
        new_high_severity,
        new_attack_surfaces: new_attack_surfaces.into_iter().collect(),
        removed_findings: removed_findings.into_iter().collect(),
        new_findings: new_findings.into_iter().collect(),
        structural_deltas,
    }
}

fn build_version_slices<'a>(bytes: &'a [u8], startxrefs: &[u64]) -> Vec<&'a [u8]> {
    if startxrefs.is_empty() {
        return vec![bytes];
    }
    let mut out = Vec::new();
    for (idx, startxref) in startxrefs.iter().enumerate() {
        let end = if idx + 1 < startxrefs.len() {
            startxrefs[idx + 1] as usize
        } else {
            bytes.len()
        };
        let end = end.min(bytes.len());
        if end == 0 {
            continue;
        }
        out.push(&bytes[..end]);
        if *startxref as usize >= bytes.len() {
            break;
        }
    }
    if out.is_empty() {
        vec![bytes]
    } else {
        out
    }
}

fn is_high_severity(finding: &Finding) -> bool {
    matches!(finding.severity, Severity::High | Severity::Critical)
}

fn add_structural_deltas(label: &str, prev: &Report, current: &Report, deltas: &mut Vec<String>) {
    let Some(prev_struct) = &prev.structural_summary else {
        return;
    };
    let Some(curr_struct) = &current.structural_summary else {
        return;
    };
    if prev_struct.object_count != curr_struct.object_count {
        deltas.push(format!(
            "{}: objects {} -> {}",
            label, prev_struct.object_count, curr_struct.object_count
        ));
    }
    if prev_struct.trailer_count != curr_struct.trailer_count {
        deltas.push(format!(
            "{}: trailers {} -> {}",
            label, prev_struct.trailer_count, curr_struct.trailer_count
        ));
    }
    if prev_struct.objstm_count != curr_struct.objstm_count {
        deltas.push(format!(
            "{}: objstm {} -> {}",
            label, prev_struct.objstm_count, curr_struct.objstm_count
        ));
    }
    if prev_struct.recover_xref != curr_struct.recover_xref {
        deltas.push(format!(
            "{}: recover_xref {} -> {}",
            label, prev_struct.recover_xref, curr_struct.recover_xref
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Confidence;
    use crate::report::Report;
    use crate::scan::{FontAnalysisOptions, ProfileFormat};

    fn test_opts() -> ScanOptions {
        ScanOptions {
            deep: false,
            max_decode_bytes: 32 * 1024 * 1024,
            max_total_decoded_bytes: 256 * 1024 * 1024,
            recover_xref: true,
            parallel: false,
            batch_parallel: false,
            diff_parser: false,
            max_objects: 500_000,
            max_recursion_depth: 64,
            fast: false,
            focus_trigger: None,
            yara_scope: None,
            focus_depth: 0,
            strict: false,
            strict_summary: false,
            ir: false,
            ml_config: None,
        font_analysis: FontAnalysisOptions::default(),
        profile: false,
        profile_format: ProfileFormat::Text,
    }
    }

    fn empty_report(findings: Vec<Finding>) -> Report {
        Report::from_findings(
            findings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            None,
        )
    }

    #[test]
    fn test_temporal_signal_summary() -> Result<()> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/synthetic.pdf");
        let bytes = std::fs::read(path)?;
        let graph1 = parse_pdf(
            &bytes,
            ParseOptions {
                recover_xref: true,
                deep: false,
                strict: false,
                max_objstm_bytes: 32 * 1024 * 1024,
                max_objects: 500_000,
                max_objstm_total_bytes: 256 * 1024 * 1024,
                carve_stream_objects: false,
                max_carved_objects: 0,
                max_carved_bytes: 0,
            },
        )?;
        let graph2 = parse_pdf(
            &bytes,
            ParseOptions {
                recover_xref: true,
                deep: false,
                strict: false,
                max_objstm_bytes: 32 * 1024 * 1024,
                max_objects: 500_000,
                max_objstm_total_bytes: 256 * 1024 * 1024,
                carve_stream_objects: false,
                max_carved_objects: 0,
                max_carved_bytes: 0,
            },
        )?;
        let ctx1 = ScanContext::new(&bytes, graph1, test_opts());
        let ctx2 = ScanContext::new(&bytes, graph2, test_opts());

        let report1 = empty_report(vec![Finding {
            id: "f1".to_string(),
            surface: AttackSurface::Metadata,
            kind: "low_signal".to_string(),
            severity: Severity::Low,
            confidence: Confidence::Heuristic,
            title: "Low".to_string(),
            description: "test".to_string(),
            objects: vec![],
            evidence: vec![],
            remediation: None,
            meta: Default::default(),
            yara: None,
            position: None,
            positions: Vec::new(),
        }]);

        let report2 = empty_report(vec![Finding {
            id: "f2".to_string(),
            surface: AttackSurface::Actions,
            kind: "high_signal".to_string(),
            severity: Severity::High,
            confidence: Confidence::Strong,
            title: "High".to_string(),
            description: "test".to_string(),
            objects: vec![],
            evidence: vec![],
            remediation: None,
            meta: Default::default(),
            yara: None,
            position: None,
            positions: Vec::new(),
        }]);

        let scans = vec![
            VersionedScan {
                label: "v1".to_string(),
                bytes: &bytes,
                report: report1,
                context: ctx1,
            },
            VersionedScan {
                label: "v2".to_string(),
                bytes: &bytes,
                report: report2,
                context: ctx2,
            },
        ];

        let summary = build_temporal_signal_summary(&scans);
        assert_eq!(summary.revisions, 2);
        assert_eq!(summary.new_high_severity, 1);
        assert!(summary
            .new_findings
            .iter()
            .any(|v| v.contains("high_signal")));
        assert!(summary
            .new_attack_surfaces
            .iter()
            .any(|v| v.contains("Actions")));
        Ok(())
    }
}

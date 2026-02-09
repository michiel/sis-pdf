use std::time::Duration;

use anyhow::Result;

use js_analysis::{
    is_file_call, is_network_call, run_sandbox, DynamicOptions, DynamicOutcome, RuntimeKind,
    RuntimeMode, RuntimeProfile,
};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;

use crate::js_payload_candidates_from_entry;

pub struct JavaScriptSandboxDetector;

const JS_WALLCLOCK_TIMEOUT: Duration = Duration::from_secs(5);
const JS_SANDBOX_MAX_BYTES: usize = 256 * 1024;

struct ProfileRun {
    profile_id: String,
    outcome: DynamicOutcome,
}

#[derive(Default)]
struct ProfileDivergenceSummary {
    profile_ids: Vec<String>,
    profile_statuses: Vec<String>,
    executed_profiles: Vec<String>,
    executed_count: usize,
    timed_out_count: usize,
    skipped_count: usize,
    network_count: usize,
    file_count: usize,
    risky_count: usize,
    calls_count: usize,
}

impl ProfileDivergenceSummary {
    fn total(&self) -> usize {
        self.profile_ids.len()
    }

    fn divergence_label(&self) -> &'static str {
        if self.executed_count < 2 {
            return "insufficient";
        }
        let ratios =
            [self.network_ratio(), self.file_ratio(), self.risky_ratio(), self.calls_ratio()];
        let mut seen_present = false;
        let mut seen_absent = false;
        for ratio in ratios.into_iter().flatten() {
            if ratio > 0.0 {
                seen_present = true;
            }
            if ratio < 1.0 {
                seen_absent = true;
            }
        }
        if seen_present && seen_absent {
            "divergent"
        } else {
            "consistent"
        }
    }

    fn network_ratio(&self) -> Option<f64> {
        ratio(self.network_count, self.executed_count)
    }

    fn file_ratio(&self) -> Option<f64> {
        ratio(self.file_count, self.executed_count)
    }

    fn risky_ratio(&self) -> Option<f64> {
        ratio(self.risky_count, self.executed_count)
    }

    fn calls_ratio(&self) -> Option<f64> {
        ratio(self.calls_count, self.executed_count)
    }
}

fn ratio(numerator: usize, denominator: usize) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

fn configured_profiles() -> [RuntimeProfile; 3] {
    [
        RuntimeProfile {
            kind: RuntimeKind::PdfReader,
            vendor: "adobe".to_string(),
            version: "11".to_string(),
            mode: RuntimeMode::Compat,
        },
        RuntimeProfile {
            kind: RuntimeKind::Browser,
            vendor: "chromium".to_string(),
            version: "120".to_string(),
            mode: RuntimeMode::Compat,
        },
        RuntimeProfile {
            kind: RuntimeKind::Node,
            vendor: "nodejs".to_string(),
            version: "20".to_string(),
            mode: RuntimeMode::Compat,
        },
    ]
}

fn execute_profiles(bytes: &[u8]) -> (Vec<ProfileRun>, ProfileDivergenceSummary) {
    let mut runs = Vec::new();
    let mut summary = ProfileDivergenceSummary::default();
    for profile in configured_profiles() {
        let profile_id = profile.id();
        let options = DynamicOptions {
            max_bytes: JS_SANDBOX_MAX_BYTES,
            timeout_ms: JS_WALLCLOCK_TIMEOUT.as_millis(),
            runtime_profile: profile.clone(),
            ..Default::default()
        };
        let outcome = run_sandbox(bytes, &options);
        summary.profile_ids.push(profile_id.clone());
        match &outcome {
            DynamicOutcome::Executed(signals) => {
                summary.executed_count += 1;
                summary.executed_profiles.push(profile_id.clone());
                let has_network = signals.calls.iter().any(|c| is_network_call(c));
                let has_file = signals.calls.iter().any(|c| is_file_call(c));
                let has_risky = signals.calls.iter().any(|c| {
                    c.eq_ignore_ascii_case("eval")
                        || c.eq_ignore_ascii_case("app.eval")
                        || c.eq_ignore_ascii_case("event.target.eval")
                        || c.eq_ignore_ascii_case("unescape")
                        || c.eq_ignore_ascii_case("Function")
                });
                let has_calls = signals.call_count > 0;
                if has_network {
                    summary.network_count += 1;
                }
                if has_file {
                    summary.file_count += 1;
                }
                if has_risky {
                    summary.risky_count += 1;
                }
                if has_calls {
                    summary.calls_count += 1;
                }
                summary.profile_statuses.push(format!(
                    "{}:executed:calls={}:network={}:file={}:risky={}",
                    profile_id, signals.call_count, has_network, has_file, has_risky
                ));
            }
            DynamicOutcome::TimedOut { timeout_ms } => {
                summary.timed_out_count += 1;
                summary.profile_statuses.push(format!("{}:timeout:{}ms", profile_id, timeout_ms));
            }
            DynamicOutcome::Skipped { reason, .. } => {
                summary.skipped_count += 1;
                summary.profile_statuses.push(format!("{}:skipped:{}", profile_id, reason));
            }
        }
        runs.push(ProfileRun { profile_id, outcome });
    }
    (runs, summary)
}

fn select_primary_outcome(runs: &[ProfileRun]) -> Option<DynamicOutcome> {
    for run in runs {
        if run.profile_id.starts_with("pdf_reader:") {
            if let DynamicOutcome::Executed(_) = run.outcome {
                return Some(run.outcome.clone());
            }
        }
    }
    for run in runs {
        if let DynamicOutcome::Executed(_) = run.outcome {
            return Some(run.outcome.clone());
        }
    }
    for run in runs {
        if let DynamicOutcome::TimedOut { .. } = run.outcome {
            return Some(run.outcome.clone());
        }
    }
    runs.first().map(|run| run.outcome.clone())
}

fn insert_profile_meta(
    meta: &mut std::collections::HashMap<String, String>,
    summary: &ProfileDivergenceSummary,
) {
    meta.insert("js.runtime.profile_count".into(), summary.total().to_string());
    meta.insert("js.runtime.profile_executed_count".into(), summary.executed_count.to_string());
    meta.insert("js.runtime.profile_timed_out_count".into(), summary.timed_out_count.to_string());
    meta.insert("js.runtime.profile_skipped_count".into(), summary.skipped_count.to_string());
    meta.insert("js.runtime.profile_ids".into(), summary.profile_ids.join(", "));
    if !summary.executed_profiles.is_empty() {
        meta.insert("js.runtime.profile_executed".into(), summary.executed_profiles.join(", "));
    }
    if !summary.profile_statuses.is_empty() {
        meta.insert("js.runtime.profile_status".into(), summary.profile_statuses.join(" | "));
    }
    meta.insert("js.runtime.profile_divergence".into(), summary.divergence_label().to_string());
    if let Some(value) = summary.network_ratio() {
        meta.insert("js.runtime.profile_network_ratio".into(), format!("{value:.2}"));
    }
    if let Some(value) = summary.file_ratio() {
        meta.insert("js.runtime.profile_file_ratio".into(), format!("{value:.2}"));
    }
    if let Some(value) = summary.risky_ratio() {
        meta.insert("js.runtime.profile_risky_ratio".into(), format!("{value:.2}"));
    }
    if let Some(value) = summary.calls_ratio() {
        meta.insert("js.runtime.profile_calls_ratio".into(), format!("{value:.2}"));
    }
}

fn promote_severity(value: Severity) -> Severity {
    match value {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High => Severity::Critical,
        Severity::Critical => Severity::Critical,
    }
}

fn demote_severity(value: Severity) -> Severity {
    match value {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Info,
        Severity::Info => Severity::Info,
    }
}

fn promote_confidence(value: Confidence) -> Confidence {
    match value {
        Confidence::Certain => Confidence::Certain,
        Confidence::Strong => Confidence::Certain,
        Confidence::Probable => Confidence::Strong,
        Confidence::Tentative => Confidence::Probable,
        Confidence::Weak => Confidence::Tentative,
        Confidence::Heuristic => Confidence::Weak,
    }
}

fn demote_confidence(value: Confidence) -> Confidence {
    match value {
        Confidence::Certain => Confidence::Strong,
        Confidence::Strong => Confidence::Probable,
        Confidence::Probable => Confidence::Tentative,
        Confidence::Tentative => Confidence::Weak,
        Confidence::Weak => Confidence::Heuristic,
        Confidence::Heuristic => Confidence::Heuristic,
    }
}

fn adjust_by_ratio(
    base_severity: Severity,
    base_confidence: Confidence,
    ratio: Option<f64>,
) -> (Severity, Confidence) {
    let Some(value) = ratio else {
        return (base_severity, base_confidence);
    };
    if value >= 0.67 {
        (promote_severity(base_severity), promote_confidence(base_confidence))
    } else if value <= 0.34 {
        (demote_severity(base_severity), demote_confidence(base_confidence))
    } else {
        (base_severity, base_confidence)
    }
}

fn apply_profile_scoring(
    kind: &str,
    base_severity: Severity,
    base_confidence: Confidence,
    summary: &ProfileDivergenceSummary,
) -> (Severity, Confidence, Option<f64>, &'static str) {
    let (ratio, signal) = match kind {
        "js_runtime_network_intent" => (summary.network_ratio(), "network"),
        "js_runtime_file_probe" => (summary.file_ratio(), "file"),
        "js_runtime_risky_calls" => (summary.risky_ratio(), "risky_calls"),
        "js_sandbox_exec" => (summary.calls_ratio(), "calls"),
        _ => (None, "none"),
    };
    let (severity, confidence) = adjust_by_ratio(base_severity, base_confidence, ratio);
    (severity, confidence, ratio, signal)
}

fn apply_profile_scoring_meta(
    meta: &mut std::collections::HashMap<String, String>,
    summary: &ProfileDivergenceSummary,
    kind: &str,
    base_severity: Severity,
    base_confidence: Confidence,
) -> (Severity, Confidence) {
    insert_profile_meta(meta, summary);
    let (severity, confidence, ratio, signal) =
        apply_profile_scoring(kind, base_severity, base_confidence, summary);
    if signal != "none" {
        meta.insert("js.runtime.profile_consistency_signal".into(), signal.to_string());
    }
    if let Some(value) = ratio {
        meta.insert("js.runtime.profile_consistency_ratio".into(), format!("{value:.2}"));
    }
    if severity != base_severity {
        meta.insert(
            "js.runtime.profile_severity_adjusted".into(),
            format!("{:?}->{:?}", base_severity, severity),
        );
    }
    if confidence != base_confidence {
        meta.insert(
            "js.runtime.profile_confidence_adjusted".into(),
            format!("{:?}->{:?}", base_confidence, confidence),
        );
    }
    (severity, confidence)
}

impl Detector for JavaScriptSandboxDetector {
    fn id(&self) -> &'static str {
        "js_sandbox"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::JavaScript
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Expensive
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            let candidates = js_payload_candidates_from_entry(ctx, entry);
            if candidates.is_empty() {
                continue;
            }
            for candidate in candidates {
                let info = candidate.payload;
                let mut evidence = candidate.evidence;
                if evidence.is_empty() {
                    evidence.push(span_to_evidence(entry.full_span, "JavaScript object"));
                }

                let (profile_runs, profile_summary) = execute_profiles(&info.bytes);
                let Some(primary_outcome) = select_primary_outcome(&profile_runs) else {
                    continue;
                };
                match primary_outcome {
                    DynamicOutcome::Skipped { reason, limit, actual } => {
                        let mut meta = std::collections::HashMap::new();
                        meta.insert("js.sandbox_exec".into(), "false".into());
                        meta.insert("js.sandbox_skip_reason".into(), reason);
                        meta.insert("payload.decoded_len".into(), actual.to_string());
                        meta.insert("js.sandbox_limit_bytes".into(), limit.to_string());
                        if let Some(label) = candidate.source.meta_value() {
                            meta.insert("js.source".into(), label.into());
                        }
                        insert_profile_meta(&mut meta, &profile_summary);
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "js_sandbox_skipped".into(),
                            severity: Severity::Info,
                            confidence: Confidence::Probable,
            impact: None,
                            title: "JavaScript sandbox skipped".into(),
                            description: "Sandbox skipped because the JS payload exceeds the size limit or sandbox is unavailable.".into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: evidence.clone(),
                            remediation: Some("Inspect the JS payload size and consider manual analysis.".into()),
                            meta,
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                        ..Finding::default()
                        });
                    }
                    DynamicOutcome::TimedOut { timeout_ms } => {
                        let mut meta = std::collections::HashMap::new();
                        meta.insert("js.sandbox_exec".into(), "true".into());
                        meta.insert("js.sandbox_timeout".into(), "true".into());
                        meta.insert("js.sandbox_timeout_ms".into(), timeout_ms.to_string());
                        if let Some(label) = candidate.source.meta_value() {
                            meta.insert("js.source".into(), label.into());
                        }
                        insert_profile_meta(&mut meta, &profile_summary);
                        findings.push(Finding {
                            id: String::new(),
                            surface: self.surface(),
                            kind: "js_sandbox_timeout".into(),
                            severity: Severity::Low,
                            confidence: Confidence::Probable,
                            impact: None,
                            title: "JavaScript sandbox timeout".into(),
                            description: "Sandbox execution exceeded the time limit.".into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: evidence.clone(),
                            remediation: Some(
                                "Inspect the JS payload for long-running loops.".into(),
                            ),
                            meta,
                            yara: None,
                            position: None,
                            positions: Vec::new(),
                            ..Finding::default()
                        });
                    }
                    DynamicOutcome::Executed(signals) => {
                        if signals.call_count == 0 {
                            let mut meta = std::collections::HashMap::new();
                            meta.insert("js.sandbox_exec".into(), "true".into());
                            meta.insert("js.runtime.replay_id".into(), signals.replay_id.clone());
                            meta.insert("js.runtime.ordering".into(), "deterministic".into());
                            meta.insert(
                                "js.runtime.profile".into(),
                                signals.runtime_profile.clone(),
                            );
                            if let Some(label) = candidate.source.meta_value() {
                                meta.insert("js.source".into(), label.into());
                            }
                            if let Some(ms) = signals.elapsed_ms {
                                meta.insert("js.sandbox_exec_ms".into(), ms.to_string());
                            }
                            if !signals.prop_reads.is_empty() {
                                meta.insert(
                                    "js.runtime.prop_reads".into(),
                                    signals.prop_reads.join(", "),
                                );
                                meta.insert(
                                    "js.runtime.unique_prop_reads".into(),
                                    signals.unique_prop_reads.to_string(),
                                );
                            }
                            if !signals.errors.is_empty() {
                                meta.insert("js.runtime.errors".into(), signals.errors.join("; "));
                            }
                            if !signals.prop_writes.is_empty() {
                                meta.insert(
                                    "js.runtime.prop_writes".into(),
                                    signals.prop_writes.join(", "),
                                );
                            }
                            if !signals.prop_deletes.is_empty() {
                                meta.insert(
                                    "js.runtime.prop_deletes".into(),
                                    signals.prop_deletes.join(", "),
                                );
                            }
                            if !signals.reflection_probes.is_empty() {
                                meta.insert(
                                    "js.runtime.reflection_probes".into(),
                                    signals.reflection_probes.join(", "),
                                );
                            }
                            if !signals.dynamic_code_calls.is_empty() {
                                meta.insert(
                                    "js.runtime.dynamic_code_calls".into(),
                                    signals.dynamic_code_calls.join(", "),
                                );
                            }
                            if signals.truncation.calls_dropped > 0 {
                                meta.insert(
                                    "js.runtime.truncation.calls_dropped".into(),
                                    signals.truncation.calls_dropped.to_string(),
                                );
                            }
                            if signals.truncation.call_args_dropped > 0 {
                                meta.insert(
                                    "js.runtime.truncation.call_args_dropped".into(),
                                    signals.truncation.call_args_dropped.to_string(),
                                );
                            }
                            if signals.truncation.prop_reads_dropped > 0 {
                                meta.insert(
                                    "js.runtime.truncation.prop_reads_dropped".into(),
                                    signals.truncation.prop_reads_dropped.to_string(),
                                );
                            }
                            if signals.truncation.errors_dropped > 0 {
                                meta.insert(
                                    "js.runtime.truncation.errors_dropped".into(),
                                    signals.truncation.errors_dropped.to_string(),
                                );
                            }
                            if signals.truncation.urls_dropped > 0 {
                                meta.insert(
                                    "js.runtime.truncation.urls_dropped".into(),
                                    signals.truncation.urls_dropped.to_string(),
                                );
                            }
                            if signals.truncation.domains_dropped > 0 {
                                meta.insert(
                                    "js.runtime.truncation.domains_dropped".into(),
                                    signals.truncation.domains_dropped.to_string(),
                                );
                            }
                            if !signals.phases.is_empty() {
                                let phase_order = signals
                                    .phases
                                    .iter()
                                    .map(|phase| phase.phase.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                let phase_summary = signals
                                    .phases
                                    .iter()
                                    .map(|phase| {
                                        format!(
                                            "{}:calls={} props={} errors={} ms={}",
                                            phase.phase,
                                            phase.call_count,
                                            phase.prop_read_count,
                                            phase.error_count,
                                            phase.elapsed_ms
                                        )
                                    })
                                    .collect::<Vec<_>>()
                                    .join(" | ");
                                meta.insert("js.runtime.phase_order".into(), phase_order);
                                meta.insert("js.runtime.phase_summaries".into(), phase_summary);
                                meta.insert(
                                    "js.runtime.phase_count".into(),
                                    signals.phases.len().to_string(),
                                );
                            }
                            if let Some(delta) = signals.delta_summary.as_ref() {
                                meta.insert("js.delta.phase".into(), delta.phase.clone());
                                if !delta.trigger_calls.is_empty() {
                                    meta.insert(
                                        "js.delta.trigger_calls".into(),
                                        delta.trigger_calls.join(", "),
                                    );
                                }
                                meta.insert(
                                    "js.delta.generated_snippets".into(),
                                    delta.generated_snippets.to_string(),
                                );
                                meta.insert(
                                    "js.delta.added_identifier_count".into(),
                                    delta.added_identifier_count.to_string(),
                                );
                                meta.insert(
                                    "js.delta.added_string_literal_count".into(),
                                    delta.added_string_literal_count.to_string(),
                                );
                                meta.insert(
                                    "js.delta.added_call_count".into(),
                                    delta.added_call_count.to_string(),
                                );
                                if !delta.new_identifiers.is_empty() {
                                    meta.insert(
                                        "js.delta.new_identifiers".into(),
                                        delta.new_identifiers.join(", "),
                                    );
                                }
                                if !delta.new_string_literals.is_empty() {
                                    meta.insert(
                                        "js.delta.new_string_literals".into(),
                                        delta.new_string_literals.join(", "),
                                    );
                                }
                                if !delta.new_calls.is_empty() {
                                    meta.insert(
                                        "js.delta.new_calls".into(),
                                        delta.new_calls.join(", "),
                                    );
                                }
                            }
                            let description = if !signals.prop_reads.is_empty() {
                                "Sandbox executed JS; property accesses observed."
                            } else if signals.errors.is_empty() {
                                "Sandbox executed JS; no monitored API calls observed."
                            } else {
                                "Sandbox executed JS; execution errors observed."
                            };
                            let (severity, confidence) = apply_profile_scoring_meta(
                                &mut meta,
                                &profile_summary,
                                "js_sandbox_exec",
                                Severity::Info,
                                Confidence::Probable,
                            );
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_sandbox_exec".into(),
                                severity,
                                confidence,
                                impact: None,
                                title: "JavaScript sandbox executed".into(),
                                description: description.into(),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: evidence.clone(),
                                remediation: Some("Review JS payload and runtime errors.".into()),
                                meta,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                                ..Finding::default()
                            });
                            continue;
                        }

                        let mut base_meta = std::collections::HashMap::new();
                        base_meta.insert("js.runtime.replay_id".into(), signals.replay_id.clone());
                        base_meta.insert("js.runtime.ordering".into(), "deterministic".into());
                        base_meta
                            .insert("js.runtime.profile".into(), signals.runtime_profile.clone());
                        base_meta.insert("js.runtime.calls".into(), signals.calls.join(","));
                        base_meta
                            .insert("js.runtime.call_count".into(), signals.call_count.to_string());
                        base_meta.insert(
                            "js.runtime.unique_calls".into(),
                            signals.unique_calls.to_string(),
                        );
                        if !signals.call_args.is_empty() {
                            base_meta.insert(
                                "js.runtime.call_args".into(),
                                signals.call_args.join("; "),
                            );
                        }
                        if !signals.urls.is_empty() {
                            base_meta.insert("js.runtime.urls".into(), signals.urls.join(", "));
                        }
                        if !signals.domains.is_empty() {
                            base_meta
                                .insert("js.runtime.domains".into(), signals.domains.join(", "));
                        }
                        if !signals.prop_reads.is_empty() {
                            base_meta.insert(
                                "js.runtime.prop_reads".into(),
                                signals.prop_reads.join(", "),
                            );
                            base_meta.insert(
                                "js.runtime.unique_prop_reads".into(),
                                signals.unique_prop_reads.to_string(),
                            );
                        }
                        if !signals.prop_writes.is_empty() {
                            base_meta.insert(
                                "js.runtime.prop_writes".into(),
                                signals.prop_writes.join(", "),
                            );
                        }
                        if !signals.prop_deletes.is_empty() {
                            base_meta.insert(
                                "js.runtime.prop_deletes".into(),
                                signals.prop_deletes.join(", "),
                            );
                        }
                        if !signals.reflection_probes.is_empty() {
                            base_meta.insert(
                                "js.runtime.reflection_probes".into(),
                                signals.reflection_probes.join(", "),
                            );
                        }
                        if !signals.dynamic_code_calls.is_empty() {
                            base_meta.insert(
                                "js.runtime.dynamic_code_calls".into(),
                                signals.dynamic_code_calls.join(", "),
                            );
                        }
                        if signals.truncation.calls_dropped > 0 {
                            base_meta.insert(
                                "js.runtime.truncation.calls_dropped".into(),
                                signals.truncation.calls_dropped.to_string(),
                            );
                        }
                        if signals.truncation.call_args_dropped > 0 {
                            base_meta.insert(
                                "js.runtime.truncation.call_args_dropped".into(),
                                signals.truncation.call_args_dropped.to_string(),
                            );
                        }
                        if signals.truncation.prop_reads_dropped > 0 {
                            base_meta.insert(
                                "js.runtime.truncation.prop_reads_dropped".into(),
                                signals.truncation.prop_reads_dropped.to_string(),
                            );
                        }
                        if signals.truncation.errors_dropped > 0 {
                            base_meta.insert(
                                "js.runtime.truncation.errors_dropped".into(),
                                signals.truncation.errors_dropped.to_string(),
                            );
                        }
                        if signals.truncation.urls_dropped > 0 {
                            base_meta.insert(
                                "js.runtime.truncation.urls_dropped".into(),
                                signals.truncation.urls_dropped.to_string(),
                            );
                        }
                        if signals.truncation.domains_dropped > 0 {
                            base_meta.insert(
                                "js.runtime.truncation.domains_dropped".into(),
                                signals.truncation.domains_dropped.to_string(),
                            );
                        }
                        if !signals.phases.is_empty() {
                            let phase_order = signals
                                .phases
                                .iter()
                                .map(|phase| phase.phase.as_str())
                                .collect::<Vec<_>>()
                                .join(", ");
                            let phase_summary = signals
                                .phases
                                .iter()
                                .map(|phase| {
                                    format!(
                                        "{}:calls={} props={} errors={} ms={}",
                                        phase.phase,
                                        phase.call_count,
                                        phase.prop_read_count,
                                        phase.error_count,
                                        phase.elapsed_ms
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(" | ");
                            base_meta.insert("js.runtime.phase_order".into(), phase_order);
                            base_meta.insert("js.runtime.phase_summaries".into(), phase_summary);
                            base_meta.insert(
                                "js.runtime.phase_count".into(),
                                signals.phases.len().to_string(),
                            );
                        }
                        if let Some(delta) = signals.delta_summary.as_ref() {
                            base_meta.insert("js.delta.phase".into(), delta.phase.clone());
                            if !delta.trigger_calls.is_empty() {
                                base_meta.insert(
                                    "js.delta.trigger_calls".into(),
                                    delta.trigger_calls.join(", "),
                                );
                            }
                            base_meta.insert(
                                "js.delta.generated_snippets".into(),
                                delta.generated_snippets.to_string(),
                            );
                            base_meta.insert(
                                "js.delta.added_identifier_count".into(),
                                delta.added_identifier_count.to_string(),
                            );
                            base_meta.insert(
                                "js.delta.added_string_literal_count".into(),
                                delta.added_string_literal_count.to_string(),
                            );
                            base_meta.insert(
                                "js.delta.added_call_count".into(),
                                delta.added_call_count.to_string(),
                            );
                            if !delta.new_identifiers.is_empty() {
                                base_meta.insert(
                                    "js.delta.new_identifiers".into(),
                                    delta.new_identifiers.join(", "),
                                );
                            }
                            if !delta.new_string_literals.is_empty() {
                                base_meta.insert(
                                    "js.delta.new_string_literals".into(),
                                    delta.new_string_literals.join(", "),
                                );
                            }
                            if !delta.new_calls.is_empty() {
                                base_meta.insert(
                                    "js.delta.new_calls".into(),
                                    delta.new_calls.join(", "),
                                );
                            }
                        }
                        if !signals.errors.is_empty() {
                            base_meta.insert("js.runtime.errors".into(), signals.errors.join("; "));
                        }
                        if let Some(ms) = signals.elapsed_ms {
                            base_meta.insert("js.sandbox_exec_ms".into(), ms.to_string());
                        }
                        if let Some(label) = candidate.source.meta_value() {
                            base_meta.insert("js.source".into(), label.into());
                        }
                        let mut risky_calls = Vec::new();
                        if signals.calls.iter().any(|c| c.eq_ignore_ascii_case("eval")) {
                            risky_calls.push("eval");
                        }
                        if signals.calls.iter().any(|c| c.eq_ignore_ascii_case("unescape")) {
                            risky_calls.push("unescape");
                        }
                        let risky_call_label = if risky_calls.is_empty() {
                            None
                        } else {
                            Some(risky_calls.join(", "))
                        };
                        if let Some(label) = risky_call_label.as_ref() {
                            base_meta.insert("js.runtime.risky_calls".into(), label.clone());
                        }
                        let has_network = signals.calls.iter().any(|c| is_network_call(c));
                        let has_file = signals.calls.iter().any(|c| is_file_call(c));
                        if has_network {
                            let mut meta = base_meta.clone();
                            meta.insert("js.sandbox_exec".into(), "true".into());
                            let (severity, confidence) = apply_profile_scoring_meta(
                                &mut meta,
                                &profile_summary,
                                "js_runtime_network_intent",
                                Severity::High,
                                Confidence::Probable,
                            );
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_runtime_network_intent".into(),
                                severity,
                                confidence,
            impact: None,
                                title: "Runtime network intent".into(),
                                description: "JavaScript invoked network-capable APIs during sandboxed execution.".into(),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: evidence.clone(),
                                remediation: Some("Inspect runtime JS calls and network targets.".into()),
                                meta,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                            ..Finding::default()
                            });
                        }
                        if has_file {
                            let mut meta = base_meta.clone();
                            meta.insert("js.sandbox_exec".into(), "true".into());
                            let (severity, confidence) = apply_profile_scoring_meta(
                                &mut meta,
                                &profile_summary,
                                "js_runtime_file_probe",
                                Severity::Medium,
                                Confidence::Probable,
                            );
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_runtime_file_probe".into(),
                                severity,
                                confidence,
            impact: None,
                                title: "Runtime file or object probe".into(),
                                description: "JavaScript invoked file or object-related APIs during sandboxed execution.".into(),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: evidence.clone(),
                                remediation: Some("Review runtime JS calls for file or export operations.".into()),
                                meta,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                            ..Finding::default()
                            });
                        }
                        if let Some(label) = risky_call_label.as_ref() {
                            let mut meta = base_meta.clone();
                            meta.insert("js.sandbox_exec".into(), "true".into());
                            let (severity, confidence) = apply_profile_scoring_meta(
                                &mut meta,
                                &profile_summary,
                                "js_runtime_risky_calls",
                                Severity::High,
                                Confidence::Strong,
                            );
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_runtime_risky_calls".into(),
                                severity,
                                confidence,
            impact: None,
                                title: "Runtime risky JavaScript calls".into(),
                                description: format!(
                                    "JavaScript invoked high-risk calls during sandboxed execution ({}).",
                                    label
                                ),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: evidence.clone(),
                                remediation: Some(
                                    "Review high-risk calls and deobfuscate the payload.".into(),
                                ),
                                meta,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                            ..Finding::default()
                            });
                        }
                        if !has_network && !has_file {
                            let mut meta = base_meta;
                            meta.insert("js.sandbox_exec".into(), "true".into());
                            let (severity, confidence) = apply_profile_scoring_meta(
                                &mut meta,
                                &profile_summary,
                                "js_sandbox_exec",
                                Severity::Info,
                                Confidence::Probable,
                            );
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_sandbox_exec".into(),
                                severity,
                                confidence,
            impact: None,
                                title: "JavaScript sandbox executed".into(),
                                description: "Sandbox executed JS; monitored API calls were observed but no network/file APIs.".into(),
                                objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                                evidence: evidence.clone(),
                                remediation: Some("Review runtime JS calls for additional behaviour.".into()),
                                meta,
                                yara: None,
                                position: None,
                                positions: Vec::new(),
                            ..Finding::default()
                            });
                        }
                    }
                }
            }
        }
        Ok(findings)
    }
}

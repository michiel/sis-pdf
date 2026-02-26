use std::time::Duration;

use anyhow::Result;

use js_analysis::{
    is_file_call, is_network_call, run_sandbox, DynamicOptions, DynamicOutcome, DynamicSignals,
    RuntimeKind, RuntimeMode, RuntimePhase, RuntimeProfile,
};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Impact, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_core::time_compat::Instant;

use crate::js_payload_candidates_from_entry;

pub struct JavaScriptSandboxDetector;

const JS_SANDBOX_MAX_BYTES: usize = 256 * 1024;
#[cfg(not(target_arch = "wasm32"))]
const JS_WALLCLOCK_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_arch = "wasm32")]
const JS_WALLCLOCK_TIMEOUT: Duration = Duration::from_millis(900);
#[cfg(not(target_arch = "wasm32"))]
const JS_PHASE_TIMEOUT_MS: u128 = 1_250;
#[cfg(target_arch = "wasm32")]
const JS_PHASE_TIMEOUT_MS: u128 = 250;

#[cfg(target_arch = "wasm32")]
const JS_DOCUMENT_BUDGET: Duration = Duration::from_millis(1_500);

struct ProfileRun {
    profile_id: String,
    outcome: DynamicOutcome,
}

#[derive(Default)]
struct ProfileDivergenceSummary {
    profile_ids: Vec<String>,
    profile_statuses: Vec<String>,
    timeout_contexts: Vec<String>,
    executed_profiles: Vec<String>,
    executed_count: usize,
    timed_out_count: usize,
    skipped_count: usize,
    network_count: usize,
    file_count: usize,
    risky_count: usize,
    calls_count: usize,
    compat_profiles: usize,
    deception_hardened_profiles: usize,
    strict_profiles: usize,
    interaction_open_profiles: usize,
    interaction_idle_profiles: usize,
    interaction_click_profiles: usize,
    interaction_form_profiles: usize,
    unresolved_identifier_error_total: usize,
    unresolved_callable_error_total: usize,
    callable_hint_total: usize,
    unresolved_callee_hint_total: usize,
    unresolved_identifier_error_profiles: usize,
    unresolved_callable_error_profiles: usize,
    unresolved_callee_hint_profiles: usize,
    capability_signature_count: usize,
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
        let has_divergent_band =
            ratios.into_iter().flatten().any(|ratio| (0.2..=0.6).contains(&ratio));
        if has_divergent_band {
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

struct RuntimeProfilePlan {
    profile: RuntimeProfile,
    phases: Vec<RuntimePhase>,
}

fn sandbox_document_budget() -> Option<Duration> {
    #[cfg(target_arch = "wasm32")]
    {
        return Some(JS_DOCUMENT_BUDGET);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

fn is_risky_call(name: &str) -> bool {
    name.eq_ignore_ascii_case("eval")
        || name.eq_ignore_ascii_case("app.eval")
        || name.eq_ignore_ascii_case("event.target.eval")
        || name.eq_ignore_ascii_case("unescape")
        || name.eq_ignore_ascii_case("function")
}

fn impact_for_kind(kind: &str) -> Option<Impact> {
    match kind {
        "js_payload_non_javascript_format" => Some(Impact::Low),
        "js_sandbox_exec" => Some(Impact::None),
        "js_sandbox_skipped" => Some(Impact::None),
        "js_runtime_unknown_behaviour_pattern" => Some(Impact::Low),
        "js_runtime_error_recovery_patterns" => Some(Impact::Low),
        "js_runtime_dormant_or_gated_execution" => Some(Impact::Medium),
        "js_runtime_downloader_pattern" => Some(Impact::Critical),
        "js_runtime_network_intent" => Some(Impact::High),
        "js_runtime_file_probe" => Some(Impact::Low),
        "js_runtime_risky_calls" => Some(Impact::Medium),
        "js_runtime_heap_manipulation" => Some(Impact::Medium),
        "js_runtime_path_morphism" => Some(Impact::High),
        "js_sandbox_timeout" => Some(Impact::None),
        "js_runtime_recursion_limit" => Some(Impact::Low),
        "js_emulation_breakpoint" => Some(Impact::Low),
        value if value.starts_with("js_runtime_") => Some(Impact::Medium),
        _ => Some(Impact::None),
    }
}

fn configured_profiles() -> Vec<RuntimeProfilePlan> {
    #[cfg(target_arch = "wasm32")]
    {
        vec![RuntimeProfilePlan {
            profile: RuntimeProfile {
                kind: RuntimeKind::PdfReader,
                vendor: "adobe".to_string(),
                version: "11".to_string(),
                mode: RuntimeMode::Compat,
            },
            phases: vec![RuntimePhase::Open, RuntimePhase::Click],
        }]
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        vec![
            RuntimeProfilePlan {
                profile: RuntimeProfile {
                    kind: RuntimeKind::PdfReader,
                    vendor: "adobe".to_string(),
                    version: "11".to_string(),
                    mode: RuntimeMode::Compat,
                },
                phases: vec![
                    RuntimePhase::Open,
                    RuntimePhase::Idle,
                    RuntimePhase::Click,
                    RuntimePhase::Form,
                ],
            },
            RuntimeProfilePlan {
                profile: RuntimeProfile {
                    kind: RuntimeKind::Browser,
                    vendor: "chromium".to_string(),
                    version: "120".to_string(),
                    mode: RuntimeMode::Compat,
                },
                phases: vec![
                    RuntimePhase::Open,
                    RuntimePhase::Idle,
                    RuntimePhase::Click,
                    RuntimePhase::Form,
                ],
            },
            RuntimeProfilePlan {
                profile: RuntimeProfile {
                    kind: RuntimeKind::Browser,
                    vendor: "chromium".to_string(),
                    version: "120".to_string(),
                    mode: RuntimeMode::DeceptionHardened,
                },
                phases: vec![
                    RuntimePhase::Open,
                    RuntimePhase::Idle,
                    RuntimePhase::Click,
                    RuntimePhase::Form,
                ],
            },
            RuntimeProfilePlan {
                profile: RuntimeProfile {
                    kind: RuntimeKind::Node,
                    vendor: "nodejs".to_string(),
                    version: "20".to_string(),
                    mode: RuntimeMode::Compat,
                },
                phases: vec![
                    RuntimePhase::Open,
                    RuntimePhase::Idle,
                    RuntimePhase::Click,
                    RuntimePhase::Form,
                ],
            },
            RuntimeProfilePlan {
                profile: RuntimeProfile {
                    kind: RuntimeKind::Bun,
                    vendor: "bun".to_string(),
                    version: "1.1".to_string(),
                    mode: RuntimeMode::Compat,
                },
                phases: vec![
                    RuntimePhase::Open,
                    RuntimePhase::Idle,
                    RuntimePhase::Click,
                    RuntimePhase::Form,
                ],
            },
        ]
    }
}

fn unresolved_error_counters(errors: &[String]) -> (usize, usize, usize, usize) {
    let unresolved_identifier_count = errors
        .iter()
        .filter(|error| {
            let lower = error.to_ascii_lowercase();
            lower.contains("is not defined") || lower.contains("undefined variable")
        })
        .count();
    let unresolved_callable_count = errors
        .iter()
        .filter(|error| error.to_ascii_lowercase().contains("not a callable function"))
        .count();
    let callable_hint_count =
        errors.iter().filter(|error| error.contains("Callable recovery hint:")).count();
    let unresolved_callee_hint_count =
        errors.iter().filter(|error| error.contains("callee=")).count();
    (
        unresolved_identifier_count,
        unresolved_callable_count,
        callable_hint_count,
        unresolved_callee_hint_count,
    )
}

fn execute_profiles(bytes: &[u8]) -> (Vec<ProfileRun>, ProfileDivergenceSummary) {
    let mut runs = Vec::new();
    let mut summary = ProfileDivergenceSummary::default();
    let mut capability_signatures = std::collections::BTreeSet::new();
    for plan in configured_profiles() {
        let profile = plan.profile.clone();
        let profile_id = profile.id();
        match profile.mode {
            RuntimeMode::Compat => summary.compat_profiles += 1,
            RuntimeMode::DeceptionHardened => summary.deception_hardened_profiles += 1,
            RuntimeMode::Strict => summary.strict_profiles += 1,
        }
        let options = DynamicOptions {
            max_bytes: JS_SANDBOX_MAX_BYTES,
            timeout_ms: JS_WALLCLOCK_TIMEOUT.as_millis(),
            phase_timeout_ms: JS_PHASE_TIMEOUT_MS,
            runtime_profile: profile.clone(),
            phases: plan.phases.clone(),
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
                let has_risky = signals.calls.iter().any(|c| is_risky_call(c));
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
                let phase_labels =
                    signals.phases.iter().map(|phase| phase.phase.as_str()).collect::<Vec<_>>();
                if phase_labels.iter().any(|phase| *phase == "open") {
                    summary.interaction_open_profiles += 1;
                }
                if phase_labels.iter().any(|phase| *phase == "idle") {
                    summary.interaction_idle_profiles += 1;
                }
                if phase_labels.iter().any(|phase| *phase == "click") {
                    summary.interaction_click_profiles += 1;
                }
                if phase_labels.iter().any(|phase| *phase == "form") {
                    summary.interaction_form_profiles += 1;
                }
                let (
                    unresolved_identifier_count,
                    unresolved_callable_count,
                    callable_hint_count,
                    unresolved_callee_hint_count,
                ) = unresolved_error_counters(&signals.errors);
                summary.unresolved_identifier_error_total += unresolved_identifier_count;
                summary.unresolved_callable_error_total += unresolved_callable_count;
                summary.callable_hint_total += callable_hint_count;
                summary.unresolved_callee_hint_total += unresolved_callee_hint_count;
                if unresolved_identifier_count > 0 {
                    summary.unresolved_identifier_error_profiles += 1;
                }
                if unresolved_callable_count > 0 {
                    summary.unresolved_callable_error_profiles += 1;
                }
                if unresolved_callee_hint_count > 0 {
                    summary.unresolved_callee_hint_profiles += 1;
                }
                let call_set = signals
                    .calls
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<std::collections::BTreeSet<_>>();
                let prop_set = signals
                    .prop_reads
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<std::collections::BTreeSet<_>>();
                let capability_signature = format!(
                    "calls={}|props={}|dynamic={}|reflection={}",
                    if call_set.is_empty() {
                        "-".to_string()
                    } else {
                        call_set.iter().copied().collect::<Vec<_>>().join(",")
                    },
                    if prop_set.is_empty() {
                        "-".to_string()
                    } else {
                        prop_set.iter().copied().collect::<Vec<_>>().join(",")
                    },
                    if signals.dynamic_code_calls.is_empty() {
                        "-".to_string()
                    } else {
                        signals.dynamic_code_calls.join(",")
                    },
                    if signals.reflection_probes.is_empty() {
                        "-".to_string()
                    } else {
                        signals.reflection_probes.join(",")
                    }
                );
                capability_signatures.insert(capability_signature);
                summary.profile_statuses.push(format!(
                    "{}:executed:calls={}:network={}:file={}:risky={}",
                    profile_id, signals.call_count, has_network, has_file, has_risky
                ));
            }
            DynamicOutcome::TimedOut { timeout_ms, context } => {
                summary.timed_out_count += 1;
                let phase = context.phase.clone().unwrap_or_else(|| "unknown".to_string());
                let elapsed = context
                    .elapsed_ms
                    .map(|value| format!("{value}ms"))
                    .unwrap_or_else(|| "unknown".to_string());
                let ratio = context
                    .budget_ratio
                    .map(|value| format!("{value:.2}"))
                    .unwrap_or_else(|| "unknown".to_string());
                summary.profile_statuses.push(format!(
                    "{}:timeout:{}ms:phase={}:elapsed={}:ratio={}",
                    profile_id, timeout_ms, phase, elapsed, ratio
                ));
                summary.timeout_contexts.push(format!(
                    "{}:phase={}:elapsed={}:ratio={}",
                    context.runtime_profile, phase, elapsed, ratio
                ));
            }
            DynamicOutcome::Skipped { reason, .. } => {
                summary.skipped_count += 1;
                summary.profile_statuses.push(format!("{}:skipped:{}", profile_id, reason));
            }
        }
        runs.push(ProfileRun { profile_id, outcome });
    }
    summary.capability_signature_count = capability_signatures.len();
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
    if !summary.timeout_contexts.is_empty() {
        meta.insert("js.runtime.timeout_contexts".into(), summary.timeout_contexts.join(" | "));
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
    meta.insert("js.runtime.profile_mode.compat_count".into(), summary.compat_profiles.to_string());
    meta.insert(
        "js.runtime.profile_mode.deception_hardened_count".into(),
        summary.deception_hardened_profiles.to_string(),
    );
    meta.insert("js.runtime.profile_mode.strict_count".into(), summary.strict_profiles.to_string());
    meta.insert("js.runtime.interaction_pack_order".into(), "open,idle,click,form".into());
    meta.insert(
        "js.runtime.interaction_pack.open_profiles".into(),
        summary.interaction_open_profiles.to_string(),
    );
    meta.insert(
        "js.runtime.interaction_pack.idle_profiles".into(),
        summary.interaction_idle_profiles.to_string(),
    );
    meta.insert(
        "js.runtime.interaction_pack.click_profiles".into(),
        summary.interaction_click_profiles.to_string(),
    );
    meta.insert(
        "js.runtime.interaction_pack.form_profiles".into(),
        summary.interaction_form_profiles.to_string(),
    );
    meta.insert(
        "js.runtime.unresolved_identifier_error_total".into(),
        summary.unresolved_identifier_error_total.to_string(),
    );
    meta.insert(
        "js.runtime.unresolved_callable_error_total".into(),
        summary.unresolved_callable_error_total.to_string(),
    );
    meta.insert("js.runtime.callable_hint_total".into(), summary.callable_hint_total.to_string());
    meta.insert(
        "js.runtime.unresolved_callee_hint_total".into(),
        summary.unresolved_callee_hint_total.to_string(),
    );
    meta.insert(
        "js.runtime.unresolved_identifier_error_profiles".into(),
        summary.unresolved_identifier_error_profiles.to_string(),
    );
    meta.insert(
        "js.runtime.unresolved_callable_error_profiles".into(),
        summary.unresolved_callable_error_profiles.to_string(),
    );
    meta.insert(
        "js.runtime.unresolved_callee_hint_profiles".into(),
        summary.unresolved_callee_hint_profiles.to_string(),
    );
    meta.insert(
        "js.runtime.capability_matrix.distinct_signatures".into(),
        summary.capability_signature_count.to_string(),
    );
}

fn populate_base_metadata(
    meta: &mut std::collections::HashMap<String, String>,
    signals: &DynamicSignals,
    source_label: Option<&str>,
    timed_out_profiles: usize,
    include_calls: bool,
) {
    meta.insert("js.runtime.replay_id".into(), signals.replay_id.clone());
    meta.insert("js.runtime.ordering".into(), "deterministic".into());
    meta.insert("js.runtime.profile".into(), signals.runtime_profile.clone());
    if include_calls {
        meta.insert("js.runtime.calls".into(), signals.calls.join(","));
        meta.insert("js.runtime.call_count".into(), signals.call_count.to_string());
        meta.insert("js.runtime.unique_calls".into(), signals.unique_calls.to_string());
        if !signals.call_args.is_empty() {
            meta.insert("js.runtime.call_args".into(), signals.call_args.join("; "));
        }
        if !signals.urls.is_empty() {
            meta.insert("js.runtime.urls".into(), signals.urls.join(", "));
        }
        if !signals.domains.is_empty() {
            meta.insert("js.runtime.domains".into(), signals.domains.join(", "));
        }
    }
    if !signals.prop_reads.is_empty() {
        meta.insert("js.runtime.prop_reads".into(), signals.prop_reads.join(", "));
        meta.insert("js.runtime.unique_prop_reads".into(), signals.unique_prop_reads.to_string());
    }
    if !signals.prop_writes.is_empty() {
        meta.insert("js.runtime.prop_writes".into(), signals.prop_writes.join(", "));
    }
    if !signals.prop_deletes.is_empty() {
        meta.insert("js.runtime.prop_deletes".into(), signals.prop_deletes.join(", "));
    }
    if !signals.reflection_probes.is_empty() {
        meta.insert("js.runtime.reflection_probes".into(), signals.reflection_probes.join(", "));
    }
    if !signals.dynamic_code_calls.is_empty() {
        meta.insert("js.runtime.dynamic_code_calls".into(), signals.dynamic_code_calls.join(", "));
    }
    if signals.heap_allocation_count > 0 {
        meta.insert(
            "js.runtime.heap.allocation_count".into(),
            signals.heap_allocation_count.to_string(),
        );
        if !signals.heap_allocations.is_empty() {
            meta.insert("js.runtime.heap.allocations".into(), signals.heap_allocations.join(" | "));
        }
    }
    if signals.heap_view_count > 0 {
        meta.insert("js.runtime.heap.view_count".into(), signals.heap_view_count.to_string());
        if !signals.heap_views.is_empty() {
            meta.insert("js.runtime.heap.views".into(), signals.heap_views.join(" | "));
        }
    }
    if signals.heap_access_count > 0 {
        meta.insert("js.runtime.heap.access_count".into(), signals.heap_access_count.to_string());
        if !signals.heap_accesses.is_empty() {
            meta.insert("js.runtime.heap.accesses".into(), signals.heap_accesses.join(" | "));
        }
    }
    if !signals.errors.is_empty() {
        meta.insert("js.runtime.errors".into(), signals.errors.join("; "));
        let (
            unresolved_identifier_count,
            unresolved_callable_count,
            callable_hint_count,
            unresolved_callee_hint_count,
        ) = unresolved_error_counters(&signals.errors);
        meta.insert(
            "js.runtime.unresolved_identifier_error_count".into(),
            unresolved_identifier_count.to_string(),
        );
        meta.insert(
            "js.runtime.unresolved_callable_error_count".into(),
            unresolved_callable_count.to_string(),
        );
        meta.insert("js.runtime.callable_hint_count".into(), callable_hint_count.to_string());
        meta.insert(
            "js.runtime.unresolved_callee_hint_count".into(),
            unresolved_callee_hint_count.to_string(),
        );
    }
    if timed_out_profiles > 0 {
        meta.insert("js.runtime.script_timeout_profiles".into(), timed_out_profiles.to_string());
    }
    if let Some(ms) = signals.elapsed_ms {
        meta.insert("js.sandbox_exec_ms".into(), ms.to_string());
    }
    meta.insert(
        "js.runtime.execution.adaptive_loop_iteration_limit".into(),
        signals.execution_stats.adaptive_loop_iteration_limit.to_string(),
    );
    meta.insert(
        "js.runtime.execution.adaptive_loop_profile".into(),
        signals.execution_stats.adaptive_loop_profile.clone(),
    );
    meta.insert(
        "js.runtime.execution.loop_iteration_limit_hits".into(),
        signals.execution_stats.loop_iteration_limit_hits.to_string(),
    );
    if signals.execution_stats.probe_loop_short_circuit_hits > 0 {
        meta.insert(
            "js.runtime.execution.probe_loop_short_circuit_hits".into(),
            signals.execution_stats.probe_loop_short_circuit_hits.to_string(),
        );
        meta.insert(
            "js.runtime.partial_execution_marker".into(),
            "probe_loop_short_circuit".into(),
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
    if signals.truncation.heap_allocations_dropped > 0 {
        meta.insert(
            "js.runtime.truncation.heap_allocations_dropped".into(),
            signals.truncation.heap_allocations_dropped.to_string(),
        );
    }
    if signals.truncation.heap_views_dropped > 0 {
        meta.insert(
            "js.runtime.truncation.heap_views_dropped".into(),
            signals.truncation.heap_views_dropped.to_string(),
        );
    }
    if signals.truncation.heap_accesses_dropped > 0 {
        meta.insert(
            "js.runtime.truncation.heap_accesses_dropped".into(),
            signals.truncation.heap_accesses_dropped.to_string(),
        );
    }
    if !signals.phases.is_empty() {
        let phase_order =
            signals.phases.iter().map(|phase| phase.phase.as_str()).collect::<Vec<_>>().join(", ");
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
        meta.insert("js.runtime.phase_count".into(), signals.phases.len().to_string());
    }
    let sw_registration_calls = signals
        .calls
        .iter()
        .filter(|call| call.as_str() == "navigator.serviceWorker.register")
        .count();
    let sw_update_calls = signals
        .calls
        .iter()
        .filter(|call| call.as_str() == "navigator.serviceWorker.update")
        .count();
    let sw_handler_calls =
        signals.calls.iter().filter(|call| call.as_str() == "self.addEventListener").count();
    let sw_cache_calls = signals.calls.iter().filter(|call| call.starts_with("caches.")).count();
    let sw_indexeddb_calls = signals
        .calls
        .iter()
        .filter(|call| call.starts_with("indexedDB.") || call.starts_with("IDBObjectStore."))
        .count();
    let sw_lifecycle_events =
        signals.phases.iter().filter(|phase| phase.phase.starts_with("sw_")).count();
    if sw_registration_calls > 0 || sw_lifecycle_events > 0 {
        meta.insert(
            "js.runtime.service_worker.registration_calls".into(),
            sw_registration_calls.to_string(),
        );
        meta.insert("js.runtime.service_worker.update_calls".into(), sw_update_calls.to_string());
        meta.insert(
            "js.runtime.service_worker.event_handlers_registered".into(),
            sw_handler_calls.to_string(),
        );
        meta.insert(
            "js.runtime.service_worker.lifecycle_events_executed".into(),
            sw_lifecycle_events.to_string(),
        );
        meta.insert("js.runtime.service_worker.cache_calls".into(), sw_cache_calls.to_string());
        meta.insert(
            "js.runtime.service_worker.indexeddb_calls".into(),
            sw_indexeddb_calls.to_string(),
        );
    }
    let realtime_send_count = signals
        .calls
        .iter()
        .filter(|call| call.as_str() == "WebSocket.send" || call.as_str() == "RTCDataChannel.send")
        .count();
    let mut channel_types = std::collections::BTreeSet::new();
    if signals.calls.iter().any(|call| call.starts_with("WebSocket")) {
        channel_types.insert("websocket");
    }
    if signals.calls.iter().any(|call| call.starts_with("RTC")) {
        channel_types.insert("rtc_datachannel");
    }
    if realtime_send_count > 0 || !channel_types.is_empty() {
        meta.insert("js.runtime.realtime.session_count".into(), channel_types.len().to_string());
        meta.insert("js.runtime.realtime.unique_targets".into(), signals.urls.len().to_string());
        meta.insert("js.runtime.realtime.send_count".into(), realtime_send_count.to_string());
        meta.insert("js.runtime.realtime.avg_payload_len".into(), "0.0".to_string());
        meta.insert(
            "js.runtime.realtime.channel_types".into(),
            channel_types.into_iter().collect::<Vec<_>>().join(", "),
        );
    }
    let lifecycle_phase = signals
        .phases
        .iter()
        .find(|phase| phase.phase.starts_with("npm.") || phase.phase == "bun.install")
        .map(|phase| phase.phase.clone());
    if let Some(phase) = lifecycle_phase {
        meta.insert("js.runtime.lifecycle.phase".into(), phase);
        let hook_calls = signals
            .calls
            .iter()
            .filter(|call| {
                matches!(
                    call.as_str(),
                    "require" | "child_process.exec" | "child_process.spawn" | "Bun.spawn"
                )
            })
            .count();
        meta.insert("js.runtime.lifecycle.hook_calls".into(), hook_calls.to_string());
        let background_attempts = signals
            .calls
            .iter()
            .filter(|call| {
                matches!(call.as_str(), "child_process.exec" | "child_process.spawn" | "Bun.spawn")
            })
            .count();
        meta.insert(
            "js.runtime.lifecycle.background_attempts".into(),
            background_attempts.to_string(),
        );
    }
    if let Some(delta) = signals.delta_summary.as_ref() {
        meta.insert("js.delta.phase".into(), delta.phase.clone());
        if !delta.trigger_calls.is_empty() {
            meta.insert("js.delta.trigger_calls".into(), delta.trigger_calls.join(", "));
        }
        meta.insert("js.delta.generated_snippets".into(), delta.generated_snippets.to_string());
        meta.insert(
            "js.delta.added_identifier_count".into(),
            delta.added_identifier_count.to_string(),
        );
        meta.insert(
            "js.delta.added_string_literal_count".into(),
            delta.added_string_literal_count.to_string(),
        );
        meta.insert("js.delta.added_call_count".into(), delta.added_call_count.to_string());
        if !delta.new_identifiers.is_empty() {
            meta.insert("js.delta.new_identifiers".into(), delta.new_identifiers.join(", "));
        }
        if !delta.new_string_literals.is_empty() {
            meta.insert(
                "js.delta.new_string_literals".into(),
                delta.new_string_literals.join(", "),
            );
        }
        if !delta.new_calls.is_empty() {
            meta.insert("js.delta.new_calls".into(), delta.new_calls.join(", "));
        }
    }
    if let Some(label) = source_label {
        meta.insert("js.source".into(), label.into());
    }
}

#[derive(Default)]
struct PathMorphismSummary {
    executed_profiles: usize,
    distinct_path_signatures: usize,
    delta_profiles: usize,
    total_delta_added_calls: usize,
    total_delta_added_identifiers: usize,
    total_delta_added_literals: usize,
    trigger_call_count: usize,
    phase_set_size: usize,
    score: usize,
}

fn summarise_path_morphism(profile_runs: &[ProfileRun]) -> Option<PathMorphismSummary> {
    let mut signatures = std::collections::BTreeSet::new();
    let mut phase_signatures = std::collections::BTreeSet::new();
    let mut summary = PathMorphismSummary::default();
    for run in profile_runs {
        let DynamicOutcome::Executed(signals) = &run.outcome else {
            continue;
        };
        summary.executed_profiles += 1;
        let call_set = signals
            .calls
            .iter()
            .map(|value| value.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let prop_set = signals
            .prop_reads
            .iter()
            .map(|value| value.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let call_signature = if call_set.is_empty() {
            "-".to_string()
        } else {
            call_set.iter().copied().collect::<Vec<_>>().join(",")
        };
        let prop_signature = if prop_set.is_empty() {
            "-".to_string()
        } else {
            prop_set.iter().copied().collect::<Vec<_>>().join(",")
        };
        let phase_signature = if signals.phases.is_empty() {
            "-".to_string()
        } else {
            signals.phases.iter().map(|phase| phase.phase.clone()).collect::<Vec<_>>().join(">")
        };
        phase_signatures.insert(phase_signature.clone());

        let mut delta_signature = "-".to_string();
        if let Some(delta) = &signals.delta_summary {
            summary.delta_profiles += 1;
            summary.total_delta_added_calls += delta.added_call_count;
            summary.total_delta_added_identifiers += delta.added_identifier_count;
            summary.total_delta_added_literals += delta.added_string_literal_count;
            summary.trigger_call_count += delta.trigger_calls.len();
            delta_signature = format!(
                "{}:{}:{}:{}",
                delta.phase,
                delta.added_call_count,
                delta.added_identifier_count,
                delta.added_string_literal_count
            );
        }
        signatures.insert(format!("calls={call_signature}|props={prop_signature}|phase={phase_signature}|delta={delta_signature}"));
    }
    if summary.executed_profiles < 2 {
        return None;
    }
    summary.distinct_path_signatures = signatures.len();
    summary.phase_set_size = phase_signatures.len();
    summary.score = summary.distinct_path_signatures.saturating_sub(1)
        + summary.delta_profiles
        + usize::from(summary.phase_set_size > 1)
        + usize::from(summary.total_delta_added_calls >= 3)
        + usize::from(summary.total_delta_added_identifiers >= 4)
        + usize::from(summary.total_delta_added_literals >= 4);
    if summary.score < 3 {
        return None;
    }
    Some(summary)
}

fn extend_with_path_morphism_finding(
    findings: &mut Vec<Finding>,
    surface: AttackSurface,
    object_ref: &str,
    evidence: &[sis_pdf_core::model::EvidenceSpan],
    base_meta: &std::collections::HashMap<String, String>,
    profile_summary: &ProfileDivergenceSummary,
    profile_runs: &[ProfileRun],
) {
    let Some(morphism) = summarise_path_morphism(profile_runs) else {
        return;
    };
    let mut meta = base_meta.clone();
    meta.insert("js.sandbox_exec".into(), "true".into());
    meta.insert(
        "js.runtime.path_morphism.executed_profiles".into(),
        morphism.executed_profiles.to_string(),
    );
    meta.insert(
        "js.runtime.path_morphism.distinct_signatures".into(),
        morphism.distinct_path_signatures.to_string(),
    );
    meta.insert(
        "js.runtime.path_morphism.delta_profiles".into(),
        morphism.delta_profiles.to_string(),
    );
    meta.insert(
        "js.runtime.path_morphism.added_calls".into(),
        morphism.total_delta_added_calls.to_string(),
    );
    meta.insert(
        "js.runtime.path_morphism.added_identifiers".into(),
        morphism.total_delta_added_identifiers.to_string(),
    );
    meta.insert(
        "js.runtime.path_morphism.added_string_literals".into(),
        morphism.total_delta_added_literals.to_string(),
    );
    meta.insert(
        "js.runtime.path_morphism.trigger_call_count".into(),
        morphism.trigger_call_count.to_string(),
    );
    meta.insert(
        "js.runtime.path_morphism.phase_set_size".into(),
        morphism.phase_set_size.to_string(),
    );
    meta.insert("js.runtime.path_morphism.score".into(), morphism.score.to_string());

    let base_severity = if morphism.score >= 6 { Severity::High } else { Severity::Medium };
    let base_confidence =
        if morphism.score >= 6 { Confidence::Strong } else { Confidence::Probable };
    let (severity, confidence) = apply_profile_scoring_meta(
        &mut meta,
        profile_summary,
        "js_runtime_path_morphism",
        base_severity,
        base_confidence,
    );
    findings.push(Finding {
        id: String::new(),
        surface,
        kind: "js_runtime_path_morphism".into(),
        severity,
        confidence,
        impact: impact_for_kind("js_runtime_path_morphism"),
        title: "Runtime path morphism detected".into(),
        description:
            "Runtime execution paths diverged across profiles with AST delta activity, consistent with self-modifying or profile-gated behaviour."
                .into(),
        objects: vec![object_ref.to_string()],
        evidence: evidence.to_vec(),
        remediation: Some(
            "Replay under expanded profile matrices and inspect delta triggers/new calls for gated payload activation."
                .into(),
        ),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    });
}

fn promote_severity(value: Severity) -> Severity {
    // Symmetric ladder with floor/ceiling handled by enum extremes.
    match value {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High => Severity::Critical,
        Severity::Critical => Severity::Critical,
    }
}

fn demote_severity(value: Severity) -> Severity {
    // Symmetric ladder with floor/ceiling handled by enum extremes.
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
    if value >= 0.6 {
        (promote_severity(base_severity), promote_confidence(base_confidence))
    } else if value <= 0.34 {
        (demote_severity(base_severity), demote_confidence(base_confidence))
    } else {
        (base_severity, base_confidence)
    }
}

/// Acrobat-specific file-targeting APIs that are unambiguously dangerous when targeting executables.
const ACROBAT_FILE_APIS: &[&str] =
    &["openDoc", "launchURL", "importTextData", "submitForm", "saveAs", "mailDoc"];

/// File extensions indicating an executable or system-level target.
const EXECUTABLE_PATH_EXTENSIONS: &[&str] = &[".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".sh"];

fn has_acrobat_file_api_call(calls: &[String]) -> bool {
    calls.iter().any(|c| ACROBAT_FILE_APIS.iter().any(|api| c.as_str() == *api))
}

fn call_args_contain_executable_target(call_args: &[String]) -> bool {
    call_args.iter().any(|arg| {
        let lower = arg.to_ascii_lowercase();
        EXECUTABLE_PATH_EXTENSIONS.iter().any(|ext| lower.contains(ext))
            || lower.contains("\\\\\\\\")
    })
}

fn adobe_compat_in_executed_profiles(summary: &ProfileDivergenceSummary) -> bool {
    summary.executed_profiles.iter().any(|id| {
        id.starts_with("pdf_reader:adobe:") && id.ends_with(":compat")
    })
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
    let (severity, confidence, consistency_ratio, signal) =
        apply_profile_scoring(kind, base_severity, base_confidence, summary);
    if signal != "none" {
        meta.insert("js.runtime.profile_consistency_signal".into(), signal.to_string());
    }
    if let Some(value) = consistency_ratio {
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
    if summary.timed_out_count > 0
        && matches!(
            kind,
            "js_runtime_network_intent"
                | "js_runtime_file_probe"
                | "js_runtime_risky_calls"
                | "js_runtime_downloader_pattern"
        )
    {
        let timeout_ratio = ratio(summary.timed_out_count, summary.total()).unwrap_or(0.0);
        meta.insert(
            "js.runtime.script_timeout_profiles".into(),
            summary.timed_out_count.to_string(),
        );
        meta.insert("js.runtime.script_timeout_ratio".into(), format!("{timeout_ratio:.2}"));
        meta.insert("js.runtime.partial_dynamic_trace".into(), "true".into());
        let adjusted_confidence = demote_confidence(confidence);
        if adjusted_confidence != confidence {
            meta.insert(
                "js.runtime.timeout_confidence_adjusted".into(),
                format!("{:?}->{:?}", confidence, adjusted_confidence),
            );
        }
        return (severity, adjusted_confidence);
    }
    (severity, confidence)
}

fn extract_js_error_message(raw: &str) -> String {
    let marker = "message: \"";
    if let Some(start) = raw.find(marker) {
        let offset = start + marker.len();
        if let Some(end_rel) = raw[offset..].find('"') {
            return raw[offset..offset + end_rel].to_string();
        }
    }
    raw.to_string()
}

fn classify_emulation_breakpoint(error_message: &str) -> &'static str {
    let lower = error_message.to_ascii_lowercase();
    if lower.contains("maximum loop iteration limit")
        || lower.contains("loop iteration limit")
        || lower.contains("runtime limit")
    {
        "loop_iteration_limit"
    } else if lower.contains("exceeded maximum number of recursive calls")
        || lower.contains("too much recursion")
    {
        "recursion_limit"
    } else if lower.contains("not a callable function") {
        "missing_callable"
    } else if lower.contains("not a constructor") {
        "missing_constructor"
    } else if lower.contains("cannot convert 'null' or 'undefined' to object")
        || lower.contains("cannot convert null")
    {
        "null_object_conversion"
    } else if lower.contains("expected token")
        || lower.contains("syntax error")
        || lower.contains("parse")
    {
        "parser_dialect_mismatch"
    } else if lower.contains("is not defined") || lower.contains("undefined") {
        "missing_symbol"
    } else {
        "runtime_error"
    }
}

fn loop_iteration_limit_hits(errors: &[String]) -> usize {
    errors
        .iter()
        .map(|raw| extract_js_error_message(raw))
        .filter(|message| {
            let lower = message.to_ascii_lowercase();
            lower.contains("maximum loop iteration limit") || lower.contains("loop iteration limit")
        })
        .count()
}

fn recursion_limit_hits(errors: &[String]) -> usize {
    errors
        .iter()
        .map(|raw| extract_js_error_message(raw))
        .filter(|message| {
            let lower = message.to_ascii_lowercase();
            lower.contains("exceeded maximum number of recursive calls")
                || lower.contains("too much recursion")
        })
        .count()
}

fn likely_non_javascript_payload(bytes: &[u8]) -> Option<&'static str> {
    let preview = String::from_utf8_lossy(bytes);
    let trimmed = preview.trim_start_matches(|ch: char| ch.is_whitespace() || ch == '\u{feff}');
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("<!doctype html")
        || lower.starts_with("<html")
        || lower.starts_with("<script")
    {
        return Some("html_markup");
    }
    if lower.starts_with("<?xml") || lower.starts_with("<svg") || lower.starts_with("<!doctype svg")
    {
        return Some("xml_markup");
    }
    None
}

fn extend_with_payload_format_finding(
    findings: &mut Vec<Finding>,
    detector_surface: AttackSurface,
    object_ref: String,
    evidence: &[sis_pdf_core::model::EvidenceSpan],
    source_label: Option<&'static str>,
    format_hint: &str,
    payload_len: usize,
) {
    let mut meta = std::collections::HashMap::new();
    meta.insert("js.sandbox_exec".into(), "false".into());
    meta.insert("js.payload.format_hint".into(), format_hint.to_string());
    meta.insert("payload.decoded_len".into(), payload_len.to_string());
    if let Some(label) = source_label {
        meta.insert("js.source".into(), label.to_string());
    }
    findings.push(Finding {
        id: String::new(),
        surface: detector_surface,
        kind: "js_payload_non_javascript_format".into(),
        severity: Severity::Medium,
        confidence: Confidence::Strong,
        impact: impact_for_kind("js_payload_non_javascript_format"),
        title: "JavaScript payload format mismatch".into(),
        description: "Payload identified as JavaScript appears to be markup or non-JS script format; sandbox parse behaviour may be unreliable.".into(),
        objects: vec![object_ref],
        evidence: evidence.to_vec(),
        remediation: Some(
            "Review payload source and route to an appropriate parser before JavaScript sandbox execution.".into(),
        ),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    });
}

fn extend_with_recursion_limit_finding(
    findings: &mut Vec<Finding>,
    detector_surface: AttackSurface,
    object_ref: String,
    evidence: &[sis_pdf_core::model::EvidenceSpan],
    base_meta: &std::collections::HashMap<String, String>,
    summary: &ProfileDivergenceSummary,
    recursion_hits: usize,
) {
    if recursion_hits == 0 {
        return;
    }
    let mut meta = base_meta.clone();
    meta.insert("js.sandbox_exec".into(), "true".into());
    meta.insert("js.runtime.recursion_limit_hits".into(), recursion_hits.to_string());
    let (severity, confidence) = apply_profile_scoring_meta(
        &mut meta,
        summary,
        "js_sandbox_exec",
        Severity::Medium,
        Confidence::Strong,
    );
    findings.push(Finding {
        id: String::new(),
        surface: detector_surface,
        kind: "js_runtime_recursion_limit".into(),
        severity,
        confidence,
        impact: impact_for_kind("js_runtime_recursion_limit"),
        title: "JavaScript recursion limit reached".into(),
        description: "Sandbox execution hit recursion limits, which may indicate recursion bombs or heavily nested obfuscation.".into(),
        objects: vec![object_ref],
        evidence: evidence.to_vec(),
        remediation: Some("Investigate recursive control-flow and deobfuscate the script to determine intent.".into()),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    });
}

fn extend_with_script_timeout_finding(
    findings: &mut Vec<Finding>,
    detector_surface: AttackSurface,
    object_ref: String,
    evidence: &[sis_pdf_core::model::EvidenceSpan],
    base_meta: &std::collections::HashMap<String, String>,
    summary: &ProfileDivergenceSummary,
    timeout_ms: Option<u128>,
    timeout_runtime_profile: Option<&str>,
    timeout_phase: Option<&str>,
    timeout_elapsed_ms: Option<u128>,
    timeout_budget_ratio: Option<f64>,
    partial: bool,
) {
    if summary.timed_out_count == 0 {
        return;
    }
    let mut meta = base_meta.clone();
    meta.insert("js.sandbox_exec".into(), "true".into());
    meta.insert("js.sandbox_timeout".into(), "true".into());
    meta.insert("js.runtime.script_timeout_profiles".into(), summary.timed_out_count.to_string());
    if let Some(value) = ratio(summary.timed_out_count, summary.total()) {
        meta.insert("js.runtime.script_timeout_ratio".into(), format!("{value:.2}"));
    }
    if let Some(ms) = timeout_ms {
        meta.insert("js.sandbox_timeout_ms".into(), ms.to_string());
    }
    if let Some(value) = timeout_runtime_profile {
        meta.insert("js.runtime.timeout_profile".into(), value.to_string());
    }
    if let Some(value) = timeout_phase {
        meta.insert("js.runtime.timeout_phase".into(), value.to_string());
    }
    if let Some(value) = timeout_elapsed_ms {
        meta.insert("js.runtime.timeout_elapsed_ms".into(), value.to_string());
    }
    if let Some(value) = timeout_budget_ratio {
        meta.insert("js.runtime.timeout_budget_ratio".into(), format!("{value:.2}"));
    }
    let timeout_base_severity =
        if summary.timed_out_count == summary.total() { Severity::Medium } else { Severity::Low };
    let (severity, confidence) = apply_profile_scoring_meta(
        &mut meta,
        summary,
        "js_sandbox_exec",
        timeout_base_severity,
        Confidence::Probable,
    );
    findings.push(Finding {
        id: String::new(),
        surface: detector_surface,
        kind: "js_sandbox_timeout".into(),
        severity,
        confidence,
        impact: impact_for_kind("js_sandbox_timeout"),
        title: "JavaScript sandbox timeout".into(),
        description: if partial {
            "Sandbox execution timed out in one or more runtime profiles; dynamic trace may be partial.".into()
        } else {
            "Sandbox execution exceeded the time limit.".into()
        },
        objects: vec![object_ref],
        evidence: evidence.to_vec(),
        remediation: Some(
            "Inspect long-running loop behaviour and review dynamic findings with partial-trace caution."
                .into(),
        ),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    });
}

fn push_budget_skipped_finding(
    findings: &mut Vec<Finding>,
    detector_surface: AttackSurface,
    object_ref: String,
    evidence: &[sis_pdf_core::model::EvidenceSpan],
    source_label: Option<&str>,
    budget_ms: u128,
    elapsed_ms: u128,
) {
    let mut meta = std::collections::HashMap::new();
    meta.insert("js.sandbox_exec".into(), "false".into());
    meta.insert("js.sandbox_skip_reason".into(), "document_budget_exhausted".into());
    meta.insert("js.sandbox_budget_ms".into(), budget_ms.to_string());
    meta.insert("js.sandbox_elapsed_ms".into(), elapsed_ms.to_string());
    if let Some(label) = source_label {
        meta.insert("js.source".into(), label.to_string());
    }

    findings.push(Finding {
        id: String::new(),
        surface: detector_surface,
        kind: "js_sandbox_skipped".into(),
        severity: Severity::Info,
        confidence: Confidence::Strong,
        impact: impact_for_kind("js_sandbox_skipped"),
        title: "JavaScript sandbox skipped".into(),
        description: "Sandbox execution skipped because the per-document dynamic analysis budget was exhausted."
            .into(),
        objects: vec![object_ref],
        evidence: evidence.to_vec(),
        remediation: Some(
            "Re-run in CLI/native mode or with a higher dynamic budget when deeper JavaScript runtime coverage is required."
                .into(),
        ),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    });
}

fn detect_downloader_pattern(calls: &[String]) -> Option<(usize, usize, usize)> {
    let create_count = calls
        .iter()
        .filter(|call| {
            call.as_str() == "ActiveXObject"
                || call.as_str() == "WScript.CreateObject"
                || call.as_str() == "CreateObject"
        })
        .count();
    let open_count = calls
        .iter()
        .filter(|call| {
            call.as_str() == "MSXML2.XMLHTTP.open" || call.as_str() == "MSXML2.XMLHTTP.Open"
        })
        .count();
    let send_count = calls
        .iter()
        .filter(|call| {
            call.as_str() == "MSXML2.XMLHTTP.send" || call.as_str() == "MSXML2.XMLHTTP.Send"
        })
        .count();
    if create_count >= 2 && open_count >= 2 && send_count >= 2 {
        Some((create_count, open_count, send_count))
    } else {
        None
    }
}

fn detect_probe_loop_context(calls: &[String]) -> Option<(String, usize, usize, f64)> {
    let probe_apis = [
        "ActiveXObject",
        "CreateObject",
        "WScript.CreateObject",
        "Scripting.FileSystemObject.FolderExists",
        "Scripting.FileSystemObject.FileExists",
    ];
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for call in calls {
        if probe_apis.iter().any(|api| call == api) {
            *counts.entry(call.clone()).or_insert(0) += 1;
        }
    }
    if counts.is_empty() {
        return None;
    }
    let total_probe_calls = counts.values().copied().sum::<usize>();
    let unique_probe_apis = counts.len();
    let (dominant_api, dominant_count) = counts
        .into_iter()
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(&left.0)))?;
    let dominance_ratio =
        if total_probe_calls == 0 { 0.0 } else { dominant_count as f64 / total_probe_calls as f64 };
    Some((dominant_api, total_probe_calls, unique_probe_apis, dominance_ratio))
}

fn severity_from_behavioral(value: &str) -> Severity {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn confidence_from_behavioral(value: f64) -> Confidence {
    if value >= 0.90 {
        Confidence::Certain
    } else if value >= 0.75 {
        Confidence::Strong
    } else if value >= 0.60 {
        Confidence::Probable
    } else if value >= 0.45 {
        Confidence::Tentative
    } else if value >= 0.30 {
        Confidence::Weak
    } else {
        Confidence::Heuristic
    }
}

fn behavioral_pattern_title(name: &str) -> Option<&'static str> {
    match name {
        "wasm_loader_staging" => Some("WASM loader staging observed"),
        "runtime_dependency_loader_abuse" => Some("Runtime dependency loader abuse"),
        "credential_harvest_form_emulation" => Some("Credential-harvest form emulation"),
        "chunked_data_exfil_pipeline" => Some("Chunked data exfiltration pipeline"),
        "interaction_coercion_loop" => Some("Interaction coercion loop"),
        "lotl_api_chain_execution" => Some("Living-off-the-land API chain execution"),
        "service_worker_persistence_abuse" => Some("Service worker persistence abuse"),
        "webcrypto_key_staging_exfil" => Some("WebCrypto key staging and exfiltration"),
        "storage_backed_payload_staging" => Some("Storage-backed payload staging"),
        "dynamic_module_graph_evasion" => Some("Dynamic module graph evasion"),
        "covert_realtime_channel_abuse" => Some("Covert realtime channel abuse"),
        "clipboard_session_hijack_behaviour" => Some("Clipboard/session hijack behaviour"),
        "dom_sink_policy_bypass_attempt" => Some("DOM sink policy bypass attempt"),
        "wasm_memory_unpacker_pipeline" => Some("WASM memory unpacker pipeline"),
        "extension_api_abuse_probe" => Some("Extension API abuse probe"),
        "modern_fingerprint_evasion" => Some("Modern fingerprinting evasion"),
        "api_call_sequence_malicious" => Some("Suspicious API call sequence"),
        "source_sink_complexity" => Some("Complex source-to-sink data flow"),
        "entropy_at_sink" => Some("High-entropy payload at execution sink"),
        "dynamic_string_materialisation_sink" => {
            Some("Dynamic string materialisation into execution sink")
        }
        "error_recovery_patterns" => Some("Runtime error recovery patterning"),
        "dormant_or_gated_execution" => Some("Dormant or gated execution behaviour"),
        _ => None,
    }
}

fn behavioral_pattern_kind(name: &str) -> Option<&'static str> {
    match name {
        "wasm_loader_staging" => Some("js_runtime_wasm_loader_staging"),
        "runtime_dependency_loader_abuse" => Some("js_runtime_dependency_loader_abuse"),
        "credential_harvest_form_emulation" => Some("js_runtime_credential_harvest"),
        "chunked_data_exfil_pipeline" => Some("js_runtime_chunked_data_exfil"),
        "interaction_coercion_loop" => Some("js_runtime_interaction_coercion"),
        "lotl_api_chain_execution" => Some("js_runtime_lotl_api_chain_execution"),
        "service_worker_persistence_abuse" => Some("js_runtime_service_worker_persistence"),
        "webcrypto_key_staging_exfil" => Some("js_runtime_webcrypto_key_staging"),
        "storage_backed_payload_staging" => Some("js_runtime_storage_payload_staging"),
        "dynamic_module_graph_evasion" => Some("js_runtime_dynamic_module_evasion"),
        "covert_realtime_channel_abuse" => Some("js_runtime_realtime_channel_abuse"),
        "clipboard_session_hijack_behaviour" => Some("js_runtime_clipboard_session_hijack"),
        "dom_sink_policy_bypass_attempt" => Some("js_runtime_dom_policy_bypass"),
        "wasm_memory_unpacker_pipeline" => Some("js_runtime_wasm_memory_unpacker"),
        "extension_api_abuse_probe" => Some("js_runtime_extension_api_abuse"),
        "modern_fingerprint_evasion" => Some("js_runtime_modern_fingerprint_evasion"),
        "api_call_sequence_malicious" => Some("js_runtime_api_sequence_malicious"),
        "source_sink_complexity" => Some("js_runtime_source_sink_complexity"),
        "entropy_at_sink" => Some("js_runtime_entropy_at_sink"),
        "dynamic_string_materialisation_sink" => Some("js_runtime_dynamic_string_materialisation"),
        "error_recovery_patterns" => Some("js_runtime_error_recovery_patterns"),
        "dormant_or_gated_execution" => Some("js_runtime_dormant_or_gated_execution"),
        _ => None,
    }
}

fn behavioral_pattern_description(name: &str) -> Option<&'static str> {
    match name {
        "wasm_loader_staging" => {
            Some("JavaScript invoked WebAssembly loader APIs in a sequence consistent with staged execution.")
        }
        "runtime_dependency_loader_abuse" => {
            Some("JavaScript dynamically loaded runtime modules and invoked execution or write sinks.")
        }
        "credential_harvest_form_emulation" => {
            Some("JavaScript combined field/form APIs with outbound submission behaviour, consistent with credential harvesting.")
        }
        "chunked_data_exfil_pipeline" => {
            Some("JavaScript staged data in chunks and transmitted it across repeated outbound sends.")
        }
        "interaction_coercion_loop" => {
            Some("JavaScript repeatedly invoked dialog primitives with loop or gating cues consistent with coercive lures.")
        }
        "lotl_api_chain_execution" => {
            Some("JavaScript chained benign host APIs from environment and staging surfaces into execution behaviour.")
        }
        "service_worker_persistence_abuse" => {
            Some("JavaScript used service worker lifecycle and cache APIs in a persistence-oriented sequence.")
        }
        "webcrypto_key_staging_exfil" => {
            Some("JavaScript handled WebCrypto key material and then attempted outbound transmission.")
        }
        "storage_backed_payload_staging" => {
            Some("JavaScript staged payload content in browser storage before decode or execution.")
        }
        "dynamic_module_graph_evasion" => {
            Some("JavaScript performed dynamic module loading and graph traversal with execution sinks.")
        }
        "covert_realtime_channel_abuse" => {
            Some("JavaScript prepared encoded data and sent it through realtime communication channels.")
        }
        "clipboard_session_hijack_behaviour" => {
            Some("JavaScript accessed clipboard/session artefacts and attempted outbound transfer.")
        }
        "dom_sink_policy_bypass_attempt" => {
            Some("JavaScript routed obfuscated input into sensitive DOM or script sink surfaces.")
        }
        "wasm_memory_unpacker_pipeline" => {
            Some("JavaScript combined WebAssembly memory operations with unpacking and dynamic execution.")
        }
        "extension_api_abuse_probe" => {
            Some("JavaScript probed extension runtime APIs, indicating privilege and environment reconnaissance.")
        }
        "modern_fingerprint_evasion" => {
            Some("JavaScript performed modern fingerprint probes with timing or gating behaviour.")
        }
        "api_call_sequence_malicious" => {
            Some("JavaScript executed a suspicious source/transform/sink API sequence consistent with staged malicious intent.")
        }
        "source_sink_complexity" => {
            Some("JavaScript routed data from acquisition sources to sensitive sinks with a multi-step transformation chain.")
        }
        "entropy_at_sink" => {
            Some("JavaScript passed high-entropy runtime strings into execution sinks, consistent with obfuscated payload staging.")
        }
        "dynamic_string_materialisation_sink" => {
            Some("JavaScript dynamically materialised executable strings before invoking execution sinks.")
        }
        "error_recovery_patterns" => {
            Some("JavaScript repeatedly triggered errors and immediately pivoted to fallback execution paths, consistent with runtime adaptation or anti-analysis behaviour.")
        }
        "dormant_or_gated_execution" => {
            Some("JavaScript payload appears dormant under current emulation and may require specific runtime gates, interaction, or environment triggers to activate.")
        }
        _ => None,
    }
}

fn extend_with_behavioral_pattern_findings(
    findings: &mut Vec<Finding>,
    surface: AttackSurface,
    object_ref: &str,
    evidence: &[sis_pdf_core::model::EvidenceSpan],
    base_meta: &std::collections::HashMap<String, String>,
    profile_summary: &ProfileDivergenceSummary,
    signals: &js_analysis::DynamicSignals,
) {
    for pattern in &signals.behavioral_patterns {
        let kind = behavioral_pattern_kind(&pattern.name)
            .unwrap_or("js_runtime_unknown_behaviour_pattern");
        let title =
            behavioral_pattern_title(&pattern.name).unwrap_or("Unknown runtime behaviour pattern");
        let description = behavioral_pattern_description(&pattern.name).unwrap_or(
            "Sandbox reported a behavioural pattern that is not yet mapped in detector metadata.",
        );

        let mut meta = base_meta.clone();
        meta.insert("js.sandbox_exec".into(), "true".into());
        meta.insert("js.runtime.behavior.name".into(), pattern.name.clone());
        meta.insert(
            "js.runtime.behavior.confidence_score".into(),
            format!("{:.2}", pattern.confidence),
        );
        meta.insert("js.runtime.behavior.severity".into(), pattern.severity.clone());
        meta.insert("js.runtime.behavior.evidence".into(), pattern.evidence.clone());
        for (key, value) in &pattern.metadata {
            meta.insert(format!("js.runtime.behavior.meta.{key}"), value.clone());
        }
        let base_severity = severity_from_behavioral(&pattern.severity);
        let base_confidence = confidence_from_behavioral(pattern.confidence);
        let (severity, confidence) = apply_profile_scoring_meta(
            &mut meta,
            profile_summary,
            kind,
            base_severity,
            base_confidence,
        );
        findings.push(Finding {
            id: String::new(),
            surface,
            kind: kind.into(),
            severity,
            confidence,
            impact: impact_for_kind(kind),
            title: title.into(),
            description: description.into(),
            objects: vec![object_ref.to_string()],
            evidence: evidence.to_vec(),
            remediation: Some(
                "Review dynamic telemetry and correlate with static JS artefacts.".into(),
            ),
            meta,
            yara: None,
            positions: Vec::new(),
            ..Finding::default()
        });
    }
}

fn extend_with_heap_manipulation_finding(
    findings: &mut Vec<Finding>,
    detector_surface: AttackSurface,
    object_ref: &str,
    evidence: &[sis_pdf_core::model::EvidenceSpan],
    base_meta: &std::collections::HashMap<String, String>,
    summary: &ProfileDivergenceSummary,
    signals: &js_analysis::DynamicSignals,
) {
    let allocation_count = signals.heap_allocation_count;
    let view_count = signals.heap_view_count;
    let access_count = signals.heap_access_count;
    if allocation_count == 0 && view_count == 0 && access_count == 0 {
        return;
    }
    let mut stages = 0usize;
    if allocation_count > 0 {
        stages += 1;
    }
    if view_count > 0 {
        stages += 1;
    }
    if access_count > 0 {
        stages += 1;
    }
    let mut meta = base_meta.clone();
    meta.insert("js.sandbox_exec".into(), "true".into());
    meta.insert("js.runtime.heap.stage_count".into(), stages.to_string());
    let base_severity =
        if stages >= 3 || access_count >= 8 { Severity::Medium } else { Severity::Low };
    let base_confidence = if stages >= 3 {
        Confidence::Strong
    } else if stages == 2 {
        Confidence::Probable
    } else {
        Confidence::Tentative
    };
    let (severity, confidence) = apply_profile_scoring_meta(
        &mut meta,
        summary,
        "js_runtime_heap_manipulation",
        base_severity,
        base_confidence,
    );
    findings.push(Finding {
        id: String::new(),
        surface: detector_surface,
        kind: "js_runtime_heap_manipulation".into(),
        severity,
        confidence,
        impact: impact_for_kind("js_runtime_heap_manipulation"),
        title: "Runtime heap manipulation primitives".into(),
        description: format!(
            "JavaScript exercised heap-related primitives (allocations={}, views={}, accesses={}).",
            allocation_count, view_count, access_count
        ),
        objects: vec![object_ref.to_string()],
        evidence: evidence.to_vec(),
        remediation: Some(
            "Review typed-array/DataView usage and correlate with decoder or execution-stage behaviour."
                .into(),
        ),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    });
}

fn extend_with_emulation_breakpoint_finding(
    findings: &mut Vec<Finding>,
    detector_surface: AttackSurface,
    object_ref: String,
    evidence: &[sis_pdf_core::model::EvidenceSpan],
    base_meta: &std::collections::HashMap<String, String>,
    errors: &[String],
    summary: &ProfileDivergenceSummary,
) {
    if errors.is_empty() {
        return;
    }
    let mut bucket_counts = std::collections::BTreeMap::<String, usize>::new();
    let mut normalised = Vec::new();
    for raw in errors {
        let message = extract_js_error_message(raw);
        normalised.push(message.clone());
        let bucket = classify_emulation_breakpoint(&message).to_string();
        *bucket_counts.entry(bucket).or_insert(0) += 1;
    }
    let mut meta = base_meta.clone();
    meta.insert("js.sandbox_exec".into(), "true".into());
    meta.insert("js.runtime.error_count".into(), errors.len().to_string());
    meta.insert("js.runtime.error_messages".into(), normalised.join(" | "));
    meta.insert(
        "js.emulation_breakpoint.buckets".into(),
        bucket_counts
            .iter()
            .map(|(bucket, count)| format!("{bucket}:{count}"))
            .collect::<Vec<_>>()
            .join(", "),
    );
    if let Some((top_bucket, top_count)) = bucket_counts
        .iter()
        .max_by(|left, right| left.1.cmp(right.1).then_with(|| right.0.cmp(left.0)))
    {
        meta.insert("js.emulation_breakpoint.top_bucket".into(), top_bucket.clone());
        meta.insert("js.emulation_breakpoint.top_bucket_count".into(), top_count.to_string());
    }
    let parser_mismatch = bucket_counts.contains_key("parser_dialect_mismatch");
    let base_severity = if parser_mismatch { Severity::Low } else { Severity::Low };
    let base_confidence = if parser_mismatch { Confidence::Probable } else { Confidence::Probable };
    let (severity, mut confidence) = apply_profile_scoring_meta(
        &mut meta,
        summary,
        "js_sandbox_exec",
        base_severity,
        base_confidence,
    );
    if bucket_counts.contains_key("loop_iteration_limit") {
        if let Some(calls_raw) = base_meta.get("js.runtime.calls") {
            let calls = calls_raw
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            if let Some((dominant_api, total_probe_calls, unique_probe_apis, dominance_ratio)) =
                detect_probe_loop_context(&calls)
            {
                let loop_hits = *bucket_counts.get("loop_iteration_limit").unwrap_or(&0);
                let pressure_ratio = if total_probe_calls == 0 {
                    0.0
                } else {
                    loop_hits as f64 / total_probe_calls as f64
                };
                meta.insert("js.runtime.probe_loop".into(), "true".into());
                meta.insert("js.runtime.probe_loop_dominant_api".into(), dominant_api);
                meta.insert(
                    "js.runtime.probe_loop_call_count".into(),
                    total_probe_calls.to_string(),
                );
                meta.insert(
                    "js.runtime.probe_loop_unique_api_count".into(),
                    unique_probe_apis.to_string(),
                );
                meta.insert(
                    "js.runtime.probe_loop_dominance_ratio".into(),
                    format!("{dominance_ratio:.2}"),
                );
                meta.insert(
                    "js.runtime.loop_iteration_pressure_ratio".into(),
                    format!("{pressure_ratio:.2}"),
                );
                let demoted = demote_confidence(confidence);
                if demoted != confidence {
                    meta.insert(
                        "js.runtime.probe_loop_confidence_adjusted".into(),
                        format!("{:?}->{:?}", confidence, demoted),
                    );
                    confidence = demoted;
                }
            }
        }
    }
    findings.push(Finding {
        id: String::new(),
        surface: detector_surface,
        kind: "js_emulation_breakpoint".into(),
        severity,
        confidence,
        impact: impact_for_kind("js_emulation_breakpoint"),
        title: "JavaScript emulation breakpoint".into(),
        description: "Sandbox execution encountered recoverable runtime errors that may indicate emulation coverage gaps or guarded behaviour.".into(),
        objects: vec![object_ref],
        evidence: evidence.to_vec(),
        remediation: Some(
            "Review error buckets and extend runtime stubs or parsing support for the affected API/dialect.".into(),
        ),
        meta,
        yara: None,
        positions: Vec::new(),
        ..Finding::default()
    });
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
        let document_budget = sandbox_document_budget();
        let budget_start = Instant::now();
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
                let object_ref = format!("{} {} obj", entry.obj, entry.gen);
                if let Some(budget) = document_budget {
                    let elapsed = budget_start.elapsed();
                    if elapsed >= budget {
                        push_budget_skipped_finding(
                            &mut findings,
                            self.surface(),
                            object_ref,
                            &evidence,
                            candidate.source.meta_value(),
                            budget.as_millis(),
                            elapsed.as_millis(),
                        );
                        continue;
                    }
                }
                if let Some(format_hint) = likely_non_javascript_payload(&info.bytes) {
                    extend_with_payload_format_finding(
                        &mut findings,
                        self.surface(),
                        object_ref,
                        &evidence,
                        candidate.source.meta_value(),
                        format_hint,
                        info.bytes.len(),
                    );
                    continue;
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
                            impact: impact_for_kind("js_sandbox_skipped"),
                            title: "JavaScript sandbox skipped".into(),
                            description: "Sandbox skipped because the JS payload exceeds the size limit or sandbox is unavailable.".into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: evidence.clone(),
                            remediation: Some("Inspect the JS payload size and consider manual analysis.".into()),
                            meta,
                            yara: None,
                            positions: Vec::new(),
                        ..Finding::default()
                        });
                    }
                    DynamicOutcome::TimedOut { timeout_ms, context } => {
                        let mut meta = std::collections::HashMap::new();
                        if let Some(label) = candidate.source.meta_value() {
                            meta.insert("js.source".into(), label.into());
                        }
                        extend_with_script_timeout_finding(
                            &mut findings,
                            self.surface(),
                            format!("{} {} obj", entry.obj, entry.gen),
                            &evidence,
                            &meta,
                            &profile_summary,
                            Some(timeout_ms),
                            Some(&context.runtime_profile),
                            context.phase.as_deref(),
                            context.elapsed_ms,
                            context.budget_ratio,
                            false,
                        );
                    }
                    DynamicOutcome::Executed(signals) => {
                        if signals.call_count == 0 {
                            let mut meta = std::collections::HashMap::new();
                            meta.insert("js.sandbox_exec".into(), "true".into());
                            populate_base_metadata(
                                &mut meta,
                                &signals,
                                candidate.source.meta_value(),
                                profile_summary.timed_out_count,
                                false,
                            );
                            let object_ref = format!("{} {} obj", entry.obj, entry.gen);
                            let recursion_hits = recursion_limit_hits(&signals.errors);
                            let loop_hits = loop_iteration_limit_hits(&signals.errors);
                            if loop_hits > 0 {
                                meta.insert(
                                    "js.runtime.loop_iteration_limit_hits".into(),
                                    loop_hits.to_string(),
                                );
                            }
                            extend_with_script_timeout_finding(
                                &mut findings,
                                self.surface(),
                                object_ref.clone(),
                                &evidence,
                                &meta,
                                &profile_summary,
                                None,
                                None,
                                None,
                                None,
                                None,
                                true,
                            );
                            extend_with_emulation_breakpoint_finding(
                                &mut findings,
                                self.surface(),
                                object_ref.clone(),
                                &evidence,
                                &meta,
                                &signals.errors,
                                &profile_summary,
                            );
                            extend_with_recursion_limit_finding(
                                &mut findings,
                                self.surface(),
                                object_ref.clone(),
                                &evidence,
                                &meta,
                                &profile_summary,
                                recursion_hits,
                            );
                            extend_with_behavioral_pattern_findings(
                                &mut findings,
                                self.surface(),
                                &object_ref,
                                &evidence,
                                &meta,
                                &profile_summary,
                                &signals,
                            );
                            extend_with_heap_manipulation_finding(
                                &mut findings,
                                self.surface(),
                                &object_ref,
                                &evidence,
                                &meta,
                                &profile_summary,
                                &signals,
                            );
                            extend_with_path_morphism_finding(
                                &mut findings,
                                self.surface(),
                                &object_ref,
                                &evidence,
                                &meta,
                                &profile_summary,
                                &profile_runs,
                            );
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
                                impact: impact_for_kind("js_sandbox_exec"),
                                title: "JavaScript sandbox executed".into(),
                                description: description.into(),
                                objects: vec![object_ref],
                                evidence: evidence.clone(),
                                remediation: Some("Review JS payload and runtime errors.".into()),
                                meta,
                                yara: None,
                                positions: Vec::new(),
                                ..Finding::default()
                            });
                            continue;
                        }

                        let mut base_meta = std::collections::HashMap::new();
                        populate_base_metadata(
                            &mut base_meta,
                            &signals,
                            candidate.source.meta_value(),
                            profile_summary.timed_out_count,
                            true,
                        );
                        let object_ref = format!("{} {} obj", entry.obj, entry.gen);
                        let recursion_hits = recursion_limit_hits(&signals.errors);
                        let loop_hits = loop_iteration_limit_hits(&signals.errors);
                        if recursion_hits > 0 {
                            base_meta.insert(
                                "js.runtime.recursion_limit_hits".into(),
                                recursion_hits.to_string(),
                            );
                        }
                        if loop_hits > 0 {
                            base_meta.insert(
                                "js.runtime.loop_iteration_limit_hits".into(),
                                loop_hits.to_string(),
                            );
                        }
                        extend_with_script_timeout_finding(
                            &mut findings,
                            self.surface(),
                            object_ref.clone(),
                            &evidence,
                            &base_meta,
                            &profile_summary,
                            None,
                            None,
                            None,
                            None,
                            None,
                            true,
                        );
                        extend_with_emulation_breakpoint_finding(
                            &mut findings,
                            self.surface(),
                            object_ref.clone(),
                            &evidence,
                            &base_meta,
                            &signals.errors,
                            &profile_summary,
                        );
                        extend_with_recursion_limit_finding(
                            &mut findings,
                            self.surface(),
                            object_ref.clone(),
                            &evidence,
                            &base_meta,
                            &profile_summary,
                            recursion_hits,
                        );
                        extend_with_behavioral_pattern_findings(
                            &mut findings,
                            self.surface(),
                            &object_ref,
                            &evidence,
                            &base_meta,
                            &profile_summary,
                            &signals,
                        );
                        extend_with_heap_manipulation_finding(
                            &mut findings,
                            self.surface(),
                            &object_ref,
                            &evidence,
                            &base_meta,
                            &profile_summary,
                            &signals,
                        );
                        extend_with_path_morphism_finding(
                            &mut findings,
                            self.surface(),
                            &object_ref,
                            &evidence,
                            &base_meta,
                            &profile_summary,
                            &profile_runs,
                        );
                        let mut risky_calls = signals
                            .calls
                            .iter()
                            .filter(|call| is_risky_call(call))
                            .map(|call| call.as_str())
                            .collect::<std::collections::BTreeSet<_>>()
                            .into_iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>();
                        risky_calls.sort();
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
                        if let Some((create_count, open_count, send_count)) =
                            detect_downloader_pattern(&signals.calls)
                        {
                            let mut meta = base_meta.clone();
                            meta.insert("js.sandbox_exec".into(), "true".into());
                            meta.insert(
                                "js.runtime.downloader.create_calls".into(),
                                create_count.to_string(),
                            );
                            meta.insert(
                                "js.runtime.downloader.open_calls".into(),
                                open_count.to_string(),
                            );
                            meta.insert(
                                "js.runtime.downloader.send_calls".into(),
                                send_count.to_string(),
                            );
                            let (severity, confidence) = apply_profile_scoring_meta(
                                &mut meta,
                                &profile_summary,
                                "js_runtime_network_intent",
                                Severity::High,
                                Confidence::Strong,
                            );
                            let mut final_confidence = confidence;
                            if signals.errors.is_empty()
                                && profile_summary.timed_out_count == 0
                                && loop_hits == 0
                            {
                                let promoted = promote_confidence(confidence);
                                if promoted != confidence {
                                    final_confidence = promoted;
                                    meta.insert(
                                        "js.runtime.clean_execution_confidence_adjusted".into(),
                                        format!("{:?}->{:?}", confidence, promoted),
                                    );
                                }
                            }
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_runtime_downloader_pattern".into(),
                                severity,
                                confidence: final_confidence,
                                impact: impact_for_kind("js_runtime_downloader_pattern"),
                                title: "Runtime downloader loop pattern".into(),
                                description: "JavaScript repeatedly created script-host objects and issued XMLHTTP open/send calls, consistent with downloader loop behaviour.".into(),
                                objects: vec![object_ref.clone()],
                                evidence: evidence.clone(),
                                remediation: Some(
                                    "Inspect request targets, response handling, and follow-on execution/file write operations.".into(),
                                ),
                                meta,
                                yara: None,
                                positions: Vec::new(),
                                ..Finding::default()
                            });
                        }
                        if has_network {
                            let mut meta = base_meta.clone();
                            meta.insert("js.sandbox_exec".into(), "true".into());
                            let (severity, confidence) = apply_profile_scoring_meta(
                                &mut meta,
                                &profile_summary,
                                "js_runtime_network_intent",
                                Severity::Medium,
                                Confidence::Probable,
                            );
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_runtime_network_intent".into(),
                                severity,
                                confidence,
                                impact: impact_for_kind("js_runtime_network_intent"),
                                title: "Runtime network intent".into(),
                                description: "JavaScript invoked network-capable APIs during sandboxed execution.".into(),
                                objects: vec![object_ref.clone()],
                                evidence: evidence.clone(),
                                remediation: Some("Inspect runtime JS calls and network targets.".into()),
                                meta,
                                yara: None,
                                positions: Vec::new(),
                            ..Finding::default()
                            });
                        }
                        if has_file {
                            let mut meta = base_meta.clone();
                            meta.insert("js.sandbox_exec".into(), "true".into());
                            let (severity, mut confidence) = apply_profile_scoring_meta(
                                &mut meta,
                                &profile_summary,
                                "js_runtime_file_probe",
                                Severity::Medium,
                                Confidence::Probable,
                            );
                            // D1/CAL-01: Confidence floor override for explicit Acrobat API calls
                            // targeting executables. Cross-profile divergence is expected because
                            // app.openDoc / launchURL / etc. are only meaningful in Adobe's runtime.
                            if confidence > Confidence::Probable
                                && adobe_compat_in_executed_profiles(&profile_summary)
                                && has_acrobat_file_api_call(&signals.calls)
                                && call_args_contain_executable_target(&signals.call_args)
                            {
                                confidence = Confidence::Probable;
                                meta.insert(
                                    "js.runtime.acrobat_api_execution_override".into(),
                                    "true".into(),
                                );
                            }
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_runtime_file_probe".into(),
                                severity,
                                confidence,
                                impact: impact_for_kind("js_runtime_file_probe"),
                                title: "Runtime file or object probe".into(),
                                description: "JavaScript invoked file or object-related APIs during sandboxed execution.".into(),
                                objects: vec![object_ref.clone()],
                                evidence: evidence.clone(),
                                remediation: Some("Review runtime JS calls for file or export operations.".into()),
                                meta,
                                yara: None,
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
                                impact: impact_for_kind("js_runtime_risky_calls"),
                                title: "Runtime risky JavaScript calls".into(),
                                description: format!(
                                    "JavaScript invoked high-risk calls during sandboxed execution ({}).",
                                    label
                                ),
                                objects: vec![object_ref.clone()],
                                evidence: evidence.clone(),
                                remediation: Some(
                                    "Review high-risk calls and deobfuscate the payload.".into(),
                                ),
                                meta,
                                yara: None,
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
                                impact: impact_for_kind("js_sandbox_exec"),
                                title: "JavaScript sandbox executed".into(),
                                description: "Sandbox executed JS; monitored API calls were observed but no network/file APIs.".into(),
                                objects: vec![object_ref],
                                evidence: evidence.clone(),
                                remediation: Some("Review runtime JS calls for additional behaviour.".into()),
                                meta,
                                yara: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use js_analysis::types::{
        BehaviorPattern, DynamicDeltaSummary, DynamicPhaseSummary, ExecutionStats,
    };

    const MAPPED_BEHAVIORAL_PATTERN_NAMES: &[&str] = &[
        "wasm_loader_staging",
        "runtime_dependency_loader_abuse",
        "credential_harvest_form_emulation",
        "chunked_data_exfil_pipeline",
        "interaction_coercion_loop",
        "lotl_api_chain_execution",
        "service_worker_persistence_abuse",
        "webcrypto_key_staging_exfil",
        "storage_backed_payload_staging",
        "dynamic_module_graph_evasion",
        "covert_realtime_channel_abuse",
        "clipboard_session_hijack_behaviour",
        "dom_sink_policy_bypass_attempt",
        "wasm_memory_unpacker_pipeline",
        "extension_api_abuse_probe",
        "modern_fingerprint_evasion",
        "api_call_sequence_malicious",
        "source_sink_complexity",
        "entropy_at_sink",
        "dynamic_string_materialisation_sink",
        "error_recovery_patterns",
        "dormant_or_gated_execution",
    ];

    fn minimal_dynamic_signals_with_patterns(
        patterns: Vec<BehaviorPattern>,
    ) -> js_analysis::DynamicSignals {
        js_analysis::DynamicSignals {
            replay_id: "test-replay".into(),
            runtime_profile: "pdf_reader:adobe:11:compat".into(),
            calls: Vec::new(),
            call_args: Vec::new(),
            urls: Vec::new(),
            domains: Vec::new(),
            errors: Vec::new(),
            prop_reads: Vec::new(),
            prop_writes: Vec::new(),
            prop_deletes: Vec::new(),
            reflection_probes: Vec::new(),
            dynamic_code_calls: Vec::new(),
            heap_allocations: Vec::new(),
            heap_views: Vec::new(),
            heap_accesses: Vec::new(),
            heap_allocation_count: 0,
            heap_view_count: 0,
            heap_access_count: 0,
            call_count: 0,
            unique_calls: 0,
            unique_prop_reads: 0,
            elapsed_ms: Some(1),
            truncation: js_analysis::DynamicTruncationSummary::default(),
            phases: Vec::new(),
            delta_summary: None,
            behavioral_patterns: patterns,
            execution_stats: ExecutionStats {
                total_function_calls: 0,
                unique_function_calls: 0,
                variable_promotions: 0,
                error_recoveries: 0,
                successful_recoveries: 0,
                execution_depth: 0,
                loop_iteration_limit_hits: 0,
                adaptive_loop_iteration_limit: 0,
                adaptive_loop_profile: "baseline".into(),
                downloader_scheduler_hardening: false,
                probe_loop_short_circuit_hits: 0,
            },
        }
    }

    #[test]
    fn summarise_path_morphism_detects_profile_path_deltas() {
        let mut profile_a = minimal_dynamic_signals_with_patterns(Vec::new());
        profile_a.runtime_profile = "pdf_reader:adobe:11:compat".into();
        profile_a.calls = vec!["app.alert".into(), "app.launchURL".into()];
        profile_a.call_count = profile_a.calls.len();
        profile_a.unique_calls = profile_a.calls.len();
        profile_a.phases = vec![DynamicPhaseSummary {
            phase: "open".into(),
            call_count: 2,
            prop_read_count: 0,
            error_count: 0,
            elapsed_ms: 1,
        }];
        profile_a.delta_summary = Some(DynamicDeltaSummary {
            phase: "open".into(),
            trigger_calls: vec!["app.launchURL".into()],
            generated_snippets: 1,
            added_identifier_count: 6,
            added_string_literal_count: 5,
            added_call_count: 4,
            new_identifiers: vec!["fnA".into()],
            new_string_literals: vec!["x".into()],
            new_calls: vec!["eval".into()],
        });

        let mut profile_b = minimal_dynamic_signals_with_patterns(Vec::new());
        profile_b.runtime_profile = "browser:chromium:120:compat".into();
        profile_b.calls = vec!["window.atob".into(), "Function".into()];
        profile_b.call_count = profile_b.calls.len();
        profile_b.unique_calls = profile_b.calls.len();
        profile_b.phases = vec![DynamicPhaseSummary {
            phase: "click".into(),
            call_count: 2,
            prop_read_count: 0,
            error_count: 0,
            elapsed_ms: 1,
        }];
        profile_b.delta_summary = Some(DynamicDeltaSummary {
            phase: "click".into(),
            trigger_calls: vec!["Function".into()],
            generated_snippets: 1,
            added_identifier_count: 5,
            added_string_literal_count: 4,
            added_call_count: 3,
            new_identifiers: vec!["fnB".into()],
            new_string_literals: vec!["y".into()],
            new_calls: vec!["setTimeout".into()],
        });

        let profile_runs = vec![
            ProfileRun {
                profile_id: profile_a.runtime_profile.clone(),
                outcome: DynamicOutcome::Executed(Box::new(profile_a)),
            },
            ProfileRun {
                profile_id: profile_b.runtime_profile.clone(),
                outcome: DynamicOutcome::Executed(Box::new(profile_b)),
            },
        ];

        let summary = summarise_path_morphism(&profile_runs).expect("morphism summary");
        assert_eq!(summary.executed_profiles, 2);
        assert!(summary.distinct_path_signatures >= 2);
        assert!(summary.delta_profiles >= 2);
        assert!(summary.score >= 3);
    }

    #[test]
    fn populate_base_metadata_counts_unresolved_runtime_errors() {
        let mut signals = minimal_dynamic_signals_with_patterns(Vec::new());
        signals.errors = vec![
            "ReferenceError: foo is not defined".into(),
            "TypeError: bar is not a callable function".into(),
            "Callable recovery hint: line=1 columns=[1] callee=bar".into(),
        ];
        let mut meta = std::collections::HashMap::new();
        populate_base_metadata(&mut meta, &signals, Some("inline"), 0, false);
        assert_eq!(
            meta.get("js.runtime.unresolved_identifier_error_count").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            meta.get("js.runtime.unresolved_callable_error_count").map(String::as_str),
            Some("1")
        );
        assert_eq!(meta.get("js.runtime.callable_hint_count").map(String::as_str), Some("1"));
        assert_eq!(
            meta.get("js.runtime.unresolved_callee_hint_count").map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn configured_profiles_include_deception_hardened_browser_mode() {
        let plans = configured_profiles();
        assert_eq!(plans.len(), 5);
        assert!(plans.iter().any(|plan| {
            matches!(plan.profile.kind, RuntimeKind::Browser)
                && matches!(plan.profile.mode, RuntimeMode::DeceptionHardened)
        }));
    }

    #[test]
    fn insert_profile_meta_includes_interaction_and_unresolved_rollups() {
        let mut meta = std::collections::HashMap::new();
        let summary = ProfileDivergenceSummary {
            profile_ids: vec![
                "pdf_reader:adobe:11:compat".into(),
                "browser:chromium:120:compat".into(),
                "browser:chromium:120:deception_hardened".into(),
            ],
            executed_count: 3,
            compat_profiles: 2,
            deception_hardened_profiles: 1,
            interaction_open_profiles: 3,
            interaction_idle_profiles: 3,
            interaction_click_profiles: 2,
            interaction_form_profiles: 2,
            unresolved_identifier_error_total: 5,
            unresolved_callable_error_total: 4,
            callable_hint_total: 2,
            unresolved_callee_hint_total: 2,
            unresolved_identifier_error_profiles: 2,
            unresolved_callable_error_profiles: 2,
            unresolved_callee_hint_profiles: 1,
            capability_signature_count: 2,
            ..ProfileDivergenceSummary::default()
        };
        insert_profile_meta(&mut meta, &summary);
        assert_eq!(
            meta.get("js.runtime.profile_mode.deception_hardened_count").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            meta.get("js.runtime.interaction_pack_order").map(String::as_str),
            Some("open,idle,click,form")
        );
        assert_eq!(
            meta.get("js.runtime.unresolved_identifier_error_total").map(String::as_str),
            Some("5")
        );
        assert_eq!(
            meta.get("js.runtime.capability_matrix.distinct_signatures").map(String::as_str),
            Some("2")
        );
    }

    #[test]
    fn all_profile_timeouts_raise_timeout_finding_severity() {
        let mut findings = Vec::new();
        let mut base_meta = std::collections::HashMap::new();
        base_meta.insert("js.source".into(), "inline".into());
        let summary = ProfileDivergenceSummary {
            profile_ids: vec![
                "pdf_reader:adobe:11:compat".into(),
                "browser:chromium:120:compat".into(),
                "node:nodejs:20:compat".into(),
            ],
            timed_out_count: 3,
            ..ProfileDivergenceSummary::default()
        };
        extend_with_script_timeout_finding(
            &mut findings,
            AttackSurface::JavaScript,
            "5 0 obj".into(),
            &[],
            &base_meta,
            &summary,
            Some(5000),
            Some("pdf_reader:adobe:11:compat"),
            Some("open"),
            Some(5000),
            Some(1.0),
            true,
        );
        let finding = findings.first().expect("timeout finding");
        assert_eq!(finding.kind, "js_sandbox_timeout");
        assert_eq!(finding.severity, Severity::Medium);
        assert!(matches!(
            finding.confidence,
            Confidence::Probable | Confidence::Tentative | Confidence::Weak
        ));
    }

    #[test]
    fn downloader_pattern_timeout_demotes_confidence() {
        let summary = ProfileDivergenceSummary {
            profile_ids: vec![
                "pdf_reader:adobe:11:compat".into(),
                "browser:chromium:120:compat".into(),
                "node:nodejs:20:compat".into(),
            ],
            executed_count: 2,
            timed_out_count: 1,
            network_count: 2,
            ..ProfileDivergenceSummary::default()
        };
        let mut meta = std::collections::HashMap::new();
        let (_, confidence) = apply_profile_scoring_meta(
            &mut meta,
            &summary,
            "js_runtime_downloader_pattern",
            Severity::High,
            Confidence::Strong,
        );
        assert_eq!(confidence, Confidence::Probable);
        assert_eq!(
            meta.get("js.runtime.timeout_confidence_adjusted").map(String::as_str),
            Some("Strong->Probable")
        );
    }

    #[test]
    fn maps_error_recovery_pattern_to_dedicated_kind() {
        assert_eq!(
            behavioral_pattern_kind("error_recovery_patterns"),
            Some("js_runtime_error_recovery_patterns")
        );
        assert_eq!(
            behavioral_pattern_title("error_recovery_patterns"),
            Some("Runtime error recovery patterning")
        );
        assert!(behavioral_pattern_description("error_recovery_patterns").is_some());
    }

    #[test]
    fn maps_dormant_or_gated_execution_to_dedicated_kind() {
        assert_eq!(
            behavioral_pattern_kind("dormant_or_gated_execution"),
            Some("js_runtime_dormant_or_gated_execution")
        );
        assert_eq!(
            behavioral_pattern_title("dormant_or_gated_execution"),
            Some("Dormant or gated execution behaviour")
        );
        assert!(behavioral_pattern_description("dormant_or_gated_execution").is_some());
    }

    #[test]
    fn mapped_behavioral_patterns_have_full_metadata() {
        for name in MAPPED_BEHAVIORAL_PATTERN_NAMES {
            assert!(behavioral_pattern_kind(name).is_some(), "missing kind mapping for {name}");
            assert!(behavioral_pattern_title(name).is_some(), "missing title mapping for {name}");
            assert!(
                behavioral_pattern_description(name).is_some(),
                "missing description mapping for {name}"
            );
        }
    }

    #[test]
    fn unknown_behavioral_pattern_preserves_name_and_evidence_meta() {
        let mut findings = Vec::new();
        let summary = ProfileDivergenceSummary::default();
        let mut base_meta = std::collections::HashMap::new();
        base_meta.insert("js.source".into(), "inline".into());
        let unknown_pattern = BehaviorPattern {
            name: "new_unmapped_runtime_pattern".into(),
            confidence: 0.42,
            evidence: "Observed unusual call/prop progression".into(),
            severity: "Low".into(),
            metadata: std::collections::BTreeMap::new(),
        };
        let signals = minimal_dynamic_signals_with_patterns(vec![unknown_pattern]);
        extend_with_behavioral_pattern_findings(
            &mut findings,
            AttackSurface::JavaScript,
            "8 0 obj",
            &[],
            &base_meta,
            &summary,
            &signals,
        );
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.kind, "js_runtime_unknown_behaviour_pattern");
        assert_eq!(
            finding.meta.get("js.runtime.behavior.name").map(String::as_str),
            Some("new_unmapped_runtime_pattern")
        );
        assert_eq!(
            finding.meta.get("js.runtime.behavior.evidence").map(String::as_str),
            Some("Observed unusual call/prop progression")
        );
    }

    // --- D1/CAL-01: Acrobat API confidence floor helper unit tests ---

    #[test]
    fn has_acrobat_file_api_call_detects_open_doc() {
        assert!(has_acrobat_file_api_call(&["openDoc".into()]));
    }

    #[test]
    fn has_acrobat_file_api_call_detects_launch_url() {
        assert!(has_acrobat_file_api_call(&["launchURL".into()]));
    }

    #[test]
    fn has_acrobat_file_api_call_detects_import_text_data() {
        assert!(has_acrobat_file_api_call(&["importTextData".into()]));
    }

    #[test]
    fn has_acrobat_file_api_call_returns_false_for_non_acrobat() {
        assert!(!has_acrobat_file_api_call(&["fs.readFile".into(), "fetch".into()]));
    }

    #[test]
    fn has_acrobat_file_api_call_returns_false_for_empty() {
        assert!(!has_acrobat_file_api_call(&[]));
    }

    #[test]
    fn call_args_contain_executable_target_detects_exe_extension() {
        assert!(call_args_contain_executable_target(&[
            r#"openDoc(/C/Windows/System32/calc.exe)"#.into()
        ]));
    }

    #[test]
    fn call_args_contain_executable_target_detects_bat_extension() {
        assert!(call_args_contain_executable_target(&["openDoc(run.bat)".into()]));
    }

    #[test]
    fn call_args_contain_executable_target_returns_false_for_pdf() {
        assert!(!call_args_contain_executable_target(&["openDoc(report.pdf)".into()]));
    }

    #[test]
    fn call_args_contain_executable_target_returns_false_for_empty() {
        assert!(!call_args_contain_executable_target(&[]));
    }

    #[test]
    fn adobe_compat_in_executed_profiles_detects_compat_profile() {
        let summary = ProfileDivergenceSummary {
            executed_profiles: vec!["pdf_reader:adobe:11:compat".into()],
            ..ProfileDivergenceSummary::default()
        };
        assert!(adobe_compat_in_executed_profiles(&summary));
    }

    #[test]
    fn adobe_compat_in_executed_profiles_returns_false_for_deception_hardened() {
        let summary = ProfileDivergenceSummary {
            executed_profiles: vec!["pdf_reader:adobe:11:deception_hardened".into()],
            ..ProfileDivergenceSummary::default()
        };
        assert!(!adobe_compat_in_executed_profiles(&summary));
    }

    #[test]
    fn adobe_compat_in_executed_profiles_returns_false_for_empty() {
        assert!(!adobe_compat_in_executed_profiles(&ProfileDivergenceSummary::default()));
    }
}

use std::time::Duration;

use anyhow::Result;

use js_analysis::{is_file_call, is_network_call, run_sandbox, DynamicOptions, DynamicOutcome};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;

use crate::js_payload_candidates_from_entry;

pub struct JavaScriptSandboxDetector;

const JS_WALLCLOCK_TIMEOUT: Duration = Duration::from_secs(5);
const JS_SANDBOX_MAX_BYTES: usize = 256 * 1024;

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

                let options = DynamicOptions {
                    max_bytes: JS_SANDBOX_MAX_BYTES,
                    timeout_ms: JS_WALLCLOCK_TIMEOUT.as_millis(),
                    ..Default::default()
                };

                match run_sandbox(&info.bytes, &options) {
                    DynamicOutcome::Skipped { reason, limit, actual } => {
                        let mut meta = std::collections::HashMap::new();
                        meta.insert("js.sandbox_exec".into(), "false".into());
                        meta.insert("js.sandbox_skip_reason".into(), reason);
                        meta.insert("payload.decoded_len".into(), actual.to_string());
                        meta.insert("js.sandbox_limit_bytes".into(), limit.to_string());
                        if let Some(label) = candidate.source.meta_value() {
                            meta.insert("js.source".into(), label.into());
                        }
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
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_sandbox_exec".into(),
                                severity: Severity::Info,
                                confidence: Confidence::Probable,
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
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_runtime_network_intent".into(),
                                severity: Severity::High,
                                confidence: Confidence::Probable,
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
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_runtime_file_probe".into(),
                                severity: Severity::Medium,
                                confidence: Confidence::Probable,
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
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_runtime_risky_calls".into(),
                                severity: Severity::High,
                                confidence: Confidence::Strong,
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
                            findings.push(Finding {
                                id: String::new(),
                                surface: self.surface(),
                                kind: "js_sandbox_exec".into(),
                                severity: Severity::Info,
                                confidence: Confidence::Probable,
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

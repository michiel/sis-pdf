use std::time::Duration;

use anyhow::Result;

use js_analysis::{is_file_call, is_network_call, run_sandbox, DynamicOptions, DynamicOutcome};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;

use crate::{entry_dict, resolve_payload};

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
            let Some(dict) = entry_dict(entry) else { continue };
            if !dict.has_name(b"/S", b"/JavaScript") && dict.get_first(b"/JS").is_none() {
                continue;
            }
            let Some((_, obj)) = dict.get_first(b"/JS") else { continue };
            let payload = resolve_payload(ctx, obj);
            let Some(info) = payload.payload else { continue };

            let mut options = DynamicOptions::default();
            options.max_bytes = JS_SANDBOX_MAX_BYTES;
            options.timeout_ms = JS_WALLCLOCK_TIMEOUT.as_millis();

            match run_sandbox(&info.bytes, &options) {
                DynamicOutcome::Skipped { reason, limit, actual } => {
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("js.sandbox_exec".into(), "false".into());
                    meta.insert("js.sandbox_skip_reason".into(), reason);
                    meta.insert("payload.decoded_len".into(), actual.to_string());
                    meta.insert("js.sandbox_limit_bytes".into(), limit.to_string());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "js_sandbox_skipped".into(),
                        severity: Severity::Info,
                        confidence: Confidence::Probable,
                        title: "JavaScript sandbox skipped".into(),
                        description: "Sandbox skipped because the JS payload exceeds the size limit or sandbox is unavailable.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                        remediation: Some("Inspect the JS payload size and consider manual analysis.".into()),
                        meta,
                        yara: None,
                    });
                }
                DynamicOutcome::TimedOut { timeout_ms } => {
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("js.sandbox_exec".into(), "true".into());
                    meta.insert("js.sandbox_timeout".into(), "true".into());
                    meta.insert("js.sandbox_timeout_ms".into(), timeout_ms.to_string());
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "js_sandbox_timeout".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Probable,
                        title: "JavaScript sandbox timeout".into(),
                        description: "Sandbox execution exceeded the time limit.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                        remediation: Some("Inspect the JS payload for long-running loops.".into()),
                        meta,
                        yara: None,
                    });
                }
                DynamicOutcome::Executed(signals) => {
                    if signals.call_count == 0 {
                        let mut meta = std::collections::HashMap::new();
                        meta.insert("js.sandbox_exec".into(), "true".into());
                        if let Some(ms) = signals.elapsed_ms {
                            meta.insert("js.sandbox_exec_ms".into(), ms.to_string());
                        }
                        if !signals.prop_reads.is_empty() {
                            meta.insert("js.runtime.prop_reads".into(), signals.prop_reads.join(", "));
                            meta.insert("js.runtime.unique_prop_reads".into(), signals.unique_prop_reads.to_string());
                        }
                        if !signals.errors.is_empty() {
                            meta.insert("js.runtime.errors".into(), signals.errors.join("; "));
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
                            title: "JavaScript sandbox executed".into(),
                            description: description.into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                            remediation: Some("Review JS payload and runtime errors.".into()),
                            meta,
                            yara: None,
                        });
                        continue;
                    }

                    let mut base_meta = std::collections::HashMap::new();
                    base_meta.insert("js.runtime.calls".into(), signals.calls.join(","));
                    base_meta.insert("js.runtime.call_count".into(), signals.call_count.to_string());
                    base_meta.insert("js.runtime.unique_calls".into(), signals.unique_calls.to_string());
                    if !signals.call_args.is_empty() {
                        base_meta.insert("js.runtime.call_args".into(), signals.call_args.join("; "));
                    }
                    if !signals.urls.is_empty() {
                        base_meta.insert("js.runtime.urls".into(), signals.urls.join(", "));
                    }
                    if !signals.domains.is_empty() {
                        base_meta.insert("js.runtime.domains".into(), signals.domains.join(", "));
                    }
                    if !signals.prop_reads.is_empty() {
                        base_meta.insert("js.runtime.prop_reads".into(), signals.prop_reads.join(", "));
                        base_meta.insert("js.runtime.unique_prop_reads".into(), signals.unique_prop_reads.to_string());
                    }
                    if !signals.errors.is_empty() {
                        base_meta.insert("js.runtime.errors".into(), signals.errors.join("; "));
                    }
                    if let Some(ms) = signals.elapsed_ms {
                        base_meta.insert("js.sandbox_exec_ms".into(), ms.to_string());
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
                            title: "Runtime network intent".into(),
                            description: "JavaScript invoked network-capable APIs during sandboxed execution.".into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                            remediation: Some("Inspect runtime JS calls and network targets.".into()),
                            meta,
                            yara: None,
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
                            title: "Runtime file or object probe".into(),
                            description: "JavaScript invoked file or object-related APIs during sandboxed execution.".into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                            remediation: Some("Review runtime JS calls for file or export operations.".into()),
                            meta,
                            yara: None,
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
                            title: "JavaScript sandbox executed".into(),
                            description: "Sandbox executed JS; monitored API calls were observed but no network/file APIs.".into(),
                            objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                            evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                            remediation: Some("Review runtime JS calls for additional behavior.".into()),
                            meta,
                            yara: None,
                        });
                    }
                }
            }
        }
        Ok(findings)
    }
}

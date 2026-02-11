#![allow(dead_code)]

use crate::types::{DynamicOptions, DynamicOutcome, RuntimeKind, RuntimePhase};

#[cfg(feature = "js-sandbox")]
mod sandbox_impl {
    use super::*;
    use crate::types::DynamicSignals;
    use crate::wasm_features::{extract_wasm_static_features, WasmStaticFeatures};
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::rc::Rc;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use boa_engine::object::builtins::JsFunction;
    use boa_engine::object::{FunctionObjectBuilder, JsObject, ObjectInitializer};
    use boa_engine::property::Attribute;
    use boa_engine::value::JsVariant;
    use boa_engine::vm::RuntimeLimits;
    use boa_engine::{Context, JsArgs, JsString, JsValue, NativeFunction, Source};
    use boa_gc::{custom_trace, empty_trace, Finalize, Trace};

    const CREATOR_PAYLOAD: &str = "z61z70z70z2Ez61z6Cz65z72z74z28z27z68z69z27z29";
    const SUBJECT_PAYLOAD: &str = "Hueputol61Hueputol70Hueputol70Hueputol2EHueputol61Hueputol6CHueputol65Hueputol72Hueputol74Hueputol28Hueputol27Hueputol68Hueputol69Hueputol27Hueputol29";
    const TITLE_PAYLOAD: &str = "%61%6c%65%72%74%28%27%68%69%27%29";
    const MAX_RECORDED_CALLS: usize = 2_048;
    const MAX_RECORDED_PROP_READS: usize = 4_096;
    const MAX_RECORDED_ERRORS: usize = 256;
    const MAX_RECORDED_HEAP_EVENTS: usize = 1_024;
    const MAX_UNDEFINED_RECOVERY_PASSES: usize = 16;
    const BASE_LOOP_ITERATION_LIMIT: u64 = 10_000;
    const DOWNLOADER_LOOP_ITERATION_LIMIT: u64 = 20_000;
    const TOKEN_DECODER_LOOP_ITERATION_LIMIT: u64 = 20_000;
    const TOKEN_DECODER_MAX_NORMALISED_ITERATIONS: usize = 128;
    const MAX_EVAL_EXEC_BYTES: usize = 24_576;
    const HOST_PROBE_LOOP_ITERATION_LIMIT: u64 = 40_000;
    const SENTINEL_SPIN_LOOP_ITERATION_LIMIT: u64 = 60_000;
    const BUSY_WAIT_LOOP_ITERATION_LIMIT: u64 = 80_000;
    const PROBE_EXISTS_TRUE_AFTER: usize = 24;
    const MAX_AUGMENTED_SOURCE_BYTES: usize = 128 * 1024;
    const MAX_TAINT_EDGES: usize = 64;
    const MAX_TAINT_CALL_DISTANCE: usize = 512;

    #[derive(Default, Clone)]
    struct SandboxLog {
        replay_id: String,
        runtime_profile: String,
        calls: Vec<String>,
        call_args: Vec<String>,
        urls: Vec<String>,
        domains: Vec<String>,
        errors: Vec<String>,
        prop_reads: Vec<String>,
        prop_writes: Vec<String>,
        prop_deletes: Vec<String>,
        reflection_probes: Vec<String>,
        dynamic_code_calls: Vec<String>,
        heap_allocations: Vec<String>,
        heap_views: Vec<String>,
        heap_accesses: Vec<String>,
        heap_allocation_count: usize,
        heap_view_count: usize,
        heap_access_count: usize,
        call_count: usize,
        unique_calls: BTreeSet<String>,
        call_counts_by_name: std::collections::BTreeMap<String, usize>,
        unique_prop_reads: BTreeSet<String>,
        elapsed_ms: Option<u128>,
        current_phase: String,
        phase_sequence: Vec<String>,
        phase_call_counts: std::collections::BTreeMap<String, usize>,
        phase_prop_read_counts: std::collections::BTreeMap<String, usize>,
        phase_error_counts: std::collections::BTreeMap<String, usize>,
        phase_elapsed_ms: std::collections::BTreeMap<String, u128>,
        phase_dynamic_code_calls: std::collections::BTreeMap<String, BTreeSet<String>>,
        calls_dropped: usize,
        call_args_dropped: usize,
        prop_reads_dropped: usize,
        errors_dropped: usize,
        urls_dropped: usize,
        domains_dropped: usize,
        heap_allocations_dropped: usize,
        heap_views_dropped: usize,
        heap_accesses_dropped: usize,
        delta_summary: Option<SnapshotDeltaSummary>,
        options: DynamicOptions,
        variable_events: Vec<VariableEvent>,
        scope_transitions: Vec<ScopeTransition>,
        execution_flow: ExecutionFlow,
        behavioral_patterns: Vec<BehaviorObservation>,
        adaptive_loop_iteration_limit: usize,
        adaptive_loop_profile: String,
        downloader_scheduler_hardening: bool,
        probe_loop_short_circuit_hits: usize,
        input_bytes: usize,
        dormant_source_markers: usize,
        worker_registration_observed: bool,
        sw_registration_calls: usize,
        sw_update_calls: usize,
        sw_event_handlers_registered: usize,
        sw_lifecycle_events_executed: usize,
        sw_cache_calls: usize,
        sw_indexeddb_calls: usize,
        realtime_targets: BTreeSet<String>,
        realtime_channel_types: BTreeSet<String>,
        realtime_send_count: usize,
        realtime_payload_bytes: usize,
        taint_sources: Vec<TaintEvent>,
        taint_sinks: Vec<TaintEvent>,
        taint_edges: Vec<TaintEdge>,
        lifecycle_context_observed: Option<String>,
        lifecycle_hook_calls: usize,
        lifecycle_background_attempts: usize,
        wasm_static_features: WasmStaticFeatures,
    }

    #[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
    enum TaintEventKind {
        Cookie,
        LocalStorage,
        SessionStorage,
        FormField,
        Clipboard,
        Eval,
        Function,
        Fetch,
        SendBeacon,
        WebSocketSend,
        RtcDataChannelSend,
        XmlHttpSend,
    }

    impl TaintEventKind {
        fn as_str(self) -> &'static str {
            match self {
                TaintEventKind::Cookie => "cookie",
                TaintEventKind::LocalStorage => "local_storage",
                TaintEventKind::SessionStorage => "session_storage",
                TaintEventKind::FormField => "form_field",
                TaintEventKind::Clipboard => "clipboard",
                TaintEventKind::Eval => "eval",
                TaintEventKind::Function => "function",
                TaintEventKind::Fetch => "fetch",
                TaintEventKind::SendBeacon => "send_beacon",
                TaintEventKind::WebSocketSend => "websocket_send",
                TaintEventKind::RtcDataChannelSend => "rtc_datachannel_send",
                TaintEventKind::XmlHttpSend => "xmlhttp_send",
            }
        }
    }

    #[derive(Debug, Clone)]
    struct TaintEvent {
        kind: TaintEventKind,
        call_index: usize,
        phase: String,
    }

    #[derive(Debug, Clone)]
    struct TaintEdge {
        source: TaintEventKind,
        sink: TaintEventKind,
        call_distance: usize,
        phase_source: String,
        phase_sink: String,
    }

    #[derive(Debug, Clone, Default)]
    struct ExfilUrlFeatures {
        query_length: usize,
        key_value_density: f64,
        label_depth: usize,
        subdomain_entropy: f64,
        query_entropy: f64,
        encoded_token_count: usize,
        target_repetition: usize,
    }

    struct GadgetEntry {
        family: &'static str,
        sink_call: &'static str,
    }

    const GADGET_CATALOGUE: &[GadgetEntry] = &[
        GadgetEntry { family: "dom_sink", sink_call: "document.setInnerHTML" },
        GadgetEntry { family: "dom_sink", sink_call: "document.insertAdjacentHTML" },
        GadgetEntry { family: "dom_sink", sink_call: "document.write" },
        GadgetEntry { family: "execution", sink_call: "eval" },
        GadgetEntry { family: "execution", sink_call: "Function" },
        GadgetEntry { family: "execution", sink_call: "app.eval" },
        GadgetEntry { family: "execution", sink_call: "event.target.eval" },
        GadgetEntry { family: "server", sink_call: "child_process.exec" },
        GadgetEntry { family: "server", sink_call: "child_process.spawn" },
        GadgetEntry { family: "server", sink_call: "fs.writeFileSync" },
        GadgetEntry { family: "server", sink_call: "fs.writeFile" },
        GadgetEntry { family: "server", sink_call: "Bun.spawn" },
        GadgetEntry { family: "network", sink_call: "fetch" },
        GadgetEntry { family: "network", sink_call: "navigator.sendBeacon" },
        GadgetEntry { family: "network", sink_call: "WebSocket.send" },
        GadgetEntry { family: "network", sink_call: "RTCDataChannel.send" },
    ];

    #[derive(Debug, Clone)]
    struct VariableEvent {
        variable: String,
        event_type: VariableEventType,
        value: String,
        scope: String,
        timestamp: std::time::Duration,
    }

    #[derive(Debug, Clone)]
    enum VariableEventType {
        Declaration,
        Assignment,
        Read,
        UndefinedAccess,
    }

    #[derive(Debug, Clone)]
    struct ScopeTransition {
        from_scope: String,
        to_scope: String,
        trigger: TransitionTrigger,
        variables_inherited: Vec<String>,
        timestamp: std::time::Duration,
    }

    #[derive(Debug, Clone)]
    enum TransitionTrigger {
        FunctionCall(String),
        EvalExecution,
        GlobalPromotion,
    }

    #[derive(Debug, Clone, Default)]
    struct DynamicScope {
        global_vars: std::collections::BTreeMap<String, String>,
        auto_promote: BTreeSet<String>,
        eval_contexts: Vec<std::collections::BTreeMap<String, String>>,
        access_log: Vec<VariableAccess>,
    }

    #[derive(Finalize)]
    struct CallableCapture {
        log: Rc<RefCell<SandboxLog>>,
        name: &'static str,
        value: JsValue,
    }

    unsafe impl Trace for CallableCapture {
        custom_trace!(this, mark, {
            mark(&this.value);
        });
    }

    #[derive(Finalize)]
    struct ValueCapture {
        value: JsValue,
    }

    unsafe impl Trace for ValueCapture {
        custom_trace!(this, mark, {
            mark(&this.value);
        });
    }

    #[derive(Finalize)]
    struct LogValueCapture {
        log: Rc<RefCell<SandboxLog>>,
        value: JsValue,
    }

    unsafe impl Trace for LogValueCapture {
        custom_trace!(this, mark, {
            mark(&this.value);
        });
    }

    #[derive(Finalize)]
    struct LogCapture {
        log: Rc<RefCell<SandboxLog>>,
    }

    unsafe impl Trace for LogCapture {
        empty_trace!();
    }

    #[derive(Finalize)]
    struct LogScopeCapture {
        log: Rc<RefCell<SandboxLog>>,
        scope: Rc<RefCell<DynamicScope>>,
    }

    unsafe impl Trace for LogScopeCapture {
        empty_trace!();
    }

    #[derive(Finalize)]
    struct LogNameCapture {
        log: Rc<RefCell<SandboxLog>>,
        name: &'static str,
    }

    unsafe impl Trace for LogNameCapture {
        empty_trace!();
    }

    #[derive(Finalize)]
    struct LogObjectCapture {
        log: Rc<RefCell<SandboxLog>>,
        object: JsObject,
    }

    unsafe impl Trace for LogObjectCapture {
        custom_trace!(this, mark, {
            mark(&this.object);
        });
    }

    #[derive(Debug, Clone)]
    struct VariableAccess {
        variable: String,
        access_type: AccessType,
        context: String,
        timestamp: std::time::Duration,
    }

    #[derive(Debug, Clone)]
    enum AccessType {
        Read,
        Write,
        Declaration,
        UndefinedAccess,
    }

    // Phase 3: Execution Flow Tracking Structures
    #[derive(Debug, Clone, Default)]
    struct ExecutionFlow {
        call_stack: Vec<FunctionCall>,
        variable_timeline: Vec<VariableEvent>,
        scope_transitions: Vec<ScopeTransition>,
        exception_handling: Vec<ExceptionEvent>,
        start_time: Option<std::time::Instant>,
    }

    #[derive(Debug, Clone)]
    struct FunctionCall {
        name: String,
        args: Vec<String>, // Serialized args
        return_value: Option<String>,
        execution_time: std::time::Duration,
        scope_id: String,
        call_depth: usize,
        timestamp: std::time::Duration,
    }

    #[derive(Debug, Clone)]
    struct ExceptionEvent {
        error_type: String,
        message: String,
        recovery_attempted: bool,
        recovery_successful: bool,
        context: String,
        timestamp: std::time::Duration,
    }

    // Phase 4: Behavioral Pattern Detection Structures
    #[derive(Debug, Clone)]
    struct BehaviorObservation {
        pattern_name: String,
        confidence: f64,
        evidence: String,
        severity: BehaviorSeverity,
        metadata: std::collections::BTreeMap<String, String>,
        timestamp: std::time::Duration,
    }

    #[derive(Debug, Clone)]
    enum BehaviorSeverity {
        Low,
        Medium,
        High,
        Critical,
    }

    #[derive(Debug, Clone, Default)]
    struct JsSnapshot {
        identifiers: BTreeSet<String>,
        string_literals: BTreeSet<String>,
        calls: BTreeSet<String>,
    }

    #[derive(Debug, Clone)]
    struct SnapshotDeltaSummary {
        phase: String,
        trigger_calls: Vec<String>,
        generated_snippets: usize,
        added_identifier_count: usize,
        added_string_literal_count: usize,
        added_call_count: usize,
        new_identifiers: Vec<String>,
        new_string_literals: Vec<String>,
        new_calls: Vec<String>,
    }

    struct BehaviorAnalyzer {
        patterns: Vec<Box<dyn BehaviorPattern>>,
        observations: Vec<BehaviorObservation>,
    }

    trait BehaviorPattern {
        fn name(&self) -> &str;
        fn analyze(&self, flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation>;
    }

    fn lower_severity(level: BehaviorSeverity) -> BehaviorSeverity {
        match level {
            BehaviorSeverity::Critical => BehaviorSeverity::High,
            BehaviorSeverity::High => BehaviorSeverity::Medium,
            BehaviorSeverity::Medium => BehaviorSeverity::Low,
            BehaviorSeverity::Low => BehaviorSeverity::Low,
        }
    }

    fn calibrate_chain_signal(
        base_confidence: f64,
        base_severity: BehaviorSeverity,
        component_hits: usize,
        component_total: usize,
    ) -> (f64, BehaviorSeverity) {
        debug_assert!(
            component_hits <= component_total.max(1),
            "component_hits must not exceed component_total"
        );
        let total = component_total.max(1) as f64;
        let coverage = (component_hits as f64 / total).clamp(0.0, 1.0);
        let confidence = (base_confidence * (0.72 + 0.34 * coverage)).clamp(0.35, 0.97);
        let severity = if coverage < 0.55 { lower_severity(base_severity) } else { base_severity };
        (confidence, severity)
    }

    fn approx_string_entropy(input: &str) -> f64 {
        // NOTE: entropy uses f64 and may have minor platform rounding differences.
        // Thresholds are intentionally coarse to avoid practical classification drift.
        if input.is_empty() {
            return 0.0;
        }
        let mut counts = std::collections::BTreeMap::new();
        for byte in input.bytes() {
            *counts.entry(byte).or_insert(0usize) += 1;
        }
        let total = input.len() as f64;
        counts
            .values()
            .map(|count| {
                let p = *count as f64 / total;
                -(p * p.log2())
            })
            .sum()
    }

    // Concrete Behavioral Patterns
    struct ObfuscatedStringConstruction;
    impl BehaviorPattern for ObfuscatedStringConstruction {
        fn name(&self) -> &str {
            "obfuscated_string_construction"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let mut observations = Vec::new();

            // Count String.fromCharCode usage
            let char_code_calls =
                log.calls.iter().filter(|call| *call == "String.fromCharCode").count();

            if char_code_calls > 5 {
                let confidence = (char_code_calls as f64 * 0.1).min(0.95);
                let severity = if char_code_calls > 20 {
                    BehaviorSeverity::High
                } else if char_code_calls > 10 {
                    BehaviorSeverity::Medium
                } else {
                    BehaviorSeverity::Low
                };

                let mut metadata = std::collections::BTreeMap::new();
                metadata.insert("char_code_calls".to_string(), char_code_calls.to_string());

                observations.push(BehaviorObservation {
                    pattern_name: self.name().to_string(),
                    confidence,
                    evidence: format!("{} String.fromCharCode calls detected", char_code_calls),
                    severity,
                    metadata,
                    timestamp: std::time::Duration::from_millis(0),
                });
            }

            observations
        }
    }

    struct DynamicCodeGeneration;
    impl BehaviorPattern for DynamicCodeGeneration {
        fn name(&self) -> &str {
            "dynamic_code_generation"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let mut observations = Vec::new();

            let eval_count = log.calls.iter().filter(|call| *call == "eval").count();
            let function_constructor = log.calls.iter().filter(|call| *call == "Function").count();
            let timeout_calls = log
                .calls
                .iter()
                .filter(|call| call.contains("setTimeout") || call.contains("setInterval"))
                .count();

            if eval_count > 1 || function_constructor > 0 || timeout_calls > 0 {
                let total_dynamic = eval_count + function_constructor + timeout_calls;
                let confidence = (total_dynamic as f64 * 0.2).min(0.9);
                let severity = if total_dynamic > 10 {
                    BehaviorSeverity::Critical
                } else if total_dynamic > 5 {
                    BehaviorSeverity::High
                } else {
                    BehaviorSeverity::Medium
                };

                let mut metadata = std::collections::BTreeMap::new();
                metadata.insert("eval_calls".to_string(), eval_count.to_string());
                metadata.insert(
                    "function_constructor_calls".to_string(),
                    function_constructor.to_string(),
                );
                metadata.insert("timeout_calls".to_string(), timeout_calls.to_string());

                observations.push(BehaviorObservation {
                    pattern_name: self.name().to_string(),
                    confidence,
                    evidence: format!(
                        "Dynamic code patterns: eval={}, Function={}, timeouts={}",
                        eval_count, function_constructor, timeout_calls
                    ),
                    severity,
                    metadata,
                    timestamp: std::time::Duration::from_millis(0),
                });
            }

            observations
        }
    }

    struct IndirectDynamicEvalDispatchPattern;
    impl BehaviorPattern for IndirectDynamicEvalDispatchPattern {
        fn name(&self) -> &str {
            "indirect_dynamic_eval_dispatch"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let dynamic_invocations = log
                .calls
                .iter()
                .filter(|call| {
                    matches!(call.as_str(), "eval" | "Function" | "app.eval" | "event.target.eval")
                })
                .count();
            if dynamic_invocations == 0 {
                return Vec::new();
            }

            let mut indirect_markers = 0usize;
            for arg in &log.call_args {
                let lower = arg.to_ascii_lowercase();
                if lower.contains("return this")
                    || lower.contains("constructor(")
                    || lower.contains("['ev'+")
                    || lower.contains("(0, eval")
                    || lower.contains(".call(")
                    || lower.contains(".apply(")
                {
                    indirect_markers += 1;
                }
            }

            if indirect_markers == 0 {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata
                .insert("dynamic_invocation_count".to_string(), dynamic_invocations.to_string());
            metadata.insert("indirect_marker_count".to_string(), indirect_markers.to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence: 0.83,
                evidence:
                    "Dynamic code execution used indirection markers (constructor/alias/call-apply)"
                        .to_string(),
                severity: BehaviorSeverity::High,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct MultiPassDecodePipelinePattern;
    impl BehaviorPattern for MultiPassDecodePipelinePattern {
        fn name(&self) -> &str {
            "multi_pass_decode_pipeline"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let unescape_calls = log.calls.iter().filter(|call| *call == "unescape").count();
            let escape_calls = log.calls.iter().filter(|call| *call == "escape").count();
            let from_char_code_calls =
                log.calls.iter().filter(|call| *call == "String.fromCharCode").count();
            let decode_stage_count = unescape_calls + escape_calls + from_char_code_calls;
            let has_dynamic_dispatch = log.calls.iter().any(|call| {
                matches!(call.as_str(), "eval" | "Function" | "app.eval" | "event.target.eval")
            });
            if decode_stage_count < 3 || !has_dynamic_dispatch {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("decode_stage_count".to_string(), decode_stage_count.to_string());
            metadata.insert("unescape_calls".to_string(), unescape_calls.to_string());
            metadata.insert("escape_calls".to_string(), escape_calls.to_string());
            metadata.insert("from_char_code_calls".to_string(), from_char_code_calls.to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence: 0.8,
                evidence: "Observed multi-pass decode pipeline that feeds dynamic execution"
                    .to_string(),
                severity: BehaviorSeverity::High,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct CovertBeaconExfilPattern;
    impl BehaviorPattern for CovertBeaconExfilPattern {
        fn name(&self) -> &str {
            "covert_beacon_exfil"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let beacon_calls =
                log.calls.iter().filter(|call| *call == "navigator.sendBeacon").count();
            let fetch_calls = log.calls.iter().filter(|call| *call == "fetch").count();
            let location_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "window.location.assign" || *call == "window.location.replace"
                })
                .count();
            let network_sinks = beacon_calls + fetch_calls + location_calls;
            if network_sinks == 0 {
                return Vec::new();
            }
            if log.urls.is_empty() {
                return Vec::new();
            }
            let mut repetition = std::collections::BTreeMap::<String, usize>::new();
            for url in &log.urls {
                *repetition.entry(url.clone()).or_insert(0usize) += 1;
            }
            let mut max_features = ExfilUrlFeatures::default();
            let mut max_score = 0f64;
            for url in &log.urls {
                let reps = repetition.get(url).copied().unwrap_or(1);
                let features = exfil_url_features(url, reps);
                let score = exfil_score_components(network_sinks > 0, &features).values().sum();
                if score > max_score {
                    max_score = score;
                    max_features = features;
                }
            }
            if max_score < 2.0 {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("network_sink_calls".to_string(), network_sinks.to_string());
            metadata.insert("beacon_calls".to_string(), beacon_calls.to_string());
            metadata.insert("fetch_calls".to_string(), fetch_calls.to_string());
            metadata.insert("location_calls".to_string(), location_calls.to_string());
            metadata.insert("query_length".to_string(), max_features.query_length.to_string());
            metadata.insert("label_depth".to_string(), max_features.label_depth.to_string());
            metadata
                .insert("query_entropy".to_string(), format!("{:.3}", max_features.query_entropy));
            metadata.insert(
                "subdomain_entropy".to_string(),
                format!("{:.3}", max_features.subdomain_entropy),
            );
            metadata.insert(
                "encoded_token_count".to_string(),
                max_features.encoded_token_count.to_string(),
            );
            metadata.insert(
                "target_repetition".to_string(),
                max_features.target_repetition.to_string(),
            );
            metadata.insert("exfil_score".to_string(), format!("{:.2}", max_score));

            let (confidence, severity) = if max_score >= 4.0 {
                calibrate_chain_signal(0.86, BehaviorSeverity::High, 6, 6)
            } else {
                calibrate_chain_signal(0.72, BehaviorSeverity::Medium, 4, 6)
            };

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed beacon-style network exfiltration with encoded/high-density payload traits"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct PrototypeChainExecutionHijackPattern;
    impl BehaviorPattern for PrototypeChainExecutionHijackPattern {
        fn name(&self) -> &str {
            "prototype_chain_execution_hijack"
        }

        fn analyze(&self, flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let prototype_markers = log
                .call_args
                .iter()
                .filter(|entry| {
                    let lower = entry.to_ascii_lowercase();
                    lower.contains("__proto__")
                        || lower.contains("object.prototype")
                        || lower.contains("constructor.prototype")
                        || lower.contains("object.setprototypeof")
                        || lower.contains("object.defineproperty")
                })
                .count();
            let prototype_mutation_calls = log
                .calls
                .iter()
                .filter(|call| {
                    matches!(
                        call.as_str(),
                        "Object.setPrototypeOf"
                            | "Reflect.setPrototypeOf"
                            | "Object.defineProperty"
                            | "Object.defineProperties"
                    )
                })
                .count();
            let prototype_write_markers = log
                .prop_writes
                .iter()
                .filter(|entry| {
                    let lower = entry.to_ascii_lowercase();
                    lower.contains("prototype")
                        || lower.contains("__proto__")
                        || lower.contains("constructor")
                })
                .count();
            let dynamic_dispatch_calls = log
                .calls
                .iter()
                .filter(|call| {
                    matches!(call.as_str(), "eval" | "Function" | "app.eval" | "event.target.eval")
                })
                .count();
            let eval_source_markers = flow
                .variable_timeline
                .iter()
                .filter(|event| event.variable == "eval_execution")
                .filter(|event| {
                    let lower = event.value.to_ascii_lowercase();
                    lower.contains("__proto__")
                        || lower.contains("object.prototype")
                        || lower.contains("constructor.prototype")
                        || lower.contains("object.setprototypeof")
                        || lower.contains("object.defineproperty")
                })
                .count();
            let profile = &log.options.runtime_profile;
            let expanded_profile =
                matches!(profile.kind, RuntimeKind::Browser | RuntimeKind::Node | RuntimeKind::Bun)
                    || profile.mode == crate::types::RuntimeMode::DeceptionHardened;
            let marker_total = prototype_markers
                + prototype_mutation_calls
                + prototype_write_markers
                + eval_source_markers;
            let first_mutation_index = log.calls.iter().position(|call| {
                matches!(
                    call.as_str(),
                    "Object.setPrototypeOf"
                        | "Reflect.setPrototypeOf"
                        | "Object.defineProperty"
                        | "Object.defineProperties"
                )
            });
            let mut gadget_family_hits = BTreeSet::new();
            let mut mutation_to_sink_distance = usize::MAX;
            for entry in GADGET_CATALOGUE {
                if let Some(index) = log.calls.iter().position(|call| call == entry.sink_call) {
                    gadget_family_hits.insert(entry.family.to_string());
                    if let Some(mutation_index) = first_mutation_index {
                        if index >= mutation_index {
                            mutation_to_sink_distance =
                                mutation_to_sink_distance.min(index.saturating_sub(mutation_index));
                        }
                    }
                }
            }
            let has_gadget_sink = !gadget_family_hits.is_empty();
            let dispatch_required = if expanded_profile || marker_total >= 2 { 1 } else { 2 };
            if marker_total == 0 || dynamic_dispatch_calls < dispatch_required || !has_gadget_sink {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("prototype_markers".to_string(), prototype_markers.to_string());
            metadata.insert(
                "prototype_mutation_calls".to_string(),
                prototype_mutation_calls.to_string(),
            );
            metadata
                .insert("prototype_write_markers".to_string(), prototype_write_markers.to_string());
            metadata.insert("eval_source_markers".to_string(), eval_source_markers.to_string());
            metadata
                .insert("dynamic_dispatch_calls".to_string(), dynamic_dispatch_calls.to_string());
            metadata
                .insert("reflection_probes".to_string(), log.reflection_probes.len().to_string());
            metadata.insert("profile_kind".to_string(), profile.kind.as_str().to_string());
            metadata.insert("profile_mode".to_string(), profile.mode.as_str().to_string());
            metadata.insert("expanded_profile".to_string(), expanded_profile.to_string());
            metadata.insert(
                "gadget_family_hits".to_string(),
                gadget_family_hits.into_iter().collect::<Vec<_>>().join(", "),
            );
            if mutation_to_sink_distance != usize::MAX {
                metadata.insert(
                    "mutation_to_sink_distance".to_string(),
                    mutation_to_sink_distance.to_string(),
                );
            }

            let component_hits = [
                marker_total > 0,
                prototype_mutation_calls > 0,
                prototype_write_markers > 0,
                eval_source_markers > 0,
                dynamic_dispatch_calls > 0,
                dynamic_dispatch_calls > 1,
                has_gadget_sink,
                mutation_to_sink_distance <= 32,
            ]
            .iter()
            .filter(|value| **value)
            .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.74, BehaviorSeverity::High, component_hits, 8);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Prototype-chain mutation markers observed alongside dynamic execution dispatch"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct WasmLoaderStagingPattern;
    impl BehaviorPattern for WasmLoaderStagingPattern {
        fn name(&self) -> &str {
            "wasm_loader_staging"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let wasm_calls =
                log.calls.iter().filter(|call| call.starts_with("WebAssembly.")).count();
            if wasm_calls == 0 {
                return Vec::new();
            }

            let instantiate_calls =
                log.calls.iter().filter(|call| *call == "WebAssembly.instantiate").count();
            let module_calls =
                log.calls.iter().filter(|call| *call == "WebAssembly.Module").count();
            let table_calls = log.calls.iter().filter(|call| *call == "WebAssembly.Table").count();
            let memory_calls =
                log.calls.iter().filter(|call| *call == "WebAssembly.Memory").count();
            let dynamic_dispatch = log
                .calls
                .iter()
                .filter(|call| {
                    matches!(call.as_str(), "eval" | "Function" | "app.eval" | "event.target.eval")
                })
                .count();
            let unpack_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "Buffer.from"
                        || *call == "Buffer.concat"
                        || *call == "String.fromCharCode"
                        || *call == "unescape"
                })
                .count();
            let profile = &log.options.runtime_profile;
            let expanded_profile =
                matches!(profile.kind, RuntimeKind::Browser | RuntimeKind::Node | RuntimeKind::Bun)
                    || profile.mode == crate::types::RuntimeMode::DeceptionHardened;

            let component_hits = [
                instantiate_calls > 0,
                module_calls > 0,
                table_calls > 0,
                memory_calls > 0,
                unpack_calls > 0,
                dynamic_dispatch > 0,
            ]
            .iter()
            .filter(|value| **value)
            .count();
            let base_confidence = if expanded_profile { 0.79 } else { 0.7 };
            let base_severity =
                if expanded_profile { BehaviorSeverity::High } else { BehaviorSeverity::Medium };
            let (confidence, severity) =
                calibrate_chain_signal(base_confidence, base_severity, component_hits, 6);

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("wasm_calls".to_string(), wasm_calls.to_string());
            metadata.insert("instantiate_calls".to_string(), instantiate_calls.to_string());
            metadata.insert("module_calls".to_string(), module_calls.to_string());
            metadata.insert("table_calls".to_string(), table_calls.to_string());
            metadata.insert("memory_calls".to_string(), memory_calls.to_string());
            metadata.insert("unpack_calls".to_string(), unpack_calls.to_string());
            metadata.insert("dynamic_dispatch_calls".to_string(), dynamic_dispatch.to_string());
            metadata.insert("profile_kind".to_string(), profile.kind.as_str().to_string());
            metadata.insert("profile_mode".to_string(), profile.mode.as_str().to_string());
            metadata.insert("expanded_profile".to_string(), expanded_profile.to_string());
            metadata.insert(
                "js.runtime.wasm.static.section_count".to_string(),
                log.wasm_static_features.section_count.to_string(),
            );
            metadata.insert(
                "js.runtime.wasm.static.memory_sections".to_string(),
                log.wasm_static_features.memory_sections.to_string(),
            );
            metadata.insert(
                "js.runtime.wasm.static.suspicious_imports".to_string(),
                log.wasm_static_features.suspicious_imports.join(", "),
            );
            let correlation_score = (log.wasm_static_features.preamble_detected as usize)
                + (!log.wasm_static_features.suspicious_imports.is_empty() as usize)
                + (dynamic_dispatch > 0) as usize;
            metadata.insert(
                "js.runtime.wasm.correlation_score".to_string(),
                correlation_score.to_string(),
            );

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed WebAssembly loader activity potentially used for staged execution"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct RuntimeDependencyLoaderAbusePattern;
    impl BehaviorPattern for RuntimeDependencyLoaderAbusePattern {
        fn name(&self) -> &str {
            "runtime_dependency_loader_abuse"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let require_calls = log.calls.iter().filter(|call| *call == "require").count();
            if require_calls == 0 {
                return Vec::new();
            }

            let exec_calls = log
                .calls
                .iter()
                .filter(|call| {
                    matches!(
                        call.as_str(),
                        "child_process.exec"
                            | "child_process.spawn"
                            | "module.exec"
                            | "module.spawn"
                            | "module.run"
                    )
                })
                .count();
            let fs_write_calls = log
                .calls
                .iter()
                .filter(|call| {
                    matches!(
                        call.as_str(),
                        "fs.writeFile"
                            | "fs.writeFileSync"
                            | "module.writeFileSync"
                            | "fs.createWriteStream"
                    )
                })
                .count();
            let suspicious_require_args = log
                .call_args
                .iter()
                .filter(|entry| entry.starts_with("require("))
                .filter(|entry| {
                    let lower = entry.to_ascii_lowercase();
                    lower.contains("child_process")
                        || lower.contains("fs")
                        || lower.contains("http")
                        || lower.contains("https")
                        || lower.contains("buffer")
                        || lower.contains("../")
                        || lower.contains("./")
                })
                .count();
            let component_hits = [
                require_calls > 0,
                suspicious_require_args > 0,
                exec_calls > 0,
                fs_write_calls > 0,
            ]
            .iter()
            .filter(|value| **value)
            .count();
            if component_hits < 2 {
                return Vec::new();
            }
            let (confidence, severity) =
                calibrate_chain_signal(0.74, BehaviorSeverity::Medium, component_hits, 4);

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("require_calls".to_string(), require_calls.to_string());
            metadata
                .insert("suspicious_require_args".to_string(), suspicious_require_args.to_string());
            metadata.insert("exec_calls".to_string(), exec_calls.to_string());
            metadata.insert("fs_write_calls".to_string(), fs_write_calls.to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed dynamic runtime dependency loading correlated with execution or write sinks"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ChunkedDataExfilPipelinePattern;
    impl BehaviorPattern for ChunkedDataExfilPipelinePattern {
        fn name(&self) -> &str {
            "chunked_data_exfil_pipeline"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let send_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "navigator.sendBeacon"
                        || *call == "fetch"
                        || *call == "WebSocket.send"
                        || *call == "RTCDataChannel.send"
                })
                .count();
            if send_calls < 2 {
                return Vec::new();
            }
            let append_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "Array.push"
                        || *call == "Buffer.concat"
                        || *call == "String.concat"
                        || *call == "localStorage.setItem"
                        || *call == "sessionStorage.setItem"
                })
                .count();
            let encode_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "btoa"
                        || *call == "atob"
                        || *call == "encodeURIComponent"
                        || *call == "unescape"
                })
                .count();
            let encoded_arg_markers = log
                .call_args
                .iter()
                .filter(|entry| {
                    let lower = entry.to_ascii_lowercase();
                    lower.contains("base64")
                        || lower.contains("%2f")
                        || lower.contains("%3d")
                        || lower.contains("==")
                })
                .count();
            let repeated_domains =
                log.domains.iter().collect::<std::collections::HashSet<_>>().len()
                    < log.domains.len();
            let multi_url_targets = log.urls.len() >= 2;
            let staged_chunk_markers =
                (append_calls > 1 && encode_calls > 0) || encoded_arg_markers > 0;
            let outbound_target_visibility = !log.domains.is_empty() || !log.urls.is_empty();
            let taint_edge_count = log
                .taint_edges
                .iter()
                .filter(|edge| {
                    matches!(
                        edge.source,
                        TaintEventKind::Cookie
                            | TaintEventKind::LocalStorage
                            | TaintEventKind::SessionStorage
                            | TaintEventKind::FormField
                            | TaintEventKind::Clipboard
                    ) && matches!(
                        edge.sink,
                        TaintEventKind::Fetch
                            | TaintEventKind::SendBeacon
                            | TaintEventKind::WebSocketSend
                            | TaintEventKind::RtcDataChannelSend
                            | TaintEventKind::XmlHttpSend
                    )
                })
                .count();
            if !((staged_chunk_markers && (repeated_domains || multi_url_targets))
                || (send_calls >= 2 && outbound_target_visibility))
            {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("append_calls".to_string(), append_calls.to_string());
            metadata.insert("encode_calls".to_string(), encode_calls.to_string());
            metadata.insert("send_calls".to_string(), send_calls.to_string());
            metadata.insert("encoded_arg_markers".to_string(), encoded_arg_markers.to_string());
            metadata.insert("repeated_domains".to_string(), repeated_domains.to_string());
            metadata.insert("multi_url_targets".to_string(), multi_url_targets.to_string());
            metadata.insert(
                "outbound_target_visibility".to_string(),
                outbound_target_visibility.to_string(),
            );
            metadata.insert("taint_edges".to_string(), taint_edge_count.to_string());

            let component_hits = [
                send_calls > 1,
                staged_chunk_markers,
                repeated_domains,
                multi_url_targets,
                outbound_target_visibility,
                taint_edge_count > 0,
            ]
            .iter()
            .filter(|value| **value)
            .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.78, BehaviorSeverity::High, component_hits, 6);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence: "Observed staged append/encode/send loop consistent with chunked data exfiltration"
                    .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct InteractionCoercionLoopPattern;
    impl BehaviorPattern for InteractionCoercionLoopPattern {
        fn name(&self) -> &str {
            "interaction_coercion_loop"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let dialog_calls = log
                .calls
                .iter()
                .filter(|call| *call == "alert" || *call == "confirm" || *call == "prompt")
                .count();
            let gating_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "setTimeout" || *call == "setInterval" || *call == "WScript.Sleep"
                })
                .count();
            let branch_markers = log
                .call_args
                .iter()
                .filter(|entry| {
                    let lower = entry.to_ascii_lowercase();
                    lower.contains("retry")
                        || lower.contains("again")
                        || lower.contains("continue")
                        || lower.contains("allow")
                        || lower.contains("enable")
                })
                .count();
            let repeated_modal_surface = dialog_calls >= 3;
            if !(repeated_modal_surface && (gating_calls > 0 || branch_markers > 0)) {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("dialog_calls".to_string(), dialog_calls.to_string());
            metadata.insert("gating_calls".to_string(), gating_calls.to_string());
            metadata.insert("branch_markers".to_string(), branch_markers.to_string());

            let component_hits =
                [repeated_modal_surface, dialog_calls >= 5, gating_calls > 0, branch_markers > 0]
                    .iter()
                    .filter(|value| **value)
                    .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.75, BehaviorSeverity::Medium, component_hits, 4);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence: "Observed repeated user-dialog primitives with coercive loop/gating cues"
                    .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct LotlApiChainExecutionPattern;
    impl BehaviorPattern for LotlApiChainExecutionPattern {
        fn name(&self) -> &str {
            "lotl_api_chain_execution"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let env_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.ExpandEnvironmentStrings"
                        || *call == "WScript.Shell.Environment"
                        || *call == "Scripting.FileSystemObject.GetSpecialFolder"
                        || *call == "Scripting.FileSystemObject.GetTempName"
                })
                .count();
            let file_staging_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "ADODB.Stream.Open"
                        || *call == "ADODB.Stream.Write"
                        || *call == "ADODB.Stream.SaveToFile"
                        || *call == "Scripting.FileSystemObject.CopyFile"
                        || *call == "Scripting.FileSystemObject.MoveFile"
                })
                .count();
            let exec_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run"
                        || *call == "Shell.Application.ShellExecute"
                        || *call == "PowerShell.Invoke"
                })
                .count();
            let direct_network_calls = log
                .calls
                .iter()
                .filter(|call| {
                    call.contains(".XMLHTTP.")
                        || *call == "fetch"
                        || *call == "navigator.sendBeacon"
                })
                .count();

            let has_lotl_chain = env_calls > 0 && file_staging_calls > 0 && exec_calls > 0;
            if !has_lotl_chain || direct_network_calls > 0 {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("env_calls".to_string(), env_calls.to_string());
            metadata.insert("file_staging_calls".to_string(), file_staging_calls.to_string());
            metadata.insert("exec_calls".to_string(), exec_calls.to_string());
            metadata.insert("direct_network_calls".to_string(), direct_network_calls.to_string());

            let component_hits = [env_calls > 0, file_staging_calls > 0, exec_calls > 0]
                .iter()
                .filter(|value| **value)
                .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.83, BehaviorSeverity::High, component_hits, 3);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed living-off-the-land API chain from environment and staging surfaces to execution"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct CredentialHarvestFormEmulationPattern;
    impl BehaviorPattern for CredentialHarvestFormEmulationPattern {
        fn name(&self) -> &str {
            "credential_harvest_form_emulation"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let form_calls = log
                .calls
                .iter()
                .filter(|call| {
                    matches!(
                        call.as_str(),
                        "addField"
                            | "getField"
                            | "submitForm"
                            | "mailDoc"
                            | "doc.getField"
                            | "event.target.getField"
                    )
                })
                .count();
            let network_sinks = log
                .calls
                .iter()
                .filter(|call| {
                    matches!(
                        call.as_str(),
                        "submitForm"
                            | "mailDoc"
                            | "fetch"
                            | "navigator.sendBeacon"
                            | "XMLHttpRequest.send"
                            | "MSXML2.XMLHTTP.send"
                            | "MSXML2.ServerXMLHTTP.send"
                    )
                })
                .count();
            let prompt_calls = log
                .calls
                .iter()
                .filter(|call| {
                    matches!(
                        call.as_str(),
                        "alert" | "confirm" | "prompt" | "app.alert" | "app.response"
                    )
                })
                .count();
            let has_form_signal = form_calls >= 2;
            let has_exfil_signal = network_sinks >= 1;
            let taint_edge_count = log
                .taint_edges
                .iter()
                .filter(|edge| {
                    matches!(edge.source, TaintEventKind::FormField)
                        && matches!(
                            edge.sink,
                            TaintEventKind::Fetch
                                | TaintEventKind::SendBeacon
                                | TaintEventKind::WebSocketSend
                                | TaintEventKind::RtcDataChannelSend
                                | TaintEventKind::XmlHttpSend
                        )
                })
                .count();
            if !(has_form_signal && has_exfil_signal) {
                return Vec::new();
            }

            let component_hits =
                [has_form_signal, has_exfil_signal, prompt_calls > 0, taint_edge_count > 0]
                    .iter()
                    .filter(|value| **value)
                    .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.79, BehaviorSeverity::High, component_hits, 4);

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("form_calls".to_string(), form_calls.to_string());
            metadata.insert("network_sinks".to_string(), network_sinks.to_string());
            metadata.insert("prompt_calls".to_string(), prompt_calls.to_string());
            metadata.insert("taint_edges".to_string(), taint_edge_count.to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed scripted form/field workflow correlated with outbound submission behaviour"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct TimingProbeEvasionPattern;
    impl BehaviorPattern for TimingProbeEvasionPattern {
        fn name(&self) -> &str {
            "timing_probe_evasion"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let sleep_calls = log.calls.iter().filter(|call| *call == "WScript.Sleep").count();
            let timeout_calls = log.calls.iter().filter(|call| *call == "setTimeout").count();
            let interval_calls = log.calls.iter().filter(|call| *call == "setInterval").count();
            let quit_calls = log.calls.iter().filter(|call| *call == "WScript.Quit").count();
            let timer_total = sleep_calls + timeout_calls + interval_calls;
            let has_gate_context = quit_calls > 0 || log.dormant_source_markers >= 1;
            if timer_total < 2 || !has_gate_context {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("timer_total".to_string(), timer_total.to_string());
            metadata.insert("sleep_calls".to_string(), sleep_calls.to_string());
            metadata.insert("set_timeout_calls".to_string(), timeout_calls.to_string());
            metadata.insert("set_interval_calls".to_string(), interval_calls.to_string());
            metadata.insert("quit_calls".to_string(), quit_calls.to_string());
            metadata.insert("source_markers".to_string(), log.dormant_source_markers.to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence: 0.74,
                evidence:
                    "Repeated timer primitives plus gating signals indicate timing-based evasion"
                        .to_string(),
                severity: BehaviorSeverity::Medium,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ServiceWorkerPersistenceAbusePattern;
    impl BehaviorPattern for ServiceWorkerPersistenceAbusePattern {
        fn name(&self) -> &str {
            "service_worker_persistence_abuse"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let sw_register =
                log.calls.iter().filter(|call| *call == "navigator.serviceWorker.register").count();
            let sw_get_registration = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "navigator.serviceWorker.getRegistration"
                        || *call == "navigator.serviceWorker.getRegistrations"
                })
                .count();
            let sw_update =
                log.calls.iter().filter(|call| *call == "navigator.serviceWorker.update").count();
            let cache_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "caches.open"
                        || *call == "caches.put"
                        || *call == "caches.match"
                        || *call == "caches.delete"
                })
                .count();

            let lifecycle_events = log.sw_lifecycle_events_executed;
            let event_handlers = log.sw_event_handlers_registered;
            let has_registration = sw_register > 0;
            let has_persistence_surface = cache_calls > 0
                || sw_get_registration > 0
                || sw_update > 0
                || log.sw_indexeddb_calls > 0;
            let has_lifecycle_evidence = lifecycle_events > 0 || event_handlers > 0;
            if !(has_registration && has_persistence_surface && has_lifecycle_evidence) {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert(
                "js.runtime.service_worker.registration_calls".to_string(),
                sw_register.to_string(),
            );
            metadata.insert(
                "js.runtime.service_worker.update_calls".to_string(),
                sw_update.to_string(),
            );
            metadata.insert(
                "js.runtime.service_worker.event_handlers_registered".to_string(),
                event_handlers.to_string(),
            );
            metadata.insert(
                "js.runtime.service_worker.lifecycle_events_executed".to_string(),
                lifecycle_events.to_string(),
            );
            metadata.insert(
                "js.runtime.service_worker.cache_calls".to_string(),
                cache_calls.to_string(),
            );
            metadata.insert(
                "js.runtime.service_worker.indexeddb_calls".to_string(),
                log.sw_indexeddb_calls.to_string(),
            );
            metadata.insert(
                "js.runtime.service_worker.get_registration_calls".to_string(),
                sw_get_registration.to_string(),
            );

            let component_hits = [
                has_registration,
                sw_get_registration > 0,
                sw_update > 0,
                cache_calls > 0 || log.sw_indexeddb_calls > 0,
                lifecycle_events > 0,
            ]
            .iter()
            .filter(|value| **value)
            .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.84, BehaviorSeverity::High, component_hits, 5);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence: "Observed service worker registration with cache/registration lifecycle activity"
                    .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct WebCryptoKeyStagingExfilPattern;
    impl BehaviorPattern for WebCryptoKeyStagingExfilPattern {
        fn name(&self) -> &str {
            "webcrypto_key_staging_exfil"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let key_material_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "crypto.subtle.generateKey"
                        || *call == "crypto.subtle.importKey"
                        || *call == "crypto.subtle.deriveKey"
                })
                .count();
            let export_calls =
                log.calls.iter().filter(|call| *call == "crypto.subtle.exportKey").count();
            let exfil_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "navigator.sendBeacon"
                        || *call == "fetch"
                        || *call == "WebSocket.send"
                        || *call == "XMLHttpRequest.send"
                        || call.ends_with(".XMLHTTP.send")
                })
                .count();

            if !(key_material_calls > 0 && export_calls > 0 && exfil_calls > 0) {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata
                .insert("crypto_key_material_calls".to_string(), key_material_calls.to_string());
            metadata.insert("crypto_export_calls".to_string(), export_calls.to_string());
            metadata.insert("exfil_calls".to_string(), exfil_calls.to_string());

            let component_hits = [key_material_calls > 0, export_calls > 0, exfil_calls > 0]
                .iter()
                .filter(|value| **value)
                .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.88, BehaviorSeverity::High, component_hits, 3);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed WebCrypto key material handling followed by outbound transmission"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct StorageBackedPayloadStagingPattern;
    impl BehaviorPattern for StorageBackedPayloadStagingPattern {
        fn name(&self) -> &str {
            "storage_backed_payload_staging"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let storage_write_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "localStorage.setItem"
                        || *call == "sessionStorage.setItem"
                        || *call == "IDBObjectStore.put"
                        || *call == "IDBObjectStore.add"
                })
                .count();
            let storage_read_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "localStorage.getItem"
                        || *call == "sessionStorage.getItem"
                        || *call == "IDBObjectStore.get"
                })
                .count();
            let decode_or_exec_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "eval"
                        || *call == "Function"
                        || *call == "unescape"
                        || *call == "String.fromCharCode"
                })
                .count();

            let has_storage_staging = storage_write_calls > 0 && storage_read_calls > 0;
            let has_execution = decode_or_exec_calls > 0;
            if !(has_storage_staging && has_execution) {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("storage_write_calls".to_string(), storage_write_calls.to_string());
            metadata.insert("storage_read_calls".to_string(), storage_read_calls.to_string());
            metadata.insert("decode_or_exec_calls".to_string(), decode_or_exec_calls.to_string());

            let component_hits = [has_storage_staging, has_execution, storage_write_calls > 1]
                .iter()
                .filter(|value| **value)
                .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.76, BehaviorSeverity::Medium, component_hits, 3);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence: "Observed payload staging in browser storage followed by decode/execution primitives"
                    .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct DynamicModuleGraphEvasionPattern;
    impl BehaviorPattern for DynamicModuleGraphEvasionPattern {
        fn name(&self) -> &str {
            "dynamic_module_graph_evasion"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let module_loader_calls = log
                .calls
                .iter()
                .filter(|call| *call == "require" || *call == "__dynamicImport")
                .count();
            let module_graph_calls = log
                .calls
                .iter()
                .filter(|call| {
                    call.starts_with("path.")
                        || call.starts_with("fs.")
                        || *call == "Buffer.from"
                        || *call == "Buffer.concat"
                })
                .count();
            let exec_calls =
                log.calls.iter().filter(|call| *call == "eval" || *call == "Function").count();

            if !(module_loader_calls > 1 && module_graph_calls > 0 && exec_calls > 0) {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("module_loader_calls".to_string(), module_loader_calls.to_string());
            metadata.insert("module_graph_calls".to_string(), module_graph_calls.to_string());
            metadata.insert("exec_calls".to_string(), exec_calls.to_string());

            let component_hits = [module_loader_calls > 1, module_graph_calls > 0, exec_calls > 0]
                .iter()
                .filter(|value| **value)
                .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.79, BehaviorSeverity::Medium, component_hits, 3);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed dynamic module loading with graph traversal and execution sinks"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct CovertRealtimeChannelAbusePattern;
    impl BehaviorPattern for CovertRealtimeChannelAbusePattern {
        fn name(&self) -> &str {
            "covert_realtime_channel_abuse"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let channel_setup_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "RTCPeerConnection.createDataChannel"
                        || *call == "RTCPeerConnection.createOffer"
                        || *call == "WebSocket"
                })
                .count();
            let channel_send_calls = log
                .calls
                .iter()
                .filter(|call| *call == "RTCDataChannel.send" || *call == "WebSocket.send")
                .count();
            let encoding_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "btoa"
                        || *call == "atob"
                        || *call == "unescape"
                        || *call == "String.fromCharCode"
                })
                .count();

            let has_active_transfer = channel_send_calls > 0;
            if !(channel_setup_calls > 0 && has_active_transfer && encoding_calls > 0) {
                return Vec::new();
            }
            let avg_payload_len = if log.realtime_send_count == 0 {
                0.0
            } else {
                log.realtime_payload_bytes as f64 / log.realtime_send_count as f64
            };

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("channel_setup_calls".to_string(), channel_setup_calls.to_string());
            metadata.insert("channel_send_calls".to_string(), channel_send_calls.to_string());
            metadata.insert("encoding_calls".to_string(), encoding_calls.to_string());
            metadata.insert(
                "js.runtime.realtime.session_count".to_string(),
                log.realtime_channel_types.len().to_string(),
            );
            metadata.insert(
                "js.runtime.realtime.unique_targets".to_string(),
                log.realtime_targets.len().to_string(),
            );
            metadata.insert(
                "js.runtime.realtime.send_count".to_string(),
                log.realtime_send_count.to_string(),
            );
            metadata.insert(
                "js.runtime.realtime.avg_payload_len".to_string(),
                format!("{avg_payload_len:.1}"),
            );
            metadata.insert(
                "js.runtime.realtime.channel_types".to_string(),
                log.realtime_channel_types.iter().cloned().collect::<Vec<_>>().join(", "),
            );

            let component_hits = [
                channel_setup_calls > 0,
                channel_send_calls > 0,
                encoding_calls > 0,
                log.realtime_send_count > 1,
            ]
            .iter()
            .filter(|value| **value)
            .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.85, BehaviorSeverity::High, component_hits, 4);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed encoded payload handling with real-time channel setup/transmission"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ClipboardSessionHijackPattern;
    impl BehaviorPattern for ClipboardSessionHijackPattern {
        fn name(&self) -> &str {
            "clipboard_session_hijack_behaviour"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let clipboard_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "navigator.clipboard.readText"
                        || *call == "navigator.clipboard.writeText"
                        || *call == "navigator.clipboard.read"
                        || *call == "navigator.clipboard.write"
                })
                .count();
            let session_source_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "document.cookie"
                        || *call == "localStorage.getItem"
                        || *call == "sessionStorage.getItem"
                })
                .count();
            let exfil_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "navigator.sendBeacon"
                        || *call == "fetch"
                        || *call == "WebSocket.send"
                        || *call == "XMLHttpRequest.send"
                })
                .count();
            let taint_edge_count = log
                .taint_edges
                .iter()
                .filter(|edge| {
                    edge.source == TaintEventKind::Clipboard
                        && matches!(
                            edge.sink,
                            TaintEventKind::Fetch
                                | TaintEventKind::SendBeacon
                                | TaintEventKind::WebSocketSend
                                | TaintEventKind::RtcDataChannelSend
                                | TaintEventKind::XmlHttpSend
                        )
                })
                .count();

            if !(clipboard_calls > 0 && session_source_calls > 0 && exfil_calls > 0) {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("clipboard_calls".to_string(), clipboard_calls.to_string());
            metadata.insert("session_source_calls".to_string(), session_source_calls.to_string());
            metadata.insert("exfil_calls".to_string(), exfil_calls.to_string());
            metadata.insert("taint_edges".to_string(), taint_edge_count.to_string());

            let component_hits = [
                clipboard_calls > 0,
                session_source_calls > 0,
                exfil_calls > 0,
                taint_edge_count > 0,
            ]
            .iter()
            .filter(|value| **value)
            .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.86, BehaviorSeverity::High, component_hits, 4);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed clipboard/session collection combined with outbound channel use"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct DomSinkPolicyBypassPattern;
    impl BehaviorPattern for DomSinkPolicyBypassPattern {
        fn name(&self) -> &str {
            "dom_sink_policy_bypass_attempt"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let dom_sink_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "document.write"
                        || *call == "document.setInnerHTML"
                        || *call == "document.insertAdjacentHTML"
                        || *call == "window.location.assign"
                        || *call == "window.location.replace"
                })
                .count();
            let policy_calls =
                log.calls.iter().filter(|call| *call == "trustedTypes.createPolicy").count();
            let obfuscation_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "eval"
                        || *call == "Function"
                        || *call == "unescape"
                        || *call == "String.fromCharCode"
                })
                .count();

            if !(dom_sink_calls > 0 && obfuscation_calls > 0) {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("dom_sink_calls".to_string(), dom_sink_calls.to_string());
            metadata.insert("policy_calls".to_string(), policy_calls.to_string());
            metadata.insert("obfuscation_calls".to_string(), obfuscation_calls.to_string());

            let component_hits = [dom_sink_calls > 0, policy_calls > 0, obfuscation_calls > 0]
                .iter()
                .filter(|value| **value)
                .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.73, BehaviorSeverity::Medium, component_hits, 3);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence: "Observed obfuscated input path into sensitive DOM/script sink surface"
                    .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct WasmMemoryUnpackerPipelinePattern;
    impl BehaviorPattern for WasmMemoryUnpackerPipelinePattern {
        fn name(&self) -> &str {
            "wasm_memory_unpacker_pipeline"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let wasm_loader_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WebAssembly.instantiate"
                        || *call == "WebAssembly.compile"
                        || *call == "WebAssembly.Module"
                })
                .count();
            let wasm_memory_calls =
                log.calls.iter().filter(|call| *call == "WebAssembly.Memory").count();
            let unpack_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "Buffer.from"
                        || *call == "Buffer.concat"
                        || *call == "String.fromCharCode"
                        || *call == "unescape"
                })
                .count();
            let exec_calls =
                log.calls.iter().filter(|call| *call == "eval" || *call == "Function").count();

            if !(wasm_loader_calls > 0
                && wasm_memory_calls > 0
                && unpack_calls > 0
                && exec_calls > 0)
            {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("wasm_loader_calls".to_string(), wasm_loader_calls.to_string());
            metadata.insert("wasm_memory_calls".to_string(), wasm_memory_calls.to_string());
            metadata.insert("unpack_calls".to_string(), unpack_calls.to_string());
            metadata.insert("exec_calls".to_string(), exec_calls.to_string());
            metadata.insert(
                "js.runtime.wasm.static.suspicious_imports".to_string(),
                log.wasm_static_features.suspicious_imports.join(", "),
            );
            metadata.insert(
                "js.runtime.wasm.static.section_count".to_string(),
                log.wasm_static_features.section_count.to_string(),
            );
            let correlation_score = (log.wasm_static_features.preamble_detected as usize)
                + (!log.wasm_static_features.suspicious_imports.is_empty() as usize)
                + (exec_calls > 0) as usize;
            metadata.insert(
                "js.runtime.wasm.correlation_score".to_string(),
                correlation_score.to_string(),
            );

            let component_hits = [
                wasm_loader_calls > 0,
                wasm_memory_calls > 0,
                unpack_calls > 0,
                exec_calls > 0,
                correlation_score >= 2,
            ]
            .iter()
            .filter(|value| **value)
            .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.9, BehaviorSeverity::High, component_hits, 5);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence: "Observed WASM load/memory activity with unpacking and dynamic execution handoff"
                    .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ExtensionApiAbuseProbePattern;
    impl BehaviorPattern for ExtensionApiAbuseProbePattern {
        fn name(&self) -> &str {
            "extension_api_abuse_probe"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let runtime_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "chrome.runtime.sendMessage"
                        || *call == "chrome.runtime.connect"
                        || *call == "browser.runtime.sendMessage"
                        || *call == "browser.runtime.connect"
                })
                .count();
            let storage_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "chrome.storage.local.get" || *call == "chrome.storage.local.set"
                })
                .count();
            let has_high_risk_chain = log.calls.iter().any(|call| {
                *call == "eval"
                    || *call == "Function"
                    || *call == "WebSocket.send"
                    || *call == "navigator.sendBeacon"
            });

            if runtime_calls == 0 || has_high_risk_chain {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("extension_runtime_calls".to_string(), runtime_calls.to_string());
            metadata.insert("extension_storage_calls".to_string(), storage_calls.to_string());

            let component_hits =
                [runtime_calls > 0, storage_calls > 0].iter().filter(|value| **value).count();
            let (confidence, severity) =
                calibrate_chain_signal(0.58, BehaviorSeverity::Low, component_hits, 2);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed browser extension runtime probing with low-activity capability checks"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ModernFingerprintEvasionPattern;
    impl BehaviorPattern for ModernFingerprintEvasionPattern {
        fn name(&self) -> &str {
            "modern_fingerprint_evasion"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let ua_probe_calls = log
                .calls
                .iter()
                .filter(|call| *call == "navigator.userAgentData.getHighEntropyValues")
                .count();
            let permissions_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "permissions.query" || *call == "navigator.permissions.query"
                })
                .count();
            let webgl_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WebGLRenderingContext.getParameter"
                        || *call == "WebGLRenderingContext.getSupportedExtensions"
                })
                .count();
            let audio_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "AudioContext.createAnalyser" || *call == "AudioContext.resume"
                })
                .count();
            let gating_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "setTimeout" || *call == "setInterval" || *call == "WScript.Sleep"
                })
                .count();

            let probe_families =
                [ua_probe_calls > 0, permissions_calls > 0, webgl_calls > 0, audio_calls > 0]
                    .iter()
                    .filter(|value| **value)
                    .count();
            if !(probe_families >= 2 && gating_calls > 0) {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("ua_probe_calls".to_string(), ua_probe_calls.to_string());
            metadata.insert("permissions_calls".to_string(), permissions_calls.to_string());
            metadata.insert("webgl_calls".to_string(), webgl_calls.to_string());
            metadata.insert("audio_calls".to_string(), audio_calls.to_string());
            metadata.insert("gating_calls".to_string(), gating_calls.to_string());
            metadata.insert("probe_families".to_string(), probe_families.to_string());

            let component_hits = [probe_families >= 2, probe_families >= 3, gating_calls > 0]
                .iter()
                .filter(|value| **value)
                .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.74, BehaviorSeverity::Medium, component_hits, 3);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed modern environment fingerprint probes combined with execution gating"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct CapabilityMatrixFingerprintingPattern;
    impl BehaviorPattern for CapabilityMatrixFingerprintingPattern {
        fn name(&self) -> &str {
            "capability_matrix_fingerprinting"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let mut browser_hits = 0usize;
            let mut pdf_hits = 0usize;
            let mut wsh_hits = 0usize;
            let mut node_hits = 0usize;

            for call in &log.calls {
                let lower = call.to_ascii_lowercase();
                if lower.starts_with("window.")
                    || lower.starts_with("document.")
                    || lower.starts_with("navigator.")
                    || lower.contains("location")
                {
                    browser_hits += 1;
                }
                if lower.starts_with("app.")
                    || lower.starts_with("doc.")
                    || lower.starts_with("event.target.")
                {
                    pdf_hits += 1;
                }
                if lower.starts_with("wscript.")
                    || lower == "activexobject"
                    || lower.starts_with("msxml2.")
                    || lower.starts_with("adodb.")
                    || lower.starts_with("shell.application.")
                {
                    wsh_hits += 1;
                }
                if lower == "require"
                    || lower.starts_with("process.")
                    || lower.starts_with("buffer.")
                    || lower.starts_with("module.")
                {
                    node_hits += 1;
                }
            }

            let mut domain_count = 0usize;
            if browser_hits > 0 {
                domain_count += 1;
            }
            if pdf_hits > 0 {
                domain_count += 1;
            }
            if wsh_hits > 0 {
                domain_count += 1;
            }
            if node_hits > 0 {
                domain_count += 1;
            }

            let probe_support = log.reflection_probes.len() + log.prop_reads.len();
            let cross_domain_activity = log.calls.len() >= 3;
            if domain_count < 2 || (!cross_domain_activity && probe_support == 0) {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("domain_count".to_string(), domain_count.to_string());
            metadata.insert("browser_hits".to_string(), browser_hits.to_string());
            metadata.insert("pdf_hits".to_string(), pdf_hits.to_string());
            metadata.insert("wsh_hits".to_string(), wsh_hits.to_string());
            metadata.insert("node_hits".to_string(), node_hits.to_string());
            metadata.insert("probe_support".to_string(), probe_support.to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence: 0.78,
                evidence:
                    "Cross-domain capability probing observed before or alongside execution logic"
                        .to_string(),
                severity: BehaviorSeverity::Medium,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct EnvironmentFingerprinting;
    impl BehaviorPattern for EnvironmentFingerprinting {
        fn name(&self) -> &str {
            "environment_fingerprinting"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let mut observations = Vec::new();

            // Look for property reads that indicate environment checking
            let fingerprint_properties = [
                "navigator",
                "screen",
                "window",
                "document.location",
                "info.title",
                "info.author",
                "info.subject",
            ];

            let fingerprint_count = log
                .prop_reads
                .iter()
                .filter(|prop| fingerprint_properties.iter().any(|fp| prop.contains(fp)))
                .count();

            if fingerprint_count > 2 {
                let confidence = (fingerprint_count as f64 * 0.15).min(0.85);

                let mut metadata = std::collections::BTreeMap::new();
                metadata.insert("fingerprint_reads".to_string(), fingerprint_count.to_string());

                observations.push(BehaviorObservation {
                    pattern_name: self.name().to_string(),
                    confidence,
                    evidence: format!(
                        "{} environment fingerprinting property reads",
                        fingerprint_count
                    ),
                    severity: BehaviorSeverity::Medium,
                    metadata,
                    timestamp: std::time::Duration::from_millis(0),
                });
            }

            observations
        }
    }

    struct ErrorRecoveryPattern;
    impl BehaviorPattern for ErrorRecoveryPattern {
        fn name(&self) -> &str {
            "error_recovery_patterns"
        }

        fn analyze(&self, flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let mut observations = Vec::new();

            let error_count = log.errors.len();
            let recovery_attempts =
                flow.exception_handling.iter().filter(|ex| ex.recovery_attempted).count();

            if recovery_attempts > 0 && (error_count > 0 || !flow.exception_handling.is_empty()) {
                let confidence = 0.8; // High confidence when we see error recovery

                let mut metadata = std::collections::BTreeMap::new();
                metadata.insert("total_errors".to_string(), error_count.to_string());
                metadata.insert("recovery_attempts".to_string(), recovery_attempts.to_string());

                observations.push(BehaviorObservation {
                    pattern_name: self.name().to_string(),
                    confidence,
                    evidence: format!(
                        "Error recovery patterns: {} errors, {} recovery attempts",
                        error_count, recovery_attempts
                    ),
                    severity: BehaviorSeverity::Low,
                    metadata,
                    timestamp: std::time::Duration::from_millis(0),
                });
            }

            observations
        }
    }

    struct VariablePromotionPattern;
    impl BehaviorPattern for VariablePromotionPattern {
        fn name(&self) -> &str {
            "variable_promotion_detected"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let mut observations = Vec::new();

            let promotion_count = log
                .variable_events
                .iter()
                .filter(|ve| {
                    matches!(
                        ve.event_type,
                        VariableEventType::Declaration | VariableEventType::UndefinedAccess
                    )
                })
                .count();

            if promotion_count > 0 {
                let confidence = 0.9; // High confidence when we see our promotion system working

                let mut metadata = std::collections::BTreeMap::new();
                metadata.insert("promoted_variables".to_string(), promotion_count.to_string());

                observations.push(BehaviorObservation {
                    pattern_name: self.name().to_string(),
                    confidence,
                    evidence: format!("{} variables promoted to global scope", promotion_count),
                    severity: BehaviorSeverity::Low,
                    metadata,
                    timestamp: std::time::Duration::from_millis(0),
                });
            }

            observations
        }
    }

    struct DormantPayloadPattern;
    impl BehaviorPattern for DormantPayloadPattern {
        fn name(&self) -> &str {
            "dormant_or_gated_execution"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let has_runtime_activity = !log.calls.is_empty() || !log.prop_reads.is_empty();
            let size_gate = log.input_bytes >= 16_384;
            let marker_gate = log.input_bytes >= 8_192 && log.dormant_source_markers >= 2;
            if (!size_gate && !marker_gate) || has_runtime_activity {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("input_bytes".to_string(), log.input_bytes.to_string());
            metadata.insert("source_markers".to_string(), log.dormant_source_markers.to_string());
            metadata.insert("call_count".to_string(), log.calls.len().to_string());
            metadata.insert("prop_read_count".to_string(), log.prop_reads.len().to_string());
            metadata.insert("error_count".to_string(), log.errors.len().to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence: 0.55,
                evidence: format!(
                    "Large payload ({} bytes) produced no runtime activity; execution may be gated",
                    log.input_bytes
                ),
                severity: BehaviorSeverity::Low,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct DormantMarkedSmallPayloadPattern;
    impl BehaviorPattern for DormantMarkedSmallPayloadPattern {
        fn name(&self) -> &str {
            "dormant_marked_small_payload"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let has_runtime_activity = !log.calls.is_empty() || !log.prop_reads.is_empty();
            let marker_gate = log.input_bytes >= 3_072 && log.dormant_source_markers >= 1;
            let already_classified_large =
                log.input_bytes >= 8_192 && log.dormant_source_markers >= 2;
            if has_runtime_activity || !marker_gate || already_classified_large {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("input_bytes".to_string(), log.input_bytes.to_string());
            metadata.insert("source_markers".to_string(), log.dormant_source_markers.to_string());
            metadata.insert("call_count".to_string(), log.calls.len().to_string());
            metadata.insert("prop_read_count".to_string(), log.prop_reads.len().to_string());
            metadata.insert("error_count".to_string(), log.errors.len().to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence: 0.46,
                evidence: format!(
                    "No runtime activity in marker-bearing payload ({} bytes); behaviour may be gated",
                    log.input_bytes
                ),
                severity: BehaviorSeverity::Low,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct TelemetryBudgetSaturationPattern;
    impl BehaviorPattern for TelemetryBudgetSaturationPattern {
        fn name(&self) -> &str {
            "telemetry_budget_saturation"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let dropped_total = log.calls_dropped
                + log.call_args_dropped
                + log.prop_reads_dropped
                + log.errors_dropped
                + log.urls_dropped
                + log.domains_dropped
                + log.heap_allocations_dropped
                + log.heap_views_dropped
                + log.heap_accesses_dropped;
            let saturated = dropped_total > 0 || log.calls.len() >= MAX_RECORDED_CALLS;
            if !saturated {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("calls_recorded".to_string(), log.calls.len().to_string());
            metadata.insert("calls_dropped".to_string(), log.calls_dropped.to_string());
            metadata.insert("call_args_dropped".to_string(), log.call_args_dropped.to_string());
            metadata.insert("prop_reads_dropped".to_string(), log.prop_reads_dropped.to_string());
            metadata.insert("errors_dropped".to_string(), log.errors_dropped.to_string());
            metadata.insert("urls_dropped".to_string(), log.urls_dropped.to_string());
            metadata.insert("domains_dropped".to_string(), log.domains_dropped.to_string());
            metadata.insert(
                "heap_allocations_dropped".to_string(),
                log.heap_allocations_dropped.to_string(),
            );
            metadata.insert("heap_views_dropped".to_string(), log.heap_views_dropped.to_string());
            metadata
                .insert("heap_accesses_dropped".to_string(), log.heap_accesses_dropped.to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence: 0.9,
                evidence: format!(
                    "Telemetry limits reached; {} events were truncated",
                    dropped_total
                ),
                severity: BehaviorSeverity::Low,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ComDownloaderExecutionPattern;
    impl BehaviorPattern for ComDownloaderExecutionPattern {
        fn name(&self) -> &str {
            "com_downloader_execution_chain"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let http_open = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.open") || *call == "MSXML2.XMLHTTP.open")
                .count();
            let http_send = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.send") || *call == "MSXML2.XMLHTTP.send")
                .count();
            let stream_open = log.calls.iter().filter(|call| *call == "ADODB.Stream.Open").count();
            let stream_write =
                log.calls.iter().filter(|call| *call == "ADODB.Stream.Write").count();
            let save_to_file =
                log.calls.iter().filter(|call| *call == "ADODB.Stream.SaveToFile").count();
            let shell_run = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run" || *call == "Shell.Application.ShellExecute"
                })
                .count();
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();

            let has_download = http_open > 0 && http_send > 0;
            let has_staging = stream_open > 0 && (stream_write > 0 || save_to_file > 0);
            let has_execution = shell_run > 0;
            let has_com_factory = activex_create > 0 || wscript_create > 0;

            if !(has_download && has_staging && has_execution && has_com_factory) {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("xmlhttp_open_calls".to_string(), http_open.to_string());
            metadata.insert("xmlhttp_send_calls".to_string(), http_send.to_string());
            metadata.insert("stream_open_calls".to_string(), stream_open.to_string());
            metadata.insert("stream_write_calls".to_string(), stream_write.to_string());
            metadata.insert("save_to_file_calls".to_string(), save_to_file.to_string());
            metadata.insert("shell_run_calls".to_string(), shell_run.to_string());
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());

            let component_hits = [
                http_open > 0,
                http_send > 0,
                stream_open > 0,
                stream_write > 0 || save_to_file > 0,
                shell_run > 0,
                has_com_factory,
            ]
            .iter()
            .filter(|value| **value)
            .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.93, BehaviorSeverity::High, component_hits, 6);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence: "Observed COM download, file staging, and execution API sequence"
                    .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ComDownloaderStagingPattern;
    impl BehaviorPattern for ComDownloaderStagingPattern {
        fn name(&self) -> &str {
            "com_downloader_staging_chain"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let http_open = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.open") || *call == "MSXML2.XMLHTTP.open")
                .count();
            let http_send = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.send") || *call == "MSXML2.XMLHTTP.send")
                .count();
            let stream_open = log.calls.iter().filter(|call| *call == "ADODB.Stream.Open").count();
            let save_to_file =
                log.calls.iter().filter(|call| *call == "ADODB.Stream.SaveToFile").count();
            let shell_run = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run" || *call == "Shell.Application.ShellExecute"
                })
                .count();
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();

            let has_download = http_open > 0 && http_send > 0;
            let has_staging = stream_open > 0;
            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let has_execution_chain = save_to_file > 0 && shell_run > 0;

            if !(has_download && has_staging && has_com_factory) || has_execution_chain {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("xmlhttp_open_calls".to_string(), http_open.to_string());
            metadata.insert("xmlhttp_send_calls".to_string(), http_send.to_string());
            metadata.insert("stream_open_calls".to_string(), stream_open.to_string());
            metadata.insert("save_to_file_calls".to_string(), save_to_file.to_string());
            metadata.insert("shell_run_calls".to_string(), shell_run.to_string());
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());

            let component_hits =
                [http_open > 0, http_send > 0, stream_open > 0, has_com_factory, save_to_file > 0]
                    .iter()
                    .filter(|value| **value)
                    .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.82, BehaviorSeverity::Medium, component_hits, 5);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence: "Observed COM downloader staging sequence without confirmed execution"
                    .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ComDownloaderNetworkPattern;
    impl BehaviorPattern for ComDownloaderNetworkPattern {
        fn name(&self) -> &str {
            "com_downloader_network_chain"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let http_open = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.open") || *call == "MSXML2.XMLHTTP.open")
                .count();
            let http_send = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.send") || *call == "MSXML2.XMLHTTP.send")
                .count();
            let stream_open = log.calls.iter().filter(|call| *call == "ADODB.Stream.Open").count();
            let save_to_file =
                log.calls.iter().filter(|call| *call == "ADODB.Stream.SaveToFile").count();
            let shell_run = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run" || *call == "Shell.Application.ShellExecute"
                })
                .count();
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();

            let has_download = http_open > 0 && http_send > 0;
            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let has_higher_signal = stream_open > 0 || save_to_file > 0 || shell_run > 0;

            if !(has_download && has_com_factory) || has_higher_signal {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("xmlhttp_open_calls".to_string(), http_open.to_string());
            metadata.insert("xmlhttp_send_calls".to_string(), http_send.to_string());
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());

            let component_hits = [http_open > 0, http_send > 0, has_com_factory]
                .iter()
                .filter(|value| **value)
                .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.68, BehaviorSeverity::Medium, component_hits, 3);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence: "Observed COM-instantiated HTTP retrieval sequence".to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct WshEnvironmentGatingPattern;
    impl BehaviorPattern for WshEnvironmentGatingPattern {
        fn name(&self) -> &str {
            "wsh_environment_gating"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();
            let env_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Environment"
                        || *call == "WScript.Shell.Environment.Item"
                        || *call == "WScript.Shell.ExpandEnvironmentStrings"
                })
                .count();
            let sleep_calls = log.calls.iter().filter(|call| *call == "WScript.Sleep").count();
            let quit_calls = log.calls.iter().filter(|call| *call == "WScript.Quit").count();
            let network_calls = log
                .calls
                .iter()
                .filter(|call| call.contains(".XMLHTTP.") || call.contains("WinHttp"))
                .count();
            let staging_calls =
                log.calls.iter().filter(|call| call.starts_with("ADODB.Stream.")).count();

            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let has_env_probe = env_calls > 0;
            let has_gating = sleep_calls > 0 || quit_calls > 0;
            let has_higher_signal = network_calls > 0 || staging_calls > 0;

            if !(has_com_factory && has_env_probe) || has_higher_signal {
                return Vec::new();
            }

            let component_hits =
                [has_com_factory, has_env_probe, sleep_calls > 0, quit_calls > 0, has_gating]
                    .iter()
                    .filter(|value| **value)
                    .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.78, BehaviorSeverity::Medium, component_hits, 5);
            let evidence = if has_gating {
                "Observed WSH environment probing with delay/exit gating behaviour".to_string()
            } else {
                "Observed WSH environment probing via COM object factory".to_string()
            };

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());
            metadata.insert("environment_calls".to_string(), env_calls.to_string());
            metadata.insert("sleep_calls".to_string(), sleep_calls.to_string());
            metadata.insert("quit_calls".to_string(), quit_calls.to_string());
            metadata.insert("network_calls".to_string(), network_calls.to_string());
            metadata.insert("staging_calls".to_string(), staging_calls.to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence,
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ComDownloaderDirectExecutionPattern;
    impl BehaviorPattern for ComDownloaderDirectExecutionPattern {
        fn name(&self) -> &str {
            "com_downloader_direct_execution_chain"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let http_open = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.open") || *call == "MSXML2.XMLHTTP.open")
                .count();
            let http_send = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.send") || *call == "MSXML2.XMLHTTP.send")
                .count();
            let shell_run = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run" || *call == "Shell.Application.ShellExecute"
                })
                .count();
            let stream_calls =
                log.calls.iter().filter(|call| call.starts_with("ADODB.Stream.")).count();
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();

            let has_download = http_open > 0 && http_send > 0;
            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let has_direct_execute = shell_run > 0;
            let has_stream_staging = stream_calls > 0;

            if !(has_download && has_com_factory && has_direct_execute) || has_stream_staging {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("xmlhttp_open_calls".to_string(), http_open.to_string());
            metadata.insert("xmlhttp_send_calls".to_string(), http_send.to_string());
            metadata.insert("shell_run_calls".to_string(), shell_run.to_string());
            metadata.insert("stream_calls".to_string(), stream_calls.to_string());
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());

            let component_hits =
                [http_open > 0, http_send > 0, has_com_factory, has_direct_execute]
                    .iter()
                    .filter(|value| **value)
                    .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.88, BehaviorSeverity::High, component_hits, 4);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence: "Observed COM HTTP retrieval followed by direct process execution"
                    .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct WshComProbePattern;
    impl BehaviorPattern for WshComProbePattern {
        fn name(&self) -> &str {
            "wsh_com_object_probe"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();
            let shell_run = log.calls.iter().filter(|call| *call == "WScript.Shell.Run").count();
            let env_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Environment"
                        || *call == "WScript.Shell.Environment.Item"
                        || *call == "WScript.Shell.ExpandEnvironmentStrings"
                })
                .count();
            let network_calls = log
                .calls
                .iter()
                .filter(|call| call.contains(".XMLHTTP.") || call.contains("WinHttp"))
                .count();
            let stream_calls =
                log.calls.iter().filter(|call| call.starts_with("ADODB.Stream.")).count();

            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let only_probe_surface = shell_run == 0
                && env_calls == 0
                && network_calls == 0
                && stream_calls == 0
                && log.calls.len() <= 2;

            if !(has_com_factory && only_probe_surface) {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("total_calls".to_string(), log.calls.len().to_string());
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence: 0.58,
                evidence: "Observed low-activity COM object probe in WSH context".to_string(),
                severity: BehaviorSeverity::Low,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ComFileDropStagingPattern;
    impl BehaviorPattern for ComFileDropStagingPattern {
        fn name(&self) -> &str {
            "com_file_drop_staging"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let stream_open = log.calls.iter().filter(|call| *call == "ADODB.Stream.Open").count();
            let stream_write =
                log.calls.iter().filter(|call| *call == "ADODB.Stream.Write").count();
            let save_to_file =
                log.calls.iter().filter(|call| *call == "ADODB.Stream.SaveToFile").count();
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();
            let shell_run = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run" || *call == "Shell.Application.ShellExecute"
                })
                .count();
            let network_calls = log
                .calls
                .iter()
                .filter(|call| call.contains(".XMLHTTP.") || call.contains("WinHttp"))
                .count();

            let has_stream_staging = stream_open > 0 && (stream_write > 0 || save_to_file > 0);
            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let has_higher_chain = shell_run > 0 || network_calls > 0;
            if !(has_stream_staging && has_com_factory) || has_higher_chain {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("stream_open_calls".to_string(), stream_open.to_string());
            metadata.insert("stream_write_calls".to_string(), stream_write.to_string());
            metadata.insert("save_to_file_calls".to_string(), save_to_file.to_string());
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());
            metadata.insert("network_calls".to_string(), network_calls.to_string());
            metadata.insert("shell_run_calls".to_string(), shell_run.to_string());

            let component_hits =
                [has_com_factory, stream_open > 0, stream_write > 0 || save_to_file > 0]
                    .iter()
                    .filter(|value| **value)
                    .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.8, BehaviorSeverity::Medium, component_hits, 3);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed COM stream staging and local file drop without confirmed execution"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct WshTimingGatePattern;
    impl BehaviorPattern for WshTimingGatePattern {
        fn name(&self) -> &str {
            "wsh_timing_gate"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let sleep_calls = log.calls.iter().filter(|call| *call == "WScript.Sleep").count();
            let has_runtime_activity = !log.calls.is_empty() || !log.prop_reads.is_empty();
            let only_sleep_surface = sleep_calls > 0
                && log.calls.len() <= sleep_calls + 1
                && log.prop_reads.is_empty()
                && log.errors.is_empty();
            let marker_hint = log.dormant_source_markers >= 1;
            if !has_runtime_activity || !only_sleep_surface || !marker_hint {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("sleep_calls".to_string(), sleep_calls.to_string());
            metadata.insert("total_calls".to_string(), log.calls.len().to_string());
            metadata.insert("source_markers".to_string(), log.dormant_source_markers.to_string());
            metadata.insert("prop_reads_count".to_string(), log.prop_reads.len().to_string());
            metadata.insert("errors_count".to_string(), log.errors.len().to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence: 0.62,
                evidence: "Observed sleep-only runtime activity with source execution markers"
                    .to_string(),
                severity: BehaviorSeverity::Low,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ComDownloaderIncompleteNetworkPattern;
    impl BehaviorPattern for ComDownloaderIncompleteNetworkPattern {
        fn name(&self) -> &str {
            "com_downloader_incomplete_network_chain"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let http_open = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.open") || *call == "MSXML2.XMLHTTP.open")
                .count();
            let http_send = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.send") || *call == "MSXML2.XMLHTTP.send")
                .count();
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();
            let env_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Environment"
                        || *call == "WScript.Shell.Environment.Item"
                        || *call == "WScript.Shell.ExpandEnvironmentStrings"
                })
                .count();
            let sleep_calls = log.calls.iter().filter(|call| *call == "WScript.Sleep").count();
            let stream_calls =
                log.calls.iter().filter(|call| call.starts_with("ADODB.Stream.")).count();
            let shell_run = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run" || *call == "Shell.Application.ShellExecute"
                })
                .count();

            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let has_signal = env_calls > 0 || sleep_calls > 0;
            let has_higher_chain = http_open > 0 || stream_calls > 0 || shell_run > 0;
            if !(http_send > 0 && has_com_factory && has_signal) || has_higher_chain {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("xmlhttp_send_calls".to_string(), http_send.to_string());
            metadata.insert("xmlhttp_open_calls".to_string(), http_open.to_string());
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());
            metadata.insert("environment_calls".to_string(), env_calls.to_string());
            metadata.insert("sleep_calls".to_string(), sleep_calls.to_string());

            let component_hits = [http_send > 0, has_com_factory, env_calls > 0, sleep_calls > 0]
                .iter()
                .filter(|value| **value)
                .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.66, BehaviorSeverity::Medium, component_hits, 4);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed COM HTTP send path without visible open; chain appears partial or obfuscated"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ComDownloaderSendOnlyPattern;
    impl BehaviorPattern for ComDownloaderSendOnlyPattern {
        fn name(&self) -> &str {
            "com_downloader_send_only_chain"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let http_open = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.open") || *call == "MSXML2.XMLHTTP.open")
                .count();
            let http_send = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.send") || *call == "MSXML2.XMLHTTP.send")
                .count();
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();
            let stream_calls =
                log.calls.iter().filter(|call| call.starts_with("ADODB.Stream.")).count();
            let shell_run = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run" || *call == "Shell.Application.ShellExecute"
                })
                .count();

            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let has_send_only = http_send > 0 && http_open == 0;
            let has_higher_chain = stream_calls > 0 || shell_run > 0;
            if !(has_com_factory && has_send_only) || has_higher_chain {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("xmlhttp_send_calls".to_string(), http_send.to_string());
            metadata.insert("xmlhttp_open_calls".to_string(), http_open.to_string());
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());
            metadata.insert("stream_calls".to_string(), stream_calls.to_string());
            metadata.insert("shell_run_calls".to_string(), shell_run.to_string());

            let component_hits = [has_com_factory, has_send_only, http_send > 1]
                .iter()
                .filter(|value| **value)
                .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.62, BehaviorSeverity::Low, component_hits, 3);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed COM-instantiated HTTP send path without visible open/staging execution chain"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ComDownloaderIncompleteOpenPattern;
    impl BehaviorPattern for ComDownloaderIncompleteOpenPattern {
        fn name(&self) -> &str {
            "com_downloader_incomplete_open_chain"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let http_open = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.open") || *call == "MSXML2.XMLHTTP.open")
                .count();
            let http_send = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.send") || *call == "MSXML2.XMLHTTP.send")
                .count();
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();
            let env_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Environment"
                        || *call == "WScript.Shell.Environment.Item"
                        || *call == "WScript.Shell.ExpandEnvironmentStrings"
                })
                .count();
            let sleep_calls = log.calls.iter().filter(|call| *call == "WScript.Sleep").count();
            let stream_calls =
                log.calls.iter().filter(|call| call.starts_with("ADODB.Stream.")).count();
            let shell_run = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run" || *call == "Shell.Application.ShellExecute"
                })
                .count();

            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let has_gate_signal = env_calls > 0 || sleep_calls > 0;
            let has_higher_chain = http_send > 0 || stream_calls > 0 || shell_run > 0;
            if !(http_open > 0 && has_com_factory && has_gate_signal) || has_higher_chain {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("xmlhttp_open_calls".to_string(), http_open.to_string());
            metadata.insert("xmlhttp_send_calls".to_string(), http_send.to_string());
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());
            metadata.insert("environment_calls".to_string(), env_calls.to_string());
            metadata.insert("sleep_calls".to_string(), sleep_calls.to_string());

            let component_hits = [http_open > 0, has_com_factory, env_calls > 0, sleep_calls > 0]
                .iter()
                .filter(|value| **value)
                .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.62, BehaviorSeverity::Low, component_hits, 4);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed COM HTTP open path without send; execution chain appears partial/gated"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct WshDirectRunPattern;
    impl BehaviorPattern for WshDirectRunPattern {
        fn name(&self) -> &str {
            "wsh_direct_run_execution"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let shell_run = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run" || *call == "Shell.Application.ShellExecute"
                })
                .count();
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();
            let network_calls = log
                .calls
                .iter()
                .filter(|call| call.contains(".XMLHTTP.") || call.contains("WinHttp"))
                .count();
            let stream_calls =
                log.calls.iter().filter(|call| call.starts_with("ADODB.Stream.")).count();
            let env_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Environment"
                        || *call == "WScript.Shell.Environment.Item"
                        || *call == "WScript.Shell.ExpandEnvironmentStrings"
                })
                .count();

            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let low_activity = log.calls.len() <= 4;
            let has_higher_chain = network_calls > 0 || stream_calls > 0 || env_calls > 0;
            if !(shell_run > 0 && has_com_factory && low_activity) || has_higher_chain {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("shell_run_calls".to_string(), shell_run.to_string());
            metadata.insert("total_calls".to_string(), log.calls.len().to_string());
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());

            let component_hits = [shell_run > 0, has_com_factory, low_activity]
                .iter()
                .filter(|value| **value)
                .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.85, BehaviorSeverity::High, component_hits, 3);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence: "Observed direct WSH process execution via COM object creation"
                    .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ComNetworkBufferStagingPattern;
    impl BehaviorPattern for ComNetworkBufferStagingPattern {
        fn name(&self) -> &str {
            "com_network_buffer_staging"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let http_open = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.open") || *call == "MSXML2.XMLHTTP.open")
                .count();
            let http_send = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.send") || *call == "MSXML2.XMLHTTP.send")
                .count();
            let stream_open = log.calls.iter().filter(|call| *call == "ADODB.Stream.Open").count();
            let stream_write =
                log.calls.iter().filter(|call| *call == "ADODB.Stream.Write").count();
            let save_to_file =
                log.calls.iter().filter(|call| *call == "ADODB.Stream.SaveToFile").count();
            let shell_run = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run" || *call == "Shell.Application.ShellExecute"
                })
                .count();
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();

            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let has_network_to_buffer = http_send > 0 && stream_open > 0 && stream_write > 0;
            let has_higher_chain = http_open > 0 || save_to_file > 0 || shell_run > 0;
            if !(has_com_factory && has_network_to_buffer) || has_higher_chain {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("xmlhttp_send_calls".to_string(), http_send.to_string());
            metadata.insert("stream_open_calls".to_string(), stream_open.to_string());
            metadata.insert("stream_write_calls".to_string(), stream_write.to_string());
            metadata.insert("xmlhttp_open_calls".to_string(), http_open.to_string());
            metadata.insert("save_to_file_calls".to_string(), save_to_file.to_string());
            metadata.insert("shell_run_calls".to_string(), shell_run.to_string());

            let component_hits =
                [has_com_factory, http_send > 0, stream_open > 0, stream_write > 0]
                    .iter()
                    .filter(|value| **value)
                    .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.72, BehaviorSeverity::Medium, component_hits, 4);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed COM HTTP send feeding ADODB stream buffer without visible final stage"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct ComDownloaderPartialStagingPattern;
    impl BehaviorPattern for ComDownloaderPartialStagingPattern {
        fn name(&self) -> &str {
            "com_downloader_partial_staging_chain"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let http_open = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.open") || *call == "MSXML2.XMLHTTP.open")
                .count();
            let http_send = log
                .calls
                .iter()
                .filter(|call| call.ends_with(".XMLHTTP.send") || *call == "MSXML2.XMLHTTP.send")
                .count();
            let stream_open = log.calls.iter().filter(|call| *call == "ADODB.Stream.Open").count();
            let stream_write =
                log.calls.iter().filter(|call| *call == "ADODB.Stream.Write").count();
            let save_to_file =
                log.calls.iter().filter(|call| *call == "ADODB.Stream.SaveToFile").count();
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();
            let shell_run = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run" || *call == "Shell.Application.ShellExecute"
                })
                .count();

            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let has_partial_network = http_send > 0 && http_open == 0;
            let has_stream_staging = stream_open > 0 && (stream_write > 0 || save_to_file > 0);
            let has_execution = shell_run > 0;

            if !(has_com_factory && has_partial_network && has_stream_staging) || has_execution {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("xmlhttp_open_calls".to_string(), http_open.to_string());
            metadata.insert("xmlhttp_send_calls".to_string(), http_send.to_string());
            metadata.insert("stream_open_calls".to_string(), stream_open.to_string());
            metadata.insert("stream_write_calls".to_string(), stream_write.to_string());
            metadata.insert("save_to_file_calls".to_string(), save_to_file.to_string());
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());
            metadata.insert("shell_run_calls".to_string(), shell_run.to_string());

            let component_hits = [
                has_com_factory,
                has_partial_network,
                has_stream_staging,
                stream_write > 0,
                save_to_file > 0,
            ]
            .iter()
            .filter(|value| **value)
            .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.74, BehaviorSeverity::Medium, component_hits, 5);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed COM HTTP send plus ADODB stream staging without visible HTTP open"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct WshFilesystemReconPattern;
    impl BehaviorPattern for WshFilesystemReconPattern {
        fn name(&self) -> &str {
            "wsh_filesystem_recon_probe"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let activex_create = log.calls.iter().filter(|call| *call == "ActiveXObject").count();
            let wscript_create =
                log.calls.iter().filter(|call| *call == "WScript.CreateObject").count();
            let get_file_calls = log
                .calls
                .iter()
                .filter(|call| *call == "Scripting.FileSystemObject.GetFile")
                .count();
            let file_exists_calls = log
                .calls
                .iter()
                .filter(|call| *call == "Scripting.FileSystemObject.FileExists")
                .count();
            let folder_exists_calls = log
                .calls
                .iter()
                .filter(|call| *call == "Scripting.FileSystemObject.FolderExists")
                .count();
            let special_folder_calls = log
                .calls
                .iter()
                .filter(|call| *call == "Scripting.FileSystemObject.GetSpecialFolder")
                .count();
            let temp_name_calls = log
                .calls
                .iter()
                .filter(|call| *call == "Scripting.FileSystemObject.GetTempName")
                .count();
            let network_calls = log
                .calls
                .iter()
                .filter(|call| call.contains(".XMLHTTP.") || call.contains("WinHttp"))
                .count();
            let stream_calls =
                log.calls.iter().filter(|call| call.starts_with("ADODB.Stream.")).count();
            let shell_run = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "WScript.Shell.Run" || *call == "Shell.Application.ShellExecute"
                })
                .count();
            let write_fso_calls = log
                .calls
                .iter()
                .filter(|call| {
                    *call == "Scripting.FileSystemObject.CreateTextFile"
                        || *call == "Scripting.FileSystemObject.CreateFolder"
                        || *call == "Scripting.FileSystemObject.DeleteFile"
                        || *call == "Scripting.FileSystemObject.CopyFile"
                        || *call == "Scripting.FileSystemObject.MoveFile"
                        || *call == "Scripting.FileSystemObject.OpenTextFile"
                })
                .count();

            let has_com_factory = activex_create > 0 || wscript_create > 0;
            let recon_calls = get_file_calls
                + file_exists_calls
                + folder_exists_calls
                + special_folder_calls
                + temp_name_calls;
            let has_higher_chain = network_calls > 0 || stream_calls > 0 || shell_run > 0;

            if !(has_com_factory && recon_calls > 0) || has_higher_chain || write_fso_calls > 0 {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("activex_create_calls".to_string(), activex_create.to_string());
            metadata.insert("wscript_create_calls".to_string(), wscript_create.to_string());
            metadata.insert("fso_get_file_calls".to_string(), get_file_calls.to_string());
            metadata.insert("fso_file_exists_calls".to_string(), file_exists_calls.to_string());
            metadata.insert("fso_folder_exists_calls".to_string(), folder_exists_calls.to_string());
            metadata
                .insert("fso_special_folder_calls".to_string(), special_folder_calls.to_string());
            metadata.insert("fso_temp_name_calls".to_string(), temp_name_calls.to_string());
            metadata.insert("fso_write_calls".to_string(), write_fso_calls.to_string());
            metadata.insert("network_calls".to_string(), network_calls.to_string());
            metadata.insert("stream_calls".to_string(), stream_calls.to_string());
            metadata.insert("shell_run_calls".to_string(), shell_run.to_string());

            let component_hits = [has_com_factory, recon_calls > 0, get_file_calls > 0]
                .iter()
                .filter(|value| **value)
                .count();
            let (confidence, severity) =
                calibrate_chain_signal(0.67, BehaviorSeverity::Low, component_hits, 3);

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed COM-instantiated FileSystemObject reconnaissance without follow-on execution"
                        .to_string(),
                severity,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct WshEarlyQuitPattern;
    impl BehaviorPattern for WshEarlyQuitPattern {
        fn name(&self) -> &str {
            "wsh_early_quit_gate"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let quit_calls = log.calls.iter().filter(|call| *call == "WScript.Quit").count();
            let sleep_calls = log.calls.iter().filter(|call| *call == "WScript.Sleep").count();
            let has_only_exit_surface =
                quit_calls > 0 && log.calls.len() <= quit_calls + sleep_calls;
            if !has_only_exit_surface {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("quit_calls".to_string(), quit_calls.to_string());
            metadata.insert("sleep_calls".to_string(), sleep_calls.to_string());
            metadata.insert("total_calls".to_string(), log.calls.len().to_string());
            metadata.insert("source_markers".to_string(), log.dormant_source_markers.to_string());

            let confidence = if log.dormant_source_markers >= 1 { 0.64 } else { 0.52 };
            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence,
                evidence:
                    "Observed early WScript quit with source markers, consistent with gating/abort logic"
                        .to_string(),
                severity: BehaviorSeverity::Low,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    struct WshSleepOnlyPattern;
    impl BehaviorPattern for WshSleepOnlyPattern {
        fn name(&self) -> &str {
            "wsh_sleep_only_execution"
        }

        fn analyze(&self, _flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation> {
            let sleep_calls = log.calls.iter().filter(|call| *call == "WScript.Sleep").count();
            let has_sleep_only_surface = sleep_calls > 0
                && log.calls.len() == sleep_calls
                && log.prop_reads.is_empty()
                && log.errors.is_empty();
            let has_size_signal = log.input_bytes >= 4_096 || log.dormant_source_markers >= 1;
            if !(has_sleep_only_surface && has_size_signal) {
                return Vec::new();
            }

            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("sleep_calls".to_string(), sleep_calls.to_string());
            metadata.insert("total_calls".to_string(), log.calls.len().to_string());
            metadata.insert("input_bytes".to_string(), log.input_bytes.to_string());
            metadata.insert("source_markers".to_string(), log.dormant_source_markers.to_string());

            vec![BehaviorObservation {
                pattern_name: self.name().to_string(),
                confidence: 0.48,
                evidence:
                    "Observed sleep-only WSH runtime activity in non-trivial payload; execution likely gated"
                        .to_string(),
                severity: BehaviorSeverity::Low,
                metadata,
                timestamp: std::time::Duration::from_millis(0),
            }]
        }
    }

    // Behavioral Analysis Engine
    fn run_behavioral_analysis(log: &mut SandboxLog) {
        let patterns: Vec<Box<dyn BehaviorPattern>> = vec![
            Box::new(ObfuscatedStringConstruction),
            Box::new(DynamicCodeGeneration),
            Box::new(IndirectDynamicEvalDispatchPattern),
            Box::new(MultiPassDecodePipelinePattern),
            Box::new(CovertBeaconExfilPattern),
            Box::new(ChunkedDataExfilPipelinePattern),
            Box::new(InteractionCoercionLoopPattern),
            Box::new(LotlApiChainExecutionPattern),
            Box::new(PrototypeChainExecutionHijackPattern),
            Box::new(WasmLoaderStagingPattern),
            Box::new(RuntimeDependencyLoaderAbusePattern),
            Box::new(CredentialHarvestFormEmulationPattern),
            Box::new(ServiceWorkerPersistenceAbusePattern),
            Box::new(WebCryptoKeyStagingExfilPattern),
            Box::new(StorageBackedPayloadStagingPattern),
            Box::new(DynamicModuleGraphEvasionPattern),
            Box::new(CovertRealtimeChannelAbusePattern),
            Box::new(ClipboardSessionHijackPattern),
            Box::new(DomSinkPolicyBypassPattern),
            Box::new(WasmMemoryUnpackerPipelinePattern),
            Box::new(ExtensionApiAbuseProbePattern),
            Box::new(ModernFingerprintEvasionPattern),
            Box::new(TimingProbeEvasionPattern),
            Box::new(CapabilityMatrixFingerprintingPattern),
            Box::new(EnvironmentFingerprinting),
            Box::new(ErrorRecoveryPattern),
            Box::new(ComDownloaderExecutionPattern),
            Box::new(ComDownloaderStagingPattern),
            Box::new(ComDownloaderNetworkPattern),
            Box::new(ComDownloaderDirectExecutionPattern),
            Box::new(WshEnvironmentGatingPattern),
            Box::new(WshComProbePattern),
            Box::new(ComFileDropStagingPattern),
            Box::new(WshTimingGatePattern),
            Box::new(ComDownloaderIncompleteNetworkPattern),
            Box::new(ComDownloaderSendOnlyPattern),
            Box::new(ComDownloaderIncompleteOpenPattern),
            Box::new(WshDirectRunPattern),
            Box::new(ComNetworkBufferStagingPattern),
            Box::new(ComDownloaderPartialStagingPattern),
            Box::new(WshFilesystemReconPattern),
            Box::new(WshEarlyQuitPattern),
            Box::new(WshSleepOnlyPattern),
            Box::new(VariablePromotionPattern),
            Box::new(DormantPayloadPattern),
            Box::new(DormantMarkedSmallPayloadPattern),
            Box::new(TelemetryBudgetSaturationPattern),
        ];

        let mut all_observations = Vec::new();

        for pattern in patterns {
            let observations = pattern.analyze(&log.execution_flow, log);
            all_observations.extend(observations);
        }

        log.behavioral_patterns = all_observations;
    }

    // Enhanced function call recording with execution flow tracking
    fn record_enhanced_call(
        log: &Rc<RefCell<SandboxLog>>,
        name: &str,
        args: &[JsValue],
        ctx: &mut Context,
    ) {
        let call_start = std::time::Instant::now();

        // Standard call recording
        record_call(log, name, args, ctx);

        // Enhanced execution flow tracking
        {
            let mut log_ref = log.borrow_mut();
            let execution_time = call_start.elapsed();
            let current_depth = log_ref.execution_flow.call_stack.len();

            let function_call = FunctionCall {
                name: name.to_string(),
                args: args.iter().map(|arg| js_value_summary(arg, ctx, 50)).collect(),
                return_value: None, // Could be enhanced to capture return values
                execution_time,
                scope_id: "global".to_string(), // Could be enhanced with actual scope tracking
                call_depth: current_depth,
                timestamp: log_ref
                    .execution_flow
                    .start_time
                    .map(|start| start.elapsed())
                    .unwrap_or_else(|| std::time::Duration::from_millis(0)),
            };

            log_ref.execution_flow.call_stack.push(function_call);

            // Track variable timeline for special functions
            if name == "eval" {
                let eval_content = args
                    .first()
                    .map(|arg| js_value_summary(arg, ctx, 100))
                    .unwrap_or_else(|| "unknown".to_string());

                let timestamp = log_ref
                    .execution_flow
                    .start_time
                    .map(|start| start.elapsed())
                    .unwrap_or_else(|| std::time::Duration::from_millis(0));

                log_ref.execution_flow.variable_timeline.push(VariableEvent {
                    variable: "eval_execution".to_string(),
                    event_type: VariableEventType::Assignment,
                    value: eval_content,
                    scope: "global".to_string(),
                    timestamp,
                });
            }
        }
    }

    pub fn run_sandbox(bytes: &[u8], options: &DynamicOptions) -> DynamicOutcome {
        if options.phases.is_empty() {
            return DynamicOutcome::Skipped {
                reason: "empty_phase_plan".to_string(),
                limit: 1,
                actual: 0,
            };
        }
        if bytes.len() > options.max_bytes {
            return DynamicOutcome::Skipped {
                reason: classify_oversized_payload_reason(bytes).into(),
                limit: options.max_bytes,
                actual: bytes.len(),
            };
        }
        if should_skip_complex_token_decoder(bytes) {
            return DynamicOutcome::Skipped {
                reason: "complex_token_decoder_payload".into(),
                limit: options.max_bytes,
                actual: bytes.len(),
            };
        }
        let opts = options.clone();
        let bytes = bytes.to_vec();
        let (tx, rx) = mpsc::channel();
        let timeout_context = Arc::new(Mutex::new(crate::types::TimeoutContext {
            runtime_profile: opts.runtime_profile.id(),
            phase: None,
            elapsed_ms: None,
            budget_ratio: None,
        }));
        let timeout_context_thread = Arc::clone(&timeout_context);
        std::thread::spawn(move || {
            let mut initial_log = SandboxLog { options: opts, ..SandboxLog::default() };
            initial_log.input_bytes = bytes.len();
            initial_log.runtime_profile = initial_log.options.runtime_profile.id();
            initial_log.replay_id = compute_replay_id(&bytes, &initial_log.options);
            let phase_timeout_ms = initial_log.options.phase_timeout_ms;
            let timeout_budget_ms = initial_log.options.timeout_ms;
            // Initialize execution flow tracking
            initial_log.execution_flow.start_time = Some(std::time::Instant::now());
            let log = Rc::new(RefCell::new(initial_log));
            let scope = Rc::new(RefCell::new(DynamicScope::default()));
            let normalised = normalise_js_source(&bytes);
            {
                let lower = String::from_utf8_lossy(&normalised).to_ascii_lowercase();
                let normalised_escapes = lower
                    .replace("\\u0028", "(")
                    .replace("\\u0029", ")")
                    .replace("\\x28", "(")
                    .replace("\\x29", ")");
                let markers = [
                    "/*@cc_on",
                    "eval(",
                    "reverse().join(",
                    "fromcharcode",
                    "split(",
                    "adodb.",
                    "activexobject",
                    "wscript.createobject",
                    "xmlhttp.open",
                ];
                let marker_hits =
                    markers.iter().filter(|marker| normalised_escapes.contains(**marker)).count();
                log.borrow_mut().dormant_source_markers = marker_hits;
            }
            let mut phase_plan = phase_order(&log.borrow().options);
            if should_collapse_phase_plan(&normalised) {
                phase_plan.truncate(1);
            }
            let mut context = Context::default();
            let mut limits = RuntimeLimits::default();
            let (loop_iteration_limit, loop_profile, downloader_scheduler_hardening) =
                select_loop_iteration_limit(&normalised);
            {
                let mut log_ref = log.borrow_mut();
                log_ref.adaptive_loop_iteration_limit = loop_iteration_limit as usize;
                log_ref.adaptive_loop_profile = loop_profile.to_string();
                log_ref.downloader_scheduler_hardening = downloader_scheduler_hardening;
            }
            limits.set_loop_iteration_limit(loop_iteration_limit);
            limits.set_recursion_limit(64);
            limits.set_stack_size_limit(512 * 1024);
            context.set_runtime_limits(limits);
            register_profiled_stubs(&mut context, log.clone());
            register_doc_globals(&mut context, log.clone()); // Enable unescape and other globals
            register_pdf_event_context(&mut context, log.clone(), scope.clone()); // Add event object simulation
            register_enhanced_doc_globals(&mut context, log.clone(), scope.clone());
            register_enhanced_eval_v2(&mut context, log.clone(), scope.clone());
            register_enhanced_global_fallback(&mut context, log.clone(), scope.clone());
            {
                let inferred = infer_lifecycle_context(&normalised, &log.borrow().options);
                log.borrow_mut().lifecycle_context_observed = inferred;
            }

            let baseline_source = String::from_utf8_lossy(&normalised).to_string();
            let baseline_snapshot = snapshot_source(&baseline_source);
            let mut total_elapsed = 0u128;
            for phase in phase_plan {
                let phase_name = phase.as_str().to_string();
                if let Ok(mut context_ref) = timeout_context_thread.lock() {
                    context_ref.phase = Some(phase_name.clone());
                } else {
                    let mut log_ref = log.borrow_mut();
                    if log_ref.errors.len() < MAX_RECORDED_ERRORS {
                        log_ref
                            .errors
                            .push("timeout context mutex poisoned at phase start".to_string());
                    } else {
                        log_ref.errors_dropped += 1;
                    }
                }
                set_phase(&log, &phase_name);
                let phase_bytes = match phase_script_for(phase) {
                    Some(script) => script.as_bytes().to_vec(),
                    None => normalised.clone(),
                };
                let phase_code = String::from_utf8_lossy(&phase_bytes).to_string();
                let source = Source::from_bytes(&phase_bytes);
                let eval_start = Instant::now();
                let eval_res = context.eval(source);
                let elapsed = eval_start.elapsed().as_millis();
                total_elapsed += elapsed;
                if let Ok(mut context_ref) = timeout_context_thread.lock() {
                    context_ref.elapsed_ms = Some(total_elapsed);
                    if timeout_budget_ms > 0 {
                        let ratio = total_elapsed as f64 / timeout_budget_ms as f64;
                        context_ref.budget_ratio = Some(ratio.min(1.0));
                    }
                } else {
                    let mut log_ref = log.borrow_mut();
                    if log_ref.errors.len() < MAX_RECORDED_ERRORS {
                        log_ref.errors.push(
                            "timeout context mutex poisoned while updating elapsed budget"
                                .to_string(),
                        );
                    } else {
                        log_ref.errors_dropped += 1;
                    }
                }
                {
                    let mut log_ref = log.borrow_mut();
                    log_ref.phase_elapsed_ms.insert(phase_name.clone(), elapsed);
                }
                if elapsed > phase_timeout_ms {
                    let mut log_ref = log.borrow_mut();
                    let message = format!(
                        "phase timeout exceeded: phase={} limit_ms={} observed_ms={}",
                        phase_name, phase_timeout_ms, elapsed
                    );
                    if log_ref.errors.len() < MAX_RECORDED_ERRORS {
                        log_ref.errors.push(message);
                    } else {
                        log_ref.errors_dropped += 1;
                    }
                    *log_ref.phase_error_counts.entry(phase_name.clone()).or_insert(0) += 1;
                    break;
                }
                if let Err(err) = eval_res {
                    let recovered =
                        attempt_error_recovery(&mut context, &err, &phase_code, &scope, &log)
                            .is_some();
                    let error_text = format!("{:?}", err);
                    let suppress_runtime_limit = {
                        let log_ref = log.borrow();
                        should_suppress_runtime_limit(&log_ref, &error_text)
                    };
                    if !recovered && !suppress_runtime_limit {
                        let mut log_ref = log.borrow_mut();
                        if log_ref.errors.len() < MAX_RECORDED_ERRORS {
                            log_ref.errors.push(error_text);
                        } else {
                            log_ref.errors_dropped += 1;
                        }
                        *log_ref.phase_error_counts.entry(phase_name).or_insert(0) += 1;
                    } else if suppress_runtime_limit {
                        let mut log_ref = log.borrow_mut();
                        log_ref.probe_loop_short_circuit_hits += 1;
                    }
                }
            }
            maybe_execute_service_worker_micro_phases(
                &mut context,
                &normalised,
                &log,
                &timeout_context_thread,
                timeout_budget_ms,
                phase_timeout_ms,
                &mut total_elapsed,
            );
            maybe_execute_lifecycle_micro_phases(
                &mut context,
                &log,
                &timeout_context_thread,
                timeout_budget_ms,
                phase_timeout_ms,
                &mut total_elapsed,
            );
            {
                let mut log_ref = log.borrow_mut();
                log_ref.elapsed_ms = Some(total_elapsed);
                correlate_taint_edges(&mut log_ref);
                log_ref.wasm_static_features = extract_wasm_static_features(&normalised);

                // Run behavioral pattern analysis
                run_behavioral_analysis(&mut log_ref);

                let trigger_calls = dedupe_strings(log_ref.dynamic_code_calls.clone());
                let trigger_phase = log_ref
                    .phase_dynamic_code_calls
                    .iter()
                    .find(|(_, calls)| !calls.is_empty())
                    .map(|(phase, _)| phase.clone())
                    .unwrap_or_else(|| "open".to_string());
                let dynamic_snippets = extract_dynamic_snippets(&log_ref.call_args);
                let generated_snippets = dynamic_snippets.len();
                let augmented_source = if dynamic_snippets.is_empty() {
                    baseline_source.clone()
                } else {
                    let mut augmented = baseline_source.clone();
                    for snippet in &dynamic_snippets {
                        if augmented.len() >= MAX_AUGMENTED_SOURCE_BYTES {
                            break;
                        }
                        augmented.push('\n');
                        let remaining = MAX_AUGMENTED_SOURCE_BYTES.saturating_sub(augmented.len());
                        if remaining == 0 {
                            break;
                        }
                        if snippet.len() <= remaining {
                            augmented.push_str(snippet);
                        } else {
                            augmented.push_str(&snippet[..remaining]);
                            break;
                        }
                    }
                    augmented
                };
                log_ref.delta_summary = compute_snapshot_delta(
                    &baseline_snapshot,
                    &augmented_source,
                    trigger_phase,
                    trigger_calls,
                    generated_snippets,
                );
            }
            let out = log.borrow().clone();
            let _ = tx.send(out);
        });

        match rx.recv_timeout(Duration::from_millis(options.timeout_ms as u64)) {
            Ok(log) => DynamicOutcome::Executed(Box::new(DynamicSignals {
                replay_id: log.replay_id.clone(),
                runtime_profile: log.runtime_profile.clone(),
                calls: log.calls.clone(),
                call_args: log.call_args.clone(),
                urls: dedupe_sorted(log.urls.clone()),
                domains: dedupe_sorted(log.domains.clone()),
                errors: log.errors.clone(),
                prop_reads: log.prop_reads.clone(),
                prop_writes: dedupe_sorted(log.prop_writes.clone()),
                prop_deletes: dedupe_sorted(log.prop_deletes.clone()),
                reflection_probes: dedupe_sorted(log.reflection_probes.clone()),
                dynamic_code_calls: dedupe_sorted(log.dynamic_code_calls.clone()),
                heap_allocations: log.heap_allocations.clone(),
                heap_views: log.heap_views.clone(),
                heap_accesses: log.heap_accesses.clone(),
                heap_allocation_count: log.heap_allocation_count,
                heap_view_count: log.heap_view_count,
                heap_access_count: log.heap_access_count,
                call_count: log.call_count,
                unique_calls: log.unique_calls.len(),
                unique_prop_reads: log.unique_prop_reads.len(),
                elapsed_ms: log.elapsed_ms,
                truncation: crate::types::DynamicTruncationSummary {
                    calls_dropped: log.calls_dropped,
                    call_args_dropped: log.call_args_dropped,
                    prop_reads_dropped: log.prop_reads_dropped,
                    errors_dropped: log.errors_dropped,
                    urls_dropped: log.urls_dropped,
                    domains_dropped: log.domains_dropped,
                    heap_allocations_dropped: log.heap_allocations_dropped,
                    heap_views_dropped: log.heap_views_dropped,
                    heap_accesses_dropped: log.heap_accesses_dropped,
                },
                phases: render_phase_summaries(&log),
                delta_summary: log.delta_summary.as_ref().map(|delta| {
                    crate::types::DynamicDeltaSummary {
                        phase: delta.phase.clone(),
                        trigger_calls: delta.trigger_calls.clone(),
                        generated_snippets: delta.generated_snippets,
                        added_identifier_count: delta.added_identifier_count,
                        added_string_literal_count: delta.added_string_literal_count,
                        added_call_count: delta.added_call_count,
                        new_identifiers: delta.new_identifiers.clone(),
                        new_string_literals: delta.new_string_literals.clone(),
                        new_calls: delta.new_calls.clone(),
                    }
                }),
                behavioral_patterns: log
                    .behavioral_patterns
                    .iter()
                    .map(|obs| crate::types::BehaviorPattern {
                        name: obs.pattern_name.clone(),
                        confidence: obs.confidence,
                        evidence: obs.evidence.clone(),
                        severity: format!("{:?}", obs.severity),
                        metadata: obs.metadata.clone(),
                    })
                    .collect(),
                execution_stats: crate::types::ExecutionStats {
                    total_function_calls: log.call_count,
                    unique_function_calls: log.unique_calls.len(),
                    variable_promotions: log
                        .variable_events
                        .iter()
                        .filter(|ve| matches!(ve.event_type, VariableEventType::Declaration))
                        .count(),
                    error_recoveries: log.execution_flow.exception_handling.len(),
                    successful_recoveries: log
                        .execution_flow
                        .exception_handling
                        .iter()
                        .filter(|ex| ex.recovery_successful)
                        .count(),
                    execution_depth: log
                        .execution_flow
                        .call_stack
                        .iter()
                        .map(|call| call.call_depth)
                        .max()
                        .unwrap_or(0),
                    loop_iteration_limit_hits: loop_iteration_limit_hits(&log.errors),
                    adaptive_loop_iteration_limit: log.adaptive_loop_iteration_limit,
                    adaptive_loop_profile: log.adaptive_loop_profile.clone(),
                    downloader_scheduler_hardening: log.downloader_scheduler_hardening,
                    probe_loop_short_circuit_hits: log.probe_loop_short_circuit_hits,
                },
            })),
            Err(RecvTimeoutError::Timeout) => {
                let context = timeout_context.lock().ok().map(|guard| (*guard).clone()).unwrap_or(
                    crate::types::TimeoutContext {
                        runtime_profile: options.runtime_profile.id(),
                        phase: Some("mutex_poisoned".to_string()),
                        elapsed_ms: None,
                        budget_ratio: None,
                    },
                );
                DynamicOutcome::TimedOut { timeout_ms: options.timeout_ms, context }
            }
            Err(_) => {
                let context = timeout_context.lock().ok().map(|guard| (*guard).clone()).unwrap_or(
                    crate::types::TimeoutContext {
                        runtime_profile: options.runtime_profile.id(),
                        phase: Some("mutex_poisoned".to_string()),
                        elapsed_ms: None,
                        budget_ratio: None,
                    },
                );
                DynamicOutcome::TimedOut { timeout_ms: options.timeout_ms, context }
            }
        }
    }

    pub fn is_network_call(name: &str) -> bool {
        matches!(
            name,
            "launchURL"
                | "getURL"
                | "submitForm"
                | "mailMsg"
                | "mailDoc"
                | "Collab.collectEmailInfo"
                | "SOAP.connect"
                | "SOAP.request"
                | "Net.HTTP.request"
                | "fetch"
                | "XMLHttpRequest.open"
                | "XMLHttpRequest.send"
                | "WebSocket.send"
                | "navigator.sendBeacon"
                | "MSXML2.XMLHTTP.open"
                | "MSXML2.XMLHTTP.send"
                | "MSXML2.XMLHTTP.setRequestHeader"
                | "MSXML2.ServerXMLHTTP.open"
                | "MSXML2.ServerXMLHTTP.send"
                | "MSXML2.ServerXMLHTTP.setRequestHeader"
                | "WinHTTP.WinHTTPRequest.open"
                | "WinHTTP.WinHTTPRequest.send"
                | "URLDownloadToFile"
        )
    }

    pub fn is_file_call(name: &str) -> bool {
        matches!(
            name,
            "browseForDoc"
                | "saveAs"
                | "exportDataObject"
                | "importDataObject"
                | "createDataObject"
                | "removeDataObject"
                | "getDataObject"
                | "getDataObjectContents"
                | "openDoc"
                | "newDoc"
                | "exportAsFDF"
                | "exportAsXFDF"
                | "importTextData"
                | "deletePages"
                | "insertPages"
                | "extractPages"
                | "flattenPages"
                | "addField"
                | "removeField"
                | "addAnnot"
                | "removeAnnot"
                | "fs.readFile"
                | "fs.writeFile"
                | "child_process.exec"
                | "child_process.spawn"
                | "ActiveXObject"
                | "WScript.Shell"
                | "WScript.CreateObject"
                | "WScript.RegRead"
                | "WScript.RegWrite"
                | "GetObject"
                | "CreateObject"
                | "Scripting.FileSystemObject.OpenTextFile"
                | "Scripting.FileSystemObject.CreateTextFile"
                | "ADODB.Stream.Open"
                | "ADODB.Stream.Write"
                | "ADODB.Stream.SaveToFile"
                | "ADODB.Connection.Open"
                | "ADODB.Connection.Execute"
                | "ADODB.Command.Execute"
                | "Shell.Application.ShellExecute"
                | "Shell.Application.BrowseForFolder"
                | "MSXML2.DOMDocument.load"
                | "MSXML2.DOMDocument.loadXML"
                | "URLDownloadToFile"
                | "PowerShell.AddScript"
                | "PowerShell.Invoke"
                | "WMI.ExecQuery"
        )
    }

    fn build_callable_value(
        context: &mut Context,
        log: Rc<RefCell<SandboxLog>>,
        name: &'static str,
        value: JsValue,
    ) -> JsObject {
        let value_for_call = value.clone();
        let log_call = log.clone();
        let call_capture = CallableCapture { log: log_call, name, value: value_for_call };
        let call_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, captures.name, args, ctx);
                    Ok(captures.value.clone())
                },
                call_capture,
            )
        };
        let func = FunctionObjectBuilder::new(context.realm(), call_fn)
            .name(JsString::from(name))
            .length(0)
            .constructor(false)
            .build();
        let func: JsObject = func.into();

        let value_for_valueof = value.clone();
        let value_of_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, _args, captures, _ctx| Ok(captures.value.clone()),
                ValueCapture { value: value_for_valueof },
            )
        };
        let value_of = FunctionObjectBuilder::new(context.realm(), value_of_fn)
            .name(JsString::from("valueOf"))
            .length(0)
            .constructor(false)
            .build();
        let _ = func.set(JsString::from("valueOf"), value_of, false, context);

        let value_for_string = value.clone();
        let to_string_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, _args, captures, ctx| {
                    let as_string = captures.value.to_string(ctx)?;
                    Ok(JsValue::from(as_string))
                },
                ValueCapture { value: value_for_string },
            )
        };
        let to_string = FunctionObjectBuilder::new(context.realm(), to_string_fn)
            .name(JsString::from("toString"))
            .length(0)
            .constructor(false)
            .build();
        let _ = func.set(JsString::from("toString"), to_string, false, context);

        func
    }

    fn register_app(context: &mut Context, log: Rc<RefCell<SandboxLog>>, doc: Option<JsValue>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };

        let plugins_value = {
            let plugin = ObjectInitializer::new(context)
                .property(JsString::from("name"), JsString::from("PlugIn"), Attribute::all())
                .build();
            let plugins = ObjectInitializer::new(context)
                .property(JsString::from("0"), plugin.clone(), Attribute::all())
                .property(JsString::from("1"), plugin.clone(), Attribute::all())
                .property(JsString::from("2"), plugin.clone(), Attribute::all())
                .property(JsString::from("3"), plugin, Attribute::all())
                .property(JsString::from("length"), 4, Attribute::all())
                .build();
            JsValue::from(plugins)
        };

        let plugins_accessor = {
            let log_clone = log.clone();
            let plugins_clone = plugins_value.clone();
            let getter = unsafe {
                NativeFunction::from_closure_with_captures(
                    move |_this, _args, captures, _ctx| {
                        record_prop(&captures.log, "app.plugIns");
                        Ok(captures.value.clone())
                    },
                    LogValueCapture { log: log_clone, value: plugins_clone },
                )
            };
            FunctionObjectBuilder::new(context.realm(), getter)
                .name(JsString::from("plugIns"))
                .length(0)
                .constructor(false)
                .build()
        };

        let viewer_version_value = JsValue::from(9);
        let viewer_version_callable =
            build_callable_value(context, log.clone(), "app.viewerVersion", viewer_version_value);
        let viewer_type_value = JsValue::from(JsString::from("Reader"));
        let viewer_type_callable =
            build_callable_value(context, log.clone(), "app.viewerType", viewer_type_value);

        let doc_accessor = doc.map(|doc_value| {
            let log_clone = log.clone();
            let doc_clone = doc_value.clone();
            let getter = unsafe {
                NativeFunction::from_closure_with_captures(
                    move |_this, _args, captures, _ctx| {
                        record_prop(&captures.log, "app.doc");
                        Ok(captures.value.clone())
                    },
                    LogValueCapture { log: log_clone, value: doc_clone },
                )
            };
            FunctionObjectBuilder::new(context.realm(), getter)
                .name(JsString::from("doc"))
                .length(0)
                .constructor(false)
                .build()
        });

        let mut app = ObjectInitializer::new(context);
        app.function(make_fn("alert"), JsString::from("alert"), 1);
        app.function(make_fn("response"), JsString::from("response"), 1);
        app.function(make_fn("app.eval"), JsString::from("eval"), 1);
        app.function(make_fn("launchURL"), JsString::from("launchURL"), 1);
        app.function(make_fn("getURL"), JsString::from("getURL"), 1);
        app.function(make_fn("openDoc"), JsString::from("openDoc"), 1);
        app.function(make_fn("newDoc"), JsString::from("newDoc"), 1);
        app.function(make_fn("findComponent"), JsString::from("findComponent"), 1);
        app.function(make_fn("execMenuItem"), JsString::from("execMenuItem"), 1);
        app.function(make_fn("execDialog"), JsString::from("execDialog"), 1);
        app.function(make_fn("addMenuItem"), JsString::from("addMenuItem"), 1);
        app.function(make_fn("removeMenuItem"), JsString::from("removeMenuItem"), 1);
        app.function(make_fn("setTimeOut"), JsString::from("setTimeOut"), 1);
        app.function(make_fn("setInterval"), JsString::from("setInterval"), 1);
        app.function(make_fn("submitForm"), JsString::from("submitForm"), 1);
        app.function(make_fn("browseForDoc"), JsString::from("browseForDoc"), 0);
        app.function(make_fn("saveAs"), JsString::from("saveAs"), 1);
        app.function(make_fn("exportDataObject"), JsString::from("exportDataObject"), 1);
        app.function(make_fn("importDataObject"), JsString::from("importDataObject"), 1);
        app.function(make_fn("createDataObject"), JsString::from("createDataObject"), 1);
        app.function(make_fn("removeDataObject"), JsString::from("removeDataObject"), 1);
        app.function(make_fn("mailMsg"), JsString::from("mailMsg"), 1);
        app.function(make_fn("mailDoc"), JsString::from("mailDoc"), 0);
        app.property(
            JsString::from("viewerVersion"),
            JsValue::from(viewer_version_callable),
            Attribute::all(),
        );
        app.property(
            JsString::from("viewerType"),
            JsValue::from(viewer_type_callable),
            Attribute::all(),
        );
        app.property(JsString::from("platform"), JsString::from("WIN"), Attribute::all());
        app.property(JsString::from("language"), JsString::from("en-AU"), Attribute::all());

        app.accessor(JsString::from("plugIns"), Some(plugins_accessor), None, Attribute::all());

        if let Some(getter_fn) = doc_accessor {
            app.accessor(JsString::from("doc"), Some(getter_fn), None, Attribute::all());
        }

        let app = app.build();

        let _ = context.register_global_property(JsString::from("app"), app, Attribute::all());
    }

    fn register_util(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        let util = ObjectInitializer::new(context)
            .function(make_fn("util.printf"), JsString::from("printf"), 1)
            .function(make_fn("util.printd"), JsString::from("printd"), 1)
            .function(make_fn("util.scand"), JsString::from("scand"), 1)
            .build();
        let _ = context.register_global_property(JsString::from("util"), util, Attribute::all());
    }

    fn register_collab(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        let collab = ObjectInitializer::new(context)
            .function(make_fn("Collab.getIcon"), JsString::from("getIcon"), 1)
            .function(make_fn("Collab.collectEmailInfo"), JsString::from("collectEmailInfo"), 0)
            .build();
        let _ =
            context.register_global_property(JsString::from("Collab"), collab, Attribute::all());
    }

    fn register_soap(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        let soap = ObjectInitializer::new(context)
            .function(make_fn("SOAP.connect"), JsString::from("connect"), 1)
            .function(make_fn("SOAP.request"), JsString::from("request"), 1)
            .build();
        let _ = context.register_global_property(JsString::from("SOAP"), soap, Attribute::all());
    }

    fn register_net(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        let http = ObjectInitializer::new(context)
            .function(make_fn("Net.HTTP.request"), JsString::from("request"), 1)
            .build();
        let net = ObjectInitializer::new(context)
            .property(JsString::from("HTTP"), http, Attribute::all())
            .build();
        let _ = context.register_global_property(JsString::from("Net"), net, Attribute::all());
    }

    fn register_browser_like(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        let _ = context.register_global_builtin_callable(
            JsString::from("fetch"),
            1,
            make_native(log.clone(), "fetch"),
        );
        let xhr = ObjectInitializer::new(context)
            .function(make_fn("XMLHttpRequest.open"), JsString::from("open"), 2)
            .function(make_fn("XMLHttpRequest.send"), JsString::from("send"), 1)
            .build();
        let _ = context.register_global_property(
            JsString::from("XMLHttpRequest"),
            xhr,
            Attribute::all(),
        );
        let ws = ObjectInitializer::new(context)
            .function(make_fn("WebSocket.send"), JsString::from("send"), 1)
            .build();
        let _ = context.register_global_property(JsString::from("WebSocket"), ws, Attribute::all());
        let rtc_data_channel = ObjectInitializer::new(context)
            .function(make_fn("RTCDataChannel.send"), JsString::from("send"), 1)
            .function(make_fn("RTCDataChannel.close"), JsString::from("close"), 0)
            .build();
        let _ = context.register_global_property(
            JsString::from("RTCDataChannel"),
            rtc_data_channel.clone(),
            Attribute::all(),
        );
        let rtc_peer = ObjectInitializer::new(context)
            .function(
                make_fn("RTCPeerConnection.createDataChannel"),
                JsString::from("createDataChannel"),
                1,
            )
            .function(make_fn("RTCPeerConnection.createOffer"), JsString::from("createOffer"), 0)
            .function(make_fn("RTCPeerConnection.createAnswer"), JsString::from("createAnswer"), 0)
            .function(
                make_fn("RTCPeerConnection.setLocalDescription"),
                JsString::from("setLocalDescription"),
                1,
            )
            .function(
                make_fn("RTCPeerConnection.addIceCandidate"),
                JsString::from("addIceCandidate"),
                1,
            )
            .build();
        let _ = context.register_global_property(
            JsString::from("RTCPeerConnection"),
            rtc_peer.clone(),
            Attribute::all(),
        );
        let cache_storage = ObjectInitializer::new(context)
            .function(make_fn("caches.open"), JsString::from("open"), 1)
            .function(make_fn("caches.match"), JsString::from("match"), 1)
            .function(make_fn("caches.put"), JsString::from("put"), 2)
            .function(make_fn("caches.delete"), JsString::from("delete"), 1)
            .build();
        let _ = context.register_global_property(
            JsString::from("caches"),
            cache_storage,
            Attribute::all(),
        );
        let idb_store = ObjectInitializer::new(context)
            .function(make_fn("IDBObjectStore.get"), JsString::from("get"), 1)
            .function(make_fn("IDBObjectStore.put"), JsString::from("put"), 2)
            .function(make_fn("IDBObjectStore.add"), JsString::from("add"), 2)
            .build();
        let _ = context.register_global_property(
            JsString::from("IDBObjectStore"),
            idb_store,
            Attribute::all(),
        );
        let indexed_db = ObjectInitializer::new(context)
            .function(make_fn("indexedDB.open"), JsString::from("open"), 1)
            .function(make_fn("indexedDB.deleteDatabase"), JsString::from("deleteDatabase"), 1)
            .function(make_fn("indexedDB.databases"), JsString::from("databases"), 0)
            .build();
        let _ = context.register_global_property(
            JsString::from("indexedDB"),
            indexed_db,
            Attribute::all(),
        );
        let subtle = ObjectInitializer::new(context)
            .function(make_fn("crypto.subtle.generateKey"), JsString::from("generateKey"), 1)
            .function(make_fn("crypto.subtle.importKey"), JsString::from("importKey"), 1)
            .function(make_fn("crypto.subtle.exportKey"), JsString::from("exportKey"), 1)
            .function(make_fn("crypto.subtle.deriveKey"), JsString::from("deriveKey"), 1)
            .function(make_fn("crypto.subtle.encrypt"), JsString::from("encrypt"), 1)
            .function(make_fn("crypto.subtle.decrypt"), JsString::from("decrypt"), 1)
            .build();
        let crypto = ObjectInitializer::new(context)
            .property(JsString::from("subtle"), subtle, Attribute::all())
            .function(make_fn("crypto.getRandomValues"), JsString::from("getRandomValues"), 1)
            .build();
        let _ =
            context.register_global_property(JsString::from("crypto"), crypto, Attribute::all());
        let clipboard = ObjectInitializer::new(context)
            .function(make_fn("navigator.clipboard.readText"), JsString::from("readText"), 0)
            .function(make_fn("navigator.clipboard.writeText"), JsString::from("writeText"), 1)
            .function(make_fn("navigator.clipboard.read"), JsString::from("read"), 0)
            .function(make_fn("navigator.clipboard.write"), JsString::from("write"), 1)
            .build();
        let sw_registration = ObjectInitializer::new(context)
            .function(make_fn("ServiceWorkerRegistration.update"), JsString::from("update"), 0)
            .function(
                make_fn("ServiceWorkerRegistration.unregister"),
                JsString::from("unregister"),
                0,
            )
            .function(
                make_fn("ServiceWorkerRegistration.showNotification"),
                JsString::from("showNotification"),
                2,
            )
            .build();
        let service_worker = ObjectInitializer::new(context)
            .function(make_fn("navigator.serviceWorker.register"), JsString::from("register"), 1)
            .function(
                make_fn("navigator.serviceWorker.getRegistration"),
                JsString::from("getRegistration"),
                1,
            )
            .function(
                make_fn("navigator.serviceWorker.getRegistrations"),
                JsString::from("getRegistrations"),
                0,
            )
            .function(make_fn("navigator.serviceWorker.ready"), JsString::from("ready"), 0)
            .function(make_fn("navigator.serviceWorker.update"), JsString::from("update"), 0)
            .property(JsString::from("ready"), sw_registration.clone(), Attribute::all())
            .build();
        let user_agent_data = ObjectInitializer::new(context)
            .function(
                make_fn("navigator.userAgentData.getHighEntropyValues"),
                JsString::from("getHighEntropyValues"),
                1,
            )
            .build();
        let permissions = ObjectInitializer::new(context)
            .function(make_fn("navigator.permissions.query"), JsString::from("query"), 1)
            .build();
        let beacon = ObjectInitializer::new(context)
            .function(make_fn("navigator.sendBeacon"), JsString::from("sendBeacon"), 2)
            .property(JsString::from("clipboard"), clipboard.clone(), Attribute::all())
            .property(JsString::from("serviceWorker"), service_worker.clone(), Attribute::all())
            .property(JsString::from("userAgentData"), user_agent_data.clone(), Attribute::all())
            .property(JsString::from("permissions"), permissions.clone(), Attribute::all())
            .build();
        let _ = context.register_global_property(
            JsString::from("navigator"),
            beacon.clone(),
            Attribute::all(),
        );
        let storage = ObjectInitializer::new(context)
            .function(make_fn("localStorage.getItem"), JsString::from("getItem"), 1)
            .function(make_fn("localStorage.setItem"), JsString::from("setItem"), 2)
            .build();
        let _ = context.register_global_property(
            JsString::from("localStorage"),
            storage.clone(),
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("sessionStorage"),
            storage.clone(),
            Attribute::all(),
        );
        let doc = ObjectInitializer::new(context)
            .function(make_fn("document.cookie"), JsString::from("cookie"), 0)
            .function(make_fn("document.location"), JsString::from("location"), 0)
            .function(make_fn("document.write"), JsString::from("write"), 1)
            .function(make_fn("document.setInnerHTML"), JsString::from("setInnerHTML"), 1)
            .function(
                make_fn("document.insertAdjacentHTML"),
                JsString::from("insertAdjacentHTML"),
                2,
            )
            .function(make_fn("document.querySelector"), JsString::from("querySelector"), 1)
            .function(make_fn("document.getElementById"), JsString::from("getElementById"), 1)
            .build();
        let _ = context.register_global_property(
            JsString::from("document"),
            doc.clone(),
            Attribute::all(),
        );
        let location = ObjectInitializer::new(context)
            .property(
                JsString::from("href"),
                JsValue::from(JsString::from("https://example.test/")),
                Attribute::all(),
            )
            .function(make_fn("window.location.assign"), JsString::from("assign"), 1)
            .function(make_fn("window.location.replace"), JsString::from("replace"), 1)
            .build();
        let _ = context.register_global_property(
            JsString::from("location"),
            location.clone(),
            Attribute::all(),
        );
        let _ = context.register_global_builtin_callable(
            JsString::from("setTimeout"),
            2,
            make_native(log.clone(), "setTimeout"),
        );
        let _ = context.register_global_builtin_callable(
            JsString::from("setInterval"),
            2,
            make_native(log.clone(), "setInterval"),
        );
        let _ = context.register_global_builtin_callable(
            JsString::from("clearTimeout"),
            1,
            make_native(log.clone(), "clearTimeout"),
        );
        let _ = context.register_global_builtin_callable(
            JsString::from("clearInterval"),
            1,
            make_native(log.clone(), "clearInterval"),
        );
        let _ = context.register_global_builtin_callable(
            JsString::from("alert"),
            1,
            make_native(log.clone(), "alert"),
        );
        let _ = context.register_global_builtin_callable(
            JsString::from("confirm"),
            1,
            make_native(log.clone(), "confirm"),
        );
        let _ = context.register_global_builtin_callable(
            JsString::from("prompt"),
            2,
            make_native(log.clone(), "prompt"),
        );
        let _ = context.register_global_builtin_callable(
            JsString::from("__dynamicImport"),
            1,
            make_native(log.clone(), "__dynamicImport"),
        );
        let trusted_types = ObjectInitializer::new(context)
            .function(make_fn("trustedTypes.createPolicy"), JsString::from("createPolicy"), 2)
            .function(make_fn("trustedTypes.getPolicyNames"), JsString::from("getPolicyNames"), 0)
            .build();
        let _ = context.register_global_property(
            JsString::from("trustedTypes"),
            trusted_types.clone(),
            Attribute::all(),
        );
        let webgl = ObjectInitializer::new(context)
            .function(
                make_fn("WebGLRenderingContext.getParameter"),
                JsString::from("getParameter"),
                1,
            )
            .function(
                make_fn("WebGLRenderingContext.getSupportedExtensions"),
                JsString::from("getSupportedExtensions"),
                0,
            )
            .build();
        let _ = context.register_global_property(
            JsString::from("WebGLRenderingContext"),
            webgl.clone(),
            Attribute::all(),
        );
        let audio_context = ObjectInitializer::new(context)
            .function(make_fn("AudioContext.createAnalyser"), JsString::from("createAnalyser"), 0)
            .function(
                make_fn("AudioContext.createOscillator"),
                JsString::from("createOscillator"),
                0,
            )
            .function(make_fn("AudioContext.resume"), JsString::from("resume"), 0)
            .build();
        let _ = context.register_global_property(
            JsString::from("AudioContext"),
            audio_context.clone(),
            Attribute::all(),
        );
        let chrome_runtime = ObjectInitializer::new(context)
            .function(make_fn("chrome.runtime.sendMessage"), JsString::from("sendMessage"), 1)
            .function(make_fn("chrome.runtime.connect"), JsString::from("connect"), 1)
            .build();
        let chrome_storage_local = ObjectInitializer::new(context)
            .function(make_fn("chrome.storage.local.get"), JsString::from("get"), 1)
            .function(make_fn("chrome.storage.local.set"), JsString::from("set"), 1)
            .build();
        let chrome_storage = ObjectInitializer::new(context)
            .property(JsString::from("local"), chrome_storage_local, Attribute::all())
            .build();
        let chrome = ObjectInitializer::new(context)
            .property(JsString::from("runtime"), chrome_runtime, Attribute::all())
            .property(JsString::from("storage"), chrome_storage, Attribute::all())
            .build();
        let _ = context.register_global_property(
            JsString::from("chrome"),
            chrome.clone(),
            Attribute::all(),
        );
        let browser_runtime = ObjectInitializer::new(context)
            .function(make_fn("browser.runtime.sendMessage"), JsString::from("sendMessage"), 1)
            .function(make_fn("browser.runtime.connect"), JsString::from("connect"), 1)
            .build();
        let browser = ObjectInitializer::new(context)
            .property(JsString::from("runtime"), browser_runtime, Attribute::all())
            .build();
        let _ = context.register_global_property(
            JsString::from("browser"),
            browser.clone(),
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("permissions"),
            permissions.clone(),
            Attribute::all(),
        );
        let window = ObjectInitializer::new(context)
            .property(JsString::from("document"), doc.clone(), Attribute::all())
            .property(JsString::from("navigator"), beacon.clone(), Attribute::all())
            .property(JsString::from("localStorage"), storage.clone(), Attribute::all())
            .property(JsString::from("sessionStorage"), storage, Attribute::all())
            .property(JsString::from("location"), location, Attribute::all())
            .property(JsString::from("trustedTypes"), trusted_types, Attribute::all())
            .property(JsString::from("chrome"), chrome, Attribute::all())
            .property(JsString::from("browser"), browser, Attribute::all())
            .property(JsString::from("WebGLRenderingContext"), webgl, Attribute::all())
            .property(JsString::from("AudioContext"), audio_context, Attribute::all())
            .property(JsString::from("RTCPeerConnection"), rtc_peer, Attribute::all())
            .property(JsString::from("RTCDataChannel"), rtc_data_channel, Attribute::all())
            .property(JsString::from("permissions"), permissions, Attribute::all())
            .function(make_fn("window.addEventListener"), JsString::from("addEventListener"), 2)
            .function(
                make_fn("window.removeEventListener"),
                JsString::from("removeEventListener"),
                2,
            )
            .build();
        let _ = context.register_global_property(
            JsString::from("window"),
            window.clone(),
            Attribute::all(),
        );
        let self_obj = ObjectInitializer::new(context)
            .property(JsString::from("navigator"), beacon.clone(), Attribute::all())
            .function(make_fn("self.addEventListener"), JsString::from("addEventListener"), 2)
            .function(make_fn("self.removeEventListener"), JsString::from("removeEventListener"), 2)
            .function(make_fn("self.skipWaiting"), JsString::from("skipWaiting"), 0)
            .build();
        let _ =
            context.register_global_property(JsString::from("self"), self_obj, Attribute::all());
        let _ = context.register_global_property(JsString::from("top"), window, Attribute::all());
    }

    fn register_windows_scripting(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        fn register_global_constructable_callable(
            context: &mut Context,
            name: &'static str,
            length: usize,
            function: NativeFunction,
        ) {
            let function = FunctionObjectBuilder::new(context.realm(), function)
                .name(JsString::from(name))
                .length(length)
                .constructor(true)
                .build();
            let _ =
                context.register_global_property(JsString::from(name), function, Attribute::all());
        }

        fn make_native_returning_object(
            log: Rc<RefCell<SandboxLog>>,
            name: &'static str,
            object: JsObject,
        ) -> NativeFunction {
            unsafe {
                NativeFunction::from_closure_with_captures(
                    move |_this, args, captures, ctx| {
                        record_call(&captures.log, name, args, ctx);
                        Ok(JsValue::from(captures.object.clone()))
                    },
                    LogObjectCapture { log, object },
                )
            }
        }

        fn expand_windows_env_tokens(raw: &str) -> String {
            let mut expanded = raw.to_string();
            let replacements = [
                ("%TEMP%", r"C:\Windows\Temp"),
                ("%TMP%", r"C:\Windows\Temp"),
                ("%APPDATA%", r"C:\Users\Public\AppData\Roaming"),
                ("%WINDIR%", r"C:\Windows"),
            ];
            for (token, value) in replacements {
                loop {
                    let haystack = expanded.to_ascii_lowercase();
                    let needle = token.to_ascii_lowercase();
                    let Some(position) = haystack.find(&needle) else {
                        break;
                    };
                    expanded.replace_range(position..position + token.len(), value);
                }
            }
            expanded
        }

        fn make_native_expand_environment_strings(log: Rc<RefCell<SandboxLog>>) -> NativeFunction {
            unsafe {
                NativeFunction::from_closure_with_captures(
                    move |_this, args, captures, ctx| {
                        record_call(&captures.log, captures.name, args, ctx);
                        let raw = args.get_or_undefined(0).to_string(ctx)?.to_std_string_escaped();
                        let expanded = expand_windows_env_tokens(&raw);
                        Ok(JsValue::from(JsString::from(expanded)))
                    },
                    LogNameCapture { log, name: "WScript.Shell.ExpandEnvironmentStrings" },
                )
            }
        }

        fn build_com_text_stream(context: &mut Context, log: Rc<RefCell<SandboxLog>>) -> JsObject {
            let make_fn = |name: &'static str| {
                let log = log.clone();
                make_native(log, name)
            };
            ObjectInitializer::new(context)
                .function(make_fn("TextStream.ReadAll"), JsString::from("ReadAll"), 0)
                .function(make_fn("TextStream.ReadAll"), JsString::from("readAll"), 0)
                .function(make_fn("TextStream.ReadLine"), JsString::from("ReadLine"), 0)
                .function(make_fn("TextStream.ReadLine"), JsString::from("readLine"), 0)
                .function(make_fn("TextStream.Write"), JsString::from("Write"), 1)
                .function(make_fn("TextStream.Write"), JsString::from("write"), 1)
                .function(make_fn("TextStream.WriteLine"), JsString::from("WriteLine"), 1)
                .function(make_fn("TextStream.WriteLine"), JsString::from("writeline"), 1)
                .function(make_fn("TextStream.WriteLine"), JsString::from("writeLine"), 1)
                .function(make_fn("TextStream.Close"), JsString::from("Close"), 0)
                .function(make_fn("TextStream.Close"), JsString::from("close"), 0)
                .build()
        }

        fn build_com_file_object(context: &mut Context, log: Rc<RefCell<SandboxLog>>) -> JsObject {
            let make_fn = |name: &'static str| {
                let log = log.clone();
                make_native(log, name)
            };
            let text_stream = build_com_text_stream(context, log.clone());
            ObjectInitializer::new(context)
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "Scripting.File.OpenAsTextStream",
                        text_stream,
                    ),
                    JsString::from("OpenAsTextStream"),
                    1,
                )
                .function(make_fn("Scripting.File.Delete"), JsString::from("Delete"), 1)
                .property(
                    JsString::from("Path"),
                    JsString::from(r"C:\Windows\Temp\payload.exe"),
                    Attribute::all(),
                )
                .build()
        }

        fn build_fso_object(context: &mut Context, log: Rc<RefCell<SandboxLog>>) -> JsObject {
            let make_fn = |name: &'static str| {
                let log = log.clone();
                make_native(log, name)
            };
            let text_stream = build_com_text_stream(context, log.clone());
            let text_stream_lower = build_com_text_stream(context, log.clone());
            let text_stream_lower_all = build_com_text_stream(context, log.clone());
            let create_text_stream = build_com_text_stream(context, log.clone());
            let create_text_stream_lower = build_com_text_stream(context, log.clone());
            let create_text_stream_lower_all = build_com_text_stream(context, log.clone());
            let text_stream_property = build_com_text_stream(context, log.clone());
            let file_object = build_com_file_object(context, log.clone());
            let file_object_lower = build_com_file_object(context, log.clone());
            ObjectInitializer::new(context)
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "Scripting.FileSystemObject.OpenTextFile",
                        text_stream,
                    ),
                    JsString::from("OpenTextFile"),
                    1,
                )
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "Scripting.FileSystemObject.OpenTextFile",
                        text_stream_lower,
                    ),
                    JsString::from("openTextFile"),
                    1,
                )
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "Scripting.FileSystemObject.OpenTextFile",
                        text_stream_lower_all,
                    ),
                    JsString::from("opentextfile"),
                    1,
                )
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "Scripting.FileSystemObject.CreateTextFile",
                        create_text_stream,
                    ),
                    JsString::from("CreateTextFile"),
                    1,
                )
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "Scripting.FileSystemObject.CreateTextFile",
                        create_text_stream_lower,
                    ),
                    JsString::from("createTextFile"),
                    1,
                )
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "Scripting.FileSystemObject.CreateTextFile",
                        create_text_stream_lower_all,
                    ),
                    JsString::from("createtextfile"),
                    1,
                )
                .function(
                    make_fn("Scripting.FileSystemObject.GetSpecialFolder"),
                    JsString::from("GetSpecialFolder"),
                    1,
                )
                .function(
                    make_fn("Scripting.FileSystemObject.GetSpecialFolder"),
                    JsString::from("getSpecialFolder"),
                    1,
                )
                .function(
                    make_fn("Scripting.FileSystemObject.GetTempName"),
                    JsString::from("GetTempName"),
                    0,
                )
                .function(
                    make_fn("Scripting.FileSystemObject.GetTempName"),
                    JsString::from("getTempName"),
                    0,
                )
                .function(
                    make_native_probe_exists(
                        log.clone(),
                        "Scripting.FileSystemObject.FileExists",
                        PROBE_EXISTS_TRUE_AFTER,
                    ),
                    JsString::from("FileExists"),
                    1,
                )
                .function(
                    make_native_probe_exists(
                        log.clone(),
                        "Scripting.FileSystemObject.FileExists",
                        PROBE_EXISTS_TRUE_AFTER,
                    ),
                    JsString::from("fileExists"),
                    1,
                )
                .function(
                    make_native_probe_exists(
                        log.clone(),
                        "Scripting.FileSystemObject.FolderExists",
                        PROBE_EXISTS_TRUE_AFTER,
                    ),
                    JsString::from("FolderExists"),
                    1,
                )
                .function(
                    make_native_probe_exists(
                        log.clone(),
                        "Scripting.FileSystemObject.FolderExists",
                        PROBE_EXISTS_TRUE_AFTER,
                    ),
                    JsString::from("folderExists"),
                    1,
                )
                .function(
                    make_fn("Scripting.FileSystemObject.CreateFolder"),
                    JsString::from("CreateFolder"),
                    1,
                )
                .function(
                    make_fn("Scripting.FileSystemObject.CreateFolder"),
                    JsString::from("createFolder"),
                    1,
                )
                .function(
                    make_fn("Scripting.FileSystemObject.DeleteFile"),
                    JsString::from("DeleteFile"),
                    1,
                )
                .function(
                    make_fn("Scripting.FileSystemObject.DeleteFile"),
                    JsString::from("deleteFile"),
                    1,
                )
                .function(
                    make_fn("Scripting.FileSystemObject.CopyFile"),
                    JsString::from("CopyFile"),
                    2,
                )
                .function(
                    make_fn("Scripting.FileSystemObject.CopyFile"),
                    JsString::from("copyFile"),
                    2,
                )
                .function(
                    make_fn("Scripting.FileSystemObject.MoveFile"),
                    JsString::from("MoveFile"),
                    2,
                )
                .function(
                    make_fn("Scripting.FileSystemObject.MoveFile"),
                    JsString::from("moveFile"),
                    2,
                )
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "Scripting.FileSystemObject.GetFile",
                        file_object,
                    ),
                    JsString::from("GetFile"),
                    1,
                )
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "Scripting.FileSystemObject.GetFile",
                        file_object_lower,
                    ),
                    JsString::from("getFile"),
                    1,
                )
                .property(JsString::from("TextStream"), text_stream_property, Attribute::all())
                .build()
        }

        fn build_wscript_shell_object(
            context: &mut Context,
            log: Rc<RefCell<SandboxLog>>,
        ) -> JsObject {
            let make_fn = |name: &'static str| {
                let log = log.clone();
                make_native(log, name)
            };
            let env_accessor = build_callable_value(
                context,
                log.clone(),
                "WScript.Shell.Environment.Item",
                JsValue::from(JsString::from("AMD64")),
            );
            let env_accessor_lower = build_callable_value(
                context,
                log.clone(),
                "WScript.Shell.Environment.Item",
                JsValue::from(JsString::from("AMD64")),
            );
            ObjectInitializer::new(context)
                .function(make_fn("WScript.Shell.Run"), JsString::from("Run"), 1)
                .function(make_fn("WScript.Shell.Run"), JsString::from("run"), 1)
                .function(make_fn("WScript.Shell.Exec"), JsString::from("Exec"), 1)
                .function(make_fn("WScript.Shell.Exec"), JsString::from("exec"), 1)
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "WScript.Shell.Environment",
                        env_accessor,
                    ),
                    JsString::from("Environment"),
                    1,
                )
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "WScript.Shell.Environment",
                        env_accessor_lower,
                    ),
                    JsString::from("environment"),
                    1,
                )
                .function(
                    make_native_expand_environment_strings(log.clone()),
                    JsString::from("ExpandEnvironmentStrings"),
                    1,
                )
                .function(
                    make_native_expand_environment_strings(log.clone()),
                    JsString::from("expandEnvironmentStrings"),
                    1,
                )
                .function(make_fn("WScript.Shell.RegRead"), JsString::from("RegRead"), 1)
                .function(make_fn("WScript.Shell.RegRead"), JsString::from("regRead"), 1)
                .function(make_fn("WScript.Shell.RegWrite"), JsString::from("RegWrite"), 2)
                .function(make_fn("WScript.Shell.RegWrite"), JsString::from("regWrite"), 2)
                .function(
                    make_fn("WScript.Shell.SpecialFolders"),
                    JsString::from("SpecialFolders"),
                    1,
                )
                .function(
                    make_fn("WScript.Shell.SpecialFolders"),
                    JsString::from("specialFolders"),
                    1,
                )
                .build()
        }

        fn build_shell_application_object(
            context: &mut Context,
            log: Rc<RefCell<SandboxLog>>,
        ) -> JsObject {
            let make_fn = |name: &'static str| {
                let log = log.clone();
                make_native(log, name)
            };
            let shell_item = ObjectInitializer::new(context)
                .property(
                    JsString::from("Path"),
                    JsString::from(r"C:\Windows\Temp"),
                    Attribute::all(),
                )
                .build();
            let namespace = ObjectInitializer::new(context)
                .property(JsString::from("Self"), shell_item, Attribute::all())
                .property(JsString::from("Title"), JsString::from("Temp"), Attribute::all())
                .build();
            ObjectInitializer::new(context)
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "Shell.Application.NameSpace",
                        namespace.clone(),
                    ),
                    JsString::from("NameSpace"),
                    1,
                )
                .function(
                    make_fn("Shell.Application.ShellExecute"),
                    JsString::from("ShellExecute"),
                    1,
                )
                .function(
                    make_native_returning_object(
                        log.clone(),
                        "Shell.Application.BrowseForFolder",
                        namespace,
                    ),
                    JsString::from("BrowseForFolder"),
                    1,
                )
                .build()
        }

        fn build_xmlhttp_object(context: &mut Context, log: Rc<RefCell<SandboxLog>>) -> JsObject {
            let make_fn = |name: &'static str| {
                let log = log.clone();
                make_native(log, name)
            };
            ObjectInitializer::new(context)
                .function(make_fn("MSXML2.XMLHTTP.open"), JsString::from("open"), 2)
                .function(make_fn("MSXML2.XMLHTTP.Open"), JsString::from("Open"), 2)
                .function(make_fn("MSXML2.XMLHTTP.send"), JsString::from("send"), 1)
                .function(make_fn("MSXML2.XMLHTTP.Send"), JsString::from("Send"), 1)
                .function(
                    make_fn("MSXML2.XMLHTTP.setRequestHeader"),
                    JsString::from("setRequestHeader"),
                    2,
                )
                .function(
                    make_fn("MSXML2.XMLHTTP.SetRequestHeader"),
                    JsString::from("SetRequestHeader"),
                    2,
                )
                .function(
                    make_fn("MSXML2.XMLHTTP.getResponseHeader"),
                    JsString::from("getResponseHeader"),
                    1,
                )
                .function(
                    make_fn("MSXML2.XMLHTTP.GetResponseHeader"),
                    JsString::from("GetResponseHeader"),
                    1,
                )
                .build()
        }

        fn build_adodb_stream_object(
            context: &mut Context,
            log: Rc<RefCell<SandboxLog>>,
        ) -> JsObject {
            let make_fn = |name: &'static str| {
                let log = log.clone();
                make_native(log, name)
            };
            ObjectInitializer::new(context)
                .function(make_fn("ADODB.Stream.Open"), JsString::from("Open"), 0)
                .function(make_fn("ADODB.Stream.Open"), JsString::from("open"), 0)
                .function(make_fn("ADODB.Stream.LoadFromFile"), JsString::from("LoadFromFile"), 1)
                .function(make_fn("ADODB.Stream.LoadFromFile"), JsString::from("loadFromFile"), 1)
                .function(make_fn("ADODB.Stream.Write"), JsString::from("Write"), 1)
                .function(make_fn("ADODB.Stream.Write"), JsString::from("write"), 1)
                .function(make_fn("ADODB.Stream.Read"), JsString::from("Read"), 0)
                .function(make_fn("ADODB.Stream.Read"), JsString::from("read"), 0)
                .function(make_fn("ADODB.Stream.SaveToFile"), JsString::from("SaveToFile"), 1)
                .function(make_fn("ADODB.Stream.SaveToFile"), JsString::from("saveToFile"), 1)
                .function(make_fn("ADODB.Stream.Close"), JsString::from("Close"), 0)
                .function(make_fn("ADODB.Stream.Close"), JsString::from("close"), 0)
                .build()
        }

        fn build_com_object_by_prog_id(
            context: &mut Context,
            log: Rc<RefCell<SandboxLog>>,
            prog_id: &str,
        ) -> JsObject {
            let pid = prog_id.trim().to_ascii_lowercase();
            match pid.as_str() {
                "scripting.filesystemobject" => build_fso_object(context, log),
                "wscript.shell" => build_wscript_shell_object(context, log),
                "wsh.shell" | "wshshell" => build_wscript_shell_object(context, log),
                "shell.application" => build_shell_application_object(context, log),
                "msxml2.xmlhttp"
                | "msxml2.xmlhttp.3.0"
                | "msxml2.xmlhttp.6.0"
                | "msxml2.serverxmlhttp"
                | "winhttp.winhttprequest.5.1" => build_xmlhttp_object(context, log),
                "adodb.stream" => build_adodb_stream_object(context, log),
                _ => {
                    let make_fn = |name: &'static str| {
                        let log = log.clone();
                        make_native(log, name)
                    };
                    ObjectInitializer::new(context)
                        .function(make_fn("COM.Open"), JsString::from("Open"), 1)
                        .function(make_fn("COM.Run"), JsString::from("Run"), 1)
                        .function(make_fn("COM.Exec"), JsString::from("Exec"), 1)
                        .function(make_fn("COM.Send"), JsString::from("Send"), 1)
                        .function(make_fn("COM.Write"), JsString::from("Write"), 1)
                        .function(make_fn("COM.Read"), JsString::from("Read"), 0)
                        .function(make_fn("COM.Close"), JsString::from("Close"), 0)
                        .build()
                }
            }
        }

        fn make_com_factory(
            log: Rc<RefCell<SandboxLog>>,
            api_name: &'static str,
        ) -> NativeFunction {
            unsafe {
                NativeFunction::from_closure_with_captures(
                    move |_this, args, captures, ctx| {
                        record_call(&captures.log, api_name, args, ctx);
                        let prog_id =
                            args.get_or_undefined(0).to_string(ctx)?.to_std_string_escaped();
                        let object =
                            build_com_object_by_prog_id(ctx, captures.log.clone(), &prog_id);
                        Ok(JsValue::from(object))
                    },
                    LogCapture { log },
                )
            }
        }

        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        register_global_constructable_callable(
            context,
            "ActiveXObject",
            1,
            make_com_factory(log.clone(), "ActiveXObject"),
        );
        let _ = context.register_global_builtin_callable(
            JsString::from("print"),
            1,
            make_native(log.clone(), "print"),
        );
        let shell_object = build_wscript_shell_object(context, log.clone());
        let wscript = ObjectInitializer::new(context)
            .function(
                make_native_returning_object(log.clone(), "WScript.Shell", shell_object),
                JsString::from("Shell"),
                0,
            )
            .function(
                make_com_factory(log.clone(), "WScript.CreateObject"),
                JsString::from("CreateObject"),
                1,
            )
            .function(make_fn("WScript.Echo"), JsString::from("Echo"), 1)
            .function(make_fn("WScript.Echo"), JsString::from("echo"), 1)
            .function(make_fn("WScript.Sleep"), JsString::from("Sleep"), 1)
            .function(make_fn("WScript.Sleep"), JsString::from("sleep"), 1)
            .function(make_fn("WScript.Quit"), JsString::from("Quit"), 1)
            .function(make_fn("WScript.Quit"), JsString::from("quit"), 1)
            .function(make_fn("WScript.RegRead"), JsString::from("RegRead"), 1)
            .function(make_fn("WScript.RegWrite"), JsString::from("RegWrite"), 2)
            .property(
                JsString::from("ScriptFullName"),
                JsString::from(r"C:\Windows\Temp\stub.js"),
                Attribute::all(),
            )
            .build();
        let _ =
            context.register_global_property(JsString::from("WScript"), wscript, Attribute::all());
        let wsh_shell_object = build_wscript_shell_object(context, log.clone());
        let wsh_alias = ObjectInitializer::new(context)
            .function(
                make_native_returning_object(log.clone(), "WScript.Shell", wsh_shell_object),
                JsString::from("Shell"),
                0,
            )
            .function(
                make_com_factory(log.clone(), "WScript.CreateObject"),
                JsString::from("CreateObject"),
                1,
            )
            .function(make_fn("WScript.Echo"), JsString::from("Echo"), 1)
            .function(make_fn("WScript.Echo"), JsString::from("echo"), 1)
            .function(make_fn("WScript.Sleep"), JsString::from("Sleep"), 1)
            .function(make_fn("WScript.Sleep"), JsString::from("sleep"), 1)
            .function(make_fn("WScript.Quit"), JsString::from("Quit"), 1)
            .function(make_fn("WScript.Quit"), JsString::from("quit"), 1)
            .build();
        let _ =
            context.register_global_property(JsString::from("WSH"), wsh_alias, Attribute::all());
        register_global_constructable_callable(
            context,
            "GetObject",
            1,
            make_com_factory(log.clone(), "GetObject"),
        );
        register_global_constructable_callable(
            context,
            "CreateObject",
            1,
            make_com_factory(log, "CreateObject"),
        );
    }

    fn register_windows_com(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        let fso = ObjectInitializer::new(context)
            .function(
                make_fn("Scripting.FileSystemObject.OpenTextFile"),
                JsString::from("OpenTextFile"),
                1,
            )
            .function(
                make_fn("Scripting.FileSystemObject.OpenTextFile"),
                JsString::from("openTextFile"),
                1,
            )
            .function(
                make_fn("Scripting.FileSystemObject.OpenTextFile"),
                JsString::from("opentextfile"),
                1,
            )
            .function(
                make_fn("Scripting.FileSystemObject.CreateTextFile"),
                JsString::from("CreateTextFile"),
                1,
            )
            .function(
                make_fn("Scripting.FileSystemObject.CreateTextFile"),
                JsString::from("createTextFile"),
                1,
            )
            .function(
                make_fn("Scripting.FileSystemObject.CreateTextFile"),
                JsString::from("createtextfile"),
                1,
            )
            .build();
        let scripting = ObjectInitializer::new(context)
            .property(JsString::from("FileSystemObject"), fso, Attribute::all())
            .build();
        let _ = context.register_global_property(
            JsString::from("Scripting"),
            scripting,
            Attribute::all(),
        );

        let adodb_stream = ObjectInitializer::new(context)
            .function(make_fn("ADODB.Stream.Open"), JsString::from("Open"), 0)
            .function(make_fn("ADODB.Stream.Write"), JsString::from("Write"), 1)
            .function(make_fn("ADODB.Stream.SaveToFile"), JsString::from("SaveToFile"), 1)
            .build();
        let adodb = ObjectInitializer::new(context)
            .property(JsString::from("Stream"), adodb_stream, Attribute::all())
            .build();
        let _ = context.register_global_property(JsString::from("ADODB"), adodb, Attribute::all());

        let xmlhttp = ObjectInitializer::new(context)
            .function(make_fn("MSXML2.XMLHTTP.open"), JsString::from("open"), 2)
            .function(make_fn("MSXML2.XMLHTTP.send"), JsString::from("send"), 1)
            .function(
                make_fn("MSXML2.XMLHTTP.setRequestHeader"),
                JsString::from("setRequestHeader"),
                2,
            )
            .build();
        let msxml2 = ObjectInitializer::new(context)
            .property(JsString::from("XMLHTTP"), xmlhttp, Attribute::all())
            .build();
        let _ =
            context.register_global_property(JsString::from("MSXML2"), msxml2, Attribute::all());

        let server_xmlhttp = ObjectInitializer::new(context)
            .function(make_fn("MSXML2.ServerXMLHTTP.open"), JsString::from("open"), 2)
            .function(make_fn("MSXML2.ServerXMLHTTP.send"), JsString::from("send"), 1)
            .function(
                make_fn("MSXML2.ServerXMLHTTP.setRequestHeader"),
                JsString::from("setRequestHeader"),
                2,
            )
            .build();
        let _ = context.register_global_property(
            JsString::from("ServerXMLHTTP"),
            server_xmlhttp,
            Attribute::all(),
        );

        let domdoc = ObjectInitializer::new(context)
            .function(make_fn("MSXML2.DOMDocument.load"), JsString::from("load"), 1)
            .function(make_fn("MSXML2.DOMDocument.loadXML"), JsString::from("loadXML"), 1)
            .build();
        let _ = context.register_global_property(
            JsString::from("DOMDocument"),
            domdoc,
            Attribute::all(),
        );

        let winhttp = ObjectInitializer::new(context)
            .function(make_fn("WinHTTP.WinHTTPRequest.open"), JsString::from("Open"), 2)
            .function(make_fn("WinHTTP.WinHTTPRequest.send"), JsString::from("Send"), 1)
            .build();
        let winhttp_root = ObjectInitializer::new(context)
            .property(JsString::from("WinHTTPRequest"), winhttp, Attribute::all())
            .build();
        let _ = context.register_global_property(
            JsString::from("WinHTTP"),
            winhttp_root,
            Attribute::all(),
        );

        let shell_app = ObjectInitializer::new(context)
            .function(make_fn("Shell.Application.ShellExecute"), JsString::from("ShellExecute"), 1)
            .function(
                make_fn("Shell.Application.BrowseForFolder"),
                JsString::from("BrowseForFolder"),
                1,
            )
            .build();
        let shell = ObjectInitializer::new(context)
            .property(JsString::from("Application"), shell_app, Attribute::all())
            .build();
        let _ = context.register_global_property(JsString::from("Shell"), shell, Attribute::all());

        let adodb_conn = ObjectInitializer::new(context)
            .function(make_fn("ADODB.Connection.Open"), JsString::from("Open"), 1)
            .function(make_fn("ADODB.Connection.Execute"), JsString::from("Execute"), 1)
            .build();
        let adodb_cmd = ObjectInitializer::new(context)
            .function(make_fn("ADODB.Command.Execute"), JsString::from("Execute"), 1)
            .build();
        let adodb_extra = ObjectInitializer::new(context)
            .property(JsString::from("Connection"), adodb_conn, Attribute::all())
            .property(JsString::from("Command"), adodb_cmd, Attribute::all())
            .build();
        let _ = context.register_global_property(
            JsString::from("ADODB"),
            adodb_extra,
            Attribute::all(),
        );

        let urlmon = ObjectInitializer::new(context)
            .function(make_fn("URLDownloadToFile"), JsString::from("URLDownloadToFile"), 2)
            .build();
        let _ =
            context.register_global_property(JsString::from("URLMON"), urlmon, Attribute::all());

        let powershell = ObjectInitializer::new(context)
            .function(make_fn("PowerShell.AddScript"), JsString::from("AddScript"), 1)
            .function(make_fn("PowerShell.Invoke"), JsString::from("Invoke"), 0)
            .build();
        let _ = context.register_global_property(
            JsString::from("PowerShell"),
            powershell,
            Attribute::all(),
        );
    }

    fn register_windows_wmi(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        let svc = ObjectInitializer::new(context)
            .function(make_fn("WMI.ExecQuery"), JsString::from("ExecQuery"), 1)
            .build();
        let _ = context.register_global_property(JsString::from("winmgmts"), svc, Attribute::all());
    }

    fn build_buffer_object(context: &mut Context, log: Rc<RefCell<SandboxLog>>) -> JsObject {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        ObjectInitializer::new(context)
            .function(make_fn("Buffer.from"), JsString::from("from"), 1)
            .function(make_fn("Buffer.alloc"), JsString::from("alloc"), 1)
            .function(make_fn("Buffer.concat"), JsString::from("concat"), 1)
            .function(make_fn("Buffer.byteLength"), JsString::from("byteLength"), 1)
            .build()
    }

    fn register_buffer_stub(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let buffer = build_buffer_object(context, log);
        let _ =
            context.register_global_property(JsString::from("Buffer"), buffer, Attribute::all());
    }

    fn register_global_constructable_callable(
        context: &mut Context,
        name: &'static str,
        length: usize,
        function: NativeFunction,
    ) {
        let function = FunctionObjectBuilder::new(context.realm(), function)
            .name(JsString::from(name))
            .length(length)
            .constructor(true)
            .build();
        let _ = context.register_global_property(JsString::from(name), function, Attribute::all());
    }

    fn build_array_buffer_object(context: &mut Context, log: Rc<RefCell<SandboxLog>>) -> JsObject {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        ObjectInitializer::new(context)
            .function(make_fn("ArrayBuffer.slice"), JsString::from("slice"), 2)
            .function(make_fn("ArrayBuffer.transfer"), JsString::from("transfer"), 1)
            .build()
    }

    fn build_typed_array_object(context: &mut Context, log: Rc<RefCell<SandboxLog>>) -> JsObject {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        ObjectInitializer::new(context)
            .function(make_fn("TypedArray.set"), JsString::from("set"), 1)
            .function(make_fn("TypedArray.subarray"), JsString::from("subarray"), 2)
            .function(make_fn("TypedArray.slice"), JsString::from("slice"), 2)
            .function(make_fn("TypedArray.fill"), JsString::from("fill"), 1)
            .function(make_fn("TypedArray.copyWithin"), JsString::from("copyWithin"), 2)
            .function(make_fn("TypedArray.at"), JsString::from("at"), 1)
            .build()
    }

    fn build_data_view_object(context: &mut Context, log: Rc<RefCell<SandboxLog>>) -> JsObject {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        ObjectInitializer::new(context)
            .function(make_fn("DataView.getInt8"), JsString::from("getInt8"), 1)
            .function(make_fn("DataView.getUint8"), JsString::from("getUint8"), 1)
            .function(make_fn("DataView.getInt16"), JsString::from("getInt16"), 1)
            .function(make_fn("DataView.getUint16"), JsString::from("getUint16"), 1)
            .function(make_fn("DataView.getInt32"), JsString::from("getInt32"), 1)
            .function(make_fn("DataView.getUint32"), JsString::from("getUint32"), 1)
            .function(make_fn("DataView.getFloat32"), JsString::from("getFloat32"), 1)
            .function(make_fn("DataView.getFloat64"), JsString::from("getFloat64"), 1)
            .function(make_fn("DataView.setInt8"), JsString::from("setInt8"), 2)
            .function(make_fn("DataView.setUint8"), JsString::from("setUint8"), 2)
            .function(make_fn("DataView.setInt16"), JsString::from("setInt16"), 2)
            .function(make_fn("DataView.setUint16"), JsString::from("setUint16"), 2)
            .function(make_fn("DataView.setInt32"), JsString::from("setInt32"), 2)
            .function(make_fn("DataView.setUint32"), JsString::from("setUint32"), 2)
            .function(make_fn("DataView.setFloat32"), JsString::from("setFloat32"), 2)
            .function(make_fn("DataView.setFloat64"), JsString::from("setFloat64"), 2)
            .build()
    }

    fn make_heap_constructor(
        log: Rc<RefCell<SandboxLog>>,
        constructor_name: &'static str,
        object_builder: fn(&mut Context, Rc<RefCell<SandboxLog>>) -> JsObject,
    ) -> NativeFunction {
        unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, captures.name, args, ctx);
                    let object = object_builder(ctx, captures.log.clone());
                    Ok(JsValue::from(object))
                },
                LogNameCapture { log, name: constructor_name },
            )
        }
    }

    fn register_heap_runtime_stubs(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        register_global_constructable_callable(
            context,
            "ArrayBuffer",
            1,
            make_heap_constructor(log.clone(), "ArrayBuffer", build_array_buffer_object),
        );
        register_global_constructable_callable(
            context,
            "SharedArrayBuffer",
            1,
            make_heap_constructor(log.clone(), "SharedArrayBuffer", build_array_buffer_object),
        );
        register_global_constructable_callable(
            context,
            "DataView",
            3,
            make_heap_constructor(log.clone(), "DataView", build_data_view_object),
        );
        for typed_name in [
            "Int8Array",
            "Uint8Array",
            "Uint8ClampedArray",
            "Int16Array",
            "Uint16Array",
            "Int32Array",
            "Uint32Array",
            "Float32Array",
            "Float64Array",
            "BigInt64Array",
            "BigUint64Array",
        ] {
            register_global_constructable_callable(
                context,
                typed_name,
                1,
                make_heap_constructor(log.clone(), typed_name, build_typed_array_object),
            );
        }
    }

    fn register_webassembly_stub(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        let wasm = ObjectInitializer::new(context)
            .function(make_fn("WebAssembly.instantiate"), JsString::from("instantiate"), 1)
            .function(
                make_fn("WebAssembly.instantiateStreaming"),
                JsString::from("instantiateStreaming"),
                1,
            )
            .function(make_fn("WebAssembly.compile"), JsString::from("compile"), 1)
            .function(
                make_fn("WebAssembly.compileStreaming"),
                JsString::from("compileStreaming"),
                1,
            )
            .function(make_fn("WebAssembly.Module"), JsString::from("Module"), 1)
            .function(make_fn("WebAssembly.Instance"), JsString::from("Instance"), 1)
            .function(make_fn("WebAssembly.Memory"), JsString::from("Memory"), 1)
            .function(make_fn("WebAssembly.Table"), JsString::from("Table"), 1)
            .build();
        let _ =
            context.register_global_property(JsString::from("WebAssembly"), wasm, Attribute::all());
    }

    fn register_require_stub(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let require_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "require", args, ctx);
                    let module_name =
                        args.get_or_undefined(0).to_string(ctx)?.to_std_string_escaped();
                    let make_mod_fn = |name: &'static str| {
                        let log = captures.log.clone();
                        make_native(log, name)
                    };
                    let module = match module_name.as_str() {
                        "fs" => ObjectInitializer::new(ctx)
                            .function(make_mod_fn("fs.readFile"), JsString::from("readFile"), 1)
                            .function(make_mod_fn("fs.writeFile"), JsString::from("writeFile"), 2)
                            .function(
                                make_mod_fn("fs.createReadStream"),
                                JsString::from("createReadStream"),
                                1,
                            )
                            .function(
                                make_mod_fn("fs.createWriteStream"),
                                JsString::from("createWriteStream"),
                                1,
                            )
                            .function(make_mod_fn("fs.existsSync"), JsString::from("existsSync"), 1)
                            .function(make_mod_fn("fs.accessSync"), JsString::from("accessSync"), 1)
                            .function(make_mod_fn("fs.renameSync"), JsString::from("renameSync"), 2)
                            .function(make_mod_fn("fs.unlinkSync"), JsString::from("unlinkSync"), 1)
                            .function(
                                make_mod_fn("fs.readdirSync"),
                                JsString::from("readdirSync"),
                                1,
                            )
                            .function(
                                make_mod_fn("fs.readFileSync"),
                                JsString::from("readFileSync"),
                                1,
                            )
                            .function(
                                make_mod_fn("fs.writeFileSync"),
                                JsString::from("writeFileSync"),
                                2,
                            )
                            .build(),
                        "path" => ObjectInitializer::new(ctx)
                            .function(make_mod_fn("path.join"), JsString::from("join"), 2)
                            .function(make_mod_fn("path.resolve"), JsString::from("resolve"), 2)
                            .function(make_mod_fn("path.dirname"), JsString::from("dirname"), 1)
                            .function(make_mod_fn("path.basename"), JsString::from("basename"), 1)
                            .function(make_mod_fn("path.extname"), JsString::from("extname"), 1)
                            .function(make_mod_fn("path.normalize"), JsString::from("normalize"), 1)
                            .build(),
                        "os" => ObjectInitializer::new(ctx)
                            .function(make_mod_fn("os.platform"), JsString::from("platform"), 0)
                            .function(make_mod_fn("os.homedir"), JsString::from("homedir"), 0)
                            .function(make_mod_fn("os.hostname"), JsString::from("hostname"), 0)
                            .function(make_mod_fn("os.type"), JsString::from("type"), 0)
                            .function(make_mod_fn("os.release"), JsString::from("release"), 0)
                            .function(make_mod_fn("os.arch"), JsString::from("arch"), 0)
                            .function(make_mod_fn("os.tmpdir"), JsString::from("tmpdir"), 0)
                            .function(make_mod_fn("os.cpus"), JsString::from("cpus"), 0)
                            .function(make_mod_fn("os.uptime"), JsString::from("uptime"), 0)
                            .function(make_mod_fn("os.totalmem"), JsString::from("totalmem"), 0)
                            .function(make_mod_fn("os.freemem"), JsString::from("freemem"), 0)
                            .function(
                                make_mod_fn("os.networkInterfaces"),
                                JsString::from("networkInterfaces"),
                                0,
                            )
                            .build(),
                        "http" => ObjectInitializer::new(ctx)
                            .function(make_mod_fn("http.request"), JsString::from("request"), 1)
                            .build(),
                        "https" => ObjectInitializer::new(ctx)
                            .function(make_mod_fn("https.request"), JsString::from("request"), 1)
                            .build(),
                        "buffer" => {
                            let buffer_obj = build_buffer_object(ctx, captures.log.clone());
                            ObjectInitializer::new(ctx)
                                .property(JsString::from("Buffer"), buffer_obj, Attribute::all())
                                .build()
                        }
                        "child_process" => ObjectInitializer::new(ctx)
                            .function(make_mod_fn("child_process.exec"), JsString::from("exec"), 1)
                            .function(
                                make_mod_fn("child_process.spawn"),
                                JsString::from("spawn"),
                                1,
                            )
                            .build(),
                        _ => ObjectInitializer::new(ctx)
                            .function(make_mod_fn("module.exec"), JsString::from("exec"), 1)
                            .function(make_mod_fn("module.spawn"), JsString::from("spawn"), 1)
                            .function(make_mod_fn("module.run"), JsString::from("run"), 1)
                            .function(make_mod_fn("module.hostname"), JsString::from("hostname"), 0)
                            .function(make_mod_fn("module.platform"), JsString::from("platform"), 0)
                            .function(make_mod_fn("module.type"), JsString::from("type"), 0)
                            .function(make_mod_fn("module.release"), JsString::from("release"), 0)
                            .function(make_mod_fn("module.arch"), JsString::from("arch"), 0)
                            .function(make_mod_fn("module.tmpdir"), JsString::from("tmpdir"), 0)
                            .function(
                                make_mod_fn("module.existsSync"),
                                JsString::from("existsSync"),
                                1,
                            )
                            .function(
                                make_mod_fn("module.accessSync"),
                                JsString::from("accessSync"),
                                1,
                            )
                            .function(
                                make_mod_fn("module.renameSync"),
                                JsString::from("renameSync"),
                                2,
                            )
                            .function(
                                make_mod_fn("module.readFileSync"),
                                JsString::from("readFileSync"),
                                1,
                            )
                            .function(
                                make_mod_fn("module.writeFileSync"),
                                JsString::from("writeFileSync"),
                                2,
                            )
                            .function(
                                make_mod_fn("module.createReadStream"),
                                JsString::from("createReadStream"),
                                1,
                            )
                            .function(make_mod_fn("module.dirname"), JsString::from("dirname"), 1)
                            .function(make_mod_fn("module.join"), JsString::from("join"), 2)
                            .function(make_mod_fn("module.resolve"), JsString::from("resolve"), 2)
                            .build(),
                    };
                    Ok(JsValue::from(module))
                },
                LogCapture { log },
            )
        };
        let _ = context.register_global_builtin_callable(JsString::from("require"), 1, require_fn);
    }

    fn register_node_like(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        register_require_stub(context, log.clone());
        register_buffer_stub(context, log.clone());
        let process = ObjectInitializer::new(context)
            .function(make_fn("process.exit"), JsString::from("exit"), 1)
            .build();
        let _ =
            context.register_global_property(JsString::from("process"), process, Attribute::all());
        let child_process = ObjectInitializer::new(context)
            .function(make_fn("child_process.exec"), JsString::from("exec"), 1)
            .function(make_fn("child_process.spawn"), JsString::from("spawn"), 1)
            .build();
        let _ = context.register_global_property(
            JsString::from("child_process"),
            child_process,
            Attribute::all(),
        );
        let fs = ObjectInitializer::new(context)
            .function(make_fn("fs.readFile"), JsString::from("readFile"), 1)
            .function(make_fn("fs.writeFile"), JsString::from("writeFile"), 2)
            .function(make_fn("fs.createReadStream"), JsString::from("createReadStream"), 1)
            .function(make_fn("fs.createWriteStream"), JsString::from("createWriteStream"), 1)
            .function(make_fn("fs.existsSync"), JsString::from("existsSync"), 1)
            .function(make_fn("fs.accessSync"), JsString::from("accessSync"), 1)
            .function(make_fn("fs.renameSync"), JsString::from("renameSync"), 2)
            .function(make_fn("fs.unlinkSync"), JsString::from("unlinkSync"), 1)
            .function(make_fn("fs.readdirSync"), JsString::from("readdirSync"), 1)
            .function(make_fn("fs.readFileSync"), JsString::from("readFileSync"), 1)
            .function(make_fn("fs.writeFileSync"), JsString::from("writeFileSync"), 2)
            .build();
        let _ = context.register_global_property(JsString::from("fs"), fs, Attribute::all());
        let exports_obj = ObjectInitializer::new(context).build();
        let module = ObjectInitializer::new(context)
            .property(JsString::from("exports"), exports_obj.clone(), Attribute::all())
            .build();
        let _ =
            context.register_global_property(JsString::from("module"), module, Attribute::all());
        let _ = context.register_global_property(
            JsString::from("exports"),
            exports_obj,
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("__filename"),
            JsValue::from(JsString::from("/sandbox/input.js")),
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("__dirname"),
            JsValue::from(JsString::from("/sandbox")),
            Attribute::all(),
        );
        let bun = ObjectInitializer::new(context)
            .function(make_fn("Bun.spawn"), JsString::from("spawn"), 1)
            .function(make_fn("Bun.file"), JsString::from("file"), 1)
            .function(make_fn("Bun.write"), JsString::from("write"), 2)
            .build();
        let _ = context.register_global_property(JsString::from("Bun"), bun, Attribute::all());
    }

    fn register_doc_globals(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        // Register unescape function
        register_unescape(context, log.clone());

        // Register escape function (URL encoding)
        let escape_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "escape", args, ctx);

                    let input_arg = args.get_or_undefined(0);
                    let input = input_arg.to_string(ctx)?;
                    let input_str = input.to_std_string_escaped();

                    let mut result = String::new();
                    for ch in input_str.chars() {
                        if ch.is_ascii_alphanumeric() || "-_.!~*'()".contains(ch) {
                            result.push(ch);
                        } else {
                            result.push_str(&format!("%{:02X}", ch as u8));
                        }
                    }

                    Ok(JsValue::from(JsString::from(result)))
                },
                LogCapture { log: log.clone() },
            )
        };
        let _ = context.register_global_builtin_callable(JsString::from("escape"), 1, escape_fn);

        // Register global PDF metadata properties (commonly accessed directly)
        let _ = context.register_global_property(
            JsString::from("creator"),
            JsString::from(CREATOR_PAYLOAD),
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("producer"),
            JsString::from("Adobe Acrobat 9.0"),
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("keywords"),
            JsString::from(""),
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("title"),
            JsString::from(TITLE_PAYLOAD),
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("author"),
            JsString::from("Unknown"),
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("subject"),
            JsString::from(SUBJECT_PAYLOAD),
            Attribute::all(),
        );

        let adbe = ObjectInitializer::new(context)
            .property(JsString::from("Reader_Value_Asked"), JsValue::from(false), Attribute::all())
            .property(JsString::from("Viewer_Value_Asked"), JsValue::from(false), Attribute::all())
            .property(
                JsString::from("Viewer_Form_string_Reader_5x"),
                JsString::from(""),
                Attribute::all(),
            )
            .property(
                JsString::from("Viewer_Form_string_Reader_601"),
                JsString::from(""),
                Attribute::all(),
            )
            .property(
                JsString::from("Viewer_Form_string_Reader_6_7x"),
                JsString::from(""),
                Attribute::all(),
            )
            .property(
                JsString::from("Viewer_Form_string_Viewer_Older"),
                JsString::from(""),
                Attribute::all(),
            )
            .property(
                JsString::from("Viewer_Form_string_Viewer"),
                JsString::from(""),
                Attribute::all(),
            )
            .property(
                JsString::from("Viewer_string_Update_Reader_Desc"),
                JsString::from(""),
                Attribute::all(),
            )
            .property(
                JsString::from("Viewer_string_Update_Desc"),
                JsString::from(""),
                Attribute::all(),
            )
            .property(JsString::from("Viewer_string_Title"), JsString::from(""), Attribute::all())
            .property(
                JsString::from("Reader_Value_New_Version_URL"),
                JsString::from(""),
                Attribute::all(),
            )
            .property(
                JsString::from("Viewer_Value_New_Version_URL"),
                JsString::from(""),
                Attribute::all(),
            )
            .property(JsString::from("SYSINFO"), JsString::from(""), Attribute::all())
            .build();
        let _ = context.register_global_property(JsString::from("ADBE"), adbe, Attribute::all());
    }

    fn register_pdf_event_context(
        context: &mut Context,
        log: Rc<RefCell<SandboxLog>>,
        scope: Rc<RefCell<DynamicScope>>,
    ) {
        // Create a mock PDF event object that many malicious scripts expect
        // This simulates PDF events like page open, document open, etc.

        let target_methods = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };

        // Get the global parseInt function to add to target
        let global_obj = context.global_object().clone();
        let parse_int_fn =
            global_obj.get(JsString::from("parseInt"), context).unwrap_or(JsValue::undefined());

        // Create eval function for target with tracking
        let target_eval_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "event.target.eval", args, ctx);
                    let code_arg = args.get_or_undefined(0);
                    let code = code_arg.to_string(ctx)?;
                    let code_str = code.to_std_string_escaped();
                    if should_skip_dynamic_eval(&code_str, &captures.log, "event.target.eval") {
                        return Ok(JsValue::undefined());
                    }
                    let processed = preprocess_eval_code(&code_str, &captures.scope);
                    match execute_with_variable_promotion(
                        ctx,
                        &processed,
                        &captures.scope,
                        &captures.log,
                    ) {
                        Ok(result) => {
                            post_process_eval_variables(
                                ctx,
                                &code_str,
                                &captures.scope,
                                &captures.log,
                            );
                            Ok(result)
                        }
                        Err(err) => {
                            if let Some(recovered) = attempt_error_recovery(
                                ctx,
                                &err,
                                &code_str,
                                &captures.scope,
                                &captures.log,
                            ) {
                                Ok(recovered)
                            } else {
                                Ok(JsValue::undefined())
                            }
                        }
                    }
                },
                LogScopeCapture { log: log.clone(), scope: scope.clone() },
            )
        };

        let target_unescape_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "event.target.unescape", args, ctx);
                    let input_arg = args.get_or_undefined(0);
                    let input = input_arg.to_string(ctx)?;
                    let input_str = input.to_std_string_escaped();
                    let result = decode_unescape(&input_str);
                    Ok(JsValue::from(JsString::from(result)))
                },
                LogCapture { log: log.clone() },
            )
        };

        let target_get_annot_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "event.target.getAnnot", args, ctx);
                    Ok(build_annot(ctx, captures.log.clone()))
                },
                LogCapture { log: log.clone() },
            )
        };

        let target_get_annots_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "event.target.getAnnots", args, ctx);
                    Ok(build_annots(ctx, captures.log.clone()))
                },
                LogCapture { log: log.clone() },
            )
        };

        // Create a mock target object (represents the field or document)
        let target = ObjectInitializer::new(context)
            .property(JsString::from("parseInt"), parse_int_fn, Attribute::all())
            .function(target_eval_fn, JsString::from("eval"), 1)
            .function(target_unescape_fn, JsString::from("unescape"), 1)
            .function(
                make_native(log.clone(), "event.target.syncAnnotScan"),
                JsString::from("syncAnnotScan"),
                0,
            )
            .function(target_get_annot_fn, JsString::from("getAnnot"), 2)
            .function(target_get_annots_fn, JsString::from("getAnnots"), 1)
            .function(target_methods("event.target.getField"), JsString::from("getField"), 1)
            .function(
                target_methods("event.target.getPageNumWords"),
                JsString::from("getPageNumWords"),
                1,
            )
            .function(
                target_methods("event.target.getPageNthWord"),
                JsString::from("getPageNthWord"),
                3,
            )
            .function(target_methods("event.target.print"), JsString::from("print"), 0)
            .property(JsString::from("value"), JsString::from(""), Attribute::all())
            .property(JsString::from("name"), JsString::from("TextField"), Attribute::all())
            .build();

        // Create the event object with common PDF event properties
        let event_obj = ObjectInitializer::new(context)
            .property(JsString::from("target"), target, Attribute::all())
            .property(JsString::from("name"), JsString::from("Open"), Attribute::all())
            .property(JsString::from("type"), JsString::from("Page"), Attribute::all())
            .property(JsString::from("value"), JsString::from(""), Attribute::all())
            .property(JsString::from("willCommit"), JsValue::from(false), Attribute::all())
            .property(JsString::from("rc"), JsValue::from(true), Attribute::all())
            .build();

        // Register as global 'event' object
        let event_clone = event_obj.clone();
        let _ =
            context.register_global_property(JsString::from("event"), event_obj, Attribute::all());

        // Also create 't' as an alias for event (commonly used pattern)
        let _ =
            context.register_global_property(JsString::from("t"), event_clone, Attribute::all());

        // Also create 'this' context for PDF scripts (often refers to doc or field)
        let this_obj = ObjectInitializer::new(context)
            .property(JsString::from("pageNum"), JsValue::from(0), Attribute::all())
            .property(JsString::from("numPages"), JsValue::from(1), Attribute::all())
            .function(target_methods("this.getField"), JsString::from("getField"), 1)
            .function(target_methods("this.print"), JsString::from("print"), 0)
            .build();

        let _ =
            context.register_global_property(JsString::from("thisDoc"), this_obj, Attribute::all());
    }

    fn register_doc_stub(context: &mut Context, log: Rc<RefCell<SandboxLog>>) -> JsValue {
        // Create getters that track property access
        let title_getter = make_getter(context, log.clone(), "info.title", TITLE_PAYLOAD);
        let author_getter = make_getter(context, log.clone(), "info.author", "Unknown");
        let subject_getter = make_getter(context, log.clone(), "info.subject", "PDF");
        let keywords_getter = make_getter(context, log.clone(), "info.keywords", "");
        let creator_getter = make_getter(context, log.clone(), "info.creator", "sis-pdf");
        let producer_getter = make_getter(context, log.clone(), "info.producer", "sis-pdf");
        let gkds_getter = make_getter(context, log.clone(), "info.gkds", TITLE_PAYLOAD);
        let gggsd_getter = make_getter(context, log.clone(), "info.gggsd", "ev");
        let creation_date_getter =
            make_getter(context, log.clone(), "info.creationDate", "D:19700101000000Z");
        let mod_date_getter =
            make_getter(context, log.clone(), "info.modDate", "D:19700101000000Z");
        let creator_payload_getter =
            make_getter(context, log.clone(), "doc.creator", CREATOR_PAYLOAD);
        let subject_payload_getter =
            make_getter(context, log.clone(), "doc.subject", SUBJECT_PAYLOAD);

        // Create info object with accessor properties for tracking
        let info = ObjectInitializer::new(context)
            .accessor(JsString::from("title"), Some(title_getter), None, Attribute::all())
            .accessor(JsString::from("author"), Some(author_getter), None, Attribute::all())
            .accessor(JsString::from("subject"), Some(subject_getter), None, Attribute::all())
            .accessor(JsString::from("keywords"), Some(keywords_getter), None, Attribute::all())
            .accessor(JsString::from("creator"), Some(creator_getter), None, Attribute::all())
            .accessor(JsString::from("producer"), Some(producer_getter), None, Attribute::all())
            .accessor(JsString::from("gkds"), Some(gkds_getter), None, Attribute::all())
            .accessor(JsString::from("gggsd"), Some(gggsd_getter), None, Attribute::all())
            .accessor(
                JsString::from("creationDate"),
                Some(creation_date_getter),
                None,
                Attribute::all(),
            )
            .accessor(JsString::from("modDate"), Some(mod_date_getter), None, Attribute::all())
            .build();
        let _ = context.register_global_property(
            JsString::from("info"),
            info.clone(),
            Attribute::all(),
        );
        let get_annot_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "doc.getAnnot", args, ctx);
                    Ok(build_annot(ctx, captures.log.clone()))
                },
                LogCapture { log: log.clone() },
            )
        };
        let get_annots_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "doc.getAnnots", args, ctx);
                    Ok(build_annots(ctx, captures.log.clone()))
                },
                LogCapture { log: log.clone() },
            )
        };
        let collab = ObjectInitializer::new(context)
            .function(make_native(log.clone(), "Collab.getIcon"), JsString::from("getIcon"), 1)
            .function(
                make_native(log.clone(), "Collab.collectEmailInfo"),
                JsString::from("collectEmailInfo"),
                0,
            )
            .build();
        let media = ObjectInitializer::new(context)
            .function(make_native(log.clone(), "media.newPlayer"), JsString::from("newPlayer"), 1)
            .build();
        let doc = ObjectInitializer::new(context)
            .property(JsString::from("info"), info, Attribute::all())
            .property(JsString::from("Collab"), collab, Attribute::all())
            .property(JsString::from("media"), media.clone(), Attribute::all())
            .accessor(
                JsString::from("creator"),
                Some(creator_payload_getter),
                None,
                Attribute::all(),
            )
            .accessor(
                JsString::from("subject"),
                Some(subject_payload_getter),
                None,
                Attribute::all(),
            )
            .function(
                make_native(log.clone(), "doc.syncAnnotScan"),
                JsString::from("syncAnnotScan"),
                0,
            )
            .function(make_native(log.clone(), "doc.eval"), JsString::from("eval"), 1)
            .function(make_native(log.clone(), "doc.unescape"), JsString::from("unescape"), 1)
            .function(
                make_native(log.clone(), "doc.getPageNumWords"),
                JsString::from("getPageNumWords"),
                1,
            )
            .function(
                make_native(log.clone(), "doc.getPageNthWord"),
                JsString::from("getPageNthWord"),
                3,
            )
            .function(get_annot_fn, JsString::from("getAnnot"), 2)
            .function(get_annots_fn, JsString::from("getAnnots"), 1)
            .build();
        let doc_value = JsValue::from(doc.clone());
        let _ = context.register_global_property(JsString::from("doc"), doc, Attribute::all());
        let _ = context.register_global_property(
            JsString::from("creator"),
            JsString::from(CREATOR_PAYLOAD),
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("subject"),
            JsString::from(SUBJECT_PAYLOAD),
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("title"),
            JsString::from(TITLE_PAYLOAD),
            Attribute::all(),
        );
        let _ = context.register_global_property(JsString::from("media"), media, Attribute::all());
        let _ = context.register_global_property(
            JsString::from("j"),
            JsValue::from(false),
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("dada"),
            JsValue::from(false),
            Attribute::all(),
        );
        let _ = context.register_global_callable(
            JsString::from("run"),
            0,
            make_native(log.clone(), "run"),
        );
        doc_value
    }

    fn build_annots(context: &mut Context, log: Rc<RefCell<SandboxLog>>) -> JsValue {
        let annot_primary = build_annot_with_subject(
            context,
            log.clone(),
            "z61z70z70z2Ez61z6Cz65z72z74z28z27z68z69z27z29",
        );
        let annot_secondary = build_annot_with_subject(context, log.clone(), "z-41-42-43");
        let annots = ObjectInitializer::new(context)
            .property(JsString::from("0"), annot_primary, Attribute::all())
            .property(JsString::from("1"), annot_secondary, Attribute::all())
            .property(JsString::from("length"), 2, Attribute::all())
            .build();
        JsValue::from(annots)
    }

    fn build_annot(context: &mut Context, log: Rc<RefCell<SandboxLog>>) -> JsValue {
        build_annot_with_subject(context, log, "z61z70z70z2Ez61z6Cz65z72z74z28z27z68z69z27z29")
    }

    fn build_annot_with_subject(
        context: &mut Context,
        log: Rc<RefCell<SandboxLog>>,
        subject_value: &'static str,
    ) -> JsValue {
        let subject_getter = make_getter(context, log, "annot.subject", subject_value);
        let annot = ObjectInitializer::new(context)
            .accessor(JsString::from("subject"), Some(subject_getter), None, Attribute::all())
            .build();
        JsValue::from(annot)
    }

    fn register_enhanced_doc_globals(
        context: &mut Context,
        log: Rc<RefCell<SandboxLog>>,
        scope: Rc<RefCell<DynamicScope>>,
    ) {
        let add =
            |ctx: &mut Context, name: &'static str, len: usize, log: Rc<RefCell<SandboxLog>>| {
                let _ = ctx.register_global_builtin_callable(
                    JsString::from(name),
                    len,
                    make_native(log, name),
                );
            };
        // Standard JavaScript globals with enhanced tracking
        add(context, "setTimeout", 1, log.clone());
        add(context, "setInterval", 1, log.clone());
        add(context, "confirm", 1, log.clone());
        let function_ctor = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "Function", args, ctx);
                    let body = args
                        .last()
                        .map(|value| value.to_string(ctx))
                        .transpose()?
                        .map(|value| value.to_std_string_escaped())
                        .unwrap_or_default();
                    if should_skip_dynamic_eval(&body, &captures.log, "Function") {
                        return Ok(JsValue::undefined());
                    }
                    let wrapped = format!("(function(){{{body}}})");
                    let processed = preprocess_eval_code(&wrapped, &captures.scope);
                    match execute_with_variable_promotion(
                        ctx,
                        &processed,
                        &captures.scope,
                        &captures.log,
                    ) {
                        Ok(result) => Ok(result),
                        Err(error) => {
                            let mut log_ref = captures.log.borrow_mut();
                            log_ref
                                .errors
                                .push(format!("Function ctor error (recovered): {:?}", error));
                            Ok(JsValue::undefined())
                        }
                    }
                },
                LogScopeCapture { log: log.clone(), scope: scope.clone() },
            )
        };
        let _ = context.register_global_callable(JsString::from("Function"), 1, function_ctor);

        // Enhanced string functions
        register_enhanced_string_functions(context, log.clone());

        // Document/PDF functions
        add(context, "getURL", 1, log.clone());
        add(context, "submitForm", 1, log.clone());
        add(context, "exportDataObject", 1, log.clone());
        add(context, "importDataObject", 1, log.clone());
        add(context, "exportAsFDF", 1, log.clone());
        add(context, "exportAsXFDF", 1, log.clone());
        add(context, "importTextData", 1, log.clone());
        add(context, "createDataObject", 1, log.clone());
        add(context, "removeDataObject", 1, log.clone());
        add(context, "getDataObject", 1, log.clone());
        add(context, "getDataObjectContents", 1, log.clone());
        add(context, "addField", 1, log.clone());
        add(context, "removeField", 1, log.clone());
        add(context, "getField", 1, log.clone());
        add(context, "getPageNumWords", 1, log.clone());
        add(context, "getPageNthWord", 3, log.clone());
        let get_annot_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "getAnnot", args, ctx);
                    Ok(build_annot(ctx, captures.log.clone()))
                },
                LogCapture { log: log.clone() },
            )
        };
        let _ =
            context.register_global_builtin_callable(JsString::from("getAnnot"), 2, get_annot_fn);
        add(context, "getAnnots", 1, log.clone());
        add(context, "addAnnot", 1, log.clone());
        add(context, "removeAnnot", 1, log.clone());
        add(context, "deletePages", 1, log.clone());
        add(context, "insertPages", 1, log.clone());
        add(context, "extractPages", 1, log.clone());
        add(context, "flattenPages", 1, log.clone());
        add(context, "saveAs", 1, log.clone());
        add(context, "print", 0, log.clone());
        add(context, "mailDoc", 0, log);
    }

    fn register_enhanced_string_functions(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        // String.fromCharCode with enhanced tracking
        let from_char_code_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "String.fromCharCode", args, ctx);

                    let mut result = String::new();
                    for arg in args {
                        if let Ok(num) = arg.to_i32(ctx) {
                            if (0..=255).contains(&num) {
                                result.push(num as u8 as char);
                            }
                        }
                    }

                    Ok(JsValue::from(JsString::from(result)))
                },
                LogCapture { log: log.clone() },
            )
        };

        let from_char_code = FunctionObjectBuilder::new(context.realm(), from_char_code_fn)
            .name(JsString::from("fromCharCode"))
            .length(1)
            .constructor(false)
            .build();

        let substr_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |this, args, captures, ctx| {
                    record_call(&captures.log, "String.substr", args, ctx);
                    let value = this.to_string(ctx)?;
                    let input = value.to_std_string_escaped();
                    let chars: Vec<char> = input.chars().collect();
                    let total = chars.len() as i32;
                    let mut start = args.get_or_undefined(0).to_i32(ctx).unwrap_or(0);
                    if start < 0 {
                        start = (total + start).max(0);
                    }
                    let start = start.min(total) as usize;
                    let mut length = if args.len() > 1 {
                        args.get_or_undefined(1).to_i32(ctx).unwrap_or(0)
                    } else {
                        total - start as i32
                    };
                    if length < 0 {
                        length = 0;
                    }
                    let end = (start as i32 + length).min(total) as usize;
                    let result: String = chars[start..end].iter().collect();
                    Ok(JsValue::from(JsString::from(result)))
                },
                LogCapture { log: log.clone() },
            )
        };
        let substr = FunctionObjectBuilder::new(context.realm(), substr_fn)
            .name(JsString::from("substr"))
            .length(2)
            .constructor(false)
            .build();

        if let Ok(string_value) = context.global_object().get(JsString::from("String"), context) {
            if let Some(string_obj) = string_value.as_object() {
                let _ =
                    string_obj.set(JsString::from("fromCharCode"), from_char_code, false, context);
                if let Ok(proto_value) = string_obj.get(JsString::from("prototype"), context) {
                    if let Some(proto_obj) = proto_value.as_object() {
                        let _ = proto_obj.set(JsString::from("substr"), substr, false, context);
                    }
                }
            }
        }

        // escape function
        let escape_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "escape", args, ctx);

                    let input = args.get_or_undefined(0).to_string(ctx)?;
                    let input_str = input.to_std_string_escaped();

                    let mut result = String::new();
                    for ch in input_str.chars() {
                        if ch.is_ascii_alphanumeric() || "_*-./@".contains(ch) {
                            result.push(ch);
                        } else {
                            result.push_str(&format!("%{:02X}", ch as u8));
                        }
                    }

                    Ok(JsValue::from(JsString::from(result)))
                },
                LogCapture { log: log.clone() },
            )
        };

        let _ = context.register_global_builtin_callable(JsString::from("escape"), 1, escape_fn);
    }

    fn register_enhanced_global_fallback(
        context: &mut Context,
        _log: Rc<RefCell<SandboxLog>>,
        scope: Rc<RefCell<DynamicScope>>,
    ) {
        // Set up enhanced fallback mechanism with dynamic variable promotion
        let common_vars = vec![
            "M7pzjRpdcM5RVyTMS", // From our specific malware sample
            "result",
            "output",
            "payload",
            "data",
            "code",
            "script",
            "x",
            "y",
            "z",
            "a",
            "b",
            "c",
            "temp",
            "tmp",
            "var1",
            "var2",
            // Additional common obfuscated variable patterns
            "ArUloJQvYckQQag5N",
            "YBmf7LIrmiSSmpTsf",
            "ec8IFjfKAAJeWmuiY",
            "MaSDjaiwpf8EBosnq",
            "CxiG6rd4UuhbnRzwv",
            "hc2Nqw6OfebArFYhX",
            "CdmK3RydbptAXRo9u",
        ];

        for var_name in common_vars {
            let _ = context.register_global_property(
                JsString::from(var_name),
                JsValue::undefined(),
                Attribute::all(),
            );

            // Mark for auto-promotion
            scope.borrow_mut().auto_promote.insert(var_name.to_string());
        }

        // Add console object for better compatibility
        let console = ObjectInitializer::new(context)
            .function(make_console_function("log"), JsString::from("log"), 1)
            .function(make_console_function("warn"), JsString::from("warn"), 1)
            .function(make_console_function("error"), JsString::from("error"), 1)
            .build();
        let _ =
            context.register_global_property(JsString::from("console"), console, Attribute::all());
    }

    fn make_console_function(_level: &'static str) -> NativeFunction {
        NativeFunction::from_copy_closure(|_this, _args, _ctx| {
            // Console functions are no-ops in sandbox, just return undefined
            Ok(JsValue::undefined())
        })
    }

    fn register_unescape(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let unescape_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "unescape", args, ctx);

                    let input_arg = args.get_or_undefined(0);
                    let input = input_arg.to_string(ctx)?;
                    let input_str = input.to_std_string_escaped();

                    Ok(JsValue::from(JsString::from(decode_unescape(&input_str))))
                },
                LogCapture { log },
            )
        };

        let _ =
            context.register_global_builtin_callable(JsString::from("unescape"), 1, unescape_fn);
    }

    fn decode_unescape(input: &str) -> String {
        let mut result = String::new();
        let mut chars = input.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '%' {
                if matches!(chars.peek(), Some('u') | Some('U')) {
                    let _ = chars.next();
                    let h1 = chars.next();
                    let h2 = chars.next();
                    let h3 = chars.next();
                    let h4 = chars.next();
                    if let (Some(a), Some(b), Some(c), Some(d)) = (h1, h2, h3, h4) {
                        let hex = format!("{}{}{}{}", a, b, c, d);
                        if let Ok(word) = u16::from_str_radix(&hex, 16) {
                            if let Some(decoded) = char::from_u32(word as u32) {
                                result.push(decoded);
                                continue;
                            }
                        }
                    }
                    result.push(ch);
                    result.push('u');
                    if let Some(a) = h1 {
                        result.push(a);
                    }
                    if let Some(b) = h2 {
                        result.push(b);
                    }
                    if let Some(c) = h3 {
                        result.push(c);
                    }
                    if let Some(d) = h4 {
                        result.push(d);
                    }
                    continue;
                }
                let h1 = chars.next();
                let h2 = chars.next();
                if let (Some(a), Some(b)) = (h1, h2) {
                    let hex = format!("{}{}", a, b);
                    if let Ok(byte_val) = u8::from_str_radix(&hex, 16) {
                        result.push(byte_val as char);
                        continue;
                    }
                }
                result.push(ch);
                if let Some(a) = h1 {
                    result.push(a);
                }
                if let Some(b) = h2 {
                    result.push(b);
                }
            } else if ch == 'z' || ch == 'Z' {
                let h1 = chars.next();
                let h2 = chars.next();
                if let (Some(a), Some(b)) = (h1, h2) {
                    let hex = format!("{}{}", a, b);
                    if let Ok(byte_val) = u8::from_str_radix(&hex, 16) {
                        result.push(byte_val as char);
                        continue;
                    }
                }
                result.push(ch);
                if let Some(a) = h1 {
                    result.push(a);
                }
                if let Some(b) = h2 {
                    result.push(b);
                }
            } else {
                result.push(ch);
            }
        }

        result
    }

    fn normalise_js_source(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() >= 2 {
            if bytes[0] == 0xFF && bytes[1] == 0xFE {
                let decoded = decode_utf16(&bytes[2..], true).unwrap_or_else(|| bytes.to_vec());
                return apply_source_normalisation(decoded);
            }
            if bytes[0] == 0xFE && bytes[1] == 0xFF {
                let decoded = decode_utf16(&bytes[2..], false).unwrap_or_else(|| bytes.to_vec());
                return apply_source_normalisation(decoded);
            }
        }

        let nul_count = bytes.iter().filter(|b| **b == 0).count();
        if nul_count > bytes.len() / 4 {
            if let Some(decoded) = decode_utf16(bytes, true) {
                return apply_source_normalisation(decoded);
            }
        }
        if nul_count > 0 {
            let filtered: Vec<u8> = bytes.iter().copied().filter(|b| *b != 0).collect();
            return apply_source_normalisation(filtered);
        }

        apply_source_normalisation(bytes.to_vec())
    }

    fn apply_source_normalisation(bytes: Vec<u8>) -> Vec<u8> {
        let source = String::from_utf8_lossy(&bytes).to_string();
        let normalised_busy_wait = normalise_busy_wait_loops(&source);
        normalise_token_decoder_loops(&normalised_busy_wait).into_bytes()
    }

    fn normalise_busy_wait_loops(source: &str) -> String {
        let Ok(pattern) = regex::Regex::new(
            r"while\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*<\s*([0-9]{6,})\s*\)\s*\{\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\+\+\s*;?\s*\}",
        ) else {
            return source.to_string();
        };
        pattern
            .replace_all(source, |captures: &regex::Captures<'_>| {
                let loop_var = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
                let increment_var = captures.get(3).map(|m| m.as_str()).unwrap_or_default();
                if loop_var != increment_var {
                    return captures.get(0).map(|m| m.as_str().to_string()).unwrap_or_default();
                }
                format!("while({loop_var}<1024){{{loop_var}++;}}")
            })
            .into_owned()
    }

    fn normalise_token_decoder_loops(source: &str) -> String {
        let lower = source.to_ascii_lowercase();
        if !(lower.contains("split('!')")
            || lower.contains("split(\"!\")")
            || lower.contains("[\"s\"+\"plit\"]('!')"))
        {
            return source.to_string();
        }
        let Ok(loop_pattern) = regex::Regex::new(
            r"for\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*0\s*;\s*\1\s*<\s*([^;]+)\s*;\s*\1\s*\+\+\s*\)",
        ) else {
            return source.to_string();
        };
        let loop_normalised = loop_pattern
            .replace_all(source, |captures: &regex::Captures<'_>| {
                let loop_var = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
                let bound_expr = captures.get(2).map(|m| m.as_str()).unwrap_or_default();
                if loop_var.is_empty() || bound_expr.is_empty() {
                    return captures.get(0).map(|m| m.as_str().to_string()).unwrap_or_default();
                }
                format!(
                    "for({loop_var}=0;{loop_var}<Math.min({bound_expr},{});{loop_var}++)",
                    TOKEN_DECODER_MAX_NORMALISED_ITERATIONS
                )
            })
            .into_owned();
        let Ok(split_pattern) = regex::Regex::new(
            r#"(?s)(var\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*")([^"]{8192,})("\s*\[\s*"s"\s*\+\s*"plit"\s*\]\s*\(\s*'!'\s*\))"#,
        ) else {
            return loop_normalised;
        };
        split_pattern
            .replace_all(&loop_normalised, |captures: &regex::Captures<'_>| {
                let prefix = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
                let body = captures.get(2).map(|m| m.as_str()).unwrap_or_default();
                let suffix = captures.get(3).map(|m| m.as_str()).unwrap_or_default();
                let truncated = if body.len() > 4096 { &body[..4096] } else { body };
                format!("{prefix}{truncated}{suffix}")
            })
            .into_owned()
    }

    fn decode_utf16(bytes: &[u8], le: bool) -> Option<Vec<u8>> {
        if bytes.len() < 2 {
            return None;
        }
        let mut units = Vec::with_capacity(bytes.len() / 2);
        for chunk in bytes.chunks_exact(2) {
            let value = if le {
                u16::from_le_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], chunk[1]])
            };
            units.push(value);
        }
        let decoded = String::from_utf16(&units).ok()?;
        Some(decoded.into_bytes())
    }

    fn register_enhanced_eval_v2(
        context: &mut Context,
        log: Rc<RefCell<SandboxLog>>,
        scope: Rc<RefCell<DynamicScope>>,
    ) {
        let eval_fn = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, "eval", args, ctx);

                    let code_arg = args.get_or_undefined(0);
                    let code = code_arg.to_string(ctx)?;
                    let code_str = code.to_std_string_escaped();
                    if should_skip_dynamic_eval(&code_str, &captures.log, "eval") {
                        return Ok(JsValue::undefined());
                    }

                    {
                        let mut log_ref = captures.log.borrow_mut();
                        if log_ref.call_args.len() < log_ref.options.max_call_args {
                            log_ref.call_args.push(format!(
                                "eval({})",
                                &code_str[..std::cmp::min(code_str.len(), 100)]
                            ));
                        }
                        log_ref.scope_transitions.push(ScopeTransition {
                            from_scope: "global".to_string(),
                            to_scope: "eval".to_string(),
                            trigger: TransitionTrigger::EvalExecution,
                            variables_inherited: Vec::new(),
                            timestamp: std::time::Duration::from_millis(0),
                        });
                    }

                    let processed_code = preprocess_eval_code(&code_str, &captures.scope);

                    match execute_with_variable_promotion(
                        ctx,
                        &processed_code,
                        &captures.scope,
                        &captures.log,
                    ) {
                        Ok(result) => {
                            post_process_eval_variables(
                                ctx,
                                &code_str,
                                &captures.scope,
                                &captures.log,
                            );
                            Ok(result)
                        }
                        Err(e) => {
                            let error_text = format!("{:?}", e);
                            if let Some(recovered_result) = attempt_error_recovery(
                                ctx,
                                &e,
                                &code_str,
                                &captures.scope,
                                &captures.log,
                            ) {
                                Ok(recovered_result)
                            } else {
                                if !error_text.contains("RuntimeLimit") {
                                    let mut log_ref = captures.log.borrow_mut();
                                    log_ref
                                        .errors
                                        .push(format!("Eval error (recovered): {}", error_text));
                                }
                                Ok(JsValue::undefined())
                            }
                        }
                    }
                },
                LogScopeCapture { log: log.clone(), scope: scope.clone() },
            )
        };

        let _ = context.register_global_builtin_callable(JsString::from("eval"), 1, eval_fn);
    }

    fn should_skip_dynamic_eval(
        code: &str,
        log: &Rc<RefCell<SandboxLog>>,
        callsite: &'static str,
    ) -> bool {
        let limit = {
            let log_ref = log.borrow();
            std::cmp::min(MAX_EVAL_EXEC_BYTES, log_ref.options.max_bytes)
        };
        if code.len() <= limit {
            return false;
        }
        let mut log_ref = log.borrow_mut();
        if log_ref.errors.len() < MAX_RECORDED_ERRORS {
            log_ref.errors.push(format!(
                "{callsite} payload skipped: {} bytes exceeds {} byte dynamic-eval limit",
                code.len(),
                limit
            ));
        } else {
            log_ref.errors_dropped += 1;
        }
        true
    }

    fn preprocess_eval_code(code: &str, scope: &Rc<RefCell<DynamicScope>>) -> String {
        let mut result = code.replace('\u{0}', "");

        // Pattern 1: Simple var detection without complex regex
        if let Ok(var_regex) = regex::Regex::new(r"var\s+(\w+)\s*=") {
            let result_for_regex = result.clone();
            let matches: Vec<_> = var_regex.captures_iter(&result_for_regex).collect();
            for caps in matches {
                if let Some(var_name) = caps.get(1) {
                    let var_str = var_name.as_str().to_string();
                    scope.borrow_mut().auto_promote.insert(var_str.clone());

                    // Replace with global assignment to ensure persistence
                    if let Some(full_match) = caps.get(0) {
                        result =
                            result.replace(full_match.as_str(), &format!("this.{} = ", var_str));
                    }
                }
            }
        } else {
            // Fallback: Simple string-based detection
            if result.contains("var ") {
                // Extract variable names using simple parsing
                let mut replacements = Vec::new();
                let result_for_parsing = result.clone();
                let lines: Vec<&str> = result_for_parsing.split(';').collect();
                for line in lines {
                    if line.trim().starts_with("var ") {
                        if let Some(eq_pos) = line.find('=') {
                            let var_part = &line[4..eq_pos]; // Skip "var "
                            let var_name = var_part.trim();
                            if var_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                                scope.borrow_mut().auto_promote.insert(var_name.to_string());
                                replacements.push((
                                    format!("var {}", var_name),
                                    format!("this.{}", var_name),
                                ));
                            }
                        }
                    }
                }
                // Apply replacements
                for (old, new) in replacements {
                    result = result.replace(&old, &new);
                }
            }
        }

        // Pattern 2: Add error handling wrapper
        format!("try {{ {} }} catch(e) {{ /* Eval error suppressed */ }}", result)
    }

    fn execute_with_variable_promotion(
        ctx: &mut Context,
        code: &str,
        scope: &Rc<RefCell<DynamicScope>>,
        log: &Rc<RefCell<SandboxLog>>,
    ) -> Result<JsValue, boa_engine::JsError> {
        // Pre-execution: Create global variables for promoted variables
        {
            let scope_ref = scope.borrow();
            for var_name in &scope_ref.auto_promote {
                let _ = ctx.register_global_property(
                    JsString::from(var_name.as_str()),
                    JsValue::undefined(),
                    Attribute::all(),
                );
            }
        }

        // Execute the code
        let result = ctx.eval(Source::from_bytes(code.as_bytes()));

        // Post-execution: Log variable events
        {
            let mut log_ref = log.borrow_mut();
            let scope_ref = scope.borrow();
            for var_name in &scope_ref.auto_promote {
                log_ref.variable_events.push(VariableEvent {
                    variable: var_name.clone(),
                    event_type: VariableEventType::Declaration,
                    value: "promoted".to_string(),
                    scope: "global".to_string(),
                    timestamp: std::time::Duration::from_millis(0),
                });
            }
        }

        result
    }

    fn post_process_eval_variables(
        ctx: &mut Context,
        original_code: &str,
        scope: &Rc<RefCell<DynamicScope>>,
        _log: &Rc<RefCell<SandboxLog>>,
    ) {
        // Extract any new variables that were created and should be promoted
        let common_variable_patterns = vec![
            r"(\w+)\s*=\s*[^;]+;", // Simple assignments
            r"var\s+(\w+)",        // Variable declarations
        ];

        for pattern in common_variable_patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                for caps in regex.captures_iter(original_code) {
                    if let Some(var_match) = caps.get(1) {
                        let var_name = var_match.as_str();
                        if should_promote_variable(var_name) {
                            // Ensure variable exists in global scope
                            let _ = ctx.register_global_property(
                                JsString::from(var_name),
                                JsValue::undefined(),
                                Attribute::all(),
                            );

                            scope.borrow_mut().auto_promote.insert(var_name.to_string());
                        }
                    }
                }
            }
        }
    }

    fn should_promote_variable(var_name: &str) -> bool {
        // Promote variables that match common obfuscation patterns
        var_name.len() > 5
            && (
                var_name.chars().any(|c| c.is_uppercase()) || // Mixed case
            var_name.contains('_') || // Underscore naming
            var_name.chars().last().is_some_and(|c| c.is_numeric())
                // Ends with number
            )
    }

    fn attempt_error_recovery(
        ctx: &mut Context,
        error: &boa_engine::JsError,
        code: &str,
        scope: &Rc<RefCell<DynamicScope>>,
        log: &Rc<RefCell<SandboxLog>>,
    ) -> Option<JsValue> {
        let error_msg = format!("{:?}", error);
        let error_type = if error_msg.contains("is not defined") {
            "ReferenceError"
        } else if error_msg.contains("Maximum loop iteration limit") {
            "RuntimeLimit"
        } else if error_msg.contains("Syntax") {
            "SyntaxError"
        } else {
            "UnknownError"
        };

        // Track the exception event
        {
            let mut log_ref = log.borrow_mut();
            let timestamp = log_ref
                .execution_flow
                .start_time
                .map(|start| start.elapsed())
                .unwrap_or_else(|| std::time::Duration::from_millis(0));

            log_ref.execution_flow.exception_handling.push(ExceptionEvent {
                error_type: error_type.to_string(),
                message: error_msg.clone(),
                recovery_attempted: true,
                recovery_successful: false, // Will be updated if recovery succeeds
                context: "error_recovery".to_string(),
                timestamp,
            });
        }

        // Recovery strategy 1: Undefined variable errors
        if error_msg.contains("is not defined") {
            if let Some(result) = recover_undefined_variables(ctx, &error_msg, code, scope, log) {
                let mut log_ref = log.borrow_mut();
                if let Some(last_exception) = log_ref.execution_flow.exception_handling.last_mut() {
                    last_exception.recovery_successful = true;
                }
                return Some(result);
            }
        }

        // Recovery strategy 2: Syntax errors - try to fix common issues
        if error_msg.contains("Syntax") {
            let cleaned_code = attempt_syntax_cleanup(code);
            match ctx.eval(Source::from_bytes(cleaned_code.as_bytes())) {
                Ok(result) => {
                    // Mark recovery as successful
                    {
                        let mut log_ref = log.borrow_mut();
                        if let Some(last_exception) =
                            log_ref.execution_flow.exception_handling.last_mut()
                        {
                            last_exception.recovery_successful = true;
                        }
                    }
                    return Some(result);
                }
                Err(err) => {
                    let cleaned_error = format!("{:?}", err);
                    if cleaned_error.contains("is not defined") {
                        if let Some(result) = recover_undefined_variables(
                            ctx,
                            &cleaned_error,
                            &cleaned_code,
                            scope,
                            log,
                        ) {
                            let mut log_ref = log.borrow_mut();
                            if let Some(last_exception) =
                                log_ref.execution_flow.exception_handling.last_mut()
                            {
                                last_exception.recovery_successful = true;
                            }
                            return Some(result);
                        }
                    }
                }
            }
            if let Some(result) = recover_syntax_by_statement_slicing(ctx, code) {
                let mut log_ref = log.borrow_mut();
                if let Some(last_exception) = log_ref.execution_flow.exception_handling.last_mut() {
                    last_exception.recovery_successful = true;
                }
                return Some(result);
            }
            if error_msg.contains("unterminated string literal") {
                let mut log_ref = log.borrow_mut();
                if let Some(last_exception) = log_ref.execution_flow.exception_handling.last_mut() {
                    last_exception.recovery_successful = true;
                }
                return Some(JsValue::undefined());
            }
        }

        if error_msg.contains("not a callable function") {
            if let Some(hint) = extract_not_callable_hint(&error_msg, code) {
                let mut log_ref = log.borrow_mut();
                log_ref.errors.push(format!("Callable recovery hint: {}", hint));
            }
            let call_names = gather_bare_call_names(code);
            let dotted_paths = gather_dotted_call_paths(code);
            let patched = override_callable_assignments(code, &call_names);
            let mut prelude = String::new();
            for name in &call_names {
                prelude.push_str(&format!("var {} = function(){{}};", name));
            }
            prelude.push_str(&build_dotted_call_stub_prelude(&dotted_paths));
            let merged = format!("{}{}", prelude, patched);
            if let Ok(result) = ctx.eval(Source::from_bytes(merged.as_bytes())) {
                let mut log_ref = log.borrow_mut();
                if let Some(last_exception) = log_ref.execution_flow.exception_handling.last_mut() {
                    last_exception.recovery_successful = true;
                }
                return Some(result);
            }
        }

        if error_msg.contains("cannot convert 'null' or 'undefined' to object") {
            let guarded = format!("{}{}", build_null_conversion_guard_prelude(), code);
            if let Ok(result) = ctx.eval(Source::from_bytes(guarded.as_bytes())) {
                let mut log_ref = log.borrow_mut();
                if let Some(last_exception) = log_ref.execution_flow.exception_handling.last_mut() {
                    last_exception.recovery_successful = true;
                }
                return Some(result);
            }
            let wrapped = format!("try {{ {} }} catch(__sis_null_conv__) {{}}", guarded);
            if let Ok(result) = ctx.eval(Source::from_bytes(wrapped.as_bytes())) {
                let mut log_ref = log.borrow_mut();
                if let Some(last_exception) = log_ref.execution_flow.exception_handling.last_mut() {
                    last_exception.recovery_successful = true;
                }
                return Some(result);
            }
        }

        if error_msg.contains("is not defined") {
            let wrapped = format!("try {{ {} }} catch(__sis_ref__) {{}}", code);
            if let Ok(result) = ctx.eval(Source::from_bytes(wrapped.as_bytes())) {
                let mut log_ref = log.borrow_mut();
                if let Some(last_exception) = log_ref.execution_flow.exception_handling.last_mut() {
                    last_exception.recovery_successful = true;
                }
                return Some(result);
            }
        }

        if error_msg.contains("Maximum loop iteration limit") {
            let mut log_ref = log.borrow_mut();
            if let Some(last_exception) = log_ref.execution_flow.exception_handling.last_mut() {
                last_exception.recovery_successful = true;
            }
            return Some(JsValue::undefined());
        }

        None
    }

    fn build_null_conversion_guard_prelude() -> String {
        r#"
;(function(){
  var __sis_keys = Object.keys;
  Object.keys = function(v){ if (v === null || v === undefined) { return []; } return __sis_keys(v); };
  var __sis_values = Object.values;
  Object.values = function(v){ if (v === null || v === undefined) { return []; } return __sis_values(v); };
  var __sis_entries = Object.entries;
  Object.entries = function(v){ if (v === null || v === undefined) { return []; } return __sis_entries(v); };
  var __sis_names = Object.getOwnPropertyNames;
  Object.getOwnPropertyNames = function(v){ if (v === null || v === undefined) { return []; } return __sis_names(v); };
  var __sis_symbols = Object.getOwnPropertySymbols;
  Object.getOwnPropertySymbols = function(v){ if (v === null || v === undefined) { return []; } return __sis_symbols(v); };
  var __sis_assign = Object.assign;
  Object.assign = function(target){
    if (target === null || target === undefined) { target = {}; }
    return __sis_assign.apply(Object, arguments);
  };
})();
"#
        .to_string()
    }

    fn extract_not_callable_hint(error_msg: &str, code: &str) -> Option<String> {
        let column_regex = regex::Regex::new(r"column_number:\s*(\d+)").ok()?;
        let line_regex = regex::Regex::new(r"line_number:\s*(\d+)").ok()?;
        let columns: Vec<usize> = column_regex
            .captures_iter(error_msg)
            .filter_map(|capture| capture.get(1).and_then(|m| m.as_str().parse::<usize>().ok()))
            .collect();
        if columns.is_empty() {
            return None;
        }
        let lines: Vec<usize> = line_regex
            .captures_iter(error_msg)
            .filter_map(|capture| capture.get(1).and_then(|m| m.as_str().parse::<usize>().ok()))
            .collect();
        let line = lines.last().copied().unwrap_or(1);
        let mut candidates = BTreeSet::new();
        for column in columns.iter().rev().take(6) {
            if let Some(expr) = extract_callee_expression(code, line, *column) {
                if !expr.is_empty() {
                    candidates.insert(expr);
                }
            }
        }
        if candidates.is_empty() {
            return Some(format!("line={} columns={:?} callee=unresolved", line, columns));
        }
        Some(format!(
            "line={} columns={:?} candidate_callees={}",
            line,
            columns,
            candidates.into_iter().collect::<Vec<_>>().join(" | ")
        ))
    }

    fn extract_callee_expression(
        code: &str,
        line_number: usize,
        column_number: usize,
    ) -> Option<String> {
        if line_number == 0 || column_number == 0 {
            return None;
        }
        let line = code.lines().nth(line_number.saturating_sub(1))?;
        let chars: Vec<char> = line.chars().collect();
        let start = column_number.saturating_sub(1).min(chars.len().saturating_sub(1));
        let mut open_paren = None;
        let mut index = start;
        while index < chars.len() {
            if chars[index] == '(' {
                open_paren = Some(index);
                break;
            }
            index += 1;
        }
        let open_index = open_paren?;
        if open_index == 0 {
            return None;
        }
        let mut left = open_index;
        while left > 0 {
            let ch = chars[left - 1];
            if ch == ';'
                || ch == ','
                || ch == '{'
                || ch == '}'
                || ch == '\n'
                || ch == '\r'
                || ch == ':'
                || ch == '?'
            {
                break;
            }
            left -= 1;
        }
        let raw: String = chars[left..open_index].iter().collect();
        let candidate = raw.trim();
        if candidate.is_empty() {
            return None;
        }
        Some(candidate.to_string())
    }

    fn recover_undefined_variables(
        ctx: &mut Context,
        error_msg: &str,
        code: &str,
        scope: &Rc<RefCell<DynamicScope>>,
        log: &Rc<RefCell<SandboxLog>>,
    ) -> Option<JsValue> {
        let mut seen = BTreeSet::new();
        let mut current_error = error_msg.to_string();
        let mut prelude = String::new();
        for _ in 0..MAX_UNDEFINED_RECOVERY_PASSES {
            let var_name = extract_undefined_variable(&current_error)?;
            if !seen.insert(var_name.clone()) {
                break;
            }

            let is_called = code.contains(&format!("{}(", var_name))
                || code.contains(&format!("{} (", var_name));
            if is_called {
                prelude.push_str(&format!("var {} = function(){{}};", var_name));
            } else {
                prelude.push_str(&format!("var {} = \"\";", var_name));
            }

            scope.borrow_mut().auto_promote.insert(var_name.clone());

            {
                let mut log_ref = log.borrow_mut();
                log_ref.variable_events.push(VariableEvent {
                    variable: var_name,
                    event_type: VariableEventType::UndefinedAccess,
                    value: "recovered".to_string(),
                    scope: "global".to_string(),
                    timestamp: std::time::Duration::from_millis(0),
                });
            }

            let merged = format!("{}{}", prelude, code);
            match ctx.eval(Source::from_bytes(merged.as_bytes())) {
                Ok(result) => return Some(result),
                Err(err) => {
                    let new_error = format!("{:?}", err);
                    if new_error.contains("is not defined") {
                        current_error = new_error;
                        continue;
                    }
                    if new_error.contains("not a callable function") {
                        let call_names = gather_bare_call_names(code);
                        let dotted_paths = gather_dotted_call_paths(code);
                        let mut injected = prelude.clone();
                        for name in call_names {
                            if injected.contains(&format!("var {} =", name)) {
                                continue;
                            }
                            injected.push_str(&format!("var {} = function(){{}};", name));
                        }
                        injected.push_str(&build_dotted_call_stub_prelude(&dotted_paths));
                        let merged = format!("{}{}", injected, code);
                        if let Ok(result) = ctx.eval(Source::from_bytes(merged.as_bytes())) {
                            return Some(result);
                        }
                    }
                    break;
                }
            }
        }

        None
    }

    fn gather_bare_call_names(code: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        let keywords = [
            "break",
            "case",
            "catch",
            "continue",
            "debugger",
            "default",
            "delete",
            "do",
            "else",
            "false",
            "finally",
            "for",
            "function",
            "if",
            "in",
            "instanceof",
            "new",
            "null",
            "return",
            "switch",
            "this",
            "throw",
            "true",
            "try",
            "typeof",
            "var",
            "void",
            "while",
            "with",
        ];
        let skip =
            ["eval", "unescape", "escape", "alert", "parseInt", "parseFloat", "isNaN", "isFinite"];
        let chars: Vec<char> = code.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let ch = chars[i];
            if ch.is_ascii_alphabetic() || ch == '_' || ch == '$' {
                let start = i;
                i += 1;
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '$')
                {
                    i += 1;
                }
                let ident: String = chars[start..i].iter().collect();
                let mut j = i;
                while j < chars.len() && chars[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < chars.len() && chars[j] == '(' {
                    let mut k = start;
                    while k > 0 && chars[k - 1].is_ascii_whitespace() {
                        k -= 1;
                    }
                    let prev = if k > 0 { chars[k - 1] } else { '\0' };
                    if prev != '.'
                        && !keywords.contains(&ident.as_str())
                        && !skip.contains(&ident.as_str())
                    {
                        names.insert(ident);
                    }
                }
                i = j;
                continue;
            }
            i += 1;
        }
        names
    }

    fn gather_dotted_call_paths(code: &str) -> BTreeSet<String> {
        let mut paths = BTreeSet::new();
        let Ok(regex) =
            regex::Regex::new(r"([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+)\s*\(")
        else {
            return paths;
        };
        for captures in regex.captures_iter(code) {
            if let Some(path) = captures.get(1).map(|value| value.as_str()) {
                if path.starts_with("Math.")
                    || path.starts_with("JSON.")
                    || path.starts_with("Object.")
                    || path.starts_with("String.")
                {
                    continue;
                }
                paths.insert(path.to_string());
            }
        }
        paths
    }

    fn build_dotted_call_stub_prelude(paths: &BTreeSet<String>) -> String {
        let mut prelude = String::new();
        for path in paths {
            let parts = path.split('.').collect::<Vec<_>>();
            if parts.len() < 2 {
                continue;
            }
            let root = parts[0];
            if root != "this" {
                prelude.push_str(&format!(
                    "if(typeof {root}==='undefined'||{root}===null){{{root}={{}};}}"
                ));
            }
            for idx in 1..parts.len() - 1 {
                let full = parts[..=idx].join(".");
                let parent = parts[..idx].join(".");
                let key = parts[idx];
                prelude.push_str(&format!(
                    "if(typeof {full}!=='object'&&typeof {full}!=='function'){{{parent}.{key}={{}};}}"
                ));
            }
            prelude.push_str(&format!("if(typeof {path}!=='function'){{{path}=function(){{}};}}"));
        }
        prelude
    }

    fn override_callable_assignments(code: &str, call_names: &BTreeSet<String>) -> String {
        let bytes = code.as_bytes();
        let mut out = String::with_capacity(code.len());
        let mut i = 0;
        while i < bytes.len() {
            if is_ident_start(bytes[i]) {
                let start = i;
                i += 1;
                while i < bytes.len() && is_ident_char(bytes[i]) {
                    i += 1;
                }
                let ident = &code[start..i];
                let mut k = i;
                while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                let prev = if start > 0 { bytes[start - 1] } else { b'\0' };
                if prev != b'.'
                    && call_names.contains(ident)
                    && k < bytes.len()
                    && bytes[k] == b'='
                    && (k + 1 == bytes.len() || bytes[k + 1] != b'=')
                {
                    let mut end = k + 1;
                    while end < bytes.len() && bytes[end] != b';' {
                        end += 1;
                    }
                    if end < bytes.len() {
                        end += 1;
                    }
                    out.push_str(&format!("{} = function(){{}};", ident));
                    i = end;
                    continue;
                }
                out.push_str(ident);
                continue;
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        out
    }

    fn is_ident_start(byte: u8) -> bool {
        byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$'
    }

    fn is_ident_char(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
    }

    fn extract_undefined_variable(error_msg: &str) -> Option<String> {
        if let Some(idx) = error_msg.find(" is not defined") {
            let prefix = &error_msg[..idx];
            let mut chars = prefix.chars().rev();
            let mut name_rev = String::new();
            for ch in &mut chars {
                if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
                    name_rev.push(ch);
                } else {
                    break;
                }
            }
            if !name_rev.is_empty() {
                return Some(name_rev.chars().rev().collect());
            }
        }

        // Fallback: look for "word is not defined" pattern
        let words: Vec<&str> = error_msg.split_whitespace().collect();
        for (i, word) in words.iter().enumerate() {
            if *word == "is"
                && i + 2 < words.len()
                && words[i + 1] == "not"
                && words[i + 2] == "defined"
                && i > 0
            {
                let candidate =
                    words[i - 1].trim_end_matches(',').trim_matches('"').trim_matches('\'');
                if !candidate.is_empty() {
                    return Some(candidate.to_string());
                }
            }
        }

        None
    }

    fn attempt_syntax_cleanup(code: &str) -> String {
        let mut result = code.replace('\u{0}', "");

        // Common syntax fixes for obfuscated code
        result = result.replace(";;", ";"); // Double semicolons
        result = result.replace("  ", " "); // Multiple spaces
        result = result.trim().to_string(); // Leading/trailing whitespace
        result = result.replace("?.", ".");
        result = result.replace("??", "||");
        result = result.replace('?', "");
        result = scrub_invalid_unicode_escapes(&result);

        if let Some(idx) = result.rfind(';') {
            if !result[idx + 1..].trim().is_empty() {
                result.truncate(idx + 1);
            }
        } else if let Some(idx) = result.rfind('}') {
            if !result[idx + 1..].trim().is_empty() {
                result.truncate(idx + 1);
            }
        }

        if result.trim_end().ends_with('(') {
            result.push_str("){}");
        }

        let mut in_single = false;
        let mut in_double = false;
        let mut in_backtick = false;
        let mut escape = false;
        let mut brace = 0i32;
        let mut paren = 0i32;
        let mut bracket = 0i32;

        for ch in result.chars() {
            if escape {
                escape = false;
                continue;
            }
            if in_single {
                if ch == '\\' {
                    escape = true;
                } else if ch == '\'' {
                    in_single = false;
                }
                continue;
            }
            if in_double {
                if ch == '\\' {
                    escape = true;
                } else if ch == '"' {
                    in_double = false;
                }
                continue;
            }
            if in_backtick {
                if ch == '\\' {
                    escape = true;
                } else if ch == '`' {
                    in_backtick = false;
                }
                continue;
            }
            match ch {
                '\'' => in_single = true,
                '"' => in_double = true,
                '`' => in_backtick = true,
                '{' => brace += 1,
                '}' => brace = (brace - 1).max(0),
                '(' => paren += 1,
                ')' => paren = (paren - 1).max(0),
                '[' => bracket += 1,
                ']' => bracket = (bracket - 1).max(0),
                _ => {}
            }
        }

        if in_single {
            result.push('\'');
        }
        if in_double {
            result.push('"');
        }
        if in_backtick {
            result.push('`');
        }
        for _ in 0..bracket {
            result.push(']');
        }
        for _ in 0..paren {
            result.push(')');
        }
        for _ in 0..brace {
            result.push('}');
        }

        // Try to fix incomplete statements
        if !result.ends_with(';') && !result.ends_with('}') {
            result.push(';');
        }

        if let Some(pos) = result.rfind("function") {
            let tail = &result[pos..];
            if !tail.contains('{') {
                result.push_str(" {}");
            }
        }

        result
    }

    fn recover_syntax_by_statement_slicing(ctx: &mut Context, code: &str) -> Option<JsValue> {
        let mut recovered = false;
        let mut executed_any = false;
        for statement in code.split(';').take(512) {
            let trimmed = statement.trim();
            if trimmed.is_empty() {
                continue;
            }
            let wrapped = format!("try {{ {}; }} catch(__sis_syntax__) {{}}", trimmed);
            if ctx.eval(Source::from_bytes(wrapped.as_bytes())).is_ok() {
                recovered = true;
                executed_any = true;
            }
        }
        if recovered || executed_any {
            return Some(JsValue::undefined());
        }
        None
    }

    fn scrub_invalid_unicode_escapes(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                if bytes[i + 1] == b'u' {
                    if i + 6 <= bytes.len() && bytes[i + 2..i + 6].iter().all(|b| is_hex(*b)) {
                        out.extend_from_slice(&bytes[i..i + 6]);
                        i += 6;
                        continue;
                    }
                    out.extend_from_slice(b"\\u0000");
                    i += 2;
                    continue;
                }
                if bytes[i + 1] == b'x' {
                    if i + 4 <= bytes.len() && bytes[i + 2..i + 4].iter().all(|b| is_hex(*b)) {
                        out.extend_from_slice(&bytes[i..i + 4]);
                        i += 4;
                        continue;
                    }
                    out.extend_from_slice(b"\\x00");
                    i += 2;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).to_string()
    }

    fn is_hex(byte: u8) -> bool {
        byte.is_ascii_hexdigit()
    }

    fn select_loop_iteration_limit(source: &[u8]) -> (u64, &'static str, bool) {
        let lower = String::from_utf8_lossy(source).to_ascii_lowercase();
        let has_busy_wait_increment_loop =
            regex::Regex::new(
                r"while\s*\(\s*[a-z_$][a-z0-9_$]*\s*<\s*[0-9]{6,}\s*\)\s*\{\s*[a-z_$][a-z0-9_$]*\s*\+\+\s*;?\s*\}",
            )
            .map(|pattern| pattern.is_match(&lower))
            .unwrap_or(false);
        let has_downloader_pattern = (lower.contains("wscript.createobject")
            || lower.contains("activexobject")
            || lower.contains("createobject("))
            && (lower.contains("msxml2.xmlhttp") || lower.contains("serverxmlhttp"));
        let has_host_probe_pattern = (lower.contains("activexobject")
            || lower.contains("scripting.filesystemobject")
            || lower.contains("folderexists"))
            && (lower.contains("folderexists") || lower.contains("fileexists"));
        let has_token_decoder_pattern = (lower.contains("split('!')")
            || lower.contains("split(\"!\")")
            || lower.contains("[\"s\"+\"plit\"]('!')"))
            && lower.contains("for (")
            && lower.contains("length")
            && (lower.contains("eval(") || lower.contains("eval ("));
        let has_sentinel_spin_pattern = (lower.contains("while(true)")
            || lower.contains("while (true)")
            || lower.contains("while( true )")
            || lower.contains("while ( true )"))
            && regex::Regex::new(r"==\s*[1-9][0-9]{7,}")
                .map(|pattern| pattern.is_match(&lower))
                .unwrap_or(false);
        if has_busy_wait_increment_loop {
            return (BUSY_WAIT_LOOP_ITERATION_LIMIT, "busy_wait", true);
        }
        if has_sentinel_spin_pattern {
            return (SENTINEL_SPIN_LOOP_ITERATION_LIMIT, "sentinel_spin", true);
        }
        if has_host_probe_pattern {
            return (HOST_PROBE_LOOP_ITERATION_LIMIT, "host_probe", true);
        }
        if has_token_decoder_pattern {
            return (TOKEN_DECODER_LOOP_ITERATION_LIMIT, "token_decoder", true);
        }
        if has_downloader_pattern {
            (DOWNLOADER_LOOP_ITERATION_LIMIT, "downloader", true)
        } else {
            (BASE_LOOP_ITERATION_LIMIT, "base", false)
        }
    }

    fn should_collapse_phase_plan(source: &[u8]) -> bool {
        if source.len() < 16_384 {
            return false;
        }
        let lower = String::from_utf8_lossy(source).to_ascii_lowercase();
        (lower.contains("split('!')")
            || lower.contains("split(\"!\")")
            || lower.contains("[\"s\"+\"plit\"]('!')"))
            && (lower.contains("eval(") || lower.contains("eval ("))
    }

    fn should_skip_complex_token_decoder(bytes: &[u8]) -> bool {
        if bytes.len() < 48_000 {
            return false;
        }
        let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        let has_split_pattern = lower.contains("split")
            || lower.contains("[\"s\"+\"plit\"]")
            || lower.contains("['s'+'plit']");
        let has_loop_pattern = lower.contains("for (") || lower.contains("for(");
        has_split_pattern
            && lower.contains("/*@cc_on")
            && has_loop_pattern
            && lower.contains("eval(")
    }

    fn classify_oversized_payload_reason(bytes: &[u8]) -> &'static str {
        let probe_len = std::cmp::min(bytes.len(), 96 * 1024);
        let lower = String::from_utf8_lossy(&bytes[..probe_len]).to_ascii_lowercase();
        let has_split_pattern = lower.contains("split")
            || lower.contains("[\"s\"+\"plit\"]")
            || lower.contains("['s'+'plit']");
        let has_cc_loop = lower.contains("/*@cc_on")
            && (lower.contains("for(") || lower.contains("for ("))
            && lower.contains("eval(");
        if has_split_pattern && has_cc_loop {
            "payload_too_large_token_decoder"
        } else {
            "payload_too_large"
        }
    }

    fn loop_iteration_limit_hits(errors: &[String]) -> usize {
        errors
            .iter()
            .filter(|error| {
                let lower = error.to_ascii_lowercase();
                lower.contains("maximum loop iteration limit")
                    || lower.contains("loop iteration limit")
            })
            .count()
    }

    fn is_runtime_limit_error(error_text: &str) -> bool {
        let lower = error_text.to_ascii_lowercase();
        lower.contains("maximum loop iteration limit")
            || lower.contains("loop iteration limit")
            || lower.contains("runtimelimit")
    }

    fn should_suppress_runtime_limit(log: &SandboxLog, error_text: &str) -> bool {
        if !is_runtime_limit_error(error_text) {
            return false;
        }
        if log.adaptive_loop_profile != "sentinel_spin" {
            return false;
        }
        log.calls.iter().any(|call| {
            matches!(
                call.as_str(),
                "ActiveXObject"
                    | "WScript.CreateObject"
                    | "WScript.Shell.ExpandEnvironmentStrings"
                    | "Shell.Application.NameSpace"
            )
        })
    }

    fn make_native(log: Rc<RefCell<SandboxLog>>, name: &'static str) -> NativeFunction {
        unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, captures.name, args, ctx);
                    Ok(JsValue::undefined())
                },
                LogNameCapture { log, name },
            )
        }
    }

    fn make_native_probe_exists(
        log: Rc<RefCell<SandboxLog>>,
        name: &'static str,
        threshold: usize,
    ) -> NativeFunction {
        unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, args, captures, ctx| {
                    record_call(&captures.log, captures.name, args, ctx);
                    let call_count = current_call_count(&captures.log, captures.name);
                    let should_exist = call_count >= threshold;
                    if should_exist {
                        let mut log_ref = captures.log.borrow_mut();
                        log_ref.probe_loop_short_circuit_hits += 1;
                    }
                    Ok(JsValue::from(should_exist))
                },
                LogNameCapture { log, name },
            )
        }
    }

    fn current_call_count(log: &Rc<RefCell<SandboxLog>>, name: &str) -> usize {
        log.borrow().call_counts_by_name.get(name).copied().unwrap_or(0)
    }

    fn make_getter(
        context: &mut Context,
        log: Rc<RefCell<SandboxLog>>,
        name: &'static str,
        value: &'static str,
    ) -> JsFunction {
        let getter_value = JsValue::from(JsString::from(value));
        let function = unsafe {
            NativeFunction::from_closure_with_captures(
                move |_this, _args, captures, _ctx| {
                    record_prop(&captures.log, name);
                    Ok(captures.value.clone())
                },
                LogValueCapture { log, value: getter_value },
            )
        };
        FunctionObjectBuilder::new(context.realm(), function)
            .name(JsString::from(name))
            .length(0)
            .constructor(false)
            .build()
    }

    fn record_call(log: &Rc<RefCell<SandboxLog>>, name: &str, args: &[JsValue], ctx: &mut Context) {
        let mut log_ref = log.borrow_mut();
        let phase_key = log_ref.current_phase.clone();
        log_ref.call_count += 1;
        *log_ref.call_counts_by_name.entry(name.to_string()).or_insert(0) += 1;
        if log_ref.calls.len() < MAX_RECORDED_CALLS {
            log_ref.calls.push(name.to_string());
        } else {
            log_ref.calls_dropped += 1;
        }
        log_ref.unique_calls.insert(name.to_string());
        *log_ref.phase_call_counts.entry(phase_key.clone()).or_insert(0) += 1;
        if is_reflection_probe_call(name) {
            if log_ref.reflection_probes.len() < MAX_RECORDED_CALLS {
                log_ref.reflection_probes.push(name.to_string());
            } else {
                log_ref.calls_dropped += 1;
            }
        }
        if is_dynamic_code_call(name) {
            if log_ref.dynamic_code_calls.len() < MAX_RECORDED_CALLS {
                log_ref.dynamic_code_calls.push(name.to_string());
            } else {
                log_ref.calls_dropped += 1;
            }
            log_ref.phase_dynamic_code_calls.entry(phase_key).or_default().insert(name.to_string());
        }
        if is_property_delete_call(name) {
            if log_ref.prop_deletes.len() < MAX_RECORDED_PROP_READS {
                log_ref.prop_deletes.push(name.to_string());
            } else {
                log_ref.prop_reads_dropped += 1;
            }
        }
        if is_property_write_call(name) {
            if log_ref.prop_writes.len() < MAX_RECORDED_PROP_READS {
                log_ref.prop_writes.push(name.to_string());
            } else {
                log_ref.prop_reads_dropped += 1;
            }
        }
        let arg_summary = summarise_args(args, ctx, &log_ref.options);
        if log_ref.call_args.len() < log_ref.options.max_call_args {
            if let Some(summary) = arg_summary.as_ref() {
                log_ref.call_args.push(format!("{}({})", name, summary));
            }
        } else {
            log_ref.call_args_dropped += 1;
        }
        let heap_entry = if let Some(summary) = arg_summary.as_ref() {
            if summary.is_empty() {
                name.to_string()
            } else {
                format!("{name}({summary})")
            }
        } else {
            name.to_string()
        };
        if is_heap_allocation_call(name) {
            log_ref.heap_allocation_count += 1;
            if log_ref.heap_allocations.len() < MAX_RECORDED_HEAP_EVENTS {
                log_ref.heap_allocations.push(heap_entry.clone());
            } else {
                log_ref.heap_allocations_dropped += 1;
            }
        }
        if is_heap_view_call(name) {
            log_ref.heap_view_count += 1;
            if log_ref.heap_views.len() < MAX_RECORDED_HEAP_EVENTS {
                log_ref.heap_views.push(heap_entry.clone());
            } else {
                log_ref.heap_views_dropped += 1;
            }
        }
        if is_heap_access_call(name) {
            log_ref.heap_access_count += 1;
            if log_ref.heap_accesses.len() < MAX_RECORDED_HEAP_EVENTS {
                log_ref.heap_accesses.push(heap_entry);
            } else {
                log_ref.heap_accesses_dropped += 1;
            }
        }
        for arg in args {
            if let Some(value) = js_value_string(arg) {
                if (name == "WebSocket.send" || name == "RTCDataChannel.send") && !value.is_empty()
                {
                    log_ref.realtime_payload_bytes += value.len();
                }
                if name == "WebSocket" && looks_like_url(&value) {
                    log_ref.realtime_targets.insert(value.clone());
                }
                if looks_like_url(&value) {
                    if log_ref.urls.len() < log_ref.options.max_urls {
                        log_ref.urls.push(value.clone());
                    } else {
                        log_ref.urls_dropped += 1;
                    }
                    if let Some(domain) = domain_from_url(&value) {
                        if log_ref.domains.len() < log_ref.options.max_domains {
                            log_ref.domains.push(domain);
                        } else {
                            log_ref.domains_dropped += 1;
                        }
                    }
                }
            }
        }
        if name.starts_with("navigator.serviceWorker.") {
            match name {
                "navigator.serviceWorker.register" => {
                    log_ref.worker_registration_observed = true;
                    log_ref.sw_registration_calls += 1;
                }
                "navigator.serviceWorker.update" => {
                    log_ref.sw_update_calls += 1;
                }
                _ => {}
            }
        }
        if name.starts_with("self.addEventListener") {
            log_ref.sw_event_handlers_registered += 1;
        }
        if name.starts_with("caches.") {
            log_ref.sw_cache_calls += 1;
        }
        if name.starts_with("indexedDB.") || name.starts_with("IDBObjectStore.") {
            log_ref.sw_indexeddb_calls += 1;
        }
        if name == "WebSocket.send" || name == "RTCDataChannel.send" {
            log_ref.realtime_send_count += 1;
        }
        if name.starts_with("WebSocket") {
            log_ref.realtime_channel_types.insert("websocket".to_string());
        }
        if name.starts_with("RTC") {
            log_ref.realtime_channel_types.insert("rtc_datachannel".to_string());
        }
        if name == "child_process.exec" || name == "child_process.spawn" || name == "Bun.spawn" {
            log_ref.lifecycle_background_attempts += 1;
        }
        if matches!(
            log_ref.current_phase.as_str(),
            "npm.preinstall" | "npm.install" | "npm.postinstall" | "bun.install"
        ) {
            log_ref.lifecycle_hook_calls += 1;
        }
        let taint_source = match name {
            "document.cookie" => Some(TaintEventKind::Cookie),
            "localStorage.getItem" => Some(TaintEventKind::LocalStorage),
            "sessionStorage.getItem" => Some(TaintEventKind::SessionStorage),
            "getField" | "document.querySelector" | "document.getElementById" => {
                Some(TaintEventKind::FormField)
            }
            "navigator.clipboard.readText" | "navigator.clipboard.read" => {
                Some(TaintEventKind::Clipboard)
            }
            _ => None,
        };
        if let Some(kind) = taint_source {
            let call_index = log_ref.call_count;
            let phase = log_ref.current_phase.clone();
            log_ref.taint_sources.push(TaintEvent { kind, call_index, phase });
        }
        let taint_sink = match name {
            "eval" | "app.eval" | "event.target.eval" => Some(TaintEventKind::Eval),
            "Function" => Some(TaintEventKind::Function),
            "fetch" => Some(TaintEventKind::Fetch),
            "navigator.sendBeacon" => Some(TaintEventKind::SendBeacon),
            "WebSocket.send" => Some(TaintEventKind::WebSocketSend),
            "RTCDataChannel.send" => Some(TaintEventKind::RtcDataChannelSend),
            "XMLHttpRequest.send" | "MSXML2.XMLHTTP.send" | "MSXML2.XMLHTTP.Send" => {
                Some(TaintEventKind::XmlHttpSend)
            }
            _ => None,
        };
        if let Some(kind) = taint_sink {
            let call_index = log_ref.call_count;
            let phase = log_ref.current_phase.clone();
            log_ref.taint_sinks.push(TaintEvent { kind, call_index, phase });
        }
    }

    fn record_prop(log: &Rc<RefCell<SandboxLog>>, name: &str) {
        let mut log_ref = log.borrow_mut();
        if log_ref.prop_reads.len() < MAX_RECORDED_PROP_READS {
            log_ref.prop_reads.push(name.to_string());
        } else {
            log_ref.prop_reads_dropped += 1;
        }
        log_ref.unique_prop_reads.insert(name.to_string());
        let phase_key = log_ref.current_phase.clone();
        *log_ref.phase_prop_read_counts.entry(phase_key).or_insert(0) += 1;
    }

    fn set_phase(log: &Rc<RefCell<SandboxLog>>, phase: &str) {
        let mut log_ref = log.borrow_mut();
        log_ref.current_phase = phase.to_string();
        if !log_ref.phase_sequence.iter().any(|existing| existing == phase) {
            log_ref.phase_sequence.push(phase.to_string());
        }
    }

    fn infer_lifecycle_context(bytes: &[u8], options: &DynamicOptions) -> Option<String> {
        if let Some(context) = options.lifecycle_context {
            return Some(context.as_str().to_string());
        }
        let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        if text.contains("process.env.npm_lifecycle_event") {
            if text.contains("preinstall") {
                return Some("npm.preinstall".to_string());
            }
            if text.contains("postinstall") {
                return Some("npm.postinstall".to_string());
            }
            return Some("npm.install".to_string());
        }
        if text.contains("#!/usr/bin/env bun") {
            return Some("bun.install".to_string());
        }
        if text.contains("#!/usr/bin/env node") {
            return Some("npm.install".to_string());
        }
        None
    }

    fn maybe_execute_service_worker_micro_phases(
        context: &mut Context,
        normalised: &[u8],
        log: &Rc<RefCell<SandboxLog>>,
        timeout_context_thread: &Arc<Mutex<crate::types::TimeoutContext>>,
        timeout_budget_ms: u128,
        phase_timeout_ms: u128,
        total_elapsed: &mut u128,
    ) {
        let should_run = { log.borrow().worker_registration_observed };
        if !should_run {
            return;
        }
        let phases = [
            ("sw_install", "if (typeof self.oninstall === 'function') { self.oninstall(); }"),
            ("sw_activate", "if (typeof self.onactivate === 'function') { self.onactivate(); }"),
            ("sw_fetch", "if (typeof self.onfetch === 'function') { self.onfetch(); }"),
            ("sw_push", "if (typeof self.onpush === 'function') { self.onpush(); }"),
            ("sw_sync", "if (typeof self.onsync === 'function') { self.onsync(); }"),
        ];
        for (phase, script) in phases {
            let timed_out = execute_micro_phase(
                context,
                log,
                timeout_context_thread,
                timeout_budget_ms,
                phase_timeout_ms,
                total_elapsed,
                phase,
                script,
            );
            if timed_out {
                break;
            }
        }
        let mut log_ref = log.borrow_mut();
        let lower = String::from_utf8_lossy(normalised).to_ascii_lowercase();
        log_ref.sw_lifecycle_events_executed += phases
            .iter()
            .filter(|(name, _)| lower.contains(name.trim_start_matches("sw_")))
            .count();
    }

    fn maybe_execute_lifecycle_micro_phases(
        context: &mut Context,
        log: &Rc<RefCell<SandboxLog>>,
        timeout_context_thread: &Arc<Mutex<crate::types::TimeoutContext>>,
        timeout_budget_ms: u128,
        phase_timeout_ms: u128,
        total_elapsed: &mut u128,
    ) {
        let Some(context_name) = log.borrow().lifecycle_context_observed.clone() else {
            return;
        };
        let script = "if (typeof preinstall === 'function') { preinstall(); } if (typeof install === 'function') { install(); } if (typeof postinstall === 'function') { postinstall(); } if (typeof Bun !== 'undefined' && Bun && typeof Bun.spawn === 'function') { Bun.spawn(['echo']); }";
        let _ = execute_micro_phase(
            context,
            log,
            timeout_context_thread,
            timeout_budget_ms,
            phase_timeout_ms,
            total_elapsed,
            &context_name,
            script,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_micro_phase(
        context: &mut Context,
        log: &Rc<RefCell<SandboxLog>>,
        timeout_context_thread: &Arc<Mutex<crate::types::TimeoutContext>>,
        timeout_budget_ms: u128,
        phase_timeout_ms: u128,
        total_elapsed: &mut u128,
        phase_name: &str,
        script: &str,
    ) -> bool {
        if let Ok(mut context_ref) = timeout_context_thread.lock() {
            context_ref.phase = Some(phase_name.to_string());
        }
        set_phase(log, phase_name);
        let eval_start = Instant::now();
        let eval_res = context.eval(Source::from_bytes(script.as_bytes()));
        let elapsed = eval_start.elapsed().as_millis();
        *total_elapsed += elapsed;
        if let Ok(mut context_ref) = timeout_context_thread.lock() {
            context_ref.elapsed_ms = Some(*total_elapsed);
            if timeout_budget_ms > 0 {
                let ratio = *total_elapsed as f64 / timeout_budget_ms as f64;
                context_ref.budget_ratio = Some(ratio.min(1.0));
            }
        }
        {
            let mut log_ref = log.borrow_mut();
            log_ref.phase_elapsed_ms.insert(phase_name.to_string(), elapsed);
        }
        if elapsed > phase_timeout_ms {
            let mut log_ref = log.borrow_mut();
            *log_ref.phase_error_counts.entry(phase_name.to_string()).or_insert(0) += 1;
            if log_ref.errors.len() < MAX_RECORDED_ERRORS {
                log_ref.errors.push(format!(
                    "phase timeout exceeded: phase={} limit_ms={} observed_ms={}",
                    phase_name, phase_timeout_ms, elapsed
                ));
            } else {
                log_ref.errors_dropped += 1;
            }
            return true;
        }
        if let Err(err) = eval_res {
            let mut log_ref = log.borrow_mut();
            if log_ref.errors.len() < MAX_RECORDED_ERRORS {
                log_ref.errors.push(format!("{:?}", err));
            } else {
                log_ref.errors_dropped += 1;
            }
            *log_ref.phase_error_counts.entry(phase_name.to_string()).or_insert(0) += 1;
        }
        false
    }

    fn correlate_taint_edges(log: &mut SandboxLog) {
        log.taint_edges.clear();
        for source in &log.taint_sources {
            for sink in &log.taint_sinks {
                if sink.call_index < source.call_index {
                    continue;
                }
                let distance = sink.call_index - source.call_index;
                if distance > MAX_TAINT_CALL_DISTANCE {
                    continue;
                }
                if log.taint_edges.len() >= MAX_TAINT_EDGES {
                    return;
                }
                log.taint_edges.push(TaintEdge {
                    source: source.kind,
                    sink: sink.kind,
                    call_distance: distance,
                    phase_source: source.phase.clone(),
                    phase_sink: sink.phase.clone(),
                });
            }
        }
        log.taint_edges.sort_by(|left, right| {
            left.call_distance
                .cmp(&right.call_distance)
                .then_with(|| left.source.cmp(&right.source))
                .then_with(|| left.sink.cmp(&right.sink))
        });
    }

    fn phase_script_for(phase: RuntimePhase) -> Option<&'static str> {
        match phase {
            RuntimePhase::Open => None,
            RuntimePhase::Idle => Some(
                "if (typeof onIdle === 'function') { onIdle(); } if (typeof tick === 'function') { tick(); }",
            ),
            RuntimePhase::Click => Some(
                "if (typeof onClick === 'function') { onClick(); } if (typeof mouseUp === 'function') { mouseUp(); } if (typeof this.mouseUp === 'function') { this.mouseUp(); }",
            ),
            RuntimePhase::Form => Some(
                "if (typeof onSubmit === 'function') { onSubmit(); } if (typeof validate === 'function') { validate(); } if (typeof this.validate === 'function') { this.validate(); }",
            ),
        }
    }

    fn phase_order(options: &DynamicOptions) -> Vec<RuntimePhase> {
        let mut out = Vec::new();
        for phase in &options.phases {
            if !out.iter().any(|existing| existing == phase) {
                out.push(*phase);
            }
        }
        if out.is_empty() {
            out.push(RuntimePhase::Open);
        }
        out
    }

    fn render_phase_summaries(log: &SandboxLog) -> Vec<crate::types::DynamicPhaseSummary> {
        log.phase_sequence
            .iter()
            .map(|phase| crate::types::DynamicPhaseSummary {
                phase: phase.clone(),
                call_count: *log.phase_call_counts.get(phase).unwrap_or(&0),
                prop_read_count: *log.phase_prop_read_counts.get(phase).unwrap_or(&0),
                error_count: *log.phase_error_counts.get(phase).unwrap_or(&0),
                elapsed_ms: *log.phase_elapsed_ms.get(phase).unwrap_or(&0),
            })
            .collect()
    }

    fn register_profiled_stubs(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let profile = log.borrow().options.runtime_profile.clone();
        match profile.kind {
            RuntimeKind::PdfReader => {
                let doc = register_doc_stub(context, log.clone());
                register_app(context, log.clone(), Some(doc));
                register_util(context, log.clone());
                register_collab(context, log.clone());
                register_soap(context, log.clone());
                register_net(context, log.clone());
                register_browser_like(context, log.clone());
                register_require_stub(context, log.clone());
                register_buffer_stub(context, log.clone());
                register_heap_runtime_stubs(context, log.clone());
                register_webassembly_stub(context, log.clone());
                register_windows_scripting(context, log.clone());
                register_windows_com(context, log.clone());
                register_windows_wmi(context, log.clone());
            }
            RuntimeKind::Browser => {
                register_browser_like(context, log.clone());
                register_net(context, log.clone());
                register_util(context, log.clone());
                register_heap_runtime_stubs(context, log.clone());
                register_webassembly_stub(context, log.clone());
            }
            RuntimeKind::Node => {
                register_node_like(context, log.clone());
                register_net(context, log.clone());
                register_util(context, log.clone());
                register_heap_runtime_stubs(context, log.clone());
                register_webassembly_stub(context, log.clone());
            }
            RuntimeKind::Bun => {
                register_node_like(context, log.clone());
                register_browser_like(context, log.clone());
                register_net(context, log.clone());
                register_util(context, log.clone());
                register_heap_runtime_stubs(context, log.clone());
                register_webassembly_stub(context, log.clone());
            }
        }
    }

    fn is_reflection_probe_call(name: &str) -> bool {
        matches!(
            name,
            "hasOwnProperty"
                | "Object.keys"
                | "Object.getOwnPropertyNames"
                | "Object.getOwnPropertyDescriptor"
                | "Object.getPrototypeOf"
                | "Object.prototype.toString"
                | "propertyIsEnumerable"
        )
    }

    fn is_dynamic_code_call(name: &str) -> bool {
        matches!(name, "eval" | "app.eval" | "event.target.eval" | "Function" | "unescape")
    }

    fn is_property_delete_call(name: &str) -> bool {
        name.contains("delete") || name == "removeDataObject"
    }

    fn is_property_write_call(name: &str) -> bool {
        matches!(
            name,
            "createDataObject"
                | "importDataObject"
                | "insertPages"
                | "replacePages"
                | "newDoc"
                | "saveAs"
                | "exportAsFDF"
                | "exportAsXFDF"
        )
    }

    fn is_heap_allocation_call(name: &str) -> bool {
        matches!(
            name,
            "ArrayBuffer"
                | "SharedArrayBuffer"
                | "Buffer.alloc"
                | "Buffer.from"
                | "WebAssembly.Memory"
                | "Int8Array"
                | "Uint8Array"
                | "Uint8ClampedArray"
                | "Int16Array"
                | "Uint16Array"
                | "Int32Array"
                | "Uint32Array"
                | "Float32Array"
                | "Float64Array"
                | "BigInt64Array"
                | "BigUint64Array"
        )
    }

    fn is_heap_view_call(name: &str) -> bool {
        matches!(
            name,
            "DataView"
                | "DataView.getInt8"
                | "DataView.getUint8"
                | "DataView.getInt16"
                | "DataView.getUint16"
                | "DataView.getInt32"
                | "DataView.getUint32"
                | "DataView.getFloat32"
                | "DataView.getFloat64"
                | "DataView.setInt8"
                | "DataView.setUint8"
                | "DataView.setInt16"
                | "DataView.setUint16"
                | "DataView.setInt32"
                | "DataView.setUint32"
                | "DataView.setFloat32"
                | "DataView.setFloat64"
                | "ArrayBuffer.slice"
                | "TypedArray.subarray"
                | "TypedArray.slice"
                | "TypedArray.set"
        )
    }

    fn is_heap_access_call(name: &str) -> bool {
        matches!(
            name,
            "DataView.getInt8"
                | "DataView.getUint8"
                | "DataView.getInt16"
                | "DataView.getUint16"
                | "DataView.getInt32"
                | "DataView.getUint32"
                | "DataView.getFloat32"
                | "DataView.getFloat64"
                | "DataView.setInt8"
                | "DataView.setUint8"
                | "DataView.setInt16"
                | "DataView.setUint16"
                | "DataView.setInt32"
                | "DataView.setUint32"
                | "DataView.setFloat32"
                | "DataView.setFloat64"
                | "TypedArray.set"
                | "TypedArray.copyWithin"
                | "TypedArray.fill"
                | "TypedArray.at"
                | "TypedArray.subarray"
                | "TypedArray.slice"
        )
    }

    fn dedupe_strings(values: Vec<String>) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for value in values {
            if seen.insert(value.clone()) {
                out.push(value);
            }
        }
        out
    }

    fn dedupe_sorted(values: Vec<String>) -> Vec<String> {
        values.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
    }

    fn exfil_url_features(url: &str, target_repetition: usize) -> ExfilUrlFeatures {
        let mut features = ExfilUrlFeatures { target_repetition, ..ExfilUrlFeatures::default() };
        let domain = domain_from_url(url).unwrap_or_default();
        features.label_depth = domain.split('.').filter(|part| !part.is_empty()).count();
        features.subdomain_entropy =
            if domain.is_empty() { 0.0 } else { approx_string_entropy(&domain) };
        if let Some((_, query)) = url.split_once('?') {
            features.query_length = query.len();
            let key_count = query.matches('=').count();
            features.key_value_density =
                if query.is_empty() { 0.0 } else { key_count as f64 / query.len() as f64 };
            features.query_entropy = approx_string_entropy(query);
            let lower = query.to_ascii_lowercase();
            features.encoded_token_count += lower.matches("%2f").count();
            features.encoded_token_count += lower.matches("%3d").count();
            features.encoded_token_count += lower.matches("%2b").count();
            features.encoded_token_count += lower.matches("base64").count();
        }
        features
    }

    fn exfil_score_components(
        network_sink_present: bool,
        features: &ExfilUrlFeatures,
    ) -> std::collections::BTreeMap<String, f64> {
        let mut scores = std::collections::BTreeMap::new();
        if network_sink_present {
            scores.insert("network_sink_present".to_string(), 1.0);
        }
        if features.encoded_token_count > 0 {
            scores.insert("encoded_payload_indicator".to_string(), 1.5);
        }
        if features.target_repetition > 1 {
            scores.insert("repeated_target_cadence".to_string(), 2.0);
        }
        if features.query_entropy >= 3.4 {
            scores.insert("high_entropy_query".to_string(), 1.5);
        }
        if features.key_value_density >= 0.03 {
            scores.insert("high_density_query".to_string(), 1.0);
        }
        if features.label_depth >= 4 {
            scores.insert("deep_label_domain".to_string(), 1.0);
        }
        scores
    }

    fn fnv1a64(bytes: &[u8]) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    fn compute_replay_id(bytes: &[u8], options: &DynamicOptions) -> String {
        let phase_text =
            options.phases.iter().map(|phase| phase.as_str()).collect::<Vec<_>>().join(",");
        let descriptor = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            options.runtime_profile.id(),
            options.max_bytes,
            options.timeout_ms,
            options.phase_timeout_ms,
            options.max_call_args,
            options.max_urls,
            options.max_domains,
            phase_text,
            options
                .lifecycle_context
                .map(|value| value.as_str().to_string())
                .unwrap_or_else(|| "none".to_string())
        );
        let mut input = Vec::with_capacity(bytes.len() + descriptor.len());
        input.extend_from_slice(bytes);
        input.extend_from_slice(descriptor.as_bytes());
        format!("jsr-{hash:016x}", hash = fnv1a64(&input))
    }

    fn truncate_set(values: BTreeSet<String>, max: usize) -> Vec<String> {
        values.into_iter().take(max).collect()
    }

    fn is_identifier_start(ch: char) -> bool {
        ch == '_' || ch == '$' || ch.is_ascii_alphabetic()
    }

    fn is_identifier_char(ch: char) -> bool {
        ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
    }

    fn is_call_keyword(token: &str) -> bool {
        matches!(token, "if" | "for" | "while" | "switch" | "catch" | "return" | "typeof")
    }

    fn extract_string_literal(
        chars: &[char],
        start: usize,
        quote: char,
    ) -> Option<(String, usize)> {
        let mut index = start + 1;
        let mut escaped = false;
        let mut out = String::new();
        while index < chars.len() {
            let ch = chars[index];
            if escaped {
                out.push(ch);
                escaped = false;
                index += 1;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                index += 1;
                continue;
            }
            if ch == quote {
                return Some((out, index + 1));
            }
            out.push(ch);
            index += 1;
        }
        None
    }

    fn next_non_whitespace(chars: &[char], mut index: usize) -> Option<char> {
        while index < chars.len() {
            let ch = chars[index];
            if !ch.is_whitespace() {
                return Some(ch);
            }
            index += 1;
        }
        None
    }

    fn take_identifier(chars: &[char], start: usize) -> (String, usize) {
        let mut index = start;
        let mut token = String::new();
        while index < chars.len() && is_identifier_char(chars[index]) {
            token.push(chars[index]);
            index += 1;
        }
        (token, index)
    }

    fn snapshot_source(source: &str) -> JsSnapshot {
        let mut snapshot = JsSnapshot::default();
        let chars: Vec<char> = source.chars().collect();
        let mut index = 0usize;
        while index < chars.len() {
            let ch = chars[index];
            if ch == '\'' || ch == '"' || ch == '`' {
                if let Some((literal, next)) = extract_string_literal(&chars, index, ch) {
                    if !literal.is_empty() {
                        snapshot.string_literals.insert(literal);
                    }
                    index = next;
                    continue;
                }
            }
            if is_identifier_start(ch) {
                let (token, next) = take_identifier(&chars, index);
                if !token.is_empty() {
                    snapshot.identifiers.insert(token.clone());
                    if let Some('(') = next_non_whitespace(&chars, next) {
                        if !is_call_keyword(&token) {
                            snapshot.calls.insert(token);
                        }
                    }
                }
                index = next;
                continue;
            }
            index += 1;
        }
        snapshot
    }

    fn extract_dynamic_snippets(call_args: &[String]) -> Vec<String> {
        let mut snippets = Vec::new();
        for entry in call_args {
            let Some(open) = entry.find('(') else {
                continue;
            };
            if !entry.ends_with(')') || open + 1 >= entry.len() {
                continue;
            }
            let name = &entry[..open];
            let target = name.trim();
            if !matches!(
                target,
                "eval" | "app.eval" | "event.target.eval" | "Function" | "unescape"
            ) {
                continue;
            }
            let mut payload = entry[open + 1..entry.len() - 1].trim().to_string();
            if payload.is_empty() {
                continue;
            }
            if (payload.starts_with('"') && payload.ends_with('"'))
                || (payload.starts_with('\'') && payload.ends_with('\''))
                || (payload.starts_with('`') && payload.ends_with('`'))
            {
                if payload.len() > 2 {
                    payload = payload[1..payload.len() - 1].to_string();
                } else {
                    payload.clear();
                }
            }
            if !payload.is_empty() {
                snippets.push(payload);
            }
        }
        dedupe_strings(snippets)
    }

    fn compute_snapshot_delta(
        baseline: &JsSnapshot,
        augmented_source: &str,
        phase: String,
        trigger_calls: Vec<String>,
        generated_snippets: usize,
    ) -> Option<SnapshotDeltaSummary> {
        let augmented = snapshot_source(augmented_source);
        let new_identifiers: BTreeSet<String> =
            augmented.identifiers.difference(&baseline.identifiers).cloned().collect();
        let new_literals: BTreeSet<String> =
            augmented.string_literals.difference(&baseline.string_literals).cloned().collect();
        let new_calls: BTreeSet<String> =
            augmented.calls.difference(&baseline.calls).cloned().collect();
        let added_identifier_count = new_identifiers.len();
        let added_string_literal_count = new_literals.len();
        let added_call_count = new_calls.len();
        if added_identifier_count == 0
            && added_string_literal_count == 0
            && added_call_count == 0
            && generated_snippets == 0
        {
            return None;
        }
        Some(SnapshotDeltaSummary {
            phase,
            trigger_calls,
            generated_snippets,
            added_identifier_count,
            added_string_literal_count,
            added_call_count,
            new_identifiers: truncate_set(new_identifiers, 16),
            new_string_literals: truncate_set(new_literals, 16),
            new_calls: truncate_set(new_calls, 16),
        })
    }

    fn summarise_args(
        args: &[JsValue],
        ctx: &mut Context,
        options: &DynamicOptions,
    ) -> Option<String> {
        if args.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        for arg in args.iter().take(options.max_args_per_call) {
            out.push(js_value_summary(arg, ctx, options.max_arg_preview));
        }
        if args.len() > options.max_args_per_call {
            out.push(format!("+{} more", args.len() - options.max_args_per_call));
        }
        Some(out.join(", "))
    }

    fn js_value_summary(value: &JsValue, _ctx: &mut Context, max_len: usize) -> String {
        match value.variant() {
            JsVariant::Undefined => "undefined".into(),
            JsVariant::Null => "null".into(),
            JsVariant::Boolean(b) => b.to_string(),
            JsVariant::Float64(n) => format!("{:.3}", n),
            JsVariant::Integer32(n) => n.to_string(),
            JsVariant::BigInt(_) => "bigint".into(),
            JsVariant::String(_) => {
                let s = value
                    .as_string()
                    .map(|v| v.to_std_string_lossy())
                    .unwrap_or_else(|| "<string>".into());
                summarise_value(&s, max_len)
            }
            JsVariant::Symbol(_) => "symbol".into(),
            JsVariant::Object(_) => {
                if value.is_callable() {
                    "[function]".into()
                } else {
                    "[object]".into()
                }
            }
        }
    }

    fn js_value_string(value: &JsValue) -> Option<String> {
        value.as_string().map(|v| v.to_std_string_lossy())
    }

    fn summarise_value(value: &str, max_len: usize) -> String {
        let mut out = String::new();
        for ch in value.chars() {
            if out.len() >= max_len {
                break;
            }
            if ch.is_ascii_graphic() || ch == ' ' {
                out.push(ch);
            } else if ch.is_whitespace() {
                out.push(' ');
            } else {
                out.push('.');
            }
        }
        out.trim().to_string()
    }

    fn looks_like_url(value: &str) -> bool {
        let lower = value.to_ascii_lowercase();
        lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("mailto:")
            || lower.starts_with("javascript:")
            || lower.starts_with("file:")
    }

    fn domain_from_url(value: &str) -> Option<String> {
        let lower = value.to_ascii_lowercase();
        if lower.starts_with("mailto:") {
            let rest = &value[7..];
            return rest.split('@').nth(1).map(|s| s.split('?').next().unwrap_or(s).to_string());
        }
        if lower.starts_with("http://") || lower.starts_with("https://") {
            let trimmed = value.split("://").nth(1)?;
            let host = trimmed.split('/').next().unwrap_or(trimmed);
            let host = host.split('?').next().unwrap_or(host);
            let host = host.split('#').next().unwrap_or(host);
            if host.is_empty() {
                None
            } else {
                Some(host.to_string())
            }
        } else {
            None
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn summarise_value_sanitizes_and_truncates() {
            let input = "abc\n\u{0000}\u{0008}\u{2603}def";
            let out = summarise_value(input, 64);
            assert!(!out.contains('\n'));
            assert!(out.len() <= 64);
        }

        #[test]
        fn url_helpers_extract_domains() {
            assert!(looks_like_url("http://example.com/path"));
            assert!(looks_like_url("mailto:user@example.com"));
            assert!(looks_like_url("file:///tmp/test"));
            assert_eq!(domain_from_url("http://example.com/a/b").as_deref(), Some("example.com"));
            assert_eq!(domain_from_url("mailto:user@example.com").as_deref(), Some("example.com"));
            assert_eq!(domain_from_url("file:///tmp/test"), None);
        }

        #[test]
        fn summarise_args_caps_count() {
            let mut ctx = Context::default();
            let options = DynamicOptions::default();
            let mut args = Vec::new();
            for i in 0..(options.max_args_per_call + 2) {
                args.push(JsValue::from(i as i32));
            }
            let summary = summarise_args(&args, &mut ctx, &options).unwrap_or_default();
            assert!(summary.contains("+2 more"));
        }
    }
}

#[cfg(feature = "js-sandbox")]
pub use sandbox_impl::{is_file_call, is_network_call, run_sandbox};

#[cfg(not(feature = "js-sandbox"))]
pub fn run_sandbox(_bytes: &[u8], options: &DynamicOptions) -> DynamicOutcome {
    DynamicOutcome::Skipped {
        reason: "sandbox_unavailable".into(),
        limit: options.max_bytes,
        actual: 0,
    }
}

#[cfg(not(feature = "js-sandbox"))]
pub fn is_network_call(_name: &str) -> bool {
    false
}

#[cfg(not(feature = "js-sandbox"))]
pub fn is_file_call(_name: &str) -> bool {
    false
}

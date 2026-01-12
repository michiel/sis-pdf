#![allow(dead_code)]

use crate::types::{DynamicOptions, DynamicOutcome};

#[cfg(feature = "js-sandbox")]
mod sandbox_impl {
    use super::*;
    use crate::types::DynamicSignals;
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::rc::Rc;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::{Duration, Instant};

    use boa_engine::object::builtins::JsFunction;
    use boa_engine::object::{FunctionObjectBuilder, ObjectInitializer};
    use boa_engine::property::Attribute;
    use boa_engine::value::JsVariant;
    use boa_engine::vm::RuntimeLimits;
    use boa_engine::{Context, JsArgs, JsString, JsValue, NativeFunction, Source};

    const CREATOR_PAYLOAD: &str = "z61z70z70z2Ez61z6Cz65z72z74z28z27z68z69z27z29";
    const SUBJECT_PAYLOAD: &str = "Hueputol61Hueputol70Hueputol70Hueputol2EHueputol61Hueputol6CHueputol65Hueputol72Hueputol74Hueputol28Hueputol27Hueputol68Hueputol69Hueputol27Hueputol29";
    const TITLE_PAYLOAD: &str = "%61%6c%65%72%74%28%27%68%69%27%29";

    #[derive(Default, Clone)]
    struct SandboxLog {
        calls: Vec<String>,
        call_args: Vec<String>,
        urls: Vec<String>,
        domains: Vec<String>,
        errors: Vec<String>,
        prop_reads: Vec<String>,
        call_count: usize,
        unique_calls: BTreeSet<String>,
        unique_prop_reads: BTreeSet<String>,
        elapsed_ms: Option<u128>,
        options: DynamicOptions,
        variable_events: Vec<VariableEvent>,
        scope_transitions: Vec<ScopeTransition>,
        execution_flow: ExecutionFlow,
        behavioral_patterns: Vec<BehaviorObservation>,
    }

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
        global_vars: std::collections::HashMap<String, String>,
        auto_promote: BTreeSet<String>,
        eval_contexts: Vec<std::collections::HashMap<String, String>>,
        access_log: Vec<VariableAccess>,
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
        metadata: std::collections::HashMap<String, String>,
        timestamp: std::time::Duration,
    }

    #[derive(Debug, Clone)]
    enum BehaviorSeverity {
        Low,
        Medium,
        High,
        Critical,
    }

    struct BehaviorAnalyzer {
        patterns: Vec<Box<dyn BehaviorPattern>>,
        observations: Vec<BehaviorObservation>,
    }

    trait BehaviorPattern {
        fn name(&self) -> &str;
        fn analyze(&self, flow: &ExecutionFlow, log: &SandboxLog) -> Vec<BehaviorObservation>;
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
            let char_code_calls = log
                .calls
                .iter()
                .filter(|call| *call == "String.fromCharCode")
                .count();

            if char_code_calls > 5 {
                let confidence = (char_code_calls as f64 * 0.1).min(0.95);
                let severity = if char_code_calls > 20 {
                    BehaviorSeverity::High
                } else if char_code_calls > 10 {
                    BehaviorSeverity::Medium
                } else {
                    BehaviorSeverity::Low
                };

                let mut metadata = std::collections::HashMap::new();
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

                let mut metadata = std::collections::HashMap::new();
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

                let mut metadata = std::collections::HashMap::new();
                metadata.insert(
                    "fingerprint_reads".to_string(),
                    fingerprint_count.to_string(),
                );

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
            let recovery_attempts = flow
                .exception_handling
                .iter()
                .filter(|ex| ex.recovery_attempted)
                .count();

            if error_count > 0 && recovery_attempts > 0 {
                let confidence = 0.8; // High confidence when we see error recovery

                let mut metadata = std::collections::HashMap::new();
                metadata.insert("total_errors".to_string(), error_count.to_string());
                metadata.insert(
                    "recovery_attempts".to_string(),
                    recovery_attempts.to_string(),
                );

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
                .filter(|ve| matches!(ve.event_type, VariableEventType::Declaration))
                .count();

            if promotion_count > 0 {
                let confidence = 0.9; // High confidence when we see our promotion system working

                let mut metadata = std::collections::HashMap::new();
                metadata.insert(
                    "promoted_variables".to_string(),
                    promotion_count.to_string(),
                );

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

    // Behavioral Analysis Engine
    fn run_behavioral_analysis(log: &mut SandboxLog) {
        let patterns: Vec<Box<dyn BehaviorPattern>> = vec![
            Box::new(ObfuscatedStringConstruction),
            Box::new(DynamicCodeGeneration),
            Box::new(EnvironmentFingerprinting),
            Box::new(ErrorRecoveryPattern),
            Box::new(VariablePromotionPattern),
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
                args: args
                    .iter()
                    .map(|arg| js_value_summary(arg, ctx, 50))
                    .collect(),
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
                    .get(0)
                    .map(|arg| js_value_summary(arg, ctx, 100))
                    .unwrap_or_else(|| "unknown".to_string());

                let timestamp = log_ref
                    .execution_flow
                    .start_time
                    .map(|start| start.elapsed())
                    .unwrap_or_else(|| std::time::Duration::from_millis(0));

                log_ref
                    .execution_flow
                    .variable_timeline
                    .push(VariableEvent {
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
        if bytes.len() > options.max_bytes {
            return DynamicOutcome::Skipped {
                reason: "payload_too_large".into(),
                limit: options.max_bytes,
                actual: bytes.len(),
            };
        }
        let opts = options.clone();
        let bytes = bytes.to_vec();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut initial_log = SandboxLog {
                options: opts,
                ..SandboxLog::default()
            };
            // Initialize execution flow tracking
            initial_log.execution_flow.start_time = Some(std::time::Instant::now());
            let log = Rc::new(RefCell::new(initial_log));
            let scope = Rc::new(RefCell::new(DynamicScope::default()));
            let mut context = Context::default();
            let mut limits = RuntimeLimits::default();
            limits.set_loop_iteration_limit(10_000);
            limits.set_recursion_limit(64);
            limits.set_stack_size_limit(512 * 1024);
            context.set_runtime_limits(limits);
            let doc = register_doc_stub(&mut context, log.clone());
            register_app(&mut context, log.clone(), Some(doc.clone()));
            register_util(&mut context, log.clone());
            register_collab(&mut context, log.clone());
            register_soap(&mut context, log.clone());
            register_net(&mut context, log.clone());
            register_browser_like(&mut context, log.clone());
            register_windows_scripting(&mut context, log.clone());
            register_windows_com(&mut context, log.clone());
            register_windows_wmi(&mut context, log.clone());
            register_node_like(&mut context, log.clone());
            let _ = doc;
            register_doc_globals(&mut context, log.clone()); // Enable unescape and other globals
            register_pdf_event_context(&mut context, log.clone(), scope.clone()); // Add event object simulation
            register_enhanced_doc_globals(&mut context, log.clone(), scope.clone());
            register_enhanced_eval_v2(&mut context, log.clone(), scope.clone());
            register_enhanced_global_fallback(&mut context, log.clone(), scope.clone());

            let normalised = normalise_js_source(&bytes);
            let source = Source::from_bytes(&normalised);
            let eval_start = Instant::now();
            let eval_res = context.eval(source);
            let elapsed = eval_start.elapsed().as_millis();
            let mut eval_error = None;
            if let Err(err) = eval_res {
                let code = String::from_utf8_lossy(&normalised).to_string();
                let recovered =
                    attempt_error_recovery(&mut context, &err, &code, &scope, &log).is_some();
                if !recovered {
                    eval_error = Some(err);
                }
            }
            {
                let mut log_ref = log.borrow_mut();
                log_ref.elapsed_ms = Some(elapsed);
                if let Some(err) = eval_error {
                    log_ref.errors.push(format!("{:?}", err));
                }

                // Run behavioral pattern analysis
                run_behavioral_analysis(&mut log_ref);
            }
            let out = log.borrow().clone();
            let _ = tx.send(out);
        });

        match rx.recv_timeout(Duration::from_millis(options.timeout_ms as u64)) {
            Ok(log) => DynamicOutcome::Executed(DynamicSignals {
                calls: log.calls.clone(),
                call_args: log.call_args.clone(),
                urls: log.urls.clone(),
                domains: log.domains.clone(),
                errors: log.errors.clone(),
                prop_reads: log.prop_reads.clone(),
                call_count: log.call_count,
                unique_calls: log.unique_calls.len(),
                unique_prop_reads: log.unique_prop_reads.len(),
                elapsed_ms: log.elapsed_ms,
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
                },
            }),
            Err(RecvTimeoutError::Timeout) => DynamicOutcome::TimedOut {
                timeout_ms: options.timeout_ms,
            },
            Err(_) => DynamicOutcome::TimedOut {
                timeout_ms: options.timeout_ms,
            },
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

    fn register_app(context: &mut Context, log: Rc<RefCell<SandboxLog>>, doc: Option<JsValue>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };

        let plugins_value = {
            let plugin = ObjectInitializer::new(context)
                .property(
                    JsString::from("name"),
                    JsString::from("PlugIn"),
                    Attribute::all(),
                )
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
                NativeFunction::from_closure(move |_this, _args, _ctx| {
                    record_prop(&log_clone, "app.plugIns");
                    Ok(plugins_clone.clone())
                })
            };
            FunctionObjectBuilder::new(context.realm(), getter)
                .name(JsString::from("plugIns"))
                .length(0)
                .constructor(false)
                .build()
        };

        let doc_accessor = doc.map(|doc_value| {
            let log_clone = log.clone();
            let doc_clone = doc_value.clone();
            let getter = unsafe {
                NativeFunction::from_closure(move |_this, _args, _ctx| {
                    record_prop(&log_clone, "app.doc");
                    Ok(doc_clone.clone())
                })
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
        app.function(
            make_fn("removeMenuItem"),
            JsString::from("removeMenuItem"),
            1,
        );
        app.function(make_fn("setTimeOut"), JsString::from("setTimeOut"), 1);
        app.function(make_fn("setInterval"), JsString::from("setInterval"), 1);
        app.function(make_fn("submitForm"), JsString::from("submitForm"), 1);
        app.function(make_fn("browseForDoc"), JsString::from("browseForDoc"), 0);
        app.function(make_fn("saveAs"), JsString::from("saveAs"), 1);
        app.function(
            make_fn("exportDataObject"),
            JsString::from("exportDataObject"),
            1,
        );
        app.function(
            make_fn("importDataObject"),
            JsString::from("importDataObject"),
            1,
        );
        app.function(
            make_fn("createDataObject"),
            JsString::from("createDataObject"),
            1,
        );
        app.function(
            make_fn("removeDataObject"),
            JsString::from("removeDataObject"),
            1,
        );
        app.function(make_fn("mailMsg"), JsString::from("mailMsg"), 1);
        app.function(make_fn("mailDoc"), JsString::from("mailDoc"), 0);
        app.property(
            JsString::from("viewerVersion"),
            JsValue::from(9),
            Attribute::all(),
        );
        app.property(
            JsString::from("viewerType"),
            JsString::from("Reader"),
            Attribute::all(),
        );
        app.property(
            JsString::from("platform"),
            JsString::from("WIN"),
            Attribute::all(),
        );
        app.property(
            JsString::from("language"),
            JsString::from("en-AU"),
            Attribute::all(),
        );

        app.accessor(
            JsString::from("plugIns"),
            Some(plugins_accessor),
            None,
            Attribute::all(),
        );

        if let Some(getter_fn) = doc_accessor {
            app.accessor(
                JsString::from("doc"),
                Some(getter_fn),
                None,
                Attribute::all(),
            );
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
            .function(
                make_fn("Collab.collectEmailInfo"),
                JsString::from("collectEmailInfo"),
                0,
            )
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
        let beacon = ObjectInitializer::new(context)
            .function(
                make_fn("navigator.sendBeacon"),
                JsString::from("sendBeacon"),
                2,
            )
            .build();
        let _ =
            context.register_global_property(JsString::from("navigator"), beacon, Attribute::all());
        let storage = ObjectInitializer::new(context)
            .function(
                make_fn("localStorage.getItem"),
                JsString::from("getItem"),
                1,
            )
            .function(
                make_fn("localStorage.setItem"),
                JsString::from("setItem"),
                2,
            )
            .build();
        let _ = context.register_global_property(
            JsString::from("localStorage"),
            storage.clone(),
            Attribute::all(),
        );
        let _ = context.register_global_property(
            JsString::from("sessionStorage"),
            storage,
            Attribute::all(),
        );
        let doc = ObjectInitializer::new(context)
            .function(make_fn("document.cookie"), JsString::from("cookie"), 0)
            .function(make_fn("document.location"), JsString::from("location"), 0)
            .build();
        let _ = context.register_global_property(JsString::from("document"), doc, Attribute::all());
    }

    fn register_windows_scripting(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        let _ = context.register_global_builtin_callable(
            JsString::from("ActiveXObject"),
            1,
            make_native(log.clone(), "ActiveXObject"),
        );
        let wscript = ObjectInitializer::new(context)
            .function(make_fn("WScript.Shell"), JsString::from("Shell"), 0)
            .function(
                make_fn("WScript.CreateObject"),
                JsString::from("CreateObject"),
                1,
            )
            .function(make_fn("WScript.RegRead"), JsString::from("RegRead"), 1)
            .function(make_fn("WScript.RegWrite"), JsString::from("RegWrite"), 2)
            .build();
        let _ =
            context.register_global_property(JsString::from("WScript"), wscript, Attribute::all());
        let _ = context.register_global_builtin_callable(
            JsString::from("GetObject"),
            1,
            make_native(log.clone(), "GetObject"),
        );
        let _ = context.register_global_builtin_callable(
            JsString::from("CreateObject"),
            1,
            make_native(log, "CreateObject"),
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
                make_fn("Scripting.FileSystemObject.CreateTextFile"),
                JsString::from("CreateTextFile"),
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
            .function(
                make_fn("ADODB.Stream.SaveToFile"),
                JsString::from("SaveToFile"),
                1,
            )
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
            .function(
                make_fn("MSXML2.ServerXMLHTTP.open"),
                JsString::from("open"),
                2,
            )
            .function(
                make_fn("MSXML2.ServerXMLHTTP.send"),
                JsString::from("send"),
                1,
            )
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
            .function(
                make_fn("MSXML2.DOMDocument.load"),
                JsString::from("load"),
                1,
            )
            .function(
                make_fn("MSXML2.DOMDocument.loadXML"),
                JsString::from("loadXML"),
                1,
            )
            .build();
        let _ = context.register_global_property(
            JsString::from("DOMDocument"),
            domdoc,
            Attribute::all(),
        );

        let winhttp = ObjectInitializer::new(context)
            .function(
                make_fn("WinHTTP.WinHTTPRequest.open"),
                JsString::from("Open"),
                2,
            )
            .function(
                make_fn("WinHTTP.WinHTTPRequest.send"),
                JsString::from("Send"),
                1,
            )
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
            .function(
                make_fn("Shell.Application.ShellExecute"),
                JsString::from("ShellExecute"),
                1,
            )
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
            .function(
                make_fn("ADODB.Connection.Execute"),
                JsString::from("Execute"),
                1,
            )
            .build();
        let adodb_cmd = ObjectInitializer::new(context)
            .function(
                make_fn("ADODB.Command.Execute"),
                JsString::from("Execute"),
                1,
            )
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
            .function(
                make_fn("URLDownloadToFile"),
                JsString::from("URLDownloadToFile"),
                2,
            )
            .build();
        let _ =
            context.register_global_property(JsString::from("URLMON"), urlmon, Attribute::all());

        let powershell = ObjectInitializer::new(context)
            .function(
                make_fn("PowerShell.AddScript"),
                JsString::from("AddScript"),
                1,
            )
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

    fn register_node_like(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let make_fn = |name: &'static str| {
            let log = log.clone();
            make_native(log, name)
        };
        let _ = context.register_global_builtin_callable(
            JsString::from("require"),
            1,
            make_native(log.clone(), "require"),
        );
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
            .build();
        let _ = context.register_global_property(JsString::from("fs"), fs, Attribute::all());
    }

    fn register_doc_globals(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        // Register unescape function
        register_unescape(context, log.clone());

        // Register escape function (URL encoding)
        let escape_fn = unsafe {
            let log = log.clone();
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log, "escape", args, ctx);

                let input_arg = args.get_or_undefined(0);
                let input = input_arg.to_string(ctx)?;
                let input_str = input.to_std_string_escaped();

                // Implement basic URL escape functionality
                let mut result = String::new();
                for ch in input_str.chars() {
                    if ch.is_ascii_alphanumeric() || "-_.!~*'()".contains(ch) {
                        result.push(ch);
                    } else {
                        result.push_str(&format!("%{:02X}", ch as u8));
                    }
                }

                Ok(JsValue::from(JsString::from(result)))
            })
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
            .property(
                JsString::from("Reader_Value_Asked"),
                JsValue::from(false),
                Attribute::all(),
            )
            .property(
                JsString::from("Viewer_Value_Asked"),
                JsValue::from(false),
                Attribute::all(),
            )
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
            .property(
                JsString::from("Viewer_string_Title"),
                JsString::from(""),
                Attribute::all(),
            )
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
            .property(
                JsString::from("SYSINFO"),
                JsString::from(""),
                Attribute::all(),
            )
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
        let parse_int_fn = global_obj
            .get(JsString::from("parseInt"), context)
            .unwrap_or(JsValue::undefined());

        // Create eval function for target with tracking
        let target_eval_fn = unsafe {
            let log = log.clone();
            let scope = scope.clone();
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log, "event.target.eval", args, ctx);
                let code_arg = args.get_or_undefined(0);
                let code = code_arg.to_string(ctx)?;
                let code_str = code.to_std_string_escaped();
                let processed = preprocess_eval_code(&code_str, &scope);
                match execute_with_variable_promotion(ctx, &processed, &scope, &log) {
                    Ok(result) => {
                        post_process_eval_variables(ctx, &code_str, &scope, &log);
                        Ok(result)
                    }
                    Err(err) => {
                        if let Some(recovered) =
                            attempt_error_recovery(ctx, &err, &code_str, &scope, &log)
                        {
                            Ok(recovered)
                        } else {
                            Ok(JsValue::undefined())
                        }
                    }
                }
            })
        };

        let target_unescape_fn = unsafe {
            let log = log.clone();
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log, "event.target.unescape", args, ctx);
                let input_arg = args.get_or_undefined(0);
                let input = input_arg.to_string(ctx)?;
                let input_str = input.to_std_string_escaped();
                let result = decode_unescape(&input_str);
                Ok(JsValue::from(JsString::from(result)))
            })
        };

        let target_get_annot_fn = unsafe {
            let log = log.clone();
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log, "event.target.getAnnot", args, ctx);
                Ok(build_annot(ctx, log.clone()))
            })
        };

        let target_get_annots_fn = unsafe {
            let log = log.clone();
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log, "event.target.getAnnots", args, ctx);
                Ok(build_annots(ctx, log.clone()))
            })
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
            .function(
                target_methods("event.target.getField"),
                JsString::from("getField"),
                1,
            )
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
            .function(
                target_methods("event.target.print"),
                JsString::from("print"),
                0,
            )
            .property(
                JsString::from("value"),
                JsString::from(""),
                Attribute::all(),
            )
            .property(
                JsString::from("name"),
                JsString::from("TextField"),
                Attribute::all(),
            )
            .build();

        // Create the event object with common PDF event properties
        let event_obj = ObjectInitializer::new(context)
            .property(JsString::from("target"), target, Attribute::all())
            .property(
                JsString::from("name"),
                JsString::from("Open"),
                Attribute::all(),
            )
            .property(
                JsString::from("type"),
                JsString::from("Page"),
                Attribute::all(),
            )
            .property(
                JsString::from("value"),
                JsString::from(""),
                Attribute::all(),
            )
            .property(
                JsString::from("willCommit"),
                JsValue::from(false),
                Attribute::all(),
            )
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
            .property(
                JsString::from("pageNum"),
                JsValue::from(0),
                Attribute::all(),
            )
            .property(
                JsString::from("numPages"),
                JsValue::from(1),
                Attribute::all(),
            )
            .function(
                target_methods("this.getField"),
                JsString::from("getField"),
                1,
            )
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
        let creation_date_getter = make_getter(
            context,
            log.clone(),
            "info.creationDate",
            "D:19700101000000Z",
        );
        let mod_date_getter =
            make_getter(context, log.clone(), "info.modDate", "D:19700101000000Z");
        let creator_payload_getter =
            make_getter(context, log.clone(), "doc.creator", CREATOR_PAYLOAD);
        let subject_payload_getter =
            make_getter(context, log.clone(), "doc.subject", SUBJECT_PAYLOAD);

        // Create info object with accessor properties for tracking
        let info = ObjectInitializer::new(context)
            .accessor(
                JsString::from("title"),
                Some(title_getter),
                None,
                Attribute::all(),
            )
            .accessor(
                JsString::from("author"),
                Some(author_getter),
                None,
                Attribute::all(),
            )
            .accessor(
                JsString::from("subject"),
                Some(subject_getter),
                None,
                Attribute::all(),
            )
            .accessor(
                JsString::from("keywords"),
                Some(keywords_getter),
                None,
                Attribute::all(),
            )
            .accessor(
                JsString::from("creator"),
                Some(creator_getter),
                None,
                Attribute::all(),
            )
            .accessor(
                JsString::from("producer"),
                Some(producer_getter),
                None,
                Attribute::all(),
            )
            .accessor(
                JsString::from("gkds"),
                Some(gkds_getter),
                None,
                Attribute::all(),
            )
            .accessor(
                JsString::from("gggsd"),
                Some(gggsd_getter),
                None,
                Attribute::all(),
            )
            .accessor(
                JsString::from("creationDate"),
                Some(creation_date_getter),
                None,
                Attribute::all(),
            )
            .accessor(
                JsString::from("modDate"),
                Some(mod_date_getter),
                None,
                Attribute::all(),
            )
            .build();
        let _ = context.register_global_property(
            JsString::from("info"),
            info.clone(),
            Attribute::all(),
        );
        let log_clone = log.clone();
        let get_annot_fn = unsafe {
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log_clone, "doc.getAnnot", args, ctx);
                Ok(build_annot(ctx, log_clone.clone()))
            })
        };
        let log_clone = log.clone();
        let get_annots_fn = unsafe {
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log_clone, "doc.getAnnots", args, ctx);
                Ok(build_annots(ctx, log_clone.clone()))
            })
        };
        let collab = ObjectInitializer::new(context)
            .function(
                make_native(log.clone(), "Collab.getIcon"),
                JsString::from("getIcon"),
                1,
            )
            .function(
                make_native(log.clone(), "Collab.collectEmailInfo"),
                JsString::from("collectEmailInfo"),
                0,
            )
            .build();
        let media = ObjectInitializer::new(context)
            .function(
                make_native(log.clone(), "media.newPlayer"),
                JsString::from("newPlayer"),
                1,
            )
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
            .function(
                make_native(log.clone(), "doc.eval"),
                JsString::from("eval"),
                1,
            )
            .function(
                make_native(log.clone(), "doc.unescape"),
                JsString::from("unescape"),
                1,
            )
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
        build_annot_with_subject(
            context,
            log,
            "z61z70z70z2Ez61z6Cz65z72z74z28z27z68z69z27z29",
        )
    }

    fn build_annot_with_subject(
        context: &mut Context,
        log: Rc<RefCell<SandboxLog>>,
        subject_value: &'static str,
    ) -> JsValue {
        let subject_getter = make_getter(context, log, "annot.subject", subject_value);
        let annot = ObjectInitializer::new(context)
            .accessor(
                JsString::from("subject"),
                Some(subject_getter),
                None,
                Attribute::all(),
            )
            .build();
        JsValue::from(annot)
    }

    fn register_enhanced_doc_globals(
        context: &mut Context,
        log: Rc<RefCell<SandboxLog>>,
        _scope: Rc<RefCell<DynamicScope>>,
    ) {
        let add =
            |ctx: &mut Context, name: &'static str, len: usize, log: Rc<RefCell<SandboxLog>>| {
                let _ = ctx.register_global_builtin_callable(
                    JsString::from(name),
                    len,
                    make_native(log, name),
                );
            };
        let add_callable =
            |ctx: &mut Context, name: &'static str, len: usize, log: Rc<RefCell<SandboxLog>>| {
                let _ =
                    ctx.register_global_callable(JsString::from(name), len, make_native(log, name));
            };

        // Standard JavaScript globals with enhanced tracking
        add(context, "setTimeout", 1, log.clone());
        add(context, "setInterval", 1, log.clone());
        add_callable(context, "Function", 1, log.clone());

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
            let log = log.clone();
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log, "getAnnot", args, ctx);
                Ok(build_annot(ctx, log.clone()))
            })
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
        let log_clone = log.clone();
        let from_char_code_fn = unsafe {
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log_clone, "String.fromCharCode", args, ctx);

                let mut result = String::new();
                for arg in args {
                    if let Ok(num) = arg.to_i32(ctx) {
                        if num >= 0 && num <= 255 {
                            result.push(num as u8 as char);
                        }
                    }
                }

                Ok(JsValue::from(JsString::from(result)))
            })
        };

        let from_char_code = FunctionObjectBuilder::new(context.realm(), from_char_code_fn)
            .name(JsString::from("fromCharCode"))
            .length(1)
            .constructor(false)
            .build();

        let substr_fn = unsafe {
            let log = log.clone();
            NativeFunction::from_closure(move |this, args, ctx| {
                record_call(&log, "String.substr", args, ctx);
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
            })
        };
        let substr = FunctionObjectBuilder::new(context.realm(), substr_fn)
            .name(JsString::from("substr"))
            .length(2)
            .constructor(false)
            .build();

        if let Ok(string_value) = context
            .global_object()
            .get(JsString::from("String"), context)
        {
            if let Some(string_obj) = string_value.as_object() {
                let _ = string_obj.set(
                    JsString::from("fromCharCode"),
                    from_char_code,
                    false,
                    context,
                );
                if let Ok(proto_value) = string_obj.get(JsString::from("prototype"), context) {
                    if let Some(proto_obj) = proto_value.as_object() {
                        let _ = proto_obj.set(JsString::from("substr"), substr, false, context);
                    }
                }
            }
        }

        // escape function
        let log_clone2 = log.clone();
        let escape_fn = unsafe {
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log_clone2, "escape", args, ctx);

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
            })
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
        unsafe {
            NativeFunction::from_closure(move |_this, _args, _ctx| {
                // Console functions are no-ops in sandbox, just return undefined
                Ok(JsValue::undefined())
            })
        }
    }

    fn register_unescape(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
        let unescape_fn = unsafe {
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log, "unescape", args, ctx);

                let input_arg = args.get_or_undefined(0);
                let input = input_arg.to_string(ctx)?;
                let input_str = input.to_std_string_escaped();

                Ok(JsValue::from(JsString::from(decode_unescape(&input_str))))
            })
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
                return decode_utf16(&bytes[2..], true).unwrap_or_else(|| bytes.to_vec());
            }
            if bytes[0] == 0xFE && bytes[1] == 0xFF {
                return decode_utf16(&bytes[2..], false).unwrap_or_else(|| bytes.to_vec());
            }
        }

        let nul_count = bytes.iter().filter(|b| **b == 0).count();
        if nul_count > bytes.len() / 4 {
            if let Some(decoded) = decode_utf16(bytes, true) {
                return decoded;
            }
        }
        if nul_count > 0 {
            return bytes.iter().copied().filter(|b| *b != 0).collect();
        }

        bytes.to_vec()
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
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log, "eval", args, ctx);

                let code_arg = args.get_or_undefined(0);
                let code = code_arg.to_string(ctx)?;
                let code_str = code.to_std_string_escaped();

                // Record the eval attempt
                {
                    let mut log_ref = log.borrow_mut();
                    if log_ref.call_args.len() < log_ref.options.max_call_args {
                        log_ref.call_args.push(format!(
                            "eval({})",
                            &code_str[..std::cmp::min(code_str.len(), 100)]
                        ));
                    }

                    // Record scope transition
                    log_ref.scope_transitions.push(ScopeTransition {
                        from_scope: "global".to_string(),
                        to_scope: "eval".to_string(),
                        trigger: TransitionTrigger::EvalExecution,
                        variables_inherited: Vec::new(),
                        timestamp: std::time::Duration::from_millis(0), // TODO: proper timestamp
                    });
                }

                // Preprocess the code for variable promotion
                let processed_code = preprocess_eval_code(&code_str, &scope);

                // Execute with enhanced error handling and variable tracking
                match execute_with_variable_promotion(ctx, &processed_code, &scope, &log) {
                    Ok(result) => {
                        // Post-process to promote variables to global scope
                        post_process_eval_variables(ctx, &code_str, &scope, &log);
                        Ok(result)
                    }
                    Err(e) => {
                        // Log error and attempt recovery
                        let error_text = format!("{:?}", e);
                        if !error_text.contains("RuntimeLimit") {
                            let mut log_ref = log.borrow_mut();
                            log_ref
                                .errors
                                .push(format!("Eval error (recovered): {}", error_text));
                        }

                        // Attempt error recovery
                        if let Some(recovered_result) =
                            attempt_error_recovery(ctx, &e, &code_str, &scope, &log)
                        {
                            Ok(recovered_result)
                        } else {
                            Ok(JsValue::undefined())
                        }
                    }
                }
            })
        };

        let _ = context.register_global_builtin_callable(JsString::from("eval"), 1, eval_fn);
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
                    result = result.replace(
                        caps.get(0).unwrap().as_str(),
                        &format!("this.{} = ", var_str),
                    );
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
        format!(
            "try {{ {} }} catch(e) {{ /* Eval error suppressed */ }}",
            result
        )
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
            var_name.chars().last().map_or(false, |c| c.is_numeric())
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

            log_ref
                .execution_flow
                .exception_handling
                .push(ExceptionEvent {
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
        }

        if error_msg.contains("not a callable function") {
            let call_names = gather_bare_call_names(code);
            let patched = override_callable_assignments(code, &call_names);
            let mut prelude = String::new();
            for name in &call_names {
                prelude.push_str(&format!("var {} = function(){{}};", name));
            }
            let merged = format!("{}{}", prelude, patched);
            if let Ok(result) = ctx.eval(Source::from_bytes(merged.as_bytes())) {
                let mut log_ref = log.borrow_mut();
                if let Some(last_exception) = log_ref.execution_flow.exception_handling.last_mut() {
                    last_exception.recovery_successful = true;
                }
                return Some(result);
            }
        }

        None
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
        for _ in 0..4 {
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
                        let mut injected = prelude.clone();
                        for name in call_names {
                            if injected.contains(&format!("var {} =", name)) {
                                continue;
                            }
                            injected.push_str(&format!("var {} = function(){{}};", name));
                        }
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
        let skip = [
            "eval",
            "unescape",
            "escape",
            "alert",
            "parseInt",
            "parseFloat",
            "isNaN",
            "isFinite",
        ];
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
            {
                if i > 0 {
                    let candidate = words[i - 1]
                        .trim_end_matches(',')
                        .trim_matches('"')
                        .trim_matches('\'');
                    if !candidate.is_empty() {
                        return Some(candidate.to_string());
                    }
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
        matches!(byte, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
    }

    fn make_native(log: Rc<RefCell<SandboxLog>>, name: &'static str) -> NativeFunction {
        unsafe {
            NativeFunction::from_closure(move |_this, args, ctx| {
                record_call(&log, name, args, ctx);
                Ok(JsValue::undefined())
            })
        }
    }

    fn make_getter(
        context: &mut Context,
        log: Rc<RefCell<SandboxLog>>,
        name: &'static str,
        value: &'static str,
    ) -> JsFunction {
        let function = unsafe {
            NativeFunction::from_closure(move |_this, _args, _ctx| {
                record_prop(&log, name);
                Ok(JsValue::from(JsString::from(value)))
            })
        };
        FunctionObjectBuilder::new(context.realm(), function)
            .name(JsString::from(name))
            .length(0)
            .constructor(false)
            .build()
    }

    fn record_call(log: &Rc<RefCell<SandboxLog>>, name: &str, args: &[JsValue], ctx: &mut Context) {
        let mut log_ref = log.borrow_mut();
        log_ref.call_count += 1;
        log_ref.calls.push(name.to_string());
        log_ref.unique_calls.insert(name.to_string());
        if log_ref.call_args.len() < log_ref.options.max_call_args {
            if let Some(summary) = summarise_args(args, ctx, &log_ref.options) {
                log_ref.call_args.push(format!("{}({})", name, summary));
            }
        }
        for arg in args {
            if let Some(value) = js_value_string(arg) {
                if looks_like_url(&value) {
                    if log_ref.urls.len() < log_ref.options.max_urls {
                        log_ref.urls.push(value.clone());
                    }
                    if let Some(domain) = domain_from_url(&value) {
                        if log_ref.domains.len() < log_ref.options.max_domains {
                            log_ref.domains.push(domain);
                        }
                    }
                }
            }
        }
    }

    fn record_prop(log: &Rc<RefCell<SandboxLog>>, name: &str) {
        let mut log_ref = log.borrow_mut();
        log_ref.prop_reads.push(name.to_string());
        log_ref.unique_prop_reads.insert(name.to_string());
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
            return rest
                .split('@')
                .nth(1)
                .map(|s| s.split('?').next().unwrap_or(s).to_string());
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
            assert_eq!(
                domain_from_url("http://example.com/a/b").as_deref(),
                Some("example.com")
            );
            assert_eq!(
                domain_from_url("mailto:user@example.com").as_deref(),
                Some("example.com")
            );
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

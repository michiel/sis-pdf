use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::Result;
use boa_engine::object::ObjectInitializer;
use boa_engine::property::Attribute;
use boa_engine::value::JsVariant;
use boa_engine::vm::RuntimeLimits;
use boa_engine::{Context, JsString, JsValue, NativeFunction, Source};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;

use crate::{entry_dict, resolve_payload};

pub struct JavaScriptSandboxDetector;

const JS_WALLCLOCK_TIMEOUT: Duration = Duration::from_secs(5);
const JS_WALLCLOCK_WARN: Duration = Duration::from_secs(1);
const JS_SANDBOX_MAX_BYTES: usize = 256 * 1024;
const JS_MAX_ARG_PREVIEW: usize = 240;
const JS_MAX_CALL_ARGS: usize = 64;
const JS_MAX_URLS: usize = 48;
const JS_MAX_DOMAINS: usize = 48;
const JS_MAX_ARGS_PER_CALL: usize = 8;

#[derive(Default, Clone)]
struct SandboxLog {
    calls: Vec<String>,
    call_args: Vec<String>,
    urls: Vec<String>,
    domains: Vec<String>,
    errors: Vec<String>,
    call_count: usize,
    unique_calls: BTreeSet<String>,
    elapsed_ms: Option<u128>,
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
            let Some(dict) = entry_dict(entry) else { continue };
            if !dict.has_name(b"/S", b"/JavaScript") && dict.get_first(b"/JS").is_none() {
                continue;
            }
            let Some((_, obj)) = dict.get_first(b"/JS") else { continue };
            let payload = resolve_payload(ctx, obj);
            let Some(info) = payload.payload else { continue };
            if info.bytes.len() > JS_SANDBOX_MAX_BYTES {
                let mut meta = std::collections::HashMap::new();
                meta.insert("js.sandbox_exec".into(), "false".into());
                meta.insert("js.sandbox_skip_reason".into(), "payload_too_large".into());
                meta.insert("payload.decoded_len".into(), info.bytes.len().to_string());
                meta.insert("js.sandbox_limit_bytes".into(), JS_SANDBOX_MAX_BYTES.to_string());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "js_sandbox_skipped".into(),
                    severity: Severity::Info,
                    confidence: Confidence::Probable,
                    title: "JavaScript sandbox skipped".into(),
                    description: "Sandbox skipped because the JS payload exceeds the size limit.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Inspect the JS payload size and consider manual analysis.".into()),
                    meta,
                    yara: None,
                });
                continue;
            }
            let bytes = info.bytes.clone();
            let (tx, rx) = mpsc::channel();
            let start = Instant::now();
            std::thread::spawn(move || {
                let log = Rc::new(RefCell::new(SandboxLog::default()));
                let mut context = Context::default();
                let mut limits = RuntimeLimits::default();
                limits.set_loop_iteration_limit(100_000);
                limits.set_recursion_limit(128);
                limits.set_stack_size_limit(512 * 1024);
                context.set_runtime_limits(limits);
                register_app(&mut context, log.clone());
                register_util(&mut context, log.clone());
                register_collab(&mut context, log.clone());
                register_soap(&mut context, log.clone());
                register_net(&mut context, log.clone());
                register_browser_like(&mut context, log.clone());
                register_windows_scripting(&mut context, log.clone());
                register_windows_com(&mut context, log.clone());
                register_windows_wmi(&mut context, log.clone());
                register_node_like(&mut context, log.clone());
                register_doc_globals(&mut context, log.clone());
                let source = Source::from_bytes(&bytes);
                let eval_start = Instant::now();
                let eval_res = context.eval(source);
                let elapsed = eval_start.elapsed().as_millis();
                {
                    let mut log_ref = log.borrow_mut();
                    log_ref.elapsed_ms = Some(elapsed);
                    if let Err(err) = eval_res {
                        log_ref.errors.push(format!("{:?}", err));
                    }
                }
                let calls = log.borrow().clone();
                let _ = tx.send(calls);
            });
            let log = match rx.recv_timeout(JS_WALLCLOCK_TIMEOUT) {
                Ok(calls) => calls,
                Err(RecvTimeoutError::Timeout) => {
                    eprintln!(
                        "security_boundary: JS sandbox timed out after {:?} (obj {} {})",
                        JS_WALLCLOCK_TIMEOUT,
                        entry.obj,
                        entry.gen
                    );
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("js.sandbox_exec".into(), "true".into());
                    meta.insert("js.sandbox_timeout".into(), "true".into());
                    meta.insert(
                        "js.sandbox_timeout_ms".into(),
                        JS_WALLCLOCK_TIMEOUT.as_millis().to_string(),
                    );
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
                    continue;
                }
                Err(_) => continue,
            };
            let elapsed = start.elapsed();
            if elapsed > JS_WALLCLOCK_WARN {
                eprintln!(
                    "security_boundary: JS sandbox slow execution {:?} (obj {} {})",
                    elapsed,
                    entry.obj,
                    entry.gen
                );
            }
            if log.call_count == 0 {
                let mut meta = std::collections::HashMap::new();
                meta.insert("js.sandbox_exec".into(), "true".into());
                if let Some(ms) = log.elapsed_ms {
                    meta.insert("js.sandbox_exec_ms".into(), ms.to_string());
                }
                if !log.errors.is_empty() {
                    meta.insert("js.runtime.errors".into(), log.errors.join("; "));
                }
                let description = if log.errors.is_empty() {
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
            base_meta.insert("js.runtime.calls".into(), log.calls.join(","));
            base_meta.insert("js.runtime.call_count".into(), log.call_count.to_string());
            base_meta.insert(
                "js.runtime.unique_calls".into(),
                log.unique_calls.len().to_string(),
            );
            if !log.call_args.is_empty() {
                base_meta.insert("js.runtime.call_args".into(), log.call_args.join("; "));
            }
            if !log.urls.is_empty() {
                base_meta.insert("js.runtime.urls".into(), log.urls.join(", "));
            }
            if !log.domains.is_empty() {
                base_meta.insert("js.runtime.domains".into(), log.domains.join(", "));
            }
            if !log.errors.is_empty() {
                base_meta.insert("js.runtime.errors".into(), log.errors.join("; "));
            }
            if let Some(ms) = log.elapsed_ms {
                base_meta.insert("js.sandbox_exec_ms".into(), ms.to_string());
            }
            let has_network = log.calls.iter().any(|c| is_network_call(c));
            let has_file = log.calls.iter().any(|c| is_file_call(c));
            if has_network {
                eprintln!(
                    "security_boundary: JS sandbox network-capable API invoked (obj {} {})",
                    entry.obj,
                    entry.gen
                );
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
                    meta: meta.clone(),
                    yara: None,
                });
            }
            if has_file {
                eprintln!(
                    "security_boundary: JS sandbox file-capable API invoked (obj {} {})",
                    entry.obj,
                    entry.gen
                );
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
        Ok(findings)
    }
}

fn register_app(context: &mut Context, log: Rc<RefCell<SandboxLog>>) {
    let make_fn = |name: &'static str| {
        let log = log.clone();
        make_native(log, name)
    };

    let app = ObjectInitializer::new(context)
        .function(make_fn("alert"), JsString::from("alert"), 1)
        .function(make_fn("response"), JsString::from("response"), 1)
        .function(make_fn("launchURL"), JsString::from("launchURL"), 1)
        .function(make_fn("getURL"), JsString::from("getURL"), 1)
        .function(make_fn("openDoc"), JsString::from("openDoc"), 1)
        .function(make_fn("newDoc"), JsString::from("newDoc"), 1)
        .function(make_fn("execMenuItem"), JsString::from("execMenuItem"), 1)
        .function(make_fn("execDialog"), JsString::from("execDialog"), 1)
        .function(make_fn("addMenuItem"), JsString::from("addMenuItem"), 1)
        .function(make_fn("removeMenuItem"), JsString::from("removeMenuItem"), 1)
        .function(make_fn("setTimeOut"), JsString::from("setTimeOut"), 1)
        .function(make_fn("setInterval"), JsString::from("setInterval"), 1)
        .function(make_fn("submitForm"), JsString::from("submitForm"), 1)
        .function(make_fn("browseForDoc"), JsString::from("browseForDoc"), 0)
        .function(make_fn("saveAs"), JsString::from("saveAs"), 1)
        .function(make_fn("exportDataObject"), JsString::from("exportDataObject"), 1)
        .function(make_fn("importDataObject"), JsString::from("importDataObject"), 1)
        .function(make_fn("createDataObject"), JsString::from("createDataObject"), 1)
        .function(make_fn("removeDataObject"), JsString::from("removeDataObject"), 1)
        .function(make_fn("mailMsg"), JsString::from("mailMsg"), 1)
        .function(make_fn("mailDoc"), JsString::from("mailDoc"), 0)
        .build();

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
    let _ = context.register_global_property(JsString::from("Collab"), collab, Attribute::all());
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
        .function(make_fn("navigator.sendBeacon"), JsString::from("sendBeacon"), 2)
        .build();
    let _ = context.register_global_property(
        JsString::from("navigator"),
        beacon,
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
        .function(make_fn("WScript.CreateObject"), JsString::from("CreateObject"), 1)
        .function(make_fn("WScript.RegRead"), JsString::from("RegRead"), 1)
        .function(make_fn("WScript.RegWrite"), JsString::from("RegWrite"), 2)
        .build();
    let _ = context.register_global_property(JsString::from("WScript"), wscript, Attribute::all());
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
    let _ = context.register_global_property(JsString::from("MSXML2"), msxml2, Attribute::all());

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
        .function(
            make_fn("ADODB.Connection.Open"),
            JsString::from("Open"),
            1,
        )
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
    let _ = context.register_global_property(
        JsString::from("URLMON"),
        urlmon,
        Attribute::all(),
    );

    let powershell = ObjectInitializer::new(context)
        .function(
            make_fn("PowerShell.AddScript"),
            JsString::from("AddScript"),
            1,
        )
        .function(
            make_fn("PowerShell.Invoke"),
            JsString::from("Invoke"),
            0,
        )
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
        .function(
            make_fn("WMI.ExecQuery"),
            JsString::from("ExecQuery"),
            1,
        )
        .build();
    let _ = context.register_global_property(
        JsString::from("winmgmts"),
        svc,
        Attribute::all(),
    );
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
    let _ = context.register_global_property(JsString::from("process"), process, Attribute::all());
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
    let add = |ctx: &mut Context, name: &'static str, len: usize, log: Rc<RefCell<SandboxLog>>| {
        let _ = ctx.register_global_builtin_callable(
            JsString::from(name),
            len,
            make_native(log, name),
        );
    };
    let add_callable =
        |ctx: &mut Context, name: &'static str, len: usize, log: Rc<RefCell<SandboxLog>>| {
            let _ = ctx.register_global_callable(JsString::from(name), len, make_native(log, name));
        };
    add(context, "eval", 1, log.clone());
    add(context, "setTimeout", 1, log.clone());
    add(context, "setInterval", 1, log.clone());
    add_callable(context, "Function", 1, log.clone());
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

fn make_native(log: Rc<RefCell<SandboxLog>>, name: &'static str) -> NativeFunction {
    unsafe {
        NativeFunction::from_closure(move |_this, args, ctx| {
            record_call(&log, name, args, ctx);
            Ok(JsValue::undefined())
        })
    }
}

fn record_call(log: &Rc<RefCell<SandboxLog>>, name: &str, args: &[JsValue], ctx: &mut Context) {
    let mut log_ref = log.borrow_mut();
    log_ref.call_count += 1;
    log_ref.calls.push(name.to_string());
    log_ref.unique_calls.insert(name.to_string());
    if log_ref.call_args.len() < JS_MAX_CALL_ARGS {
        if let Some(summary) = summarise_args(args, ctx) {
            log_ref.call_args.push(format!("{}({})", name, summary));
        }
    }
    for arg in args {
        if let Some(value) = js_value_string(arg) {
            if looks_like_url(&value) {
                if log_ref.urls.len() < JS_MAX_URLS {
                    log_ref.urls.push(value.clone());
                }
                if let Some(domain) = domain_from_url(&value) {
                    if log_ref.domains.len() < JS_MAX_DOMAINS {
                        log_ref.domains.push(domain);
                    }
                }
            }
        }
    }
}

fn summarise_args(args: &[JsValue], ctx: &mut Context) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for arg in args.iter().take(JS_MAX_ARGS_PER_CALL) {
        out.push(js_value_summary(arg, ctx));
    }
    if args.len() > JS_MAX_ARGS_PER_CALL {
        out.push(format!("+{} more", args.len() - JS_MAX_ARGS_PER_CALL));
    }
    Some(out.join(", "))
}

fn js_value_summary(value: &JsValue, _ctx: &mut Context) -> String {
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
            summarise_value(&s)
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

fn summarise_value(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if out.len() >= JS_MAX_ARG_PREVIEW {
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

fn is_network_call(name: &str) -> bool {
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

fn is_file_call(name: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarise_value_sanitizes_and_truncates() {
        let input = "abc\n\u{0000}\u{0008}\u{2603}def";
        let out = summarise_value(input);
        assert!(!out.contains('\n'));
        assert!(out.len() <= JS_MAX_ARG_PREVIEW);
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
        let mut args = Vec::new();
        for i in 0..(JS_MAX_ARGS_PER_CALL + 2) {
            args.push(JsValue::from(i as i32));
        }
        let summary = summarise_args(&args, &mut ctx).unwrap_or_default();
        assert!(summary.contains("+2 more"));
    }
}

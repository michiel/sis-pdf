use std::cell::RefCell;
use std::rc::Rc;

use anyhow::Result;
use boa_engine::object::ObjectInitializer;
use boa_engine::property::Attribute;
use boa_engine::{Context, JsValue, NativeFunction, Source};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;

use crate::{entry_dict, resolve_payload};

pub struct JavaScriptSandboxDetector;

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
            if info.bytes.len() > 256 * 1024 {
                continue;
            }
            let log = Rc::new(RefCell::new(Vec::<String>::new()));
            let mut context = Context::default();
            register_app(&mut context, log.clone());
            let source = Source::from_bytes(&info.bytes);
            let _ = context.eval(source);
            let calls = log.borrow().clone();
            if calls.is_empty() {
                continue;
            }
            let mut meta = std::collections::HashMap::new();
            meta.insert("js.runtime.calls".into(), calls.join(","));
            let has_network = calls.iter().any(|c| matches!(c.as_str(), "launchURL" | "getURL" | "submitForm"));
            let has_file = calls.iter().any(|c| matches!(c.as_str(), "browseForDoc" | "saveAs" | "exportDataObject"));
            if has_network {
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
        }
        Ok(findings)
    }
}

fn register_app(context: &mut Context, log: Rc<RefCell<Vec<String>>>) {
    let make_fn = |name: &'static str| {
        let log = log.clone();
        NativeFunction::from_closure(move |_this, _args, _ctx| {
            log.borrow_mut().push(name.to_string());
            Ok(JsValue::Undefined)
        })
    };

    let app = ObjectInitializer::new(context)
        .function(make_fn("launchURL"), "launchURL", 1)
        .function(make_fn("getURL"), "getURL", 1)
        .function(make_fn("submitForm"), "submitForm", 1)
        .function(make_fn("browseForDoc"), "browseForDoc", 0)
        .function(make_fn("saveAs"), "saveAs", 1)
        .function(make_fn("exportDataObject"), "exportDataObject", 1)
        .build();

    context.register_global_property("app", app, Attribute::all());
}

use js_analysis::{DynamicOptions, DynamicOutcome, RuntimePhase};

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_skips_large_payload() {
    let options = DynamicOptions { max_bytes: 8, ..DynamicOptions::default() };
    let data = b"this is too large";
    let outcome = js_analysis::run_sandbox(data, &options);
    match outcome {
        DynamicOutcome::Skipped { reason, limit, actual } => {
            assert_eq!(reason, "payload_too_large");
            assert_eq!(limit, 8);
            assert_eq!(actual, data.len());
        }
        _ => panic!("expected skip"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_exec_records_calls() {
    let options = DynamicOptions::default();
    let outcome = js_analysis::run_sandbox(b"app.alert('hi')", &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "alert"));
            assert!(signals.call_count >= 1);
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_emits_delta_summary_for_dynamic_code() {
    let options = DynamicOptions::default();
    let payload = br#"eval("var stageTwo = 7; app.alert('stage2');");"#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let delta = signals.delta_summary.expect("delta summary");
            assert!(
                delta.phase == "open"
                    || delta.phase == "idle"
                    || delta.phase == "click"
                    || delta.phase == "form"
            );
            assert!(delta.generated_snippets >= 1);
            assert!(delta.trigger_calls.iter().any(|call| call == "eval"));
            assert!(delta.added_identifier_count >= 1);
            assert!(
                delta.new_identifiers.iter().any(|value| value == "stageTwo")
                    || delta.new_calls.iter().any(|value| value == "alert")
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_omits_delta_summary_without_dynamic_code() {
    let options = DynamicOptions::default();
    let outcome = js_analysis::run_sandbox(b"app.alert('hello')", &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.delta_summary.is_none());
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_emits_phase_scoped_telemetry() {
    let options = DynamicOptions::default();
    let payload = b"
        function onIdle() { app.alert('idle'); }
        function onClick() { app.alert('click'); }
        function onSubmit() { app.alert('form'); }
        app.alert('open');
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let phase_names =
                signals.phases.iter().map(|phase| phase.phase.as_str()).collect::<Vec<_>>();
            assert_eq!(phase_names, vec!["open", "idle", "click", "form"]);
            for phase in &signals.phases {
                assert!(phase.elapsed_ms <= options.timeout_ms);
            }
            let open =
                signals.phases.iter().find(|phase| phase.phase == "open").expect("open phase");
            let click =
                signals.phases.iter().find(|phase| phase.phase == "click").expect("click phase");
            let form =
                signals.phases.iter().find(|phase| phase.phase == "form").expect("form phase");
            assert!(open.call_count >= 1);
            assert!(click.call_count >= 1);
            assert!(form.call_count >= 1);
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_respects_custom_phase_selection() {
    let mut options = DynamicOptions::default();
    options.phases = vec![RuntimePhase::Open, RuntimePhase::Idle];
    let payload = b"function onIdle(){app.alert('idle')} app.alert('open')";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let phase_names =
                signals.phases.iter().map(|phase| phase.phase.as_str()).collect::<Vec<_>>();
            assert_eq!(phase_names, vec!["open", "idle"]);
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_replay_id_is_stable_for_same_input() {
    let options = DynamicOptions::default();
    let payload = b"app.alert('stable');";
    let first = js_analysis::run_sandbox(payload, &options);
    let second = js_analysis::run_sandbox(payload, &options);
    match (first, second) {
        (DynamicOutcome::Executed(a), DynamicOutcome::Executed(b)) => {
            assert_eq!(a.replay_id, b.replay_id);
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_tracks_truncation_invariants() {
    let options = DynamicOptions::default();
    let mut payload = String::from("for (var i = 0; i < 2600; i++) {");
    payload.push_str("app.alert(i);");
    payload.push_str("fetch('https://example.test/' + i);");
    payload.push_str("}");
    let outcome = js_analysis::run_sandbox(payload.as_bytes(), &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.truncation.calls_dropped > 0);
            assert!(signals.truncation.call_args_dropped > 0);
            assert!(signals.truncation.urls_dropped > 0);
            assert!(signals.truncation.domains_dropped > 0);
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_deduped_lists_are_deterministically_sorted() {
    let options = DynamicOptions::default();
    let payload = b"
        app.newDoc();
        app.createDataObject({ cName: 'x' });
        app.exportAsFDF();
        app.newDoc();
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let mut sorted = signals.prop_writes.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(signals.prop_writes, sorted);
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_app_doc_annots_payload() {
    let options = DynamicOptions::default();
    let payload = b"var z; var y; z = y = app.doc; y = 0; z.syncAnnotScan(); y = z; var p = y.getAnnots({ nPage: 0 }); var s = p[0].subject; var l = s.replace(/z/g, '%'); s = unescape(l); eval(s); s = ''; z = 1;";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "doc.syncAnnotScan"));
            assert!(signals.calls.iter().any(|c| c == "doc.getAnnots"));
            assert!(signals.calls.iter().any(|c| c == "alert"));
            assert!(signals.prop_reads.iter().any(|p| p == "app.doc"));
            assert!(signals.prop_reads.iter().any(|p| p == "annot.subject"));
            assert!(!signals
                .errors
                .iter()
                .any(|e| e.contains("cannot convert 'null' or 'undefined' to object")));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_app_plugins_eval_payloads() {
    let options = DynamicOptions::default();
    let payload = br#"var pr = null; var fnc = 'ev'; var sum = ''; app.doc.syncAnnotScan(); if (app.plugIns.length != 0) { var num = 1; pr = app.doc.getAnnots({ nPage: 0 }); sum = pr[num].subject; } var buf = ''; if (app.plugIns.length > 3) { fnc += 'a'; var arr = sum.split(/-/); for (var i = 1; i < arr.length; i++) { buf += String.fromCharCode('0x'+arr[i]); } fnc += 'l'; } if (app.plugIns.length >= 2) { app[fnc](buf); }"#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "doc.syncAnnotScan"));
            assert!(signals.calls.iter().any(|c| c == "doc.getAnnots"));
            assert!(signals.calls.iter().any(|c| c == "app.eval"));
            assert!(signals.prop_reads.iter().any(|p| p == "app.plugIns"));
            assert!(signals.prop_reads.iter().any(|p| p == "annot.subject"));
            assert!(!signals
                .errors
                .iter()
                .any(|e| e.contains("cannot convert 'null' or 'undefined' to object")));
            assert!(!signals.errors.iter().any(|e| e.contains("not a callable function")));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_event_target_unescape_payload() {
    let options = DynamicOptions::default();
    let payload = b"var th = event.target; th.syncAnnotScan(); var p = th.getAnnots({ nPage: 0 }); var s = p[0].subject; var l = s.replace(/z/g, 'a%b'.replace(/[ab]/g, '')); s = th['unescape'](l); var e = th['eval']; e(s);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "event.target.syncAnnotScan"));
            assert!(signals.calls.iter().any(|c| c == "event.target.getAnnots"));
            assert!(signals.calls.iter().any(|c| c == "event.target.unescape"));
            assert!(signals.calls.iter().any(|c| c == "event.target.eval"));
            assert!(!signals
                .errors
                .iter()
                .any(|e| e.contains("cannot convert 'null' or 'undefined' to object")));
            assert!(!signals.errors.iter().any(|e| e.contains("not a callable function")));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_viewer_version_collab_payload() {
    let options = DynamicOptions::default();
    let payload =
        b"var v = app.viewerVersion.toString(); v = v.replace(/\\D/g, ''); app.doc.Collab.getIcon('x');";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "Collab.getIcon"));
            assert!(signals.prop_reads.iter().any(|p| p == "app.doc"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_callable_app_properties() {
    let options = DynamicOptions::default();
    let payload = b"var v = app.viewerVersion(); var s = app.viewerVersion.toString(); var t = app.viewerType(); var l = app.plugIns.length;";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "app.viewerVersion"));
            assert!(signals.calls.iter().any(|c| c == "app.viewerType"));
            assert!(!signals.errors.iter().any(|e| e.contains("not a callable function")));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_adbe_reader_payload() {
    let options = DynamicOptions::default();
    let payload = br#"if (typeof(xfa_installed) == "undefined" || typeof(xfa_version) == "undefined" || xfa_version < 2.1) { if (app.viewerType == "Reader") { if (ADBE.Reader_Value_Asked != true) { if (app.viewerVersion < 6.0) { if (app.alert(ADBE.Viewer_Form_string_Reader_5x, 1, 1) == 1) this.getURL(ADBE.Reader_Value_New_Version_URL + ADBE.SYSINFO, false); ADBE.Reader_Value_Asked = true; } else if (app.viewerVersion < 7.0) { if (app.alert(ADBE.Viewer_Form_string_Reader_601, 1, 1) == 1) app.findComponent({cType:"App", cName:"Reader7", cDesc: ADBE.Viewer_string_Update_Reader_Desc}); ADBE.Reader_Value_Asked = true; } else { if (app.alert(ADBE.Viewer_Form_string_Reader_6_7x, 1, 1) == 1) app.findComponent({cType:"Plugin", cName:"XFA", cDesc: ADBE.Viewer_string_Update_Reader_Desc}); ADBE.Reader_Value_Asked = true; } } } }"#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "alert"));
            assert!(!signals.errors.iter().any(|e| e.contains("ADBE is not defined")));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_info_gkds_payload() {
    let options = DynamicOptions::default();
    let payload =
        b"m1=this.info.gkds; m2=m1.replace(/zzzzz/g, ''); m3=this.info.gggsd+'al'; app[m3](m2);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "app.eval"));
            assert!(!signals
                .errors
                .iter()
                .any(|e| e.contains("cannot convert 'null' or 'undefined' to object")));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_recovers_undefined_string_vars() {
    let options = DynamicOptions::default();
    let payload = b"var out = str.replace(/a/g, '');";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.errors.is_empty());
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_recovers_undefined_function_vars() {
    let options = DynamicOptions::default();
    let payload = b"var vvv = z(unescape(xxx)); eval(vvv);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.errors.is_empty());
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_recovers_invalid_unicode_escapes() {
    let options = DynamicOptions::default();
    let payload = br#"var s = "\uZZZZ";"#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.errors.is_empty());
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_page_word_helpers() {
    let options = DynamicOptions::default();
    let payload = b"var n = getPageNumWords(0); var w = getPageNthWord(0, 0, false);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "getPageNumWords"));
            assert!(signals.calls.iter().any(|c| c == "getPageNthWord"));
            assert!(signals.errors.is_empty());
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_creator_subject_payloads() {
    let options = DynamicOptions::default();
    let payload = b"var b = this.creator; eval(unescape(this.creator.replace(/z/igm,'%'))); eval(unescape(this.subject.replace(/Hueputol/g, String.fromCharCode(0x3*0xC+0x1)).replace(/Dalbaeb/g,'B')));";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "eval"));
            assert!(signals.calls.iter().any(|c| c == "alert"));
            assert!(!signals.errors.iter().any(|e| e.contains("Eval error")));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_media_run_guard() {
    let options = DynamicOptions::default();
    let payload = b"j = true; run(); this.media.newPlayer(null);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "run"));
            assert!(signals.calls.iter().any(|c| c == "media.newPlayer"));
            assert!(!signals.errors.iter().any(|e| e.contains("not a callable function")));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_supports_string_substr() {
    let options = DynamicOptions::default();
    let payload = br#""abc".substr(1);"#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "String.substr"));
            assert!(signals.errors.is_empty());
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_get_annot() {
    let options = DynamicOptions::default();
    let payload = b"var a = this.getAnnot(0, '0001-0004'); if (a) { a.subject; }";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|c| c == "getAnnot"));
            assert!(signals.prop_reads.iter().any(|p| p == "annot.subject"));
            assert!(signals.errors.is_empty());
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(not(feature = "js-sandbox"))]
#[test]
fn sandbox_reports_unavailable_without_feature() {
    let options = DynamicOptions::default();
    let outcome = js_analysis::run_sandbox(b"alert(1)", &options);
    match outcome {
        DynamicOutcome::Skipped { reason, .. } => assert_eq!(reason, "sandbox_unavailable"),
        _ => panic!("expected skip"),
    }
}

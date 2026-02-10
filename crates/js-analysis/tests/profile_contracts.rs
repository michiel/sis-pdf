use js_analysis::{DynamicOptions, DynamicOutcome, RuntimeKind, RuntimeMode, RuntimeProfile};

#[cfg(feature = "js-sandbox")]
fn profile_options(kind: RuntimeKind) -> DynamicOptions {
    let mut options = DynamicOptions::default();
    options.runtime_profile = RuntimeProfile {
        kind,
        vendor: match kind {
            RuntimeKind::PdfReader => "adobe".to_string(),
            RuntimeKind::Browser => "chromium".to_string(),
            RuntimeKind::Node => "nodejs".to_string(),
        },
        version: "1".to_string(),
        mode: RuntimeMode::Compat,
    };
    options
}

#[cfg(feature = "js-sandbox")]
fn executed(outcome: DynamicOutcome) -> Box<js_analysis::DynamicSignals> {
    match outcome {
        DynamicOutcome::Executed(signals) => signals,
        DynamicOutcome::TimedOut { timeout_ms, .. } => {
            panic!("sandbox timed out unexpectedly at {} ms", timeout_ms)
        }
        DynamicOutcome::Skipped { reason, .. } => panic!("sandbox skipped unexpectedly: {reason}"),
    }
}

#[cfg(feature = "js-sandbox")]
#[test]
fn profile_id_is_emitted_in_dynamic_signals() {
    let options = profile_options(RuntimeKind::PdfReader);
    let signals = executed(js_analysis::run_sandbox(b"app.alert('hi')", &options));
    assert_eq!(signals.runtime_profile, "pdf_reader:adobe:1:compat");
}

#[cfg(feature = "js-sandbox")]
#[test]
fn pdf_profile_contract_exposes_reader_stubs() {
    let options = profile_options(RuntimeKind::PdfReader);
    let payload = b"
        if (typeof app.viewerVersion !== 'function') throw new Error('viewerVersion');
        if (typeof app.viewerType !== 'function') throw new Error('viewerType');
        app.viewerVersion();
        app.viewerType();
        app.plugIns.length;
    ";
    let signals = executed(js_analysis::run_sandbox(payload, &options));
    assert!(signals.calls.iter().any(|call| call == "app.viewerVersion"));
    assert!(signals.calls.iter().any(|call| call == "app.viewerType"));
    assert!(signals.prop_reads.iter().any(|prop| prop == "app.plugIns"));
    assert!(signals.errors.is_empty(), "unexpected errors: {:?}", signals.errors);
}

#[cfg(feature = "js-sandbox")]
#[test]
fn browser_profile_contract_exposes_fetch_stub() {
    let options = profile_options(RuntimeKind::Browser);
    let payload = b"
        if (typeof fetch !== 'function') throw new Error('fetch');
        if (typeof window !== 'object') throw new Error('window');
        if (typeof window.addEventListener !== 'function') throw new Error('window.addEventListener');
        fetch('https://example.test/path');
        window.addEventListener('load', function(){});
    ";
    let signals = executed(js_analysis::run_sandbox(payload, &options));
    assert!(signals.calls.iter().any(|call| call == "fetch"));
    assert!(signals.calls.iter().any(|call| call == "window.addEventListener"));
    assert!(signals.errors.is_empty(), "unexpected errors: {:?}", signals.errors);
}

#[cfg(feature = "js-sandbox")]
#[test]
fn node_profile_contract_exposes_require_and_process() {
    let options = profile_options(RuntimeKind::Node);
    let payload = b"
        if (typeof require !== 'function') throw new Error('require');
        if (typeof process.exit !== 'function') throw new Error('process.exit');
        if (typeof Buffer !== 'object') throw new Error('Buffer');
        if (typeof Buffer.from !== 'function') throw new Error('Buffer.from');
        require('fs');
        Buffer.from('abcd');
        process.exit(0);
    ";
    let signals = executed(js_analysis::run_sandbox(payload, &options));
    assert!(signals.calls.iter().any(|call| call == "require"));
    assert!(signals.calls.iter().any(|call| call == "Buffer.from"));
    assert!(signals.calls.iter().any(|call| call == "process.exit"));
    assert!(signals.errors.is_empty(), "unexpected errors: {:?}", signals.errors);
}

#[cfg(feature = "js-sandbox")]
#[test]
fn pdf_profile_compat_exposes_require_stub() {
    let options = profile_options(RuntimeKind::PdfReader);
    let payload = b"
        if (typeof require !== 'function') throw new Error('require');
        if (typeof Buffer !== 'object') throw new Error('Buffer');
        if (typeof Buffer.from !== 'function') throw new Error('Buffer.from');
        var fs = require('fs');
        var buffer = require('buffer');
        if (typeof buffer.Buffer.from !== 'function') throw new Error('buffer.Buffer.from');
        if (typeof fs.readFile !== 'function') throw new Error('fs.readFile');
        Buffer.from('abcd');
        buffer.Buffer.from('def');
        fs.readFile('/tmp/a');
    ";
    let signals = executed(js_analysis::run_sandbox(payload, &options));
    assert!(signals.calls.iter().any(|call| call == "require"));
    assert!(signals.calls.iter().any(|call| call == "Buffer.from"));
    assert!(signals.calls.iter().any(|call| call == "fs.readFile"));
    assert!(signals.errors.is_empty(), "unexpected errors: {:?}", signals.errors);
}

#[cfg(feature = "js-sandbox")]
#[test]
fn pdf_profile_compat_exposes_com_factory_stubs() {
    let options = profile_options(RuntimeKind::PdfReader);
    let payload = b"
        if (typeof print !== 'function') throw new Error('print');
        if (typeof ActiveXObject !== 'function') throw new Error('ActiveXObject');
        if (typeof CreateObject !== 'function') throw new Error('CreateObject');
        var shell = new ActiveXObject('WScript.Shell');
        if (typeof shell.Run !== 'function') throw new Error('WScript.Shell.Run');
        if (typeof shell.run !== 'function') throw new Error('WScript.Shell.run');
        if (typeof shell.Environment !== 'function') throw new Error('WScript.Shell.Environment');
        if (typeof WScript.Echo !== 'function') throw new Error('WScript.Echo');
        if (typeof WScript.Sleep !== 'function') throw new Error('WScript.Sleep');
        if (typeof WScript.Quit !== 'function') throw new Error('WScript.Quit');
        if (typeof WScript.echo !== 'function') throw new Error('WScript.echo');
        if (typeof WScript.sleep !== 'function') throw new Error('WScript.sleep');
        print('sandbox');
        shell.Run('cmd /c whoami');
        shell.run('cmd /c whoami');
        var env = shell.Environment('System');
        if (typeof env !== 'function') throw new Error('WScript.Shell.Environment.Item');
        env('PROCESSOR_ARCHITECTURE');
        WScript.Echo('probe');
        WScript.Sleep(1);
        WScript.echo('probe-lower');
        WScript.sleep(1);
        WScript.Quit(0);
        var fso = ActiveXObject('Scripting.FileSystemObject');
        if (typeof fso.OpenTextFile !== 'function') throw new Error('Scripting.FileSystemObject.OpenTextFile');
        if (typeof fso.GetFile !== 'function') throw new Error('Scripting.FileSystemObject.GetFile');
        if (typeof fso.deleteFile !== 'function') throw new Error('Scripting.FileSystemObject.deleteFile');
        var opened = fso.OpenTextFile('C:\\\\temp\\\\x.txt');
        if (typeof opened.Write !== 'function') throw new Error('Scripting.FileSystemObject.OpenTextFile.Write');
        opened.Write('abc');
        var file = fso.GetFile('C:\\\\temp\\\\x.txt');
        if (typeof file.OpenAsTextStream !== 'function') throw new Error('Scripting.File.OpenAsTextStream');
        file.OpenAsTextStream(1);
        fso.deleteFile('C:\\\\temp\\\\x.txt');
        var stream = CreateObject('ADODB.Stream');
        if (typeof stream.SaveToFile !== 'function') throw new Error('ADODB.Stream.SaveToFile');
        if (typeof stream.saveToFile !== 'function') throw new Error('ADODB.Stream.saveToFile');
        stream.SaveToFile('C:\\\\temp\\\\payload.bin');
        stream.saveToFile('C:\\\\temp\\\\payload2.bin');
    ";
    let signals = executed(js_analysis::run_sandbox(payload, &options));
    assert!(signals.calls.iter().any(|call| call == "print"));
    assert!(signals.calls.iter().any(|call| call == "ActiveXObject"));
    assert!(signals.calls.iter().any(|call| call == "CreateObject"));
    assert!(signals.calls.iter().any(|call| call == "WScript.Shell.Run"));
    assert!(signals
        .calls
        .iter()
        .any(|call| call == "WScript.Shell.Environment"));
    assert!(signals
        .calls
        .iter()
        .any(|call| call == "WScript.Shell.Environment.Item"));
    assert!(signals.calls.iter().any(|call| call == "WScript.Echo"));
    assert!(signals.calls.iter().any(|call| call == "WScript.Sleep"));
    assert!(signals.calls.iter().any(|call| call == "WScript.Quit"));
    assert!(signals.calls.iter().any(|call| call == "Scripting.FileSystemObject.OpenTextFile"));
    assert!(signals.calls.iter().any(|call| call == "TextStream.Write"));
    assert!(signals.calls.iter().any(|call| call == "Scripting.FileSystemObject.GetFile"));
    assert!(signals.calls.iter().any(|call| call == "Scripting.FileSystemObject.DeleteFile"));
    assert!(signals.calls.iter().any(|call| call == "Scripting.File.OpenAsTextStream"));
    assert!(signals.calls.iter().any(|call| call == "ADODB.Stream.SaveToFile"));
    assert!(signals.errors.is_empty(), "unexpected errors: {:?}", signals.errors);
}

#[cfg(feature = "js-sandbox")]
#[test]
fn pdf_profile_compat_supports_shell_namespace_and_env_expansion() {
    let options = profile_options(RuntimeKind::PdfReader);
    let payload = b"
        var shell = WScript.CreateObject('WScript.Shell');
        var tempPath = shell.ExpandEnvironmentStrings('%TEMP%');
        if (typeof tempPath !== 'string') throw new Error('ExpandEnvironmentStrings return type');
        var shellApp = new ActiveXObject('Shell.Application');
        if (typeof shellApp.NameSpace !== 'function') throw new Error('Shell.Application.NameSpace');
        var ns = shellApp.NameSpace(7);
        if (typeof ns.Self.Path !== 'string') throw new Error('Shell.Application.NameSpace.Self.Path');
        var combined = tempPath + '\\\\x.exe';
        if (combined.length < 5) throw new Error('combined path too short');
    ";
    let signals = executed(js_analysis::run_sandbox(payload, &options));
    assert!(signals
        .calls
        .iter()
        .any(|call| call == "WScript.Shell.ExpandEnvironmentStrings"));
    assert!(signals
        .calls
        .iter()
        .any(|call| call == "Shell.Application.NameSpace"));
    assert!(
        !signals
            .errors
            .iter()
            .any(|error| error.contains("not a callable function")),
        "unexpected callable error: {:?}",
        signals.errors
    );
    assert!(signals.errors.is_empty(), "unexpected errors: {:?}", signals.errors);
}

#[cfg(feature = "js-sandbox")]
#[test]
fn browser_profile_missing_pdf_api_has_stable_error_signature() {
    let options = profile_options(RuntimeKind::Browser);
    let payload = b"app.viewerVersion();";
    let signals = executed(js_analysis::run_sandbox(payload, &options));
    assert!(!signals.errors.is_empty(), "expected profile mismatch error");
    let combined = signals.errors.join(" | ").to_ascii_lowercase();
    assert!(
        combined.contains("cannot convert")
            || combined.contains("undefined")
            || combined.contains("not defined")
            || combined.contains("not a callable function"),
        "unexpected error signature: {}",
        combined
    );
}

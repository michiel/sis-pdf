# Modern Staged OpenAction JS Exploit PDF

## Threat Summary

This sample is a complex staged attack that uses an OpenAction trigger to initialize a JavaScript
runtime, which then performs environmental reconnaissance via the `exportDataObject()` JavaScript API
before proceeding with payload delivery. The attack chain spans four or more nodes (decode, render,
execute, exfiltrate/persist) and exploits renderer behaviour differences between PDF implementations
to selectively expose malicious content only in targeted reader environments.

The supply chain staged payload signal indicates the document participates in a multi-stage delivery
pipeline — the PDF is not a self-contained attack but a delivery vehicle that stages a subsequent
payload from an external source or from embedded content only accessible after the JS reconnaissance
phase. Three intent buckets are activated: ExploitPrimitive (exploitation chain), SandboxEscape
(renderer divergence and environment probing), and Persistence (supply chain staged delivery).

## File Structure

The document has a distributed chain architecture spanning at least four functional nodes:

**Node 1: OpenAction trigger**: The PDF catalog contains an `/OpenAction` entry pointing to a
JavaScript action. This action executes immediately when the document is opened by any reader that
honours OpenAction triggers (all major PDF readers do). There is no user interaction required to
initiate the attack chain — document open is sufficient.

**Node 2: JavaScript runtime initialization**: The OpenAction JS initializes the runtime environment.
The script performs capability detection — querying the PDF reader's version, the underlying platform,
and available APIs — to determine whether the environment is suitable for payload delivery. This
reconnaissance phase gates the remainder of the attack chain.

**Node 3: File probing via exportDataObject**: The JavaScript calls `exportDataObject()`, a PDF JS
API that extracts embedded file attachment objects from the PDF and writes them to the filesystem.
In the context of this sample, `exportDataObject()` is used to probe whether a specific file can be
written to the target filesystem — confirming that the PDF reader has filesystem write access and that
the environment is not a restricted sandbox. This is the `js_runtime_file_probe` signal.

**Node 4: Supply chain staged payload**: Following successful reconnaissance, the JS runtime triggers
a supply chain update mechanism — either fetching a payload from a remote staging server or extracting
a cached payload from an embedded stream using `exportDataObject()` to write it to disk. The
`supply_chain_staged_payload` finding reflects this pattern: a payload is staged for execution via
a supply-chain-mimicking delivery pathway, which may include registering persistence mechanisms.

**Renderer divergence**: The document structure also exploits known PDF.js code path differences to
trigger `renderer_behavior_divergence_known_path`. This creates a multi-reader divergence pattern:
the staged payload may only be accessible or executable in readers that exhibit the divergence
behaviour, while readers that handle the code path correctly either skip the malicious content or
fail to execute it. The PDF.js eval path risk (`pdfjs_eval_path_risk`) corroborates this — the
document exercises an `eval()`-adjacent code path in the reference renderer.

**Stage coverage**: The chain covers three attack stages:
- **Decode**: PDF content streams are decoded to reveal the embedded payload structure
- **Render**: Renderer divergence exploited to expose malicious content in targeted readers
- **Execute**: JS runtime executes file probe and staged payload delivery

## Detection Chain

Five signals form a coherent exploit chain across the four attack nodes:

1. **pdfjs_eval_path_risk (info/strong)**: The document exercises a PDF.js eval code path during
   rendering. This is the lowest-severity signal but provides early indication that the document
   stresses boundary conditions in the reference renderer. Info severity means it is logged but does
   not alone contribute to verdict scoring.

2. **js_runtime_file_probe (high/strong, exportDataObject)**: The JS static analyzer identifies a
   call to `exportDataObject()` within the OpenAction script. This API is rarely used in legitimate
   documents and is specifically associated with writing embedded content to the filesystem. The
   strong confidence comes from the function name being unambiguous — there is no legitimate document
   workflow that requires `exportDataObject()` to write to disk during OpenAction execution.

3. **supply_chain_staged_payload (high/probable)**: The combination of `exportDataObject()` usage
   and the network/staging patterns in the JS source matches a supply chain staged delivery template.
   The probable (not strong) confidence reflects that the staging endpoint or payload content was
   not directly recoverable from static analysis — the gating condition (successful reconnaissance)
   was not met during the static emulation pass.

4. **renderer_behavior_divergence_known_path (high/strong)**: Pattern match against a catalogued
   renderer divergence signature. Strong confidence because this is signature-based detection against
   a known bad code path, not heuristic inference.

5. **renderer_behavior_exploitation_chain (high/strong)**: The exploitation chain composite finding
   combines `js_runtime_file_probe` with `renderer_behavior_divergence_known_path` to establish that
   the JS probing and the renderer divergence are coordinated — both are present in the same document
   and together constitute a multi-stage exploitation chain. This composite finding drives the
   ExploitPrimitive bucket to its highest score.

Intent accumulation:
- ExploitPrimitive: `renderer_behavior_exploitation_chain` (high) + `js_runtime_file_probe` (high)
- SandboxEscape: `js_runtime_file_probe` (environment probing) + `renderer_behavior_divergence_known_path`
- Persistence: `supply_chain_staged_payload` (staged delivery with persistence mechanism)

## Evasion Techniques

**Multi-stage delivery with gated execution**: The attack only proceeds if the reconnaissance phase
confirms a suitable environment. In automated sandboxes that do not simulate a full interactive
session, the reconnaissance may fail or return sandbox-indicator results, causing the JS to terminate
without proceeding to payload delivery. The payload is never written to disk in sandbox environments,
producing a clean-looking analysis report.

**Renderer divergence for selective targeting**: By exploiting a specific PDF.js code path
difference, the attacker ensures the malicious content is accessible only in readers with the target
divergence behaviour. Security tools using a different (more compliant) renderer path will not see
the malicious content even if they fully execute the document.

**exportDataObject as a legitimate API**: `exportDataObject()` is a standard PDF JavaScript API
documented in the Adobe PDF specification. Its use does not inherently violate any policy — many
enterprise PDF workflows use it legitimately. This reduces the likelihood of the API call being
blocked by application-layer security controls.

**Supply chain mimicry**: Staging the payload delivery to resemble a software update or supply chain
pull (fetching from a legitimate-looking update endpoint) takes advantage of organization policies
that permit software update traffic. The staged payload delivery may use HTTPS to a CDN or cloud
storage endpoint, making the network traffic blend with legitimate background update activity.

**Distributed chain architecture**: By spreading the attack across four nodes with dependencies
between them, the attacker ensures that partial execution (e.g., JS runs but renderer divergence
doesn't fire) produces no observable malicious outcome. All four nodes must cooperate for the attack
to succeed, which increases the attacker's control over when and where the payload deploys.

## Key Indicators

- **SHA256**: `38851573fd1731b1bd94a38e35f5ea1bd1e4944821e08e27857d68a670c64105`
- **OpenAction**: Present — document-open trigger, no user interaction required
- **JS API**: `exportDataObject()` called in OpenAction script (file probe / payload drop)
- **Renderer divergence**: Known-path divergence signature (PDF.js code path)
- **Chain depth**: >= 4 nodes (decode/render/execute/persist)
- **Stage coverage**: Decode, Render, Execute
- **MITRE ATT&CK**: T1059.007 (JS execution), T1204.002 (User Execution: Malicious File via social
  lure for initial delivery), T1195 (Supply Chain Compromise — staged payload pattern), T1082
  (System Information Discovery — exportDataObject filesystem probe)

No specific staging domain is listed because the supply chain endpoint was not reachable during
static analysis. The JS staging URL, if present in the script, would be found in the `network_intents`
extraction output.

## Regression Coverage

- **`corpus_captured_modern_openaction_staged_baseline_stays_stable`**: Verifies that
  `renderer_behavior_divergence_known_path` (high/strong), `renderer_behavior_exploitation_chain`
  (high/strong), `supply_chain_staged_payload` (high/probable), and `js_runtime_file_probe`
  (high/strong) are all present with the expected severity and confidence levels. Verifies that
  ExploitPrimitive, SandboxEscape, and Persistence intent buckets are activated and the verdict is
  Suspicious. The test also confirms that the distributed chain has >= 4 nodes in the chain graph
  output, validating the chain architecture represents the full attack scope.

# APT42 Polyglot PDF+ZIP+PE Dropper

## Threat Summary

This sample is a polyglot file attributed to APT42, a threat actor with ties to Iranian state-sponsored
operations. The file is simultaneously a valid PDF document and a valid ZIP archive, a technique known
as a polyglot file. When opened in a PDF reader, the victim sees a document. When processed by a ZIP
parser — either by a downloader, a second-stage dropper, or the victim manually extracting it — the
archive yields two PE executables. This dual-nature structure is designed to evade file-type-based
detection and complicate forensic triage.

The PDF component has minimal content: it exists primarily as a carrier. The ZIP component is the
operational payload and contains at least two PE binaries, likely a loader and a dependency DLL
(consistent with the msvcp140.dll drift-guard pattern associated with APT42 staging toolkits).

## File Structure

The file begins with a standard PDF header (`%PDF-1.x`) followed by a minimal PDF object structure.
OBJ=1 is an 888,881-byte stream containing the raw PE/ZIP binary data with Shannon entropy of 7.99 —
essentially indistinguishable from random data, which is characteristic of compressed or encrypted
executable content. OBJ=11 is a smaller 162-byte stream with entropy 6.71, likely a stub or metadata
object.

Immediately following the PDF cross-reference table and end-of-file marker (`%%EOF`), the ZIP archive
begins. ZIP parsers read from the end of the file (the central directory record), so they locate and
extract the ZIP contents regardless of the PDF header at the start. This makes the file valid under
both formats simultaneously.

The ZIP archive contains two PE executables embedded as entries. These are the operational payloads
delivered to the victim's filesystem upon extraction or execution by a second-stage loader.

File layout summary:

- Bytes 0..N: Valid PDF structure (header, objects, xref, %%EOF)
  - OBJ=1: 888,881 bytes, entropy 7.99 (raw PE/ZIP blob)
  - OBJ=11: 162 bytes, entropy 6.71 (stub/metadata)
- Bytes N..end: Valid ZIP archive (central directory at EOF)
  - Entry 1: PE executable (loader)
  - Entry 2: PE executable (DLL dependency, likely msvcp140.dll variant)

## Detection Chain

Detection proceeds through five signals that together constitute the ExploitPrimitive and SandboxEscape
intent assessment:

1. **polyglot_signature_conflict (high/strong)**: The file header is PDF but the file also satisfies
   ZIP format validation. The signature conflict detector identifies the dual magic bytes and raises a
   high-severity strong-confidence finding immediately.

2. **embedded_payload_carved (medium/strong, zip stream)**: The content stream carver identifies a ZIP
   local-file-header signature (`PK\x03\x04`) embedded within the PDF stream data. This confirms the
   ZIP archive is not accidentally appended but is structurally present within the PDF object graph.

3. **nested_container_chain (high/probable x2, PE entries)**: Two PE signatures (`MZ\x90\x00`) are
   identified within the carved ZIP stream entries. Each PE entry produces its own nested-container
   finding, indicating a two-stage payload structure (loader + dependency).

4. **entropy_high_object_ratio (low/probable, stream entropy 7.99)**: OBJ=1's near-maximal Shannon
   entropy flags it as likely encrypted, compressed, or containing binary executable data. Taken alone
   this is a weak signal, but it corroborates the carved payload findings.

5. **polyglot_pe_dropper (critical/strong, composite)**: The correlation engine combines
   polyglot_signature_conflict with nested PE findings to emit a composite critical finding. This is
   the primary driver of the Malicious verdict.

Intent accumulation: `polyglot_pe_dropper` (critical) contributes directly to ExploitPrimitive bucket.
The embedded PE executables and sandbox-evasion polyglot structure trigger SandboxEscape bucket
signals. The combined score exceeds the Malicious verdict threshold.

## Evasion Techniques

**Polyglot structure**: By being a valid PDF and a valid ZIP simultaneously, the file can bypass
security controls that gate on file extension or single-format magic byte detection. A PDF sandbox
may execute the PDF portion without extracting the ZIP. Email filters expecting ZIP archives would see
a PDF. The attacker can choose which parser activates the payload depending on the delivery context.

**High entropy hiding payload**: OBJ=1 contains the raw PE/ZIP blob at entropy 7.99. Naive content
scanning that looks for PE headers in plaintext would miss the payload unless the full stream is
decoded and carved. The entropy alone does not prove malice but makes static analysis harder.

**Minimal PDF structure**: The PDF portion has only two stream objects, reducing the attack surface for
static analysis tools that focus on PDF-specific features (JavaScript, actions, form fields). There are
no JavaScript, OpenAction, or annotation triggers in the PDF component. The malicious content is
entirely in the binary payload, not in PDF semantics.

**APT42 operational pattern**: APT42 frequently uses polyglot files, DLL sideloading, and msvcp140.dll
as a dependency vehicle to establish persistence. The use of a familiar DLL name reduces suspicion when
files appear in process listings or filesystem scans.

## Key Indicators

- **SHA256**: `6648302d497ee2364d3b10d0bebd1c30cedf649117a682754aebd35761a5d2ff`
- **File type**: PDF+ZIP polyglot
- **Stream entropy**: OBJ=1 = 7.99 bits/byte (near-maximal, characteristic of compressed PE)
- **PE count**: 2 embedded PE executables within ZIP entries
- **Threat actor**: APT42 (Iranian state-sponsored, IRGC nexus)
- **MITRE ATT&CK**: T1027.009 (Obfuscated Files: Embedded Payloads), T1055 (Process Injection),
  T1566.001 (Spearphishing Attachment)
- **Known pattern**: msvcp140.dll drift-guard staging (APT42 toolkit fingerprint)

No network indicators were identified in this sample. The PDF itself does not contain URI annotations
or JS network calls. The payload delivery is entirely file-based; network activity would originate from
the extracted PE executables after execution.

## Regression Coverage

- **`apt42_polyglot_core_detections_present`**: Verifies that `polyglot_signature_conflict`,
  `embedded_payload_carved`, `nested_container_chain` (x2), and `polyglot_pe_dropper` findings are all
  present with the expected severity and confidence levels. Ensures the composite critical finding fires.

- **`cov6_entropy_clustering_fires_on_apt42_polyglot_deep`**: Verifies that in deep scan mode, the
  entropy clustering detector correctly identifies OBJ=1 as a high-entropy anomaly and emits the
  `entropy_high_object_ratio` finding. This test runs in deep mode only because entropy clustering is
  computationally intensive and gated behind the deep flag.

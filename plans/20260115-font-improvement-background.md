Assessment of sis‑pdf Font Detection Compared to Project Zero's 2015 BLEND Vulnerability
Background: Project Zero’s BLEND vulnerability (2015)

Google Project Zero described a vulnerability in Type 1 PostScript fonts that was exploited in Adobe Reader and Microsoft Windows’ ATMFD.dll. A flaw in the BLEND operator allowed arbitrary PostScript operations on the execution stack, enabling attackers to construct a return‑oriented‑programming (ROP) chain. This chain allowed code execution inside the PDF reader and escape from the sandbox by exploiting the same bug in the kernel. The exploit used a Type 1 charstring in a PDF to deliver payloads, and the vulnerability was fixed by Adobe and Microsoft.

Current sis‑pdf font detection capabilities

sis‑pdf uses a font‑analysis crate to inspect embedded fonts. Key elements of the current implementation include:

Static analysis heuristics: The static_scan module examines font streams for structural anomalies. It checks the SFNT header, the number and layout of tables, table sizes/offsets, duplicate or overlapping tables, and unusually large hinting programs. Findings such as font.anomalous_table_size, font.invalid_structure and font.suspicious_hinting are emitted when thresholds are exceeded.

Dynamic parsing: A simple dynamic check attempts to parse the font with Skrifa (Rust) and only records whether parsing succeeds or fails. Detailed execution of hinting programs is not performed.

Heuristics in FontExploitDetector: The FontExploitDetector in sis‑pdf‑detectors collects embedded fonts, limits the number of processed fonts, rejects huge streams, and calls font_analysis::analyse_font. It flags suspicious markers such as CFF headers or large payloads.

Would sis‑pdf detect the BLEND exploit?

Probably not: The BLEND vulnerability exploited Type 1 charstrings and the interpreter’s virtual machine. sis‑pdf currently focuses on structural anomalies and table sizes typical of TrueType/OpenType fonts. It does not parse or interpret Type 1 PostScript charstrings, nor does it recognise the presence of a Type 1 font encoded in a PDF stream. There is no heuristic for abnormal charstring operators such as large sequences of callothersubr/pop or use of the BLEND operator. Therefore, the current system would likely miss a BLEND‑style exploit. This is consistent with the fact that the only charstring‑related finding in the repository is font.suspicious_hinting, which triggers when hinting programs exceed a size threshold; this would not detect a short but malicious charstring.

Moreover, the dynamic analysis uses Skrifa’s parser for modern SFNT fonts, not a PostScript interpreter. The BLEND exploit relied on PostScript Type 1 features that are not processed by the present dynamic module. Thus, while the static scan might flag extremely large fonts, it would not interpret malicious instructions. In summary, sis‑pdf would not reliably detect the 2015 BLEND attack.

Recommendations to close this gap

Add Type 1 font recognition and analysis
Implement routines to detect PostScript Type 1 fonts in PDF streams (e.g., look for %!PS‐AdobeFont headers or FontType 1). Once detected, parse charstring programs and look for sequences of operators known to be exploited (callothersubr patterns, unusual stack growth, use of BLEND, etc.). Maintain a list of dangerous PostScript operators (e.g., aload, ashow, dup) to flag charstrings that create large stacks or unusual loops.

Integrate an open‑source Type 1 interpreter or sanitizer
Use an existing safe interpreter such as psfix or the Ghostscript font parser to emulate Type 1 charstrings in a sandbox. Analyse the execution trace for stack depth, instruction count and memory access patterns. This dynamic approach would catch hidden instructions similar to the BLEND exploit.

Extend dynamic analysis for TrueType/CFF
The dynamic module should do more than simply parse fonts. It could integrate instrumentation (e.g., by hooking FreeType or using memory‑safe engines like Skrifa) to monitor execution of hinting programs and charstrings. It should detect abnormal CFF2 charstring counts, invalid gvar lengths or mismatched hmtx/maxp tables similar to vulnerabilities from 2024–2025. When dynamic analysis is not possible, the engine should record a partial risk score.

Signature‑based detection
Maintain a database of CVE patterns for historic font exploits, including the BLEND vulnerability and recent out‑of‑bounds reads/writes (e.g., CVE‑2024‑30311/30312, CVE‑2025‑27163/27164). Each signature could check for specific table size inconsistencies (e.g., hmtx length < 4 * numberOfHMetrics) or mismatched numGlyphs and CFF2 entries. When a match is found, assign high severity.

Correlate with JavaScript and remote actions
Many PDF font exploits are combined with JavaScript or remote file actions. The detection pipeline should correlate font anomalies with presence of high‑risk JavaScript (e.g., heap sprays) or external references to fonts. Use cross‑object correlation rules to increase confidence, as suggested in the internal plan.

Continuous CVE monitoring and automatic updates
Build automation that ingests CVE feeds and security advisories. When a new vulnerability appears, update the signature database and heuristics without waiting for a release.

Trends in font exploitation up to 2026
2010–2015: PostScript and CFF abuses

Early attacks exploited Type 1 or CFF charstrings. The 2015 Project Zero case used the BLEND operator to achieve code execution and kernel escape. Attackers found logic flaws in PostScript interpreters, enabling arbitrary operations. During this period, PDF readers relied on font engines written in C/C++, leading to memory‑safety issues.

2016–2020: Matured but persistent exploitation

After vendors patched major PostScript vulnerabilities, adversaries shifted to embedded TrueType or CFF fonts. They exploited buffer overflows, use‑after‑frees and integer overflows in FreeType and proprietary engines. The internal plan notes that APT groups continued using font exploits even as defences improved.

2021–2023: Sandboxing and sanitization; emergence of Rust engines

Vendors increased isolation of font processing; Chrome and Firefox sandbox font engines and use the OpenType Sanitizer (OTS) to validate tables. Google announced replacing FreeType with the Rust‑based Skrifa engine in Chrome, reducing memory‑safety bugs. Nevertheless, Adobe’s proprietary engine remained vulnerable: Project Zero discovered a 2023 out‑of‑bound write in sfac_GetSbitBitmap due to invalid EBSC offsets in TrueType fonts. Attackers also began embedding fonts with malformed variable‑font tables and using Color Font features.

2024–2025: Out‑of‑bounds reads, incomplete patches, and FreeType zero‑days

Multiple vulnerabilities surfaced in Adobe Acrobat Reader. Cisco Talos reported two out‑of‑bounds read flaws in 2024—CVE‑2024‑30311 and CVE‑2024‑30312—that allowed specially crafted fonts to disclose sensitive memory. Talos noted that one bug had been previously patched, but the fix was incomplete. In 2025, Talos disclosed CVE‑2025‑27163 and CVE‑2025‑27164 involving mismatches between hmtx/hhea table lengths and maxp/CFF2 glyph counts, causing out‑of‑bounds reads. The timeline shows these were privately reported in January 2025 and patched in March 2025.

Around the same time, a FreeType zero‑day (CVE‑2025‑27363) exploited a type‑conversion bug where a signed short was assigned to an unsigned long; this caused an undersized heap allocation and allowed writing beyond the buffer boundary. Attackers used malicious fonts in documents to gain code execution. These incidents show that memory‑unsafe font engines remain a target.

2026 and beyond: remote linking, supply chain, and emerging formats

By 2026, PDF toolkits such as jsPDF were exploited via path traversal in server‑side contexts (CVE‑2025‑68428) where untrusted input controlled the loadFile() method, allowing attackers to read arbitrary files and embed them in PDFs. While not a font bug, it reflects a trend towards supply‑chain and remote embedding attacks. Meanwhile, remote font linking (e.g., external URIs in PDF’s ExtGState or CIDFont dictionary) may be abused to exfiltrate data or deliver malicious fonts. Researchers also forecast increased exploitation of variable fonts (CFF2, gvar) and color fonts with complex tables. The adoption of memory‑safe engines like Skrifa is expected to reduce vulnerability surfaces, but proprietary or outdated libraries (e.g., in legacy products or third‑party PDF generators) may remain vulnerable.

Future‑proof detection capabilities: recommendations

Support emerging font formats
Extend parsing and heuristics to cover variable fonts (CFF2, gvar, avar) and color font tables (COLR, CPAL). Implement checks for mismatched table counts, invalid indices and inconsistent bounding boxes, as in the 2025 vulnerabilities.

Detect remote font linking and external references
Scan PDF dictionaries for CIDFont FontFile streams pointing to remote resources or references like /F <</F1 <</Type/Action/S/GoToR/…>>>. Flag when fonts are loaded via GoToR, URI, or network actions. This will mitigate attacks that fetch malicious fonts or exfiltrate data via external servers.

Instrumented dynamic analysis
Incorporate fuzzing and instrumentation of font parsers. Tools like AFL, libFuzzer or custom harnesses can feed fonts through FreeType or Skrifa under sanitizers (ASan, MSan) to detect memory issues. Use timeouts and state coverage to avoid denial‑of‑service. This dynamic approach can discover zero‑day bugs similar to CVE‑2025‑27363 and is suitable for offline scanning pipelines.

Memory‑safe parser selection
Where possible, rely on memory‑safe engines like Skrifa or WebAssembly‑compiled FreeType with sandboxing. Validate fonts using OTS before full parsing. If a font fails OTS validation, treat it as malicious.

Correlation and ML‑based risk scoring
Develop a scoring model that considers structural anomalies, dynamic parse failures, CVE signature matches, remote linking and correlation with JavaScript. Machine‑learning models could learn from labelled malicious fonts to identify new patterns. Combine features such as instruction counts, table entropy, and unusual naming to detect unknown threats.

User‑configurable thresholds and context awareness
Provide options to adjust detection thresholds based on environment (e.g., stricter checks in server environments or when handling untrusted PDFs). Incorporate context: fonts loaded by trusted signers or built‑in standard fonts may require fewer checks than unknown ones.

Regular updates and community sharing
Stay up‑to‑date with CVEs and share heuristics with the security community. Use automatic pipelines to test detection against newly disclosed samples and integrate feedback from researchers.

Conclusion

The 2015 BLEND vulnerability underscores the risks of sophisticated font exploits. sis‑pdf currently detects structural anomalies but lacks Type 1 and deep charstring analysis; hence it may miss exploits like BLEND. Enhancing detection with Type 1 parsing, dynamic instrumentation, CVE signatures and correlation will help close current gaps. Looking forward, attackers will continue exploiting complex font tables, memory‑unsafe engines, and remote embedding. A combination of static heuristics, dynamic analysis, signature updates, and memory‑safe parsers will provide a robust, future‑proof defense.

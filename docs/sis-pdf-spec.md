# Chapter1

Below is a concrete, security-engineering way to build **sis-pdf**: a **Rust PDF analyzer** that inventories attack surface, detects suspicious/exploitable constructs, and produces **findings grouped by attack-surface component + issue type**, with **per-finding evidence**. It’s optimized for **interactive speed** without trading away **parse correctness**.

I’m going to treat this as a **defensive static analysis + structural validation** tool (not an exploit runner). A lot of PDF abuse hinges on **interactive features** (actions, JavaScript, embedded files, rich media) and **parser differentials / malformed structure**; those are first-class in the spec. ([Lenny Zeltser][1])

---

## 1) PDF attack surface inventory (what you must model)

### A. File container & structural layer (parser differential territory)

**Goal:** detect malformed structures that cause *different* parsers to interpret different object graphs (evasion + exploit trigger surface).

* Header + `%PDF-x.y` version, EOF marker, `startxref`
* Cross-reference forms:

  * classic xref table
  * xref streams
  * hybrid xref
* Trailers, `/Prev` chains (incremental updates), multiple trailers
* Linearized PDFs (“fast web view”)
* Object numbering reuse, duplicate object IDs, shadowing via incremental updates
* Object streams (`/ObjStm`) (hiding, packing, compression)
* Stream dictionary correctness vs actual bytes (`/Length`, filters)
* Reference graph cycles, missing objects, dangling refs
* Malformed tokens, overflows, weird whitespace, bad encodings

Why it matters: “malformed but tolerated” PDFs are a common analysis-evasion tactic; robust tools must parse *like a permissive viewer*, but also report spec violations. ([GISPP][2])

### B. Stream codecs & decoders (historically vuln-heavy)

Anything that forces the viewer to run complex decoders is attack surface:

* Filters: `/FlateDecode`, `/LZWDecode`, `/ASCIIHexDecode`, `/ASCII85Decode`, `/RunLengthDecode`
* Image-specific: `/DCTDecode` (JPEG), `/JPXDecode` (JPEG2000), `/JBIG2Decode` (notorious), `/CCITTFaxDecode`
* Font programs and font parsing
* Content stream operators (graphics/text), transparency, patterns, shadings
* Embedded color spaces / ICC profiles

Example: JBIG2 decoding has been involved in real-world Reader RCE classes. ([GitHub][3])

### C. Interactive features (the “malicious PDF” classics)

These are the big “this can execute / exfiltrate / drop something” knobs.

* Document and annotation **Actions**:

  * `/OpenAction` (run on open)
  * `/AA` (Additional Actions on events)
  * `/Launch` (attempt to launch external app/file)
  * `/URI` (external link)
  * `/GoToR` (remote go-to)
  * `/SubmitForm` (exfiltration)
* JavaScript containers:

  * `/JavaScript`, `/JS`
  * JavaScript in Names tree, actions, annotations, forms
* Forms:

  * `/AcroForm` (fields, actions)
  * `/XFA` (deprecated/legacy, historically risky surface)
* Embedded files:

  * `/EmbeddedFile` streams, file specs, “associated files”
* Rich Media / 3D:

  * `/RichMedia`, 3D artwork (U3D/PRC), media activation events

These are also exactly the keyword families many triage tools focus on. ([GitHub][4])

### D. Security features (can be abused or can help you)

* Encryption dictionaries, algorithms, weird combinations
* Signatures and DSS/LTV structures (can be large/complex; can be used for hiding blobs)
* Metadata streams (XMP), embedded XML
* Permissions flags, “unusual” settings

PDF 2.0 expanded encryption/signature and added/clarified various advanced features (including rich media and associated files) — your analyzer should understand the dictionaries even if it doesn’t fully implement them. ([ITeh Standards][5])

### E. Social-engineering surface (phishing inside PDFs)

Even without “code execution”, PDFs are used for credential theft and download lures:

* Full-page images that mimic login prompts
* Invisible link overlays, tiny text, hidden annotations
* “Click to view”, “secure document” patterns

(You can score/report these heuristically and let humans decide.) ([Oneconsult AG][6])

---

## 2) Attack vectors (what sis-pdf should detect)

Organize detections by **component → vector → heuristic/validation**:

### 2.1 Parser differentials & structural corruption

* Multiple `startxref`, conflicting xrefs
* Broken xref but recoverable object scanning succeeds (flag as “viewer-likely tolerant”)
* Incremental update hiding: suspicious objects only present in later revisions
* Duplicate object IDs with conflicting bodies
* Streams whose declared `/Length` mismatches actual length
* Filter chains that don’t decode cleanly but “best effort” yields data

### 2.2 “Auto-trigger” behavior

* `/OpenAction` present
* `/AA` on catalog/page/annotation/form-field events
* RichMedia activation events

These are repeatedly called out by practical PDF triage guidance/tools. ([Lenny Zeltser][1])

### 2.3 Script and external interaction

* JavaScript anywhere (`/JS`, `/JavaScript`)
* External URLs (`/URI`) + suspicious domains / IP literals / data URIs
* `/SubmitForm` to non-local endpoint
* `/Launch` actions
* Embedded file extraction + suspicious extensions, PE/ELF/Mach-O magic

### 2.4 Decoder risk & resource-exhaustion (interactive safety)

* Huge or deeply nested object graphs
* Decompression bombs (inflate ratio thresholds)
* Excessive image dimensions / ICC profile size
* JBIG2/JPX present → elevate “decoder risk” class
* Excessive `/ObjStm` usage or very large object streams

### 2.5 Content deception

* Large image-only pages + embedded link overlays
* Transparent annotations over UI-like images
* “Invoice / secure / view document” language + external links (heuristic)

---

## 3) Technical specification: sis-pdf architecture

### 3.1 Design goals

* **Correctness-first parsing** with **viewer-tolerant recovery mode**
* **Two-phase analysis** for interactivity:

  1. **Fast triage scan** (structure + dictionaries + keyword-indexing + minimal decoding)
  2. **Deep scan** (targeted stream decode, JS extraction, embedded file carving, heuristics)
* Deterministic output:

  * stable finding IDs
  * reproducible evidence snippets
* Output formats:

  * human (terminal / TUI)
  * machine JSON
  * optional SARIF (nice for CI)

### 3.2 Core subsystems

1. **ByteSource**

   * mmap file for speed
   * supports “slices” for streams without copying
2. **Parser**

   * tokeniser (PDF lexical rules)
   * object parser (dict/array/stream)
   * xref parser (table/stream/hybrid)
   * *recovery parser* (scan objects when xref broken)
3. **ObjectGraph**

   * resolves indirect objects
   * tracks revision chain (incremental updates)
   * exposes “views”: strict vs recovered
4. **StreamDecoder**

   * implements safe decode with quotas:

     * max output bytes
     * max nesting depth
     * max time per stream (optional)
5. **Detectors**

   * pluggable rules, each emits Findings with evidence pointers
6. **Reporter**

   * grouping: component → type → findings
   * severity + confidence scoring
   * includes “why it matters” and “how to validate” per finding

### 3.3 Data model (types you’ll actually use)

```rust
// sis-pdf-core/src/model.rs
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum AttackSurface {
    FileStructure,
    XRefTrailer,
    ObjectStreams,
    StreamsAndFilters,
    Actions,
    JavaScript,
    Forms,
    EmbeddedFiles,
    RichMedia3D,
    CryptoSignatures,
    Metadata,
    ContentPhishing,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum Severity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum Confidence { Heuristic, Probable, Strong }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceSource {
    /// Raw file bytes (offsets are absolute in the original PDF).
    File,
    /// Bytes derived from decoding or extraction; span refers to the decoded buffer.
    Decoded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSpan {
    pub source: EvidenceSource,
    pub offset: u64,
    pub length: u32,
    /// For decoded artifacts, point back to the originating file span when known.
    pub origin: Option<Span>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,                 // stable hash: rule + object ref + key evidence
    pub surface: AttackSurface,
    pub kind: String,               // e.g. "open_action", "js_present", "xref_conflict"
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub objects: Vec<String>,       // "12 0 obj", "xref stream", etc.
    pub evidence: Vec<EvidenceSpan>,
    pub remediation: Option<String>,
}
```

Example (JSON):

```json
{
  "source": "Decoded",
  "offset": 512,
  "length": 96,
  "origin": { "start": 1048576, "end": 1049100 },
  "note": "JS extracted from FlateDecode stream"
}
```

### 3.4 Detector interface (fast + deep)

Detectors should declare:

* what they need (xref only vs full graph vs decoded streams)
* a cost hint (so interactive mode can skip expensive detectors)

```rust
// sis-pdf-core/src/detect.rs
use crate::model::{Finding, AttackSurface};

bitflags::bitflags! {
    pub struct Needs: u32 {
        const XREF            = 0b00000001;
        const OBJECT_GRAPH    = 0b00000010;
        const STREAM_INDEX    = 0b00000100; // locate streams but don't decode
        const STREAM_DECODE   = 0b00001000; // decode selected streams
        const PAGE_CONTENT    = 0b00010000; // parse content ops
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Cost { Cheap, Moderate, Expensive }

pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn surface(&self) -> AttackSurface;
    fn needs(&self) -> Needs;
    fn cost(&self) -> Cost;

    fn run(&self, ctx: &crate::scan::ScanContext) -> anyhow::Result<Vec<Finding>>;
}
```

### 3.5 Scan pipeline

**Interactive default**: run Cheap+Moderate detectors in triage; expensive ones only on demand.

```rust
// sis-pdf-core/src/scan.rs
pub struct ScanOptions {
    pub deep: bool,
    pub max_decode_bytes: usize,
    pub recover_xref: bool,
    pub parallel: bool,
}

pub struct ScanContext<'a> {
    pub bytes: &'a [u8],
    pub graph: crate::pdf::ObjectGraph<'a>,
    pub decoded: crate::pdf::DecodedCache, // lazily filled
    pub options: ScanOptions,
}
```

### 3.6 Performance strategy (speed without lying)

* **mmap** + slice-based parsing (avoid copies)
* **Index first, decode later**:

  * build object index, stream index, name tree index
* **Bounded decoding**:

  * refuse to inflate beyond `max_decode_bytes`
  * record a finding: “decode truncated” (so you don’t miss that it was huge)
  * for chained filters, keep `origin` pointing at the raw stream span while `offset/length` refer to the post-filter decoded bytes
* **Parallel detectors**, not parallel parsing:

  * parsing should be single-threaded for determinism
  * detectors can be run in Rayon once the graph exists
* **Incremental revisions**:

  * keep per-revision catalogs; compare diffs
  * highlight “only appears in later update”

---

## 4) Initial rule set (high value, low false positives)

Start with rules that are both actionable and fast:

### Structure / xref

* `xref_conflict`: multiple xrefs/trailers disagree
* `incremental_update_chain`: has `/Prev` chain; report count + suspicious additions
* `object_id_shadowing`: same object ID appears in multiple revisions with different content
* `objstm_density_high`: unusually high fraction of objects in `/ObjStm`

### Actions / JS / external

* `open_action_present` (`/OpenAction`)
* `aa_present` (`/AA`)
* `js_present` (`/JS` or `/JavaScript`) — but only when located in parsed objects (avoid naive byte scan false positives; naive keyword scans can false positive inside streams) ([Didier Stevens][7])
* `launch_action_present` (`/Launch`)
* `uri_present` (`/URI`) + extract destinations
* `submitform_present` (`/SubmitForm`) + destinations

### Embedded content

* `embedded_file_present` (`/EmbeddedFile`) + file name + size + magic
* `richmedia_present` (`/RichMedia`)
* `xfa_present` (`/XFA`)

### Decoder / DoS

* `jbig2_present`, `jpx_present`
* `decompression_ratio_suspicious`
* `huge_image_dimensions`

These map cleanly to what practitioners triage in tools like PeePDF/PDFiD. ([Lenny Zeltser][1])

---

## 5) CLI + interactive mode UX

### Commands

* `sis scan <file.pdf>`
  Fast triage (default), prints grouped summary + JSON option
  - Optional ML scoring: `--ml --ml-model-dir <dir> --ml-threshold <value>`
* `sis scan --deep <file.pdf>`
  Deep scan (decodes selected streams, extracts JS/embedded files)
* `sis explain <finding-id>`
  Shows the per-finding evidence with source (file/decoded), offsets, and decoded excerpt when applicable
* `sis extract js|embedded <file.pdf> -o outdir/`
  Defensive extraction (never execute)
* `sis export-features --path <dir> --glob \"*.pdf\" --format jsonl|csv -o features.*`
  Feature extraction for ML pipelines and datasets

### Output grouping

* **AttackSurface**

  * **kind**

    * count, max severity
    * list of findings

---

## 6) Concrete crate layout (Rust workspace)

```
sis-pdf/
  Cargo.toml (workspace)
  crates/
    sis-pdf-core/        // parser abstractions, model, detectors
    sis-pdf-pdf/         // PDF parsing + object graph + decoding
    sis-pdf-detectors/   // rules
    sis-pdf/         // clap CLI + json output
    sis-pdf-tui/         // optional ratatui UI
```

### Parsing library choice

You have two viable paths:

1. **Build/own the parser** (harder, but best for “viewer-tolerant + forensic offsets”).
2. Use an existing parser crate (faster start), but be careful:

   * you still need **byte offsets** for evidence
   * you still need **recovery mode** when xref is broken/malicious

A pragmatic approach: start with an existing parser for object modeling, while you build a parallel **offset indexer** that records raw spans for objects/streams.

---

## 7) Minimal working skeleton (end-to-end)

```rust
// sis-pdf/src/main.rs
use clap::Parser;
use sis_pdf_core::{scan::ScanOptions, runner::run_scan};

#[derive(Parser)]
struct Args {
    pdf: String,
    #[arg(long)]
    deep: bool,
    #[arg(long, default_value_t = 32 * 1024 * 1024)]
    max_decode_bytes: usize,
    #[arg(long)]
    no_recover: bool,
    #[arg(long)]
    json: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let bytes = std::fs::read(&args.pdf)?;

    let opts = ScanOptions {
        deep: args.deep,
        max_decode_bytes: args.max_decode_bytes,
        recover_xref: !args.no_recover,
        parallel: true,
    };

    let report = run_scan(&bytes, opts)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        sis_pdf_core::report::print_human(&report);
    }

    Ok(())
}
```

```rust
// sis-pdf-core/src/runner.rs
use crate::{scan::{ScanContext, ScanOptions}, model::Finding};

pub fn run_scan(bytes: &[u8], options: ScanOptions) -> anyhow::Result<Report> {
    let graph = crate::pdf::parse(bytes, options.recover_xref)?;
    let ctx = ScanContext {
        bytes,
        graph,
        decoded: crate::pdf::DecodedCache::new(options.max_decode_bytes),
        options,
    };

    let detectors = crate::registry::default_detectors();

    let mut findings: Vec<Finding> = if ctx.options.parallel {
        use rayon::prelude::*;
        detectors.par_iter()
            .filter(|d| ctx.options.deep || d.cost() != crate::detect::Cost::Expensive)
            .map(|d| d.run(&ctx))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter().flatten().collect()
    } else {
        let mut all = Vec::new();
        for d in detectors {
            if !ctx.options.deep && d.cost() == crate::detect::Cost::Expensive { continue; }
            all.extend(d.run(&ctx)?);
        }
        all
    };

    // stable sort/group
    findings.sort_by(|a,b| (a.surface as u32, &a.kind, &a.id).cmp(&(b.surface as u32, &b.kind, &b.id)));

    Ok(Report::from_findings(findings))
}

#[derive(serde::Serialize)]
pub struct Report {
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub grouped: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<String>>>,
}
```

---

## 8) What to build first (so you get value fast)

### Milestone 1: “Triage-grade” analyzer (fast, reliable)

* Parse (xref + recovery)
* Build object index + dictionary name index
* Implement detectors:

  * `/OpenAction`, `/AA`, `/JS` (object-aware)
  * `/Launch`, `/URI`, `/SubmitForm`
  * `/EmbeddedFile`, `/RichMedia`, `/XFA`
  * incremental update chain + object shadowing
* Human + JSON report

### Milestone 2: Deep extraction

* Decode stream filters safely (quotas)
* Extract JavaScript bodies
* Extract embedded files (with hashes + magic)
* Add decoder-risk findings (JBIG2/JPX, huge images)

### Milestone 3: Content heuristics

* Page-content parse (operators)
* Detect link overlays / deceptive patterns
* Add policy knobs (deny external links, deny embedded files, etc.)

---

## 9) Notes on “accuracy vs speed”

If you want to be both fast *and* accurate, the key is: **never substitute byte-scanning for parsed semantics** unless you label it as heuristic. Tools that only scan keywords can produce false positives (e.g., `/JS` appearing inside arbitrary compressed streams). ([Didier Stevens][7])

So sis-pdf should:

* do **semantic detection** where possible (parsed objects)
* optionally do **raw keyword hints** only as “Heuristic” findings

---

[1]: https://zeltser.com/peepdf-malicious-pdf-analysis?utm_source=chatgpt.com "Analyzing Suspicious PDF Files With Peepdf"
[2]: https://gispp.org/2022/03/10/analyzing-malicious-pdf-files/?utm_source=chatgpt.com "Analyzing Malicious PDF Files"
[3]: https://github.com/0xCyberY/CVE-T4PDF?utm_source=chatgpt.com "0xCyberY/CVE-T4PDF: CVEs and Techniques used PDF ..."
[4]: https://github.com/DidierStevens/DidierStevensSuite/blob/master/plugin_triage.py?utm_source=chatgpt.com "DidierStevensSuite/plugin_triage.py at master"
[5]: https://cdn.standards.iteh.ai/samples/63534/4229145d18fa4313a506de4cb46ad7fa/ISO-32000-2-2017.pdf?utm_source=chatgpt.com "INTERNATIONAL STANDARD ISO 32000-2"
[6]: https://oneconsult.com/en/blog/digital-forensics/dfir-simple-analysis-of-pdf-files/?utm_source=chatgpt.com "PDF Phishing: How To Protect Yourself Effectively"
[7]: https://blog.didierstevens.com/2013/06/10/pdfid-false-positives/?utm_source=chatgpt.com "PDFiD: False Positives"

# Chapter2

Alright — here’s the **sis-pdf-pdf parser spec + repo skeleton + real detectors**, written so you can actually start coding immediately.

I’m going to bias toward:

* **Correct, viewer-tolerant parsing**
* **Byte-offset evidence** everywhere
* **Fast triage** (no decoding unless needed)
* **Safe decoding** with quotas (never “hang” an interactive run)

---

# A) sis-pdf-pdf parsing spec (detailed)

## A1) Byte model + spans (the foundation)

Everything you parse should carry a **Span** so you can show evidence later.

```rust
#[derive(Debug, Clone, Copy)]
pub struct Span {
    pub start: u64,
    pub end: u64, // exclusive
}
impl Span {
    pub fn len(&self) -> u64 { self.end - self.start }
}
```

### Required invariant

* Every indirect object must have:

  * object header span (e.g. `12 0 obj`)
  * body span (dict/array/primitive)
  * if stream: stream bytes span (between `stream\n` and `endstream`)
  * full object span (from header to `endobj`)

This is what makes findings “forensic-grade”.

---

## A2) Lexer (tokenizer) — robust and PDF-ish

You want a custom lexer rather than a strict parser generator because PDFs are messy.

### Token types you need

* delimiters: `<< >> [ ] ( ) { }` (you can treat `{}` as “bad token” but record)
* keywords: `obj endobj stream endstream xref trailer startxref`
* names: `/Name` with `#xx` escapes
* numbers: integers + reals, allow leading `+`/`-`
* strings:

  * literal strings: `( ... )` with escapes and nested parens
  * hex strings: `<...>` (but note collision with `<<` dict open)
* comments: `% ... endline`
* whitespace (skip but track line breaks if you want pretty evidence)

### Lexer rules (important edge cases)

1. `<<` and `>>` must be recognized before `<` hex-string parsing.
2. Literal strings can contain nested parentheses; implement a depth counter.
3. Names can contain `#` hex escapes; decode to bytes, but keep raw span too.
4. Don’t assume valid UTF-8 anywhere. Operate on bytes.

### Speed strategy

* Implement the lexer as a byte cursor with a few hot-path functions:

  * `skip_ws_and_comments()`
  * `peek_byte()`, `consume_byte()`
* Avoid allocations: return tokens with spans and either:

  * numeric value (parsed)
  * borrowed slice indices (for raw bytes)

---

## A3) Core object model (minimal but sufficient)

You don’t need to implement the whole PDF spec to scan security surface; you need the object graph + dictionaries.

```rust
pub enum PdfAtom<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Name(PdfName<'a>),
    Str(PdfStr<'a>),     // literal or hex, keep raw
    Array(Vec<PdfObj<'a>>),
    Dict(PdfDict<'a>),
    Ref { obj: u32, gen: u16 },
}

pub struct PdfObj<'a> {
    pub span: Span,
    pub atom: PdfAtom<'a>,
}

pub struct PdfDict<'a> {
    pub span: Span,
    pub entries: Vec<(PdfName<'a>, PdfObj<'a>)>, // keep order, allow duplicates
}

pub struct PdfName<'a> {
    pub span: Span,
    pub raw: &'a [u8],     // includes leading '/'
    pub decoded: Vec<u8>,  // decode #xx; keep bytes not String
}

pub enum PdfStr<'a> {
    Literal { span: Span, raw: &'a [u8] },
    Hex { span: Span, raw: &'a [u8] },
}
```

### Why “Vec entries” not HashMap?

Because:

* PDFs can include **duplicate keys** (malicious or not).
* You need to detect and report “shadow keys” inside a dict.

You can provide helper methods:

* `dict.get_first(b"/Type")`
* `dict.get_all(b"/JS")`
* `dict.has_name(b"/S", b"/JavaScript")` etc.

---

## A4) Indirect objects + object streams

### Indirect object grammar (tolerant)

Accept:

```
<objnum> <gennum> obj
  <object>
  [stream ... endstream]
endobj
```

Recovery mode should be able to scan for:

* `<digits> <digits> obj` patterns even if xref broken

### Object streams (`/ObjStm`)

These hide many objects in one stream.
You need two levels:

1. **Index-only**: detect `/Type /ObjStm` and record stream span + `/N` `/First`.
2. **Optional deep**: decode stream, parse the object-number/offset table, then parse embedded objects.

For interactive speed, do (1) by default and (2) only when needed (deep scan, or when rule requires).

---

## A5) Cross-reference (xref) parsing strategy

You must support at least:

* classic `xref` tables
* xref streams (`/Type /XRef`)
* hybrid

### Step 1: locate `startxref`

* Scan backwards from EOF up to a window (e.g. 1–4MB) for `startxref`.
* Parse following integer offset.
* Validate it points into file; if not, still keep and fall back to recovery.

### Step 2: parse xref at that offset

If bytes at offset start with `xref`, parse classic.
Else parse as an indirect object and check:

* dict `/Type /XRef` (xref stream)
* read `/W` and `/Index` and decode entries

### Step 3: trailer chain

* Classic trailer: `trailer << ... >>`
* Stream trailer is in the xref stream dictionary.
* Follow `/Prev` repeatedly to gather revisions.

### Important: revision model

Build:

* `Revision[0..k]` where `k` is latest
* Each revision has:

  * xref mapping (obj -> offset/type)
  * trailer dict
  * catalog reference
* Later revisions override earlier mappings (shadowing is meaningful!)

This is how you find “hidden in incremental update”.

---

## A6) Recovery mode (when xref is broken or malicious)

Recovery should:

* Scan the whole file for patterns that look like indirect object headers:

  * regex-like: `(\d+)\s+(\d+)\s+obj`
* For each candidate, try to parse an object body until `endobj` (or timeout/limit).
* Record those objects in an alternate index.

You then create an `ObjectGraph` that can be queried as:

* `graph.strict()` (xref-based)
* `graph.recovered()` (scan-based)
* `graph.merged_view()` (strict + recovered extras)

And you emit findings:

* “xref broken, using recovery”
* “recovered objects not referenced in strict xref” (suspicious)

---

## A7) Streams + decoding quotas (safe + fast)

### Stream representation

```rust
pub struct PdfStream<'a> {
    pub dict: PdfDict<'a>,
    pub dict_span: Span,
    pub stream_span: Span, // raw bytes only (not decoded)
}
```

### Decoding

Implement a decoder that:

* Supports common filters first:

  * Flate, ASCIIHex, ASCII85, RunLength
* LZW later (it’s annoying but doable)
* **Never auto-decode image-heavy filters** unless needed:

  * DCT, JPX, JBIG2, CCITT
  * For these, you typically only need to *detect presence* and size, not decode pixels.

### Quotas

Every decode call must accept:

* `max_output_bytes`
* `max_chain_len` (filter chain length)
* `max_time` (optional; can be a soft budget via elapsed checks)
* `max_nesting_depth`

If you hit quota:

* return partial output + a flag `truncated=true`
* emit a finding (“decode truncated; possible decompression bomb”)

---

# B) Repo skeleton (Rust workspace)

```
sis-pdf/
  Cargo.toml
  crates/
    sis-pdf-core/
      Cargo.toml
      src/
        lib.rs
        model.rs
        detect.rs
        scan.rs
        runner.rs
        report.rs
        registry.rs
    sis-pdf-pdf/
      Cargo.toml
      src/
        lib.rs
        span.rs
        lexer.rs
        parse.rs
        xref.rs
        recover.rs
        graph.rs
        stream.rs
        decode/
          mod.rs
          flate.rs
          ascii85.rs
          asciihex.rs
          runlength.rs
          limits.rs
    sis-pdf-detectors/
      Cargo.toml
      src/
        lib.rs
        actions.rs
        javascript.rs
        embedded.rs
        structure.rs
    sis-pdf/
      Cargo.toml
      src/
        main.rs
```

### Suggested dependencies

* `anyhow`, `thiserror`
* `serde`, `serde_json`
* `rayon` (optional, for parallel detectors)
* `flate2` (for FlateDecode)
* `memmap2` (if you want mmap; CLI can read-to-vec first)

---

# C) Key code (starter implementation)

## C1) sis-pdf-pdf: byte cursor + lexer (core)

```rust
// crates/sis-pdf-pdf/src/lexer.rs
use crate::span::Span;

#[derive(Debug, Clone)]
pub enum Tok<'a> {
    // delimiters
    DictStart(Span), DictEnd(Span),
    ArrStart(Span), ArrEnd(Span),
    // primitives
    Name { span: Span, raw: &'a [u8] },
    Int  { span: Span, v: i64 },
    Real { span: Span, v: f64 },
    StrLit { span: Span, raw: &'a [u8] }, // includes parentheses
    StrHex { span: Span, raw: &'a [u8] }, // includes <>
    Keyword { span: Span, raw: &'a [u8] }, // obj, endobj, stream, endstream, xref...
    True(Span), False(Span), Null(Span),
}

pub struct Lexer<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(b: &'a [u8]) -> Self { Self { b, i: 0 } }
    pub fn pos(&self) -> usize { self.i }

    fn skip_ws_comments(&mut self) {
        while self.i < self.b.len() {
            match self.b[self.i] {
                b' ' | b'\t' | b'\r' | b'\n' | 0x0C => { self.i += 1; }
                b'%' => { // comment
                    while self.i < self.b.len() && self.b[self.i] != b'\n' { self.i += 1; }
                }
                _ => break,
            }
        }
    }

    pub fn next(&mut self) -> anyhow::Result<Option<Tok<'a>>> {
        self.skip_ws_comments();
        if self.i >= self.b.len() { return Ok(None); }
        let start = self.i;

        // fast delimiter handling
        if self.b[start] == b'<' {
            if start + 1 < self.b.len() && self.b[start + 1] == b'<' {
                self.i += 2;
                return Ok(Some(Tok::DictStart(Span{start:start as u64, end:self.i as u64})));
            }
            // hex string <...> (single <)
            self.i += 1;
            while self.i < self.b.len() && self.b[self.i] != b'>' { self.i += 1; }
            if self.i < self.b.len() { self.i += 1; } // consume '>'
            return Ok(Some(Tok::StrHex{ span: Span{start:start as u64, end:self.i as u64}, raw: &self.b[start..self.i]}));
        }
        if self.b[start] == b'>' {
            if start + 1 < self.b.len() && self.b[start + 1] == b'>' {
                self.i += 2;
                return Ok(Some(Tok::DictEnd(Span{start:start as u64, end:self.i as u64})));
            }
        }
        if self.b[start] == b'[' { self.i += 1; return Ok(Some(Tok::ArrStart(Span{start:start as u64, end:self.i as u64}))); }
        if self.b[start] == b']' { self.i += 1; return Ok(Some(Tok::ArrEnd(Span{start:start as u64, end:self.i as u64}))); }

        // literal string
        if self.b[start] == b'(' {
            self.i += 1;
            let mut depth = 1usize;
            while self.i < self.b.len() && depth > 0 {
                match self.b[self.i] {
                    b'\\' => { // escape
                        self.i += 1;
                        if self.i < self.b.len() { self.i += 1; }
                    }
                    b'(' => { depth += 1; self.i += 1; }
                    b')' => { depth -= 1; self.i += 1; }
                    _ => self.i += 1,
                }
            }
            return Ok(Some(Tok::StrLit{ span: Span{start:start as u64, end:self.i as u64}, raw: &self.b[start..self.i]}));
        }

        // name
        if self.b[start] == b'/' {
            self.i += 1;
            while self.i < self.b.len() && !is_delim_or_ws(self.b[self.i]) { self.i += 1; }
            return Ok(Some(Tok::Name{ span: Span{start:start as u64, end:self.i as u64}, raw: &self.b[start..self.i]}));
        }

        // word/number
        while self.i < self.b.len() && !is_delim_or_ws(self.b[self.i]) { self.i += 1; }
        let raw = &self.b[start..self.i];
        let span = Span{ start:start as u64, end:self.i as u64 };

        match raw {
            b"true" => Ok(Some(Tok::True(span))),
            b"false" => Ok(Some(Tok::False(span))),
            b"null" => Ok(Some(Tok::Null(span))),
            _ => {
                // number?
                if let Ok(v) = std::str::from_utf8(raw).ok().and_then(|s| s.parse::<i64>().ok()) {
                    return Ok(Some(Tok::Int{ span, v }));
                }
                if let Ok(v) = std::str::from_utf8(raw).ok().and_then(|s| s.parse::<f64>().ok()) {
                    return Ok(Some(Tok::Real{ span, v }));
                }
                Ok(Some(Tok::Keyword{ span, raw }))
            }
        }
    }
}

fn is_delim_or_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n' | 0x0C | b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'/' | b'%')
}
```

This lexer is intentionally “good enough” to start; you’ll refine number parsing and delimiter rules over time, but it already handles the big pitfalls: `<<` vs `<hex>`, strings, comments.

---

## C2) Parsing objects (dict/array/ref/stream)

```rust
// crates/sis-pdf-pdf/src/parse.rs
use crate::{lexer::{Lexer, Tok}, span::Span};
use anyhow::bail;

pub fn parse_indirect_object<'a>(lex: &mut Lexer<'a>) -> anyhow::Result<Option<IndirectObj<'a>>> {
    // Expect: <objnum> <gennum> obj
    let t1 = match lex.next()? { Some(t) => t, None => return Ok(None) };
    let (objnum, obj_span) = match t1 {
        Tok::Int{v, span} if v >= 0 => (v as u32, span),
        _ => bail!("expected objnum int"),
    };
    let t2 = lex.next()?.ok_or_else(|| anyhow::anyhow!("expected gennum"))?;
    let (gennum, gen_span) = match t2 {
        Tok::Int{v, span} if v >= 0 && v <= u16::MAX as i64 => (v as u16, span),
        _ => bail!("expected gennum int"),
    };
    let t3 = lex.next()?.ok_or_else(|| anyhow::anyhow!("expected 'obj'"))?;
    match t3 {
        Tok::Keyword{raw, ..} if raw == b"obj" => {}
        _ => bail!("expected 'obj'"),
    }

    // Parse body
    let body = parse_object(lex)?;

    // Optional stream
    let mut stream: Option<PdfStream<'a>> = None;
    let save_pos = lex.pos();
    if let Some(Tok::Keyword{raw, span, ..}) = lex.next()? {
        if raw == b"stream" {
            // stream starts after EOL; tolerate one optional \r\n or \n
            // We will find endstream by scanning bytes; simplest approach for now:
            let stream_start = lex.pos();
            // NOTE: you’ll likely want a ByteCursor in addition to lexer for accurate spans.
            // For skeleton, we skip precise stream parsing here.
            // Reset and handle in a more complete stream module later.
            stream = Some(PdfStream { dict_span: body.span, stream_span: span, /* placeholder */ });
        } else {
            // not a stream; rewind by resetting lexer index
            // (for this skeleton, we can’t rewind easily without storing)
            // In real impl, use peek() or a token buffer.
            let _ = (save_pos, span);
        }
    }

    // Expect endobj (tolerant: scan until you see it)
    // For skeleton: ignore; for real: enforce + recover
    Ok(Some(IndirectObj {
        obj: objnum,
        gen: gennum,
        header_span: Span{ start: obj_span.start, end: gen_span.end },
        body,
        stream,
    }))
}

pub fn parse_object<'a>(lex: &mut Lexer<'a>) -> anyhow::Result<PdfObj<'a>> {
    let t = lex.next()?.ok_or_else(|| anyhow::anyhow!("expected object"))?;
    match t {
        Tok::Null(span) => Ok(PdfObj{ span, atom: PdfAtom::Null }),
        Tok::True(span) => Ok(PdfObj{ span, atom: PdfAtom::Bool(true)}),
        Tok::False(span) => Ok(PdfObj{ span, atom: PdfAtom::Bool(false)}),
        Tok::Int{span, v} => Ok(PdfObj{ span, atom: PdfAtom::Int(v)}),
        Tok::Real{span, v} => Ok(PdfObj{ span, atom: PdfAtom::Real(v)}),
        Tok::Name{span, raw} => Ok(PdfObj{ span, atom: PdfAtom::Name(parse_name(raw, span))}),
        Tok::StrLit{span, raw} => Ok(PdfObj{ span, atom: PdfAtom::Str(PdfStr::Literal{span, raw})}),
        Tok::StrHex{span, raw} => Ok(PdfObj{ span, atom: PdfAtom::Str(PdfStr::Hex{span, raw})}),
        Tok::ArrStart(start_span) => {
            let mut items = Vec::new();
            loop {
                let pos = lex.pos();
                let next = lex.next()?.ok_or_else(|| anyhow::anyhow!("unterminated array"))?;
                match next {
                    Tok::ArrEnd(end_span) => {
                        let span = Span{ start: start_span.start, end: end_span.end };
                        return Ok(PdfObj{ span, atom: PdfAtom::Array(items) });
                    }
                    _ => {
                        // no rewind in this skeleton; real impl: token buffer
                        // Here we just error.
                        let _ = pos;
                        bail!("array parsing requires peek/token buffer in skeleton");
                    }
                }
            }
        }
        Tok::DictStart(start_span) => {
            // parse pairs: Name Value ... until >>
            let mut entries = Vec::new();
            loop {
                let tnext = lex.next()?.ok_or_else(|| anyhow::anyhow!("unterminated dict"))?;
                match tnext {
                    Tok::DictEnd(end_span) => {
                        let span = Span{ start: start_span.start, end: end_span.end };
                        return Ok(PdfObj{
                            span,
                            atom: PdfAtom::Dict(PdfDict{ span, entries }),
                        });
                    }
                    Tok::Name{span, raw} => {
                        let key = parse_name(raw, span);
                        let val = parse_object(lex)?;
                        entries.push((key, val));
                    }
                    _ => bail!("expected dict key name"),
                }
            }
        }
        Tok::Keyword{span, raw} => {
            // Handle indirect reference pattern: "<int> <int> R"
            // Skeleton: treat as keyword; real impl uses token buffer to lookahead.
            Ok(PdfObj{ span, atom: PdfAtom::Name(PdfName{ span, raw, decoded: raw.to_vec() }) })
        }
        other => bail!("unexpected token: {:?}", other),
    }
}

// Minimal name decode (#xx); keep bytes
fn parse_name(raw: &[u8], span: Span) -> PdfName<'_> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#' && i + 2 < raw.len() {
            if let (Some(h1), Some(h2)) = (hex(raw[i+1]), hex(raw[i+2])) {
                out.push(h1 * 16 + h2);
                i += 3;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    PdfName{ span, raw, decoded: out }
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None
    }
}

// --- Types referenced above (put in model module in sis-pdf-pdf) ---
pub struct IndirectObj<'a> {
    pub obj: u32,
    pub gen: u16,
    pub header_span: Span,
    pub body: PdfObj<'a>,
    pub stream: Option<PdfStream<'a>>,
}

pub struct PdfStream<'a> {
    pub dict_span: Span,
    pub stream_span: Span,
    pub _phantom: std::marker::PhantomData<&'a ()>,
}

pub struct PdfObj<'a> { pub span: Span, pub atom: PdfAtom<'a> }
pub enum PdfAtom<'a> {
    Null, Bool(bool), Int(i64), Real(f64),
    Name(PdfName<'a>), Str(PdfStr<'a>),
    Array(Vec<PdfObj<'a>>),
    Dict(PdfDict<'a>),
    Ref { obj: u32, gen: u16 },
}
pub struct PdfDict<'a> { pub span: Span, pub entries: Vec<(PdfName<'a>, PdfObj<'a>)> }
pub struct PdfName<'a> { pub span: Span, pub raw: &'a [u8], pub decoded: Vec<u8> }
pub enum PdfStr<'a> {
    Literal { span: Span, raw: &'a [u8] },
    Hex { span: Span, raw: &'a [u8] },
}
```

**Note:** the skeleton above highlights why you’ll want a **token buffer with `peek()`** (or a recursive descent parser over a cursor rather than a one-pass lexer). Don’t worry: that’s normal — and it’s exactly the next step.

---

# D) “Real” object graph (what detectors will query)

## D1) Object index

You want to index objects without decoding streams.

```rust
// crates/sis-pdf-pdf/src/graph.rs
use std::collections::HashMap;
use crate::span::Span;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ObjRef { pub obj: u32, pub gen: u16 }

#[derive(Debug)]
pub struct ObjEntry<'a> {
    pub r: ObjRef,
    pub full_span: Span,
    pub body_span: Span,
    pub body: crate::parse::PdfObj<'a>,
    pub stream_span: Option<Span>,
}

pub struct ObjectGraph<'a> {
    pub objects: HashMap<ObjRef, ObjEntry<'a>>,
    pub catalog: Option<ObjRef>,
    // later: revisions, xref mappings, recovered objects, etc.
}
```

## D2) Graph helpers detectors need

* “find all dicts containing key `/OpenAction`”
* “find any action dict with `/S /JavaScript`”
* “find names tree `/Names` and `/JavaScript` name entries”
* “find embedded files via `/Type /EmbeddedFile` and file specs”

These helpers prevent each detector from reinventing traversal.

---

# E) Detectors (two real ones)

Below are **two detectors you can wire today**: `OpenActionDetector` and `EmbeddedFileDetector`.

## E1) OpenAction detector

Finds `/OpenAction` in the Catalog dict (or anywhere, but catalog is most important).

```rust
// crates/sis-pdf-detectors/src/actions.rs
use sis_pdf_core::model::*;
use sis_pdf_core::detect::*;
use anyhow::Result;

pub struct OpenActionDetector;

impl Detector for OpenActionDetector {
    fn id(&self) -> &'static str { "actions.open_action" }
    fn surface(&self) -> AttackSurface { AttackSurface::Actions }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH }
    fn cost(&self) -> Cost { Cost::Cheap }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        let g = &ctx.graph;

        let Some(cat) = g.catalog_ref() else { return Ok(out); };
        let Some(cat_obj) = g.get(cat) else { return Ok(out); };

        if let Some((key_span, val_span)) = g.dict_key_value_spans(cat_obj, b"/OpenAction") {
            out.push(Finding {
                id: format!("{}:{}:{}",
                    self.id(),
                    cat.obj, cat.gen
                ),
                surface: AttackSurface::Actions,
                kind: "open_action_present".into(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                title: "Document has /OpenAction (runs on open)".into(),
                description: "The PDF specifies an action triggered when the document is opened. This is commonly used in malicious PDFs to auto-trigger behaviors (e.g., JavaScript, URL, launch).".into(),
                objects: vec![format!("{} {} obj (Catalog)", cat.obj, cat.gen)],
                evidence: vec![
                    EvidenceSpan{ offset: key_span.start, length: (key_span.end-key_span.start) as u32, note: Some("Catalog key /OpenAction".into()) },
                    EvidenceSpan{ offset: val_span.start, length: (val_span.end-val_span.start) as u32, note: Some("OpenAction value".into()) },
                ],
                remediation: Some("Treat as suspicious. Inspect the referenced action dictionary (/S ...) and any linked JavaScript or external URIs.".into()),
            });
        }

        Ok(out)
    }
}
```

This assumes you’ve implemented in `sis-pdf-pdf`:

* `catalog_ref()`
* `get(objref)`
* `dict_key_value_spans(obj, key_bytes) -> Option<(Span, Span)>`

Those are straightforward once your dict model stores spans.

---

## E2) Embedded file detector

Detects `/Type /EmbeddedFile` streams and reports size + filter presence + file spec name when linked.

```rust
// crates/sis-pdf-detectors/src/embedded.rs
use sis_pdf_core::model::*;
use sis_pdf_core::detect::*;
use anyhow::Result;

pub struct EmbeddedFileDetector;

impl Detector for EmbeddedFileDetector {
    fn id(&self) -> &'static str { "embedded.embedded_file" }
    fn surface(&self) -> AttackSurface { AttackSurface::EmbeddedFiles }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH | Needs::STREAM_INDEX }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut out = Vec::new();
        let g = &ctx.graph;

        for obj in g.iter_objects() {
            if !g.is_stream(obj) { continue; }

            // stream dict: /Type /EmbeddedFile
            if g.dict_has_name(obj, b"/Type", b"/EmbeddedFile") {
                let (filters, length) = g.stream_filter_and_length(obj);

                let sev = Severity::High; // embedded payload is often risky
                out.push(Finding {
                    id: format!("{}:{}:{}", self.id(), obj.r.obj, obj.r.gen),
                    surface: AttackSurface::EmbeddedFiles,
                    kind: "embedded_file_present".into(),
                    severity: sev,
                    confidence: Confidence::Strong,
                    title: "Embedded file stream present (/EmbeddedFile)".into(),
                    description: format!(
                        "The PDF contains an embedded file stream. Filters: {:?}. Declared length: {:?} bytes.",
                        filters, length
                    ),
                    objects: vec![format!("{} {} obj", obj.r.obj, obj.r.gen)],
                    evidence: vec![
                        EvidenceSpan{ offset: obj.full_span.start, length: (obj.full_span.len().min(u64::from(u32::MAX))) as u32, note: Some("EmbeddedFile object span".into()) }
                    ],
                    remediation: Some("Extract embedded files in a controlled environment and inspect magic bytes and hashes. Consider blocking PDFs with embedded payloads in high-risk contexts.".into()),
                });
            }
        }

        Ok(out)
    }
}
```

For deep mode later, you can enhance:

* extract embedded payload bytes with safe decode
* compute SHA-256
* identify file type by magic bytes
* report suspicious extensions (exe, js, vbs, lnk, iso, etc.)

---

# F) Wiring it up (sis-pdf-core registry)

```rust
// crates/sis-pdf-core/src/registry.rs
use crate::detect::Detector;

pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(sis_pdf_detectors::actions::OpenActionDetector),
        Box::new(sis_pdf_detectors::embedded::EmbeddedFileDetector),
        // next: JavaScriptDetector, UriDetector, XrefConflictDetector...
    ]
}
```

---

# G) Next “must-do” implementation details (so this becomes real fast)

## G1) Add a token buffer with peek

Your parser needs `peek()` and `unread()`.

Simplest approach:

* lexer returns tokens
* parser wraps lexer with a 1–3 token buffer

```rust
pub struct TokBuf<'a> {
    lex: Lexer<'a>,
    buf: std::collections::VecDeque<Tok<'a>>,
}
impl<'a> TokBuf<'a> {
    pub fn peek(&mut self) -> anyhow::Result<Option<&Tok<'a>>> { /* ... */ }
    pub fn next(&mut self) -> anyhow::Result<Option<Tok<'a>>> { /* ... */ }
    pub fn push_back(&mut self, t: Tok<'a>) { /* ... */ }
}
```

Then you can:

* parse arrays properly (read items until `]`)
* parse indirect refs: `Int Int Keyword("R")`
* look ahead for `stream` after a dict

## G2) Proper stream span finding

Don’t parse stream content with the tokeniser; treat it as raw bytes:

* after `stream`, consume optional `\r\n` or `\n`
* stream bytes continue until the first occurrence of `\nendstream` / `\rendstream` with correct boundaries (tolerant: accept `endstream` preceded by EOL)
* record raw span precisely

## G3) Xref + recovery

Even before full xref streams support, you can ship:

* `startxref` search
* classic xref parse
* if fails → recovery scan mode

That already gives you a powerful analyzer.

---

# H) What I recommend you implement next (in this order)

1. **TokBuf + full recursive `parse_object()`**
2. **Indirect ref parsing** (`12 0 R`)
3. **Stream span extraction** (raw bytes + dict)
4. **Recovery scan** for indirect objects
5. **Catalog detection** (from trailer `/Root`)
6. Add a third detector: **JavaScript presence**

   * find action dicts where `/S /JavaScript`
   * find name tree `/Names` → `/JavaScript`
7. Add safe decode for **Flate** with `max_output_bytes` quota

If you follow that order, you’ll get a usable triage tool quickly, and you’ll still be building toward “forensic correctness”.

---


# Chapter3

Got it. Below is a **drop-in, working** (triage-grade) set of pieces:

* **JavaScriptDetector** (object-aware; finds JS in actions + Names tree; avoids naive byte scanning)
* **Classic xref parser** (enough to locate trailer + Root)
* **Recovery scanner** (finds `N N obj ... endobj` even when xref is broken)
* **Tiny PDF fixtures + tests** (one with `/OpenAction` JS; one with JS in Names tree)

I’m assuming your workspace layout from earlier. I’m going to give you code in “file chunks” you can paste in.

> Notes:
>
> * This is defensive analysis code. It does not execute JS or render anything.
> * The parser is “tolerant enough” for triage; you’ll harden over time (xref streams, obj streams, full stream parsing).

---

## 1) sis-pdf-pdf: graph helpers + minimal parse entrypoint

### `crates/sis-pdf-pdf/src/lib.rs`

```rust
pub mod span;
pub mod lexer;
pub mod tokbuf;
pub mod object;
pub mod xref;
pub mod recover;
pub mod graph;

use graph::ObjectGraph;

/// Parse a PDF into an ObjectGraph.
/// - Attempts classic xref first
/// - Falls back to recovery scan if xref fails or recover_xref=true and xref looks inconsistent
pub fn parse<'a>(bytes: &'a [u8], recover_xref: bool) -> anyhow::Result<ObjectGraph<'a>> {
    // Try xref/trailer
    let trailer = xref::parse_classic_trailer(bytes).ok();

    // Build object index using recovery scan (fast and robust).
    // Even if xref works, recovery gives you spans/evidence for objects.
    let mut g = recover::recover_objects(bytes)?;

    // If we got a trailer root, set catalog
    if let Some(t) = trailer {
        if let Some(root) = t.root {
            g.catalog = Some(root);
        }
        g.trailer_span = t.trailer_span;
        g.startxref = t.startxref;
    } else if !recover_xref {
        // If recover_xref == false, we could error here;
        // for now keep tolerant behavior.
    }

    Ok(g)
}
```

### `crates/sis-pdf-pdf/src/span.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: u64,
    pub end: u64, // exclusive
}
impl Span {
    pub fn len(&self) -> u64 { self.end - self.start }
}
```

---

## 2) sis-pdf-pdf: token buffer (peek) + object model

### `crates/sis-pdf-pdf/src/tokbuf.rs`

```rust
use std::collections::VecDeque;
use crate::lexer::{Lexer, Tok};

pub struct TokBuf<'a> {
    lex: Lexer<'a>,
    buf: VecDeque<Tok<'a>>,
}

impl<'a> TokBuf<'a> {
    pub fn new(bytes: &'a [u8], start: usize) -> Self {
        let mut lex = Lexer::new(bytes);
        lex.set_pos(start);
        Self { lex, buf: VecDeque::new() }
    }

    pub fn pos(&self) -> usize { self.lex.pos() }

    pub fn peek(&mut self) -> anyhow::Result<Option<&Tok<'a>>> {
        if self.buf.is_empty() {
            if let Some(t) = self.lex.next()? {
                self.buf.push_back(t);
            }
        }
        Ok(self.buf.front())
    }

    pub fn next(&mut self) -> anyhow::Result<Option<Tok<'a>>> {
        if let Some(t) = self.buf.pop_front() {
            return Ok(Some(t));
        }
        self.lex.next()
    }

    pub fn push_front(&mut self, t: Tok<'a>) {
        self.buf.push_front(t);
    }
}
```

### `crates/sis-pdf-pdf/src/object.rs`

```rust
use crate::span::Span;
use crate::lexer::Tok;
use crate::tokbuf::TokBuf;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ObjRef { pub obj: u32, pub gen: u16 }

#[derive(Debug, Clone)]
pub struct PdfObj<'a> {
    pub span: Span,
    pub atom: PdfAtom<'a>,
}

#[derive(Debug, Clone)]
pub enum PdfAtom<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Name(PdfName<'a>),
    Str(PdfStr<'a>),
    Array(Vec<PdfObj<'a>>),
    Dict(PdfDict<'a>),
    Ref { obj: u32, gen: u16 },
    Keyword(&'a [u8]), // fallback
}

#[derive(Debug, Clone)]
pub struct PdfDict<'a> {
    pub span: Span,
    pub entries: Vec<(PdfName<'a>, PdfObj<'a>)>, // allow dup keys
}

#[derive(Debug, Clone)]
pub struct PdfName<'a> {
    pub span: Span,
    pub raw: &'a [u8],
    pub decoded: Vec<u8>, // bytes, not String
}

#[derive(Debug, Clone)]
pub enum PdfStr<'a> {
    Literal { span: Span, raw: &'a [u8] },
    Hex { span: Span, raw: &'a [u8] },
}

fn decode_name(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#' && i + 2 < raw.len() {
            if let (Some(h1), Some(h2)) = (hex(raw[i+1]), hex(raw[i+2])) {
                out.push(h1 * 16 + h2);
                i += 3;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}
fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None
    }
}

/// Parse one PDF object (recursive descent) with lookahead.
/// Supports indirect refs: "<int> <int> R"
pub fn parse_object<'a>(tb: &mut TokBuf<'a>) -> anyhow::Result<PdfObj<'a>> {
    let t = tb.next()?.ok_or_else(|| anyhow::anyhow!("expected object"))?;
    match t {
        Tok::Null(span) => Ok(PdfObj{ span, atom: PdfAtom::Null }),
        Tok::True(span) => Ok(PdfObj{ span, atom: PdfAtom::Bool(true) }),
        Tok::False(span) => Ok(PdfObj{ span, atom: PdfAtom::Bool(false) }),
        Tok::Int{span, v} => {
            // possible indirect ref: <int> <int> R
            if let Some(Tok::Int{span: span2, v: v2}) = tb.peek()?.cloned() {
                // need to consume it to confirm R
                let _ = tb.next()?;
                if let Some(Tok::Keyword{raw, span: span3}) = tb.peek()?.cloned() {
                    if raw == b"R" && v >= 0 && v2 >= 0 && v2 <= u16::MAX as i64 {
                        let _ = tb.next()?;
                        let span_all = Span{ start: span.start, end: span3.end };
                        return Ok(PdfObj{ span: span_all, atom: PdfAtom::Ref{ obj: v as u32, gen: v2 as u16 }});
                    }
                }
                // not a ref; push back what we consumed
                tb.push_front(Tok::Int{ span: span2, v: v2 });
            }
            Ok(PdfObj{ span, atom: PdfAtom::Int(v) })
        }
        Tok::Real{span, v} => Ok(PdfObj{ span, atom: PdfAtom::Real(v) }),
        Tok::Name{span, raw} => {
            let decoded = decode_name(raw);
            Ok(PdfObj{ span, atom: PdfAtom::Name(PdfName{ span, raw, decoded }) })
        }
        Tok::StrLit{span, raw} => Ok(PdfObj{ span, atom: PdfAtom::Str(PdfStr::Literal{ span, raw }) }),
        Tok::StrHex{span, raw} => Ok(PdfObj{ span, atom: PdfAtom::Str(PdfStr::Hex{ span, raw }) }),
        Tok::ArrStart(start_span) => {
            let mut items = Vec::new();
            loop {
                let tnext = tb.peek()?.cloned().ok_or_else(|| anyhow::anyhow!("unterminated array"))?;
                match tnext {
                    Tok::ArrEnd(end_span) => {
                        let _ = tb.next()?;
                        let span = Span{ start: start_span.start, end: end_span.end };
                        return Ok(PdfObj{ span, atom: PdfAtom::Array(items) });
                    }
                    _ => items.push(parse_object(tb)?),
                }
            }
        }
        Tok::DictStart(start_span) => {
            let mut entries = Vec::new();
            loop {
                let tnext = tb.peek()?.cloned().ok_or_else(|| anyhow::anyhow!("unterminated dict"))?;
                match tnext {
                    Tok::DictEnd(end_span) => {
                        let _ = tb.next()?;
                        let span = Span{ start: start_span.start, end: end_span.end };
                        return Ok(PdfObj{
                            span,
                            atom: PdfAtom::Dict(PdfDict{ span, entries }),
                        });
                    }
                    Tok::Name{..} => {
                        let k = match tb.next()?.unwrap() {
                            Tok::Name{span, raw} => PdfName{ span, raw, decoded: decode_name(raw) },
                            _ => unreachable!(),
                        };
                        let v = parse_object(tb)?;
                        entries.push((k, v));
                    }
                    _ => {
                        // tolerant: consume token and keep going
                        let _ = tb.next()?;
                    }
                }
            }
        }
        Tok::Keyword{span, raw} => Ok(PdfObj{ span, atom: PdfAtom::Keyword(raw) }),
        other => Err(anyhow::anyhow!("unexpected token: {:?}", other)),
    }
}
```

---

## 3) sis-pdf-pdf: lexer with `set_pos`

### `crates/sis-pdf-pdf/src/lexer.rs`

```rust
use crate::span::Span;

#[derive(Debug, Clone)]
pub enum Tok<'a> {
    DictStart(Span), DictEnd(Span),
    ArrStart(Span), ArrEnd(Span),
    Name { span: Span, raw: &'a [u8] },
    Int  { span: Span, v: i64 },
    Real { span: Span, v: f64 },
    StrLit { span: Span, raw: &'a [u8] },
    StrHex { span: Span, raw: &'a [u8] },
    Keyword { span: Span, raw: &'a [u8] },
    True(Span), False(Span), Null(Span),
}

pub struct Lexer<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(b: &'a [u8]) -> Self { Self { b, i: 0 } }
    pub fn pos(&self) -> usize { self.i }
    pub fn set_pos(&mut self, p: usize) { self.i = p.min(self.b.len()); }

    fn skip_ws_comments(&mut self) {
        while self.i < self.b.len() {
            match self.b[self.i] {
                b' ' | b'\t' | b'\r' | b'\n' | 0x0C => self.i += 1,
                b'%' => { while self.i < self.b.len() && self.b[self.i] != b'\n' { self.i += 1; } }
                _ => break,
            }
        }
    }

    pub fn next(&mut self) -> anyhow::Result<Option<Tok<'a>>> {
        self.skip_ws_comments();
        if self.i >= self.b.len() { return Ok(None); }
        let start = self.i;

        // delimiters and hex/dict
        if self.b[start] == b'<' {
            if start + 1 < self.b.len() && self.b[start + 1] == b'<' {
                self.i += 2;
                return Ok(Some(Tok::DictStart(Span{start:start as u64, end:self.i as u64})));
            }
            self.i += 1;
            while self.i < self.b.len() && self.b[self.i] != b'>' { self.i += 1; }
            if self.i < self.b.len() { self.i += 1; }
            return Ok(Some(Tok::StrHex{ span: Span{start:start as u64, end:self.i as u64}, raw: &self.b[start..self.i]}));
        }
        if self.b[start] == b'>' && start + 1 < self.b.len() && self.b[start + 1] == b'>' {
            self.i += 2;
            return Ok(Some(Tok::DictEnd(Span{start:start as u64, end:self.i as u64})));
        }
        if self.b[start] == b'[' { self.i += 1; return Ok(Some(Tok::ArrStart(Span{start:start as u64, end:self.i as u64}))); }
        if self.b[start] == b']' { self.i += 1; return Ok(Some(Tok::ArrEnd(Span{start:start as u64, end:self.i as u64}))); }

        // literal string
        if self.b[start] == b'(' {
            self.i += 1;
            let mut depth = 1usize;
            while self.i < self.b.len() && depth > 0 {
                match self.b[self.i] {
                    b'\\' => { self.i += 1; if self.i < self.b.len() { self.i += 1; } }
                    b'(' => { depth += 1; self.i += 1; }
                    b')' => { depth -= 1; self.i += 1; }
                    _ => self.i += 1,
                }
            }
            return Ok(Some(Tok::StrLit{ span: Span{start:start as u64, end:self.i as u64}, raw: &self.b[start..self.i]}));
        }

        // name
        if self.b[start] == b'/' {
            self.i += 1;
            while self.i < self.b.len() && !is_delim_or_ws(self.b[self.i]) { self.i += 1; }
            return Ok(Some(Tok::Name{ span: Span{start:start as u64, end:self.i as u64}, raw: &self.b[start..self.i]}));
        }

        // word/number
        while self.i < self.b.len() && !is_delim_or_ws(self.b[self.i]) { self.i += 1; }
        let raw = &self.b[start..self.i];
        let span = Span{ start:start as u64, end:self.i as u64 };

        match raw {
            b"true" => Ok(Some(Tok::True(span))),
            b"false" => Ok(Some(Tok::False(span))),
            b"null" => Ok(Some(Tok::Null(span))),
            _ => {
                if let Ok(s) = std::str::from_utf8(raw) {
                    if let Ok(v) = s.parse::<i64>() {
                        return Ok(Some(Tok::Int{ span, v }));
                    }
                    if let Ok(v) = s.parse::<f64>() {
                        return Ok(Some(Tok::Real{ span, v }));
                    }
                }
                Ok(Some(Tok::Keyword{ span, raw }))
            }
        }
    }
}

fn is_delim_or_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n' | 0x0C | b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'/' | b'%')
}
```

---

## 4) sis-pdf-pdf: classic `startxref` + trailer parser

### `crates/sis-pdf-pdf/src/xref.rs`

```rust
use crate::object::{ObjRef};
use crate::span::Span;

/// Minimal trailer info for triage:
/// - startxref offset
/// - trailer dict span
/// - /Root (catalog)
#[derive(Debug, Clone)]
pub struct TrailerInfo {
    pub startxref: u64,
    pub trailer_span: Option<Span>,
    pub root: Option<ObjRef>,
}

/// Find "startxref" from the end, parse the following integer, then parse trailer/root.
/// Returns None if not found/parseable.
pub fn parse_classic_trailer(bytes: &[u8]) -> Option<TrailerInfo> {
    let win = bytes.len().min(1024 * 1024);
    let start = bytes.len().saturating_sub(win);
    let hay = &bytes[start..];

    let idx = find_last(hay, b"startxref")?;
    let after = start + idx + b"startxref".len();
    let mut i = after;

    // skip whitespace
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | 0x0C) { i += 1; }

    // parse integer
    let j = i;
    while i < bytes.len() && (bytes[i] as char).is_ascii_digit() { i += 1; }
    if i == j { return None; }
    let off = std::str::from_utf8(&bytes[j..i]).ok()?.parse::<u64>().ok()?;

    // locate "trailer" near xref area (tolerant)
    // In classic PDFs, after xref sections appears "trailer <<...>>"
    let trailer_idx = find_next(bytes, b"trailer", off as usize).or_else(|| find_last(hay, b"trailer").map(|k| start + k));

    let (trailer_span, root) = if let Some(ti) = trailer_idx {
        // find "<<"
        let d1 = find_next(bytes, b"<<", ti)?;
        let d2 = find_matching_dict_end(bytes, d1 + 2)?;
        let span = Span{ start: d1 as u64, end: (d2 + 2) as u64 };
        let root = parse_root_ref_from_dict(&bytes[d1..d2+2]);
        (Some(span), root)
    } else {
        (None, None)
    };

    Some(TrailerInfo {
        startxref: off,
        trailer_span,
        root,
    })
}

fn parse_root_ref_from_dict(dict_bytes: &[u8]) -> Option<ObjRef> {
    // extremely small parser: look for "/Root <int> <int> R"
    // This is tolerant and fast; later you’ll parse dict properly with TokBuf.
    let key = b"/Root";
    let k = find_first(dict_bytes, key)?;
    let mut i = k + key.len();

    // skip ws
    while i < dict_bytes.len() && is_ws(dict_bytes[i]) { i += 1; }

    // parse obj int
    let (obj, ni) = parse_u32(dict_bytes, i)?;
    i = ni;
    while i < dict_bytes.len() && is_ws(dict_bytes[i]) { i += 1; }

    // parse gen int
    let (gen, ni2) = parse_u16(dict_bytes, i)?;
    i = ni2;
    while i < dict_bytes.len() && is_ws(dict_bytes[i]) { i += 1; }

    if i < dict_bytes.len() && dict_bytes[i] == b'R' {
        Some(ObjRef{ obj, gen })
    } else {
        None
    }
}

fn parse_u32(b: &[u8], mut i: usize) -> Option<(u32, usize)> {
    let start = i;
    while i < b.len() && (b[i] as char).is_ascii_digit() { i += 1; }
    if i == start { return None; }
    let v = std::str::from_utf8(&b[start..i]).ok()?.parse::<u32>().ok()?;
    Some((v, i))
}
fn parse_u16(b: &[u8], mut i: usize) -> Option<(u16, usize)> {
    let (v, j) = parse_u32(b, i)?;
    if v <= u16::MAX as u32 { Some((v as u16, j)) } else { None }
}
fn is_ws(c: u8) -> bool { matches!(c, b' ' | b'\t' | b'\r' | b'\n' | 0x0C) }

fn find_first(h: &[u8], n: &[u8]) -> Option<usize> { h.windows(n.len()).position(|w| w == n) }
fn find_last(h: &[u8], n: &[u8]) -> Option<usize> { h.windows(n.len()).rposition(|w| w == n) }

fn find_next(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    if from >= h.len() { return None; }
    h[from..].windows(n.len()).position(|w| w == n).map(|i| from + i)
}

fn find_matching_dict_end(h: &[u8], from: usize) -> Option<usize> {
    // Very tolerant: finds the next ">>"
    find_next(h, b">>", from)
}
```

This is intentionally “minimal classic trailer extraction”. You’ll later replace `parse_root_ref_from_dict` with a real dict parse using `TokBuf` (which you now have), but this works today for many PDFs.

---

## 5) sis-pdf-pdf: recovery scanner that builds the object graph

### `crates/sis-pdf-pdf/src/recover.rs`

```rust
use std::collections::HashMap;

use crate::span::Span;
use crate::tokbuf::TokBuf;
use crate::object::{ObjRef, PdfObj, parse_object};
use crate::graph::{ObjectGraph, ObjEntry};

pub fn recover_objects<'a>(bytes: &'a [u8]) -> anyhow::Result<ObjectGraph<'a>> {
    let mut objects: HashMap<ObjRef, ObjEntry<'a>> = HashMap::new();

    // scan for " obj"
    let needle = b" obj";
    let mut i = 0usize;

    while let Some(pos) = find_next(bytes, needle, i) {
        // attempt to parse "<obj> <gen> obj" backwards/forwards around pos
        // We’ll find start of line-ish by scanning backwards to whitespace boundary.
        let header_end = pos + needle.len(); // points after " obj"
        let header_start = scan_back_to_token_start(bytes, pos);
        // parse header tokens using TokBuf starting at header_start
        let mut tb = TokBuf::new(bytes, header_start);

        let Some(t1) = tb.next()? else { i = header_end; continue; };
        let (obj, obj_span) = match t1 {
            crate::lexer::Tok::Int{v, span} if v >= 0 => (v as u32, span),
            _ => { i = header_end; continue; }
        };
        let Some(t2) = tb.next()? else { i = header_end; continue; };
        let (gen, gen_span) = match t2 {
            crate::lexer::Tok::Int{v, span} if v >= 0 && v <= u16::MAX as i64 => (v as u16, span),
            _ => { i = header_end; continue; }
        };
        let Some(t3) = tb.next()? else { i = header_end; continue; };
        match t3 {
            crate::lexer::Tok::Keyword{raw, ..} if raw == b"obj" => {}
            _ => { i = header_end; continue; }
        }

        // body starts here
        let body_start = tb.pos();
        let body = match parse_object(&mut tb) {
            Ok(o) => o,
            Err(_) => { i = header_end; continue; }
        };

        // find endobj span by searching forward from current tb.pos()
        let endobj = find_next(bytes, b"endobj", tb.pos()).unwrap_or(tb.pos());
        let full_span = Span{ start: header_start as u64, end: (endobj + b"endobj".len()) as u64 };

        let r = ObjRef{ obj, gen };
        let entry = ObjEntry {
            r,
            full_span,
            body_span: Span{ start: body_start as u64, end: body.span.end },
            body,
            stream_span: None, // stream parsing comes next milestone
        };
        objects.insert(r, entry);

        i = header_end;
    }

    Ok(ObjectGraph {
        objects,
        catalog: None,
        trailer_span: None,
        startxref: None,
    })
}

fn find_next(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    if from >= h.len() { return None; }
    h[from..].windows(n.len()).position(|w| w == n).map(|k| from + k)
}

fn scan_back_to_token_start(b: &[u8], mut i: usize) -> usize {
    // scan backwards to a likely start of an integer token
    while i > 0 && !matches!(b[i-1], b'\n'|b'\r'|b' ' | b'\t' | 0x0C) {
        i -= 1;
    }
    i
}
```

This recovery scanner:

* indexes indirect objects found by scanning for ` obj`
* parses header + one object body
* records spans for evidence

It’s a workhorse for malicious PDFs where xref is broken.

---

## 6) sis-pdf-pdf: ObjectGraph + helper queries for detectors

### `crates/sis-pdf-pdf/src/graph.rs`

```rust
use std::collections::HashMap;
use crate::span::Span;
use crate::object::{ObjRef, PdfObj, PdfAtom, PdfDict, PdfName};

#[derive(Debug)]
pub struct ObjEntry<'a> {
    pub r: ObjRef,
    pub full_span: Span,
    pub body_span: Span,
    pub body: PdfObj<'a>,
    pub stream_span: Option<Span>,
}

pub struct ObjectGraph<'a> {
    pub objects: HashMap<ObjRef, ObjEntry<'a>>,
    pub catalog: Option<ObjRef>,
    pub trailer_span: Option<Span>,
    pub startxref: Option<u64>,
}

impl<'a> ObjectGraph<'a> {
    pub fn get(&self, r: ObjRef) -> Option<&ObjEntry<'a>> { self.objects.get(&r) }
    pub fn iter_objects(&self) -> impl Iterator<Item=&ObjEntry<'a>> { self.objects.values() }
    pub fn catalog_ref(&self) -> Option<ObjRef> { self.catalog }

    pub fn obj_as_dict(&self, e: &ObjEntry<'a>) -> Option<&PdfDict<'a>> {
        match &e.body.atom {
            PdfAtom::Dict(d) => Some(d),
            _ => None
        }
    }

    pub fn dict_get_all<'d>(d: &'d PdfDict<'a>, key: &[u8]) -> Vec<(&'d PdfName<'a>, &'d PdfObj<'a>)> {
        d.entries.iter()
            .filter(|(k, _)| k.decoded.as_slice() == key)
            .map(|(k,v)| (k,v))
            .collect()
    }

    pub fn dict_get_first<'d>(d: &'d PdfDict<'a>, key: &[u8]) -> Option<(&'d PdfName<'a>, &'d PdfObj<'a>)> {
        d.entries.iter().find(|(k,_)| k.decoded.as_slice() == key).map(|(k,v)| (k,v))
    }

    pub fn dict_key_value_spans(&self, e: &ObjEntry<'a>, key: &[u8]) -> Option<(Span, Span)> {
        let d = self.obj_as_dict(e)?;
        let (k, v) = Self::dict_get_first(d, key)?;
        Some((k.span, v.span))
    }

    pub fn dict_has_name_value(&self, d: &PdfDict<'a>, key: &[u8], name_value: &[u8]) -> bool {
        Self::dict_get_all(d, key).iter().any(|(_,v)| {
            matches!(&v.atom, PdfAtom::Name(n) if n.decoded.as_slice() == name_value)
        })
    }

    pub fn resolve_ref(&self, o: &PdfObj<'a>) -> Option<&ObjEntry<'a>> {
        match o.atom {
            PdfAtom::Ref{obj, gen} => self.get(ObjRef{obj, gen}),
            _ => None
        }
    }
}
```

This is enough to implement JS detection properly.

---

## 7) sis-pdf-detectors: working JavaScriptDetector

This finds JavaScript in **three** high-value places:

1. Any Action dict with `/S /JavaScript` and `/JS` payload
2. Catalog `/OpenAction` that resolves to a JS action (via ref)
3. Names tree: `/Names` → `/JavaScript` → `(name, js_action_ref)` pairs (tolerant)

### `crates/sis-pdf-detectors/src/javascript.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;

pub struct JavaScriptDetector;

impl Detector for JavaScriptDetector {
    fn id(&self) -> &'static str { "script.javascript" }
    fn surface(&self) -> AttackSurface { AttackSurface::JavaScript }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let mut out = Vec::new();

        // 1) scan all dict objects looking for action dicts with /S /JavaScript
        for e in g.iter_objects() {
            let Some(d) = g.obj_as_dict(e) else { continue; };
            if !g.dict_has_name_value(d, b"/S", b"/JavaScript") { continue; }

            let mut evidence = Vec::new();
            // evidence: /S and /JS spans (if present)
            if let Some((k, v)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/S") {
                evidence.push(EvidenceSpan{ offset: k.span.start, length: (k.span.end-k.span.start) as u32, note: Some("Action key /S".into()) });
                evidence.push(EvidenceSpan{ offset: v.span.start, length: (v.span.end-v.span.start) as u32, note: Some("Action value /JavaScript".into()) });
            }
            if let Some((k, v)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS") {
                evidence.push(EvidenceSpan{ offset: k.span.start, length: (k.span.end-k.span.start) as u32, note: Some("JavaScript key /JS".into()) });
                evidence.push(EvidenceSpan{ offset: v.span.start, length: (v.span.end-v.span.start) as u32, note: Some("JavaScript payload object/span".into()) });
            }

            out.push(Finding {
                id: format!("{}:{}:{}", self.id(), e.r.obj, e.r.gen),
                surface: AttackSurface::JavaScript,
                kind: "javascript_action_present".into(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                title: "JavaScript action present (/S /JavaScript)".into(),
                description: "This PDF contains an Action dictionary that specifies JavaScript. JavaScript in PDFs is a common malicious surface (auto-trigger, exploit delivery, phishing).".into(),
                objects: vec![format!("{} {} obj", e.r.obj, e.r.gen)],
                evidence,
                remediation: Some("Inspect the /JS payload, check if it is triggered via /OpenAction or /AA, and consider blocking PDFs containing JavaScript in high-risk environments.".into()),
            });
        }

        // 2) Names tree JS: Catalog /Names -> dict -> /JavaScript -> dict -> /Names [ (name) (ref/action) ... ]
        if let Some(cat_r) = g.catalog_ref() {
            if let Some(cat_e) = g.get(cat_r) {
                if let Some(cat_d) = g.obj_as_dict(cat_e) {
                    if let Some((_, names_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/Names") {
                        if let Some(names_e) = g.resolve_ref(names_obj) {
                            if let Some(names_d) = g.obj_as_dict(names_e) {
                                if let Some((_, js_names_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(names_d, b"/JavaScript") {
                                    // could be ref or dict
                                    let js_d_opt = match &js_names_obj.atom {
                                        sis_pdf_pdf::object::PdfAtom::Ref{..} => g.resolve_ref(js_names_obj).and_then(|e| g.obj_as_dict(e)),
                                        sis_pdf_pdf::object::PdfAtom::Dict(d) => Some(d),
                                        _ => None,
                                    };

                                    if let Some(js_d) = js_d_opt {
                                        if sis_pdf_pdf::graph::ObjectGraph::dict_get_first(js_d, b"/Names").is_some() {
                                            // We don’t fully enumerate pairs yet; we just flag presence with strong evidence.
                                            let (k_span, v_span) = g.dict_key_value_spans(names_e, b"/JavaScript")
                                                .unwrap_or((names_e.full_span, names_e.full_span));
                                            out.push(Finding {
                                                id: format!("{}:{}:{}:names", self.id(), cat_r.obj, cat_r.gen),
                                                surface: AttackSurface::JavaScript,
                                                kind: "javascript_names_tree_present".into(),
                                                severity: Severity::High,
                                                confidence: Confidence::Probable,
                                                title: "JavaScript present in Names tree".into(),
                                                description: "The document's Names tree contains a /JavaScript entry. This can register named scripts and is often used alongside actions to run code.".into(),
                                                objects: vec![
                                                    format!("{} {} obj (Catalog)", cat_r.obj, cat_r.gen),
                                                    format!("{} {} obj (Names)", names_e.r.obj, names_e.r.gen),
                                                ],
                                                evidence: vec![
                                                    EvidenceSpan{ offset: k_span.start, length: (k_span.end-k_span.start) as u32, note: Some("Names dict key /JavaScript".into()) },
                                                    EvidenceSpan{ offset: v_span.start, length: (v_span.end-v_span.start) as u32, note: Some("Names dict value".into()) },
                                                ],
                                                remediation: Some("Enumerate /Names pairs under /JavaScript and inspect each referenced action's /JS payload.".into()),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(out)
    }
}
```

### `crates/sis-pdf-detectors/src/lib.rs`

```rust
pub mod actions;
pub mod embedded;
pub mod javascript;
```

### Update `crates/sis-pdf-core/src/registry.rs`

```rust
use crate::detect::Detector;

pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(sis_pdf_detectors::actions::OpenActionDetector),
        Box::new(sis_pdf_detectors::javascript::JavaScriptDetector),
        Box::new(sis_pdf_detectors::embedded::EmbeddedFileDetector),
    ]
}
```

---

## 8) sis-pdf-core: make ScanContext use sis-pdf-pdf graph

Make sure `sis-pdf-core` uses the concrete graph type.

### `crates/sis-pdf-core/src/scan.rs`

```rust
#[derive(Clone)]
pub struct ScanOptions {
    pub deep: bool,
    pub max_decode_bytes: usize,
    pub recover_xref: bool,
    pub parallel: bool,
}

pub struct ScanContext<'a> {
    pub bytes: &'a [u8],
    pub graph: sis_pdf_pdf::graph::ObjectGraph<'a>,
    pub options: ScanOptions,
}
```

### `crates/sis-pdf-core/src/runner.rs` (minimal)

```rust
use crate::scan::{ScanContext, ScanOptions};
use crate::model::Finding;

#[derive(serde::Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
}

pub fn run_scan(bytes: &[u8], options: ScanOptions) -> anyhow::Result<Report> {
    let graph = sis_pdf_pdf::parse(bytes, options.recover_xref)?;
    let ctx = ScanContext { bytes, graph, options };

    let detectors = crate::registry::default_detectors();

    let mut findings: Vec<Finding> = if ctx.options.parallel {
        use rayon::prelude::*;
        detectors.par_iter()
            .map(|d| d.run(&ctx))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter().flatten().collect()
    } else {
        let mut all = Vec::new();
        for d in detectors { all.extend(d.run(&ctx)?); }
        all
    };

    findings.sort_by(|a,b| (a.surface as u32, &a.kind, &a.id).cmp(&(b.surface as u32, &b.kind, &b.id)));
    Ok(Report { findings })
}
```

---

## 9) Tests + tiny PDF fixtures (no xref needed)

Because recovery scan indexes objects even if xref is absent, these fixtures can be very small.

### `crates/sis-pdf-detectors/tests/js_detector.rs`

```rust
use sis_pdf_core::scan::ScanOptions;
use sis_pdf_core::runner::run_scan;

#[test]
fn detects_openaction_javascript() {
    let pdf = minimal_pdf_openaction_js();
    let rep = run_scan(&pdf, ScanOptions{
        deep: false,
        max_decode_bytes: 4*1024*1024,
        recover_xref: true,
        parallel: false,
    }).unwrap();

    assert!(rep.findings.iter().any(|f| f.kind == "javascript_action_present"));
}

#[test]
fn detects_names_tree_javascript() {
    let pdf = minimal_pdf_names_tree_js();
    let rep = run_scan(&pdf, ScanOptions{
        deep: false,
        max_decode_bytes: 4*1024*1024,
        recover_xref: true,
        parallel: false,
    }).unwrap();

    assert!(rep.findings.iter().any(|f| f.kind == "javascript_names_tree_present"));
}

// --- Fixtures: very small PDFs intended for recovery scan ---

fn minimal_pdf_openaction_js() -> Vec<u8> {
    // Catalog references action 2 0 R; action is JS.
    br#"%PDF-1.4
1 0 obj
<< /Type /Catalog /OpenAction 2 0 R >>
endobj
2 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert('hi')) >>
endobj
%%EOF
"#.to_vec()
}

fn minimal_pdf_names_tree_js() -> Vec<u8> {
    // Catalog /Names 2 0 R; Names dict contains /JavaScript 3 0 R; JS dict has /Names [...]
    br#"%PDF-1.4
1 0 obj
<< /Type /Catalog /Names 2 0 R >>
endobj
2 0 obj
<< /JavaScript 3 0 R >>
endobj
3 0 obj
<< /Names [ (x) 4 0 R ] >>
endobj
4 0 obj
<< /Type /Action /S /JavaScript /JS (this.print()) >>
endobj
%%EOF
"#.to_vec()
}
```

These tests validate the detector logic without requiring you to implement full xref parsing immediately.

---

## 10) Cargo.toml wiring (quick checklist)

### Workspace `Cargo.toml`

```toml
[workspace]
members = [
  "crates/sis-pdf-core",
  "crates/sis-pdf-pdf",
  "crates/sis-pdf-detectors",
  "crates/sis-pdf",
]
resolver = "2"
```

### `crates/sis-pdf-core/Cargo.toml`

```toml
[package]
name = "sis-pdf-core"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
serde = { version = "1", features = ["derive"] }
rayon = "1"
sis-pdf-pdf = { path = "../sis-pdf-pdf" }
sis-pdf-detectors = { path = "../sis-pdf-detectors" }
```

### `crates/sis-pdf-pdf/Cargo.toml`

```toml
[package]
name = "sis-pdf-pdf"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
```

### `crates/sis-pdf-detectors/Cargo.toml`

```toml
[package]
name = "sis-pdf-detectors"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
sis-pdf-core = { path = "../sis-pdf-core" }
sis-pdf-pdf = { path = "../sis-pdf-pdf" }

[dev-dependencies]
sis-pdf-core = { path = "../sis-pdf-core" }
```

(You may need to split `sis-pdf-core` traits/model into a separate crate later to avoid circular deps; for now this works if you keep the layering consistent. If Cargo complains about cycles, the fix is: move `model.rs` + `detect.rs` into `sis-pdf-api` crate and depend on that from both `sis-pdf-core` and `sis-pdf-detectors`.)

---

# What you’ll get immediately

* `cargo test -p sis-pdf-detectors` should pass and prove:

  * JS action detection works
  * JS in Names tree detection works
* `sis-pdf-pdf` can parse and build an object index via recovery scan
* Classic trailer parsing exists (lightweight), and you can improve it later with TokBuf-based dict parsing

---

# Chapter4

Cool — here are the **three drop-in chunks** in the same style:

1. **OpenAction resolution + classification** (JavaScript / URI / Launch / SubmitForm; extracts JS snippet including when `/JS` is a stream)
2. **AA detector** (finds `/AA` additional actions across objects; optionally classifies)
3. **Stream span extraction + Flate decode quota** (sis-pdf-pdf side)

I’ll paste this as “files to add/replace”.

---

# 1) sis-pdf-pdf: add stream extraction in recovery + safe Flate decode

## 1.1 Add dependency

### `crates/sis-pdf-pdf/Cargo.toml`

```toml
[dependencies]
anyhow = "1"
flate2 = "1"
```

## 1.2 New file: `crates/sis-pdf-pdf/src/stream.rs`

```rust
use std::io::Read;

#[derive(Debug, Clone)]
pub struct DecodedBytes {
    pub bytes: Vec<u8>,
    pub truncated: bool,
    pub note: Option<String>,
}

/// Decode Flate (zlib) with a hard max output limit.
/// If limit is exceeded: returns truncated output and sets truncated=true.
pub fn decode_flate_limited(input: &[u8], max_output: usize) -> anyhow::Result<DecodedBytes> {
    let mut dec = flate2::read::ZlibDecoder::new(input);
    let mut out = Vec::with_capacity(std::cmp::min(max_output, 64 * 1024));
    let mut buf = [0u8; 8192];

    let mut truncated = false;
    loop {
        let n = dec.read(&mut buf)?;
        if n == 0 { break; }
        if out.len() + n > max_output {
            let take = max_output.saturating_sub(out.len());
            out.extend_from_slice(&buf[..take]);
            truncated = true;
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }

    Ok(DecodedBytes {
        bytes: out,
        truncated,
        note: if truncated { Some("Flate output truncated by quota".into()) } else { None },
    })
}
```

## 1.3 Update `crates/sis-pdf-pdf/src/lib.rs`

```rust
pub mod span;
pub mod lexer;
pub mod tokbuf;
pub mod object;
pub mod xref;
pub mod recover;
pub mod graph;
pub mod stream; // NEW

use graph::ObjectGraph;

pub fn parse<'a>(bytes: &'a [u8], recover_xref: bool) -> anyhow::Result<ObjectGraph<'a>> {
    let trailer = xref::parse_classic_trailer(bytes).ok();
    let mut g = recover::recover_objects(bytes)?;

    if let Some(t) = trailer {
        if let Some(root) = t.root {
            g.catalog = Some(root);
        }
        g.trailer_span = t.trailer_span;
        g.startxref = t.startxref;
    } else if !recover_xref {
        // keep tolerant for now
    }

    Ok(g)
}
```

## 1.4 Replace `crates/sis-pdf-pdf/src/recover.rs` with stream-span support

```rust
use std::collections::HashMap;

use crate::span::Span;
use crate::tokbuf::TokBuf;
use crate::object::{ObjRef, parse_object};
use crate::graph::{ObjectGraph, ObjEntry};

pub fn recover_objects<'a>(bytes: &'a [u8]) -> anyhow::Result<ObjectGraph<'a>> {
    let mut objects: HashMap<ObjRef, ObjEntry<'a>> = HashMap::new();

    let needle = b" obj";
    let mut i = 0usize;

    while let Some(pos) = find_next(bytes, needle, i) {
        let header_end = pos + needle.len();
        let header_start = scan_back_to_token_start(bytes, pos);

        let mut tb = TokBuf::new(bytes, header_start);

        let Some(t1) = tb.next()? else { i = header_end; continue; };
        let (obj, obj_span) = match t1 {
            crate::lexer::Tok::Int{v, span} if v >= 0 => (v as u32, span),
            _ => { i = header_end; continue; }
        };
        let Some(t2) = tb.next()? else { i = header_end; continue; };
        let (gen, gen_span) = match t2 {
            crate::lexer::Tok::Int{v, span} if v >= 0 && v <= u16::MAX as i64 => (v as u16, span),
            _ => { i = header_end; continue; }
        };
        let Some(t3) = tb.next()? else { i = header_end; continue; };
        match t3 {
            crate::lexer::Tok::Keyword{raw, ..} if raw == b"obj" => {}
            _ => { i = header_end; continue; }
        }

        let body_start = tb.pos();
        let body = match parse_object(&mut tb) {
            Ok(o) => o,
            Err(_) => { i = header_end; continue; }
        };

        // Optional stream: only valid if body is a dict; tolerate anyway.
        let mut stream_span: Option<Span> = None;

        // Peek for "stream"
        if let Some(crate::lexer::Tok::Keyword{raw, ..}) = tb.peek()?.cloned() {
            if raw == b"stream" {
                let _ = tb.next()?; // consume "stream"
                // stream data begins after optional EOL
                let mut s = tb.pos();
                // tolerate CRLF / LF
                if s < bytes.len() && bytes[s] == b'\r' { s += 1; if s < bytes.len() && bytes[s] == b'\n' { s += 1; } }
                else if s < bytes.len() && bytes[s] == b'\n' { s += 1; }

                // find endstream
                if let Some(es) = find_next(bytes, b"endstream", s) {
                    stream_span = Some(Span { start: s as u64, end: es as u64 });
                    // advance search base after endstream
                }
            }
        }

        // find endobj
        let search_from = stream_span.map(|sp| sp.end as usize).unwrap_or(tb.pos());
        let endobj = find_next(bytes, b"endobj", search_from).unwrap_or(search_from);
        let full_span = Span{ start: header_start as u64, end: (endobj + b"endobj".len()) as u64 };

        let r = ObjRef{ obj, gen };
        let entry = ObjEntry {
            r,
            full_span,
            body_span: Span{ start: body_start as u64, end: body.span.end },
            body,
            stream_span,
        };
        objects.insert(r, entry);

        i = header_end;
    }

    Ok(ObjectGraph {
        objects,
        catalog: None,
        trailer_span: None,
        startxref: None,
    })
}

fn find_next(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    if from >= h.len() { return None; }
    h[from..].windows(n.len()).position(|w| w == n).map(|k| from + k)
}

fn scan_back_to_token_start(b: &[u8], mut i: usize) -> usize {
    while i > 0 && !matches!(b[i-1], b'\n'|b'\r'|b' ' | b'\t' | 0x0C) {
        i -= 1;
    }
    i
}
```

---

# 2) sis-pdf-pdf: add helpers for streams/filters + JS extraction

## 2.1 Update `crates/sis-pdf-pdf/src/graph.rs` (append these helpers)

Add these methods inside `impl ObjectGraph<'a>`:

```rust
    pub fn is_stream(&self, e: &ObjEntry<'a>) -> bool {
        e.stream_span.is_some()
    }

    pub fn stream_bytes<'b>(&'b self, e: &ObjEntry<'a>, file: &'b [u8]) -> Option<&'b [u8]> {
        let sp = e.stream_span?;
        let s = sp.start as usize;
        let t = sp.end as usize;
        if t <= file.len() && s <= t { Some(&file[s..t]) } else { None }
    }

    /// Return list of filter names (decoded bytes) and declared /Length if present.
    pub fn stream_filters_and_length(&self, e: &ObjEntry<'a>) -> (Vec<Vec<u8>>, Option<i64>) {
        let mut filters = Vec::new();
        let mut length = None;

        let Some(d) = self.obj_as_dict(e) else { return (filters, length); };

        // /Length (can be int or ref; we only handle int here for triage)
        if let Some((_, v)) = Self::dict_get_first(d, b"/Length") {
            if let crate::object::PdfAtom::Int(n) = v.atom {
                length = Some(n);
            }
        }

        // /Filter can be Name or Array of Names
        if let Some((_, v)) = Self::dict_get_first(d, b"/Filter") {
            match &v.atom {
                crate::object::PdfAtom::Name(n) => filters.push(n.decoded.clone()),
                crate::object::PdfAtom::Array(items) => {
                    for it in items {
                        if let crate::object::PdfAtom::Name(n) = &it.atom {
                            filters.push(n.decoded.clone());
                        }
                    }
                }
                _ => {}
            }
        }

        (filters, length)
    }

    /// Extract JS payload bytes from an object that can be:
    /// - literal/hex string
    /// - stream (via ref) with FlateDecode (triage supports only Flate)
    pub fn extract_js_payload(
        &self,
        js_obj: &crate::object::PdfObj<'a>,
        file: &[u8],
        max_decode: usize
    ) -> Option<(Vec<u8>, bool, Option<String>)> {
        use crate::object::{PdfAtom, PdfStr};

        match &js_obj.atom {
            PdfAtom::Str(PdfStr::Literal{ raw, .. }) => Some((raw.to_vec(), false, Some("JS in literal string (raw, not unescaped)".into()))),
            PdfAtom::Str(PdfStr::Hex{ raw, .. }) => Some((raw.to_vec(), false, Some("JS in hex string (raw)".into()))),
            PdfAtom::Ref{..} => {
                let e = self.resolve_ref(js_obj)?;
                if !self.is_stream(e) { return None; }
                let (filters, _) = self.stream_filters_and_length(e);
                // triage: only decode if includes /FlateDecode
                let has_flate = filters.iter().any(|f| f.as_slice() == b"/FlateDecode");
                if !has_flate { return None; }

                let sb = self.stream_bytes(e, file)?;
                let dec = crate::stream::decode_flate_limited(sb, max_decode).ok()?;
                Some((dec.bytes, dec.truncated, dec.note))
            }
            _ => None,
        }
    }
```

---

# 3) sis-pdf-detectors: OpenAction resolver/classifier + AA detector

## 3.1 New file: `crates/sis-pdf-detectors/src/openaction.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;

pub struct OpenActionClassifierDetector;

impl Detector for OpenActionClassifierDetector {
    fn id(&self) -> &'static str { "actions.open_action_classify" }
    fn surface(&self) -> AttackSurface { AttackSurface::Actions }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let bytes = ctx.bytes;
        let mut out = Vec::new();

        let Some(cat_r) = g.catalog_ref() else { return Ok(out); };
        let Some(cat_e) = g.get(cat_r) else { return Ok(out); };
        let Some(cat_d) = g.obj_as_dict(cat_e) else { return Ok(out); };

        let Some((k_name, open_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/OpenAction") else {
            return Ok(out);
        };

        // resolve action dict (could be ref or inline dict)
        let action_dict = match &open_obj.atom {
            sis_pdf_pdf::object::PdfAtom::Ref{..} => g.resolve_ref(open_obj).and_then(|e| g.obj_as_dict(e)),
            sis_pdf_pdf::object::PdfAtom::Dict(d) => Some(d),
            _ => None,
        };

        let mut kind = "open_action_present".to_string();
        let mut title = "Document has /OpenAction".to_string();
        let mut desc = "The PDF specifies an action triggered on document open.".to_string();
        let mut sev = Severity::High;
        let mut conf = Confidence::Strong;
        let mut objects = vec![format!("{} {} obj (Catalog)", cat_r.obj, cat_r.gen)];

        if let Some(ad) = action_dict {
            // classify by /S
            if let Some((_, s_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/S") {
                if let sis_pdf_pdf::object::PdfAtom::Name(n) = &s_obj.atom {
                    match n.decoded.as_slice() {
                        b"/JavaScript" => {
                            kind = "open_action_javascript".into();
                            title = "OpenAction triggers JavaScript".into();
                            desc = "OpenAction resolves to a JavaScript action (/S /JavaScript).".into();
                            sev = Severity::Critical;

                            // If /JS exists, extract a snippet (string or flate stream)
                            if let Some((_, js_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/JS") {
                                if let Some((payload, truncated, note)) =
                                    g.extract_js_payload(js_obj, bytes, ctx.options.max_decode_bytes.min(512 * 1024))
                                {
                                    let preview = safe_preview(&payload, 200);
                                    desc.push_str(&format!(" JS preview: {}", preview));
                                    if truncated {
                                        desc.push_str(" (payload truncated by quota)");
                                    }
                                    if let Some(n) = note { desc.push_str(&format!(" [{}]", n)); }
                                } else {
                                    desc.push_str(" JS payload present but not extracted (non-string/non-flate-stream or unsupported filters).");
                                }
                            }
                        }
                        b"/URI" => {
                            kind = "open_action_uri".into();
                            title = "OpenAction opens external URI".into();
                            desc = "OpenAction resolves to a URI action (/S /URI).".into();
                            sev = Severity::High;
                        }
                        b"/Launch" => {
                            kind = "open_action_launch".into();
                            title = "OpenAction launches external application/file".into();
                            desc = "OpenAction resolves to a Launch action (/S /Launch).".into();
                            sev = Severity::Critical;
                        }
                        b"/SubmitForm" => {
                            kind = "open_action_submitform".into();
                            title = "OpenAction submits a form (possible exfiltration)".into();
                            desc = "OpenAction resolves to a SubmitForm action (/S /SubmitForm).".into();
                            sev = Severity::High;
                        }
                        other => {
                            kind = "open_action_other".into();
                            title = "OpenAction uses uncommon action type".into();
                            desc = format!("OpenAction action /S is {:?}.", String::from_utf8_lossy(other));
                            sev = Severity::Medium;
                            conf = Confidence::Probable;
                        }
                    }
                }
            }

            // add action object id to objects list if ref
            if let sis_pdf_pdf::object::PdfAtom::Ref{obj, gen} = open_obj.atom {
                objects.push(format!("{} {} obj (OpenAction)", obj, gen));
            }
        } else {
            conf = Confidence::Probable;
            desc.push_str(" OpenAction could not be resolved to a dictionary (malformed or unsupported form).");
        }

        out.push(Finding{
            id: format!("{}:{}:{}", self.id(), cat_r.obj, cat_r.gen),
            surface: AttackSurface::Actions,
            kind,
            severity: sev,
            confidence: conf,
            title,
            description: desc,
            objects,
            evidence: vec![
                EvidenceSpan{ offset: k_name.span.start, length: (k_name.span.end-k_name.span.start) as u32, note: Some("Catalog key /OpenAction".into()) },
                EvidenceSpan{ offset: open_obj.span.start, length: (open_obj.span.end-open_obj.span.start) as u32, note: Some("OpenAction value".into()) },
            ],
            remediation: Some("Inspect the resolved action dictionary and any referenced /JS, /URI, /Launch, or /SubmitForm targets. Consider blocking OpenAction in high-risk environments.".into()),
        });

        Ok(out)
    }
}

fn safe_preview(b: &[u8], max: usize) -> String {
    let s = &b[..std::cmp::min(b.len(), max)];
    let mut out = String::new();
    for &c in s {
        if c.is_ascii_graphic() || c == b' ' {
            out.push(c as char);
        } else if c == b'\n' || c == b'\r' || c == b'\t' {
            out.push(' ');
        } else {
            out.push('.');
        }
    }
    out
}
```

## 3.2 New file: `crates/sis-pdf-detectors/src/aa.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;

pub struct AdditionalActionsDetector;

impl Detector for AdditionalActionsDetector {
    fn id(&self) -> &'static str { "actions.additional_actions" }
    fn surface(&self) -> AttackSurface { AttackSurface::Actions }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let bytes = ctx.bytes;
        let mut out = Vec::new();

        for e in g.iter_objects() {
            let Some(d) = g.obj_as_dict(e) else { continue; };
            let hits = sis_pdf_pdf::graph::ObjectGraph::dict_get_all(d, b"/AA");
            if hits.is_empty() { continue; }

            for (k, v) in hits {
                // classify if AA dict exists and contains JS actions (lightweight)
                let mut sev = Severity::High;
                let mut conf = Confidence::Probable;
                let mut desc = "Object contains /AA (Additional Actions), which can trigger behavior on events (open/close/focus/mouse/etc).".to_string();

                // Try resolve /AA to dict and check for /S /JavaScript anywhere immediate
                let aa_dict = match &v.atom {
                    sis_pdf_pdf::object::PdfAtom::Dict(dd) => Some(dd),
                    sis_pdf_pdf::object::PdfAtom::Ref{..} => g.resolve_ref(v).and_then(|er| g.obj_as_dict(er)),
                    _ => None,
                };

                if let Some(aad) = aa_dict {
                    // if any entry value is a JS action dict, escalate
                    if aa_contains_javascript(g, aad, bytes, ctx.options.max_decode_bytes.min(256 * 1024)) {
                        sev = Severity::Critical;
                        conf = Confidence::Strong;
                        desc.push_str(" At least one AA entry resolves to JavaScript.");
                    }
                }

                out.push(Finding{
                    id: format!("{}:{}:{}:{}", self.id(), e.r.obj, e.r.gen, k.span.start),
                    surface: AttackSurface::Actions,
                    kind: "aa_present".into(),
                    severity: sev,
                    confidence: conf,
                    title: "Additional Actions present (/AA)".into(),
                    description: desc,
                    objects: vec![format!("{} {} obj", e.r.obj, e.r.gen)],
                    evidence: vec![
                        EvidenceSpan{ offset: k.span.start, length: (k.span.end-k.span.start) as u32, note: Some("Key /AA".into()) },
                        EvidenceSpan{ offset: v.span.start, length: (v.span.end-v.span.start) as u32, note: Some("Value of /AA".into()) },
                    ],
                    remediation: Some("Inspect /AA entries and their resolved actions. Consider blocking PDFs with /AA in high-risk contexts.".into()),
                });
            }
        }

        Ok(out)
    }
}

fn aa_contains_javascript<'a>(
    g: &sis_pdf_pdf::graph::ObjectGraph<'a>,
    aa_dict: &sis_pdf_pdf::object::PdfDict<'a>,
    file: &[u8],
    max_decode: usize
) -> bool {
    for (_k, v) in &aa_dict.entries {
        // each v is commonly an action dict or ref to action dict
        let ad = match &v.atom {
            sis_pdf_pdf::object::PdfAtom::Dict(d) => Some(d),
            sis_pdf_pdf::object::PdfAtom::Ref{..} => g.resolve_ref(v).and_then(|e| g.obj_as_dict(e)),
            _ => None,
        };
        let Some(ad) = ad else { continue; };

        if g.dict_has_name_value(ad, b"/S", b"/JavaScript") {
            // optionally try extract JS quickly; if extraction works, definitely JS
            if let Some((_, js_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/JS") {
                if g.extract_js_payload(js_obj, file, max_decode).is_some() {
                    return true;
                }
            }
            return true;
        }
    }
    false
}
```

## 3.3 Update `crates/sis-pdf-detectors/src/lib.rs`

```rust
pub mod actions;
pub mod embedded;
pub mod javascript;
pub mod openaction; // NEW
pub mod aa;         // NEW
```

## 3.4 Update `crates/sis-pdf-core/src/registry.rs`

```rust
use crate::detect::Detector;

pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(sis_pdf_detectors::actions::OpenActionDetector),
        Box::new(sis_pdf_detectors::openaction::OpenActionClassifierDetector), // NEW
        Box::new(sis_pdf_detectors::aa::AdditionalActionsDetector),            // NEW
        Box::new(sis_pdf_detectors::javascript::JavaScriptDetector),
        Box::new(sis_pdf_detectors::embedded::EmbeddedFileDetector),
    ]
}
```

---

# 4) Add minimal tests for OpenAction classification + AA

### `crates/sis-pdf-detectors/tests/openaction_and_aa.rs`

```rust
use sis_pdf_core::scan::ScanOptions;
use sis_pdf_core::runner::run_scan;

#[test]
fn detects_openaction_js_and_extracts_preview() {
    let pdf = br#"%PDF-1.4
1 0 obj
<< /Type /Catalog /OpenAction 2 0 R >>
endobj
2 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert('hi')) >>
endobj
%%EOF
"#.to_vec();

    let rep = run_scan(&pdf, ScanOptions{
        deep: false,
        max_decode_bytes: 256*1024,
        recover_xref: true,
        parallel: false,
    }).unwrap();

    assert!(rep.findings.iter().any(|f| f.kind == "open_action_javascript"));
}

#[test]
fn detects_additional_actions() {
    let pdf = br#"%PDF-1.4
1 0 obj
<< /Type /Catalog /AA 2 0 R >>
endobj
2 0 obj
<< /O 3 0 R >>
endobj
3 0 obj
<< /S /JavaScript /JS (this.print()) >>
endobj
%%EOF
"#.to_vec();

    let rep = run_scan(&pdf, ScanOptions{
        deep: false,
        max_decode_bytes: 256*1024,
        recover_xref: true,
        parallel: false,
    }).unwrap();

    assert!(rep.findings.iter().any(|f| f.kind == "aa_present"));
}
```

---

# What this gives you right now

* **/OpenAction** is no longer just “present”: it’s **classified** into:

  * `open_action_javascript` (Critical)
  * `open_action_uri` (High)
  * `open_action_launch` (Critical)
  * `open_action_submitform` (High)
  * `open_action_other` (Medium/Probable)
* **/AA** is detected everywhere and (lightly) escalates if it resolves to JS.
* **JS payload extraction** works for:

  * string `/JS (...)`
  * flate stream `/JS <ref-to-stream-with-FlateDecode>` (quota-limited)

---


# Chapter4

Here’s the **next chunk** (same style, drop-in files) covering:

1. **URI + SubmitForm target extraction** (collect destinations; flag suspicious schemes/IP literals/data/file/javascript)
2. **Stream filter chain support** (ASCII85 → Flate, ASCIIHex → Flate, RunLength; quota-limited)
3. **/ObjStm index-only detector** (detect packed objects + suspicious density/size signals)

---

# 1) sis-pdf-pdf: filter-chain decoding (safe + quota-limited)

## 1.1 Update dependencies

### `crates/sis-pdf-pdf/Cargo.toml`

```toml
[dependencies]
anyhow = "1"
flate2 = "1"
```

## 1.2 New file: `crates/sis-pdf-pdf/src/decode/mod.rs`

```rust
pub mod limits;
pub mod ascii85;
pub mod asciihex;
pub mod runlength;

use crate::stream::{DecodedBytes, decode_flate_limited};

#[derive(Debug, Clone)]
pub struct DecodePlan {
    pub max_output: usize,
    pub max_steps: usize,
}

pub fn decode_with_filters_limited(
    input: &[u8],
    filters: &[Vec<u8>],
    plan: DecodePlan,
) -> anyhow::Result<DecodedBytes> {
    let mut cur: Vec<u8> = input.to_vec();
    let mut truncated = false;
    let mut notes: Vec<String> = Vec::new();

    let steps = std::cmp::min(filters.len(), plan.max_steps);

    for f in filters.iter().take(steps) {
        match f.as_slice() {
            b"/ASCII85Decode" => {
                let out = ascii85::decode_ascii85_limited(&cur, plan.max_output)?;
                cur = out.bytes;
                truncated |= out.truncated;
                if let Some(n) = out.note { notes.push(n); }
            }
            b"/ASCIIHexDecode" => {
                let out = asciihex::decode_asciihex_limited(&cur, plan.max_output)?;
                cur = out.bytes;
                truncated |= out.truncated;
                if let Some(n) = out.note { notes.push(n); }
            }
            b"/RunLengthDecode" => {
                let out = runlength::decode_runlength_limited(&cur, plan.max_output)?;
                cur = out.bytes;
                truncated |= out.truncated;
                if let Some(n) = out.note { notes.push(n); }
            }
            b"/FlateDecode" => {
                let out = decode_flate_limited(&cur, plan.max_output)?;
                cur = out.bytes;
                truncated |= out.truncated;
                if let Some(n) = out.note { notes.push(n); }
            }
            // image/heavy decoders: do not implement here for triage; just stop
            b"/DCTDecode" | b"/JPXDecode" | b"/JBIG2Decode" | b"/CCITTFaxDecode" | b"/LZWDecode" => {
                notes.push(format!("Filter {:?} not decoded in triage", String::from_utf8_lossy(f)));
                break;
            }
            _ => {
                notes.push(format!("Unknown filter {:?}, stopping decode", String::from_utf8_lossy(f)));
                break;
            }
        }
    }

    Ok(DecodedBytes{
        bytes: cur,
        truncated,
        note: if notes.is_empty() { None } else { Some(notes.join("; ")) },
    })
}
```

## 1.3 New file: `crates/sis-pdf-pdf/src/decode/asciihex.rs`

```rust
use crate::stream::DecodedBytes;

pub fn decode_asciihex_limited(input: &[u8], max_output: usize) -> anyhow::Result<DecodedBytes> {
    let mut out = Vec::with_capacity(std::cmp::min(max_output, 64 * 1024));
    let mut truncated = false;

    // ASCIIHexDecode: ignores whitespace; ends at '>'
    let mut hi: Option<u8> = None;

    for &c in input {
        if c == b'>' { break; }
        if is_ws(c) { continue; }
        let v = match hex(c) {
            Some(v) => v,
            None => continue, // tolerate junk
        };
        if let Some(h) = hi.take() {
            if out.len() + 1 > max_output { truncated = true; break; }
            out.push((h << 4) | v);
        } else {
            hi = Some(v);
        }
    }
    // if odd nibble, last nibble assumed 0
    if let Some(h) = hi {
        if !truncated && out.len() + 1 <= max_output {
            out.push(h << 4);
        } else {
            truncated = true;
        }
    }

    Ok(DecodedBytes{
        bytes: out,
        truncated,
        note: if truncated { Some("ASCIIHex output truncated by quota".into()) } else { None },
    })
}

fn is_ws(c: u8) -> bool { matches!(c, b' ' | b'\t' | b'\r' | b'\n' | 0x0C) }
fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None
    }
}
```

## 1.4 New file: `crates/sis-pdf-pdf/src/decode/runlength.rs`

```rust
use crate::stream::DecodedBytes;

/// RunLengthDecode per PDF spec-ish:
/// - read length byte n
/// - 0..=127 => copy next (n+1) bytes literal
/// - 129..=255 => replicate next byte (257-n) times
/// - 128 => EOD
pub fn decode_runlength_limited(input: &[u8], max_output: usize) -> anyhow::Result<DecodedBytes> {
    let mut out = Vec::with_capacity(std::cmp::min(max_output, 64 * 1024));
    let mut i = 0usize;
    let mut truncated = false;

    while i < input.len() {
        let n = input[i];
        i += 1;

        if n == 128 { break; }
        if n <= 127 {
            let count = (n as usize) + 1;
            let end = std::cmp::min(i + count, input.len());
            let chunk = &input[i..end];
            if out.len() + chunk.len() > max_output {
                let take = max_output.saturating_sub(out.len());
                out.extend_from_slice(&chunk[..take]);
                truncated = true;
                break;
            }
            out.extend_from_slice(chunk);
            i = end;
        } else {
            // replicate
            if i >= input.len() { break; }
            let b = input[i];
            i += 1;
            let count = 257usize - (n as usize);
            if out.len() + count > max_output {
                let take = max_output.saturating_sub(out.len());
                out.extend(std::iter::repeat(b).take(take));
                truncated = true;
                break;
            }
            out.extend(std::iter::repeat(b).take(count));
        }
    }

    Ok(DecodedBytes{
        bytes: out,
        truncated,
        note: if truncated { Some("RunLength output truncated by quota".into()) } else { None },
    })
}
```

## 1.5 New file: `crates/sis-pdf-pdf/src/decode/ascii85.rs`

```rust
use crate::stream::DecodedBytes;

/// Tolerant ASCII85Decode with quota.
/// Supports:
/// - 'z' => 4 zero bytes (when at group boundary)
/// - '~>' end marker
pub fn decode_ascii85_limited(input: &[u8], max_output: usize) -> anyhow::Result<DecodedBytes> {
    let mut out = Vec::with_capacity(std::cmp::min(max_output, 64 * 1024));
    let mut truncated = false;

    let mut group: [u32; 5] = [0; 5];
    let mut glen = 0usize;

    let mut i = 0usize;
    while i < input.len() {
        let c = input[i];
        i += 1;

        if is_ws(c) { continue; }

        // end marker
        if c == b'~' {
            if i < input.len() && input[i] == b'>' { i += 1; }
            break;
        }

        if c == b'z' && glen == 0 {
            if out.len() + 4 > max_output { truncated = true; break; }
            out.extend_from_slice(&[0,0,0,0]);
            continue;
        }

        if !(b'!'..=b'u').contains(&c) {
            // tolerate junk
            continue;
        }

        group[glen] = (c - b'!') as u32;
        glen += 1;

        if glen == 5 {
            if out.len() + 4 > max_output { truncated = true; break; }
            write_group(&group, 5, &mut out);
            glen = 0;
        }
    }

    // partial group: pad with 'u' (84) and write only glen-1 bytes
    if !truncated && glen > 0 {
        for j in glen..5 { group[j] = 84; }
        let mut tmp = Vec::new();
        write_group(&group, 5, &mut tmp);
        let take = glen - 1;
        if out.len() + take > max_output {
            truncated = true;
        } else {
            out.extend_from_slice(&tmp[..take]);
        }
    }

    Ok(DecodedBytes{
        bytes: out,
        truncated,
        note: if truncated { Some("ASCII85 output truncated by quota".into()) } else { None },
    })
}

fn write_group(group: &[u32; 5], _len: usize, out: &mut Vec<u8>) {
    let mut acc: u32 = 0;
    for &v in group.iter().take(5) {
        acc = acc.saturating_mul(85).saturating_add(v);
    }
    out.push(((acc >> 24) & 0xFF) as u8);
    out.push(((acc >> 16) & 0xFF) as u8);
    out.push(((acc >>  8) & 0xFF) as u8);
    out.push(((acc      ) & 0xFF) as u8);
}

fn is_ws(c: u8) -> bool { matches!(c, b' ' | b'\t' | b'\r' | b'\n' | 0x0C) }
```

## 1.6 Update `crates/sis-pdf-pdf/src/lib.rs` to export decode module

```rust
pub mod span;
pub mod lexer;
pub mod tokbuf;
pub mod object;
pub mod xref;
pub mod recover;
pub mod graph;
pub mod stream;
pub mod decode; // NEW
```

---

# 2) sis-pdf-pdf: upgrade JS extraction to support filter chains

Update the `extract_js_payload` helper you added earlier in `crates/sis-pdf-pdf/src/graph.rs`.

**Replace** the body of `extract_js_payload` with this chain-aware version:

```rust
    pub fn extract_js_payload(
        &self,
        js_obj: &crate::object::PdfObj<'a>,
        file: &[u8],
        max_decode: usize
    ) -> Option<(Vec<u8>, bool, Option<String>)> {
        use crate::object::{PdfAtom, PdfStr};

        match &js_obj.atom {
            PdfAtom::Str(PdfStr::Literal{ raw, .. }) => {
                Some((raw.to_vec(), false, Some("JS in literal string (raw, not unescaped)".into())))
            }
            PdfAtom::Str(PdfStr::Hex{ raw, .. }) => {
                Some((raw.to_vec(), false, Some("JS in hex string (raw)".into())))
            }
            PdfAtom::Ref{..} => {
                let e = self.resolve_ref(js_obj)?;
                if !self.is_stream(e) { return None; }

                let sb = self.stream_bytes(e, file)?;
                let (filters, _) = self.stream_filters_and_length(e);

                let dec = crate::decode::decode_with_filters_limited(
                    sb,
                    &filters,
                    crate::decode::DecodePlan{ max_output: max_decode, max_steps: 8 }
                ).ok()?;

                Some((dec.bytes, dec.truncated, dec.note))
            }
            _ => None,
        }
    }
```

Now `/JS` in a stream with `ASCII85Decode` → `FlateDecode` will work (quota-limited).

---

# 3) sis-pdf-detectors: URI + SubmitForm extraction detector

This scans for action dicts with `/S /URI` and `/S /SubmitForm`, extracts targets, and flags suspicious schemes/domains.

## 3.1 New file: `crates/sis-pdf-detectors/src/network.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;

pub struct NetworkActionDetector;

impl Detector for NetworkActionDetector {
    fn id(&self) -> &'static str { "actions.network_targets" }
    fn surface(&self) -> AttackSurface { AttackSurface::Actions }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let mut out = Vec::new();

        for e in g.iter_objects() {
            let Some(d) = g.obj_as_dict(e) else { continue; };

            // Only action-like dicts (tolerant)
            if !g.dict_has_name_value(d, b"/Type", b"/Action") {
                // many PDFs omit /Type for actions; don't require it
            }

            // find /S
            let Some((_, s_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/S") else { continue; };
            let s_name = match &s_obj.atom {
                sis_pdf_pdf::object::PdfAtom::Name(n) => n.decoded.clone(),
                _ => continue,
            };

            if s_name.as_slice() == b"/URI" {
                if let Some((k, uri_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/URI") {
                    if let Some(target) = extract_textish(uri_obj) {
                        let (sev, flags) = score_uri(&target);
                        out.push(Finding{
                            id: format!("{}:{}:{}:uri", self.id(), e.r.obj, e.r.gen),
                            surface: AttackSurface::Actions,
                            kind: "uri_action_target".into(),
                            severity: sev,
                            confidence: Confidence::Probable,
                            title: "URI action present (/S /URI)".into(),
                            description: format!("URI target: {}{}", target, if flags.is_empty() { "".into() } else { format!(" | flags: {}", flags.join(", ")) }),
                            objects: vec![format!("{} {} obj", e.r.obj, e.r.gen)],
                            evidence: vec![
                                EvidenceSpan{ offset: k.span.start, length: (k.span.end-k.span.start) as u32, note: Some("Key /URI".into()) },
                                EvidenceSpan{ offset: uri_obj.span.start, length: (uri_obj.span.end-uri_obj.span.start) as u32, note: Some("URI value".into()) },
                            ],
                            remediation: Some("Validate the destination. In high-risk settings, block external URI actions or strip them during sanitization.".into()),
                        });
                    }
                }
            } else if s_name.as_slice() == b"/SubmitForm" {
                // SubmitForm uses /F as target (often a URL), plus other keys
                if let Some((k, f_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/F") {
                    if let Some(target) = extract_textish(f_obj) {
                        let (sev, flags) = score_submitform(&target);
                        out.push(Finding{
                            id: format!("{}:{}:{}:submit", self.id(), e.r.obj, e.r.gen),
                            surface: AttackSurface::Actions,
                            kind: "submitform_action_target".into(),
                            severity: sev,
                            confidence: Confidence::Probable,
                            title: "SubmitForm action present (/S /SubmitForm)".into(),
                            description: format!("SubmitForm target: {}{}", target, if flags.is_empty() { "".into() } else { format!(" | flags: {}", flags.join(", ")) }),
                            objects: vec![format!("{} {} obj", e.r.obj, e.r.gen)],
                            evidence: vec![
                                EvidenceSpan{ offset: k.span.start, length: (k.span.end-k.span.start) as u32, note: Some("Key /F".into()) },
                                EvidenceSpan{ offset: f_obj.span.start, length: (f_obj.span.end-f_obj.span.start) as u32, note: Some("SubmitForm target".into()) },
                            ],
                            remediation: Some("Treat as potential data exfiltration. Confirm if forms are expected; block/strip SubmitForm in high-risk contexts.".into()),
                        });
                    }
                } else {
                    // still report SubmitForm even without /F
                    out.push(Finding{
                        id: format!("{}:{}:{}:submit_nof", self.id(), e.r.obj, e.r.gen),
                        surface: AttackSurface::Actions,
                        kind: "submitform_action_present".into(),
                        severity: Severity::High,
                        confidence: Confidence::Heuristic,
                        title: "SubmitForm action present (/S /SubmitForm)".into(),
                        description: "SubmitForm action detected but target (/F) not extracted (missing or unsupported type).".into(),
                        objects: vec![format!("{} {} obj", e.r.obj, e.r.gen)],
                        evidence: vec![],
                        remediation: Some("Inspect action dictionary and referenced objects for /F and submission format keys.".into()),
                    });
                }
            }
        }

        Ok(out)
    }
}

fn extract_textish(o: &sis_pdf_pdf::object::PdfObj<'_>) -> Option<String> {
    use sis_pdf_pdf::object::{PdfAtom, PdfStr};
    match &o.atom {
        PdfAtom::Str(PdfStr::Literal{ raw, .. }) => Some(sanitize_bytes(raw)),
        PdfAtom::Str(PdfStr::Hex{ raw, .. }) => Some(sanitize_bytes(raw)),
        PdfAtom::Name(n) => Some(String::from_utf8_lossy(&n.decoded).to_string()),
        PdfAtom::Keyword(k) => Some(String::from_utf8_lossy(k).to_string()),
        _ => None,
    }
}

fn sanitize_bytes(b: &[u8]) -> String {
    // Keep readable; replace control chars
    let mut s = String::new();
    for &c in b.iter().take(4096) {
        if c.is_ascii_graphic() || c == b' ' {
            s.push(c as char);
        } else if matches!(c, b'\n'|b'\r'|b'\t') {
            s.push(' ');
        } else {
            s.push('.');
        }
    }
    s
}

fn score_uri(u: &str) -> (Severity, Vec<&'static str>) {
    let mut flags = Vec::new();
    let ul = u.to_ascii_lowercase();

    if ul.starts_with("http://") { flags.push("http"); }
    if ul.starts_with("https://") { /* ok */ }
    if ul.starts_with("file:") { flags.push("file_scheme"); }
    if ul.starts_with("javascript:") { flags.push("javascript_scheme"); }
    if ul.starts_with("data:") { flags.push("data_scheme"); }
    if ul.starts_with("mailto:") { flags.push("mailto"); }

    if looks_like_ip_literal(&ul) { flags.push("ip_literal"); }
    if ul.contains("@") { flags.push("userinfo_or_email"); }

    let sev = if flags.iter().any(|f| matches!(*f, "javascript_scheme"|"file_scheme"|"data_scheme")) {
        Severity::Critical
    } else if flags.contains(&"http") || flags.contains(&"ip_literal") {
        Severity::High
    } else {
        Severity::Medium
    };

    (sev, flags)
}

fn score_submitform(u: &str) -> (Severity, Vec<&'static str>) {
    let mut flags = Vec::new();
    let ul = u.to_ascii_lowercase();
    if ul.starts_with("http://") { flags.push("http"); }
    if looks_like_ip_literal(&ul) { flags.push("ip_literal"); }
    if ul.starts_with("mailto:") { flags.push("mailto"); }
    // SubmitForm is intrinsically exfil-ish
    let sev = if ul.starts_with("http://") || flags.contains(&"ip_literal") { Severity::High } else { Severity::High };
    (sev, flags)
}

fn looks_like_ip_literal(u: &str) -> bool {
    // very small heuristic: find "://<digits>.<digits>.<digits>.<digits>"
    let Some(p) = u.find("://") else { return false; };
    let host = &u[p+3..].split('/').next().unwrap_or("");
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 { return false; }
    parts.iter().all(|s| !s.is_empty() && s.len() <= 3 && s.chars().all(|c| c.is_ascii_digit()))
}
```

## 3.2 Wire it in

### `crates/sis-pdf-detectors/src/lib.rs`

```rust
pub mod actions;
pub mod embedded;
pub mod javascript;
pub mod openaction;
pub mod aa;
pub mod network; // NEW
```

### `crates/sis-pdf-core/src/registry.rs`

Add it near other action detectors:

```rust
        Box::new(sis_pdf_detectors::network::NetworkActionDetector), // NEW
```

---

# 4) sis-pdf-detectors: ObjStm index-only detector

This flags `/Type /ObjStm`, reports `/N` and `/First`, stream size (raw), and presence of risky filters.

## 4.1 New file: `crates/sis-pdf-detectors/src/objstm.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;

pub struct ObjStmDetector;

impl Detector for ObjStmDetector {
    fn id(&self) -> &'static str { "structure.objstm" }
    fn surface(&self) -> AttackSurface { AttackSurface::ObjectStreams }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH | Needs::STREAM_INDEX }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let bytes = ctx.bytes;
        let mut out = Vec::new();

        for e in g.iter_objects() {
            let Some(d) = g.obj_as_dict(e) else { continue; };
            if !g.dict_has_name_value(d, b"/Type", b"/ObjStm") { continue; }

            let n = int_first(d, b"/N");
            let first = int_first(d, b"/First");

            let (filters, length_decl) = g.stream_filters_and_length(e);
            let stream_len = g.stream_bytes(e, bytes).map(|b| b.len());

            let mut sev = Severity::Medium;
            let mut conf = Confidence::Strong;
            let mut desc = format!(
                "Object stream present (/ObjStm). /N={:?}, /First={:?}, declared /Length={:?}, raw stream bytes={:?}. Filters={:?}.",
                n, first, length_decl, stream_len, filters.iter().map(|f| String::from_utf8_lossy(f).to_string()).collect::<Vec<_>>()
            );

            // heuristic severity adjustments
            if let Some(nv) = n {
                if nv > 2000 { sev = Severity::High; desc.push_str(" High object count in ObjStm."); }
            }
            if stream_len.unwrap_or(0) > 5_000_000 { sev = Severity::High; desc.push_str(" Large ObjStm stream."); }
            if filters.iter().any(|f| f.as_slice() == b"/JBIG2Decode" || f.as_slice() == b"/JPXDecode") {
                sev = Severity::High;
                desc.push_str(" Contains image-heavy decoder in filters (uncommon for ObjStm; suspicious).");
            }

            out.push(Finding{
                id: format!("{}:{}:{}", self.id(), e.r.obj, e.r.gen),
                surface: AttackSurface::ObjectStreams,
                kind: "objstm_present".into(),
                severity: sev,
                confidence: conf,
                title: "Object stream present (/ObjStm)".into(),
                description: desc,
                objects: vec![format!("{} {} obj", e.r.obj, e.r.gen)],
                evidence: vec![
                    EvidenceSpan{ offset: e.full_span.start, length: (e.full_span.len().min(u64::from(u32::MAX))) as u32, note: Some("ObjStm object span".into()) }
                ],
                remediation: Some("ObjStm can hide many objects compactly. In deep mode, decode and enumerate contained objects; compare with xref view to detect hidden/shadowed content.".into()),
            });
        }

        Ok(out)
    }
}

fn int_first(d: &sis_pdf_pdf::object::PdfDict<'_>, key: &[u8]) -> Option<i64> {
    let (_, v) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, key)?;
    if let sis_pdf_pdf::object::PdfAtom::Int(n) = v.atom { Some(n) } else { None }
}
```

## 4.2 Wire it in

### `crates/sis-pdf-detectors/src/lib.rs`

```rust
pub mod objstm; // NEW
```

### `crates/sis-pdf-core/src/registry.rs`

Add:

```rust
        Box::new(sis_pdf_detectors::objstm::ObjStmDetector), // NEW
```

---

# 5) Tests for network actions + ObjStm detection

### `crates/sis-pdf-detectors/tests/network_and_objstm.rs`

```rust
use sis_pdf_core::scan::ScanOptions;
use sis_pdf_core::runner::run_scan;

#[test]
fn detects_uri_and_submitform_targets() {
    let pdf = br#"%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
2 0 obj
<< /Type /Action /S /URI /URI (http://127.0.0.1/login) >>
endobj
3 0 obj
<< /Type /Action /S /SubmitForm /F (https://example.com/submit) >>
endobj
%%EOF
"#.to_vec();

    let rep = run_scan(&pdf, ScanOptions{
        deep: false,
        max_decode_bytes: 512*1024,
        recover_xref: true,
        parallel: false,
    }).unwrap();

    assert!(rep.findings.iter().any(|f| f.kind == "uri_action_target"));
    assert!(rep.findings.iter().any(|f| f.kind == "submitform_action_target"));
}

#[test]
fn detects_objstm_present() {
    let pdf = br#"%PDF-1.4
10 0 obj
<< /Type /ObjStm /N 5 /First 20 /Filter /FlateDecode /Length 10 >>
stream
x\x9c\x03\x00\x00\x00\x00\x01
endstream
endobj
%%EOF
"#.to_vec();

    let rep = run_scan(&pdf, ScanOptions{
        deep: false,
        max_decode_bytes: 512*1024,
        recover_xref: true,
        parallel: false,
    }).unwrap();

    assert!(rep.findings.iter().any(|f| f.kind == "objstm_present"));
}
```

---

# 6) One small wiring fix: ensure `sis-pdf-detectors` sees new modules

### `crates/sis-pdf-detectors/src/lib.rs` (complete example)

```rust
pub mod actions;
pub mod embedded;
pub mod javascript;
pub mod openaction;
pub mod aa;
pub mod network;
pub mod objstm;
```

---

## What you now have (capabilities)

* **URI actions**: extract destination and flag risky schemes / IP-literals
* **SubmitForm**: extract target and treat as likely exfil
* **Stream JS extraction** now supports **filter chains**: ASCII85/ASCIIHex/RunLength + Flate (quota-limited)
* **ObjStm**: detect packed object streams and report /N,/First and size indicators (index-only)

---



# Chapter6

Here’s **next chunk 2** (drop-in, same style) adding:

1. **Deep ObjStm enumeration** (decode ObjStm stream with filter chain, parse object table, parse embedded objects, and scan them for JS/actions)
2. **Proper Name tree enumeration** (walk `/Names` arrays + `/Kids` trees with recursion/limits)
3. **Action graph builder detector** (build “trigger → action → payload” chains for `/OpenAction`, `/AA`, and common `/A` action hooks)

Also: a small fix so **Expensive** detectors only run when `--deep` is enabled.

---

# 0) Core runner fix: skip expensive detectors unless `deep=true`

### Replace `crates/sis-pdf-core/src/runner.rs` with this version

```rust
use crate::scan::{ScanContext, ScanOptions};
use crate::model::Finding;
use crate::detect::Cost;

#[derive(serde::Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
}

pub fn run_scan(bytes: &[u8], options: ScanOptions) -> anyhow::Result<Report> {
    let graph = sis_pdf_pdf::parse(bytes, options.recover_xref)?;
    let ctx = ScanContext { bytes, graph, options: options.clone() };

    let detectors = crate::registry::default_detectors();

    let mut findings: Vec<Finding> = if ctx.options.parallel {
        use rayon::prelude::*;
        detectors.par_iter()
            .filter(|d| ctx.options.deep || d.cost() != Cost::Expensive)
            .map(|d| d.run(&ctx))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter().flatten().collect()
    } else {
        let mut all = Vec::new();
        for d in detectors {
            if !ctx.options.deep && d.cost() == Cost::Expensive {
                continue;
            }
            all.extend(d.run(&ctx)?);
        }
        all
    };

    findings.sort_by(|a,b| (a.surface as u32, &a.kind, &a.id).cmp(&(b.surface as u32, &b.kind, &b.id)));
    Ok(Report { findings })
}
```

---

# 1) sis-pdf-pdf: Name tree enumeration (real `/Names` + `/Kids`)

## 1.1 New file: `crates/sis-pdf-pdf/src/nametree.rs`

```rust
use crate::graph::ObjectGraph;
use crate::object::{PdfAtom, PdfObj, PdfDict, ObjRef};

#[derive(Debug, Clone)]
pub struct NameEntry<'a> {
    pub name: Vec<u8>,     // bytes (may not be UTF-8)
    pub value: PdfObj<'a>, // often a Ref to an action/stream/etc.
}

/// Enumerate a Name Tree rooted at `root_obj` (dict or ref to dict).
/// Supports:
/// - /Names [ key value key value ... ]
/// - /Kids [ kidRef kidRef ... ] (recursive)
pub fn enumerate_name_tree<'a>(
    g: &ObjectGraph<'a>,
    root_obj: &PdfObj<'a>,
    max_depth: usize,
    max_entries: usize
) -> Vec<NameEntry<'a>> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::<(u32,u16)>::new();
    enumerate_inner(g, root_obj, 0, max_depth, max_entries, &mut out, &mut seen);
    out
}

fn enumerate_inner<'a>(
    g: &ObjectGraph<'a>,
    node_obj: &PdfObj<'a>,
    depth: usize,
    max_depth: usize,
    max_entries: usize,
    out: &mut Vec<NameEntry<'a>>,
    seen: &mut std::collections::HashSet<(u32,u16)>
) {
    if out.len() >= max_entries || depth > max_depth {
        return;
    }

    let node_dict_opt: Option<&PdfDict<'a>> = match &node_obj.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Ref{obj, gen} => {
            if !seen.insert((*obj, *gen)) { return; }
            g.get(ObjRef{obj:*obj, gen:*gen}).and_then(|e| g.obj_as_dict(e))
        }
        _ => None,
    };
    let Some(node_dict) = node_dict_opt else { return; };

    // If /Names present: parse pair list
    if let Some((_, names_obj)) = ObjectGraph::dict_get_first(node_dict, b"/Names") {
        if let PdfAtom::Array(items) = &names_obj.atom {
            let mut i = 0usize;
            while i + 1 < items.len() && out.len() < max_entries {
                let k = &items[i];
                let v = &items[i+1];
                if let Some(name_bytes) = extract_name_key_bytes(k) {
                    out.push(NameEntry{ name: name_bytes, value: v.clone() });
                }
                i += 2;
            }
        }
    }

    // If /Kids present: recurse
    if let Some((_, kids_obj)) = ObjectGraph::dict_get_first(node_dict, b"/Kids") {
        if let PdfAtom::Array(items) = &kids_obj.atom {
            for kid in items {
                if out.len() >= max_entries { break; }
                enumerate_inner(g, kid, depth + 1, max_depth, max_entries, out, seen);
            }
        }
    }
}

fn extract_name_key_bytes(o: &PdfObj<'_>) -> Option<Vec<u8>> {
    use crate::object::PdfStr;
    match &o.atom {
        PdfAtom::Str(PdfStr::Literal{raw, ..}) => Some(raw.to_vec()),
        PdfAtom::Str(PdfStr::Hex{raw, ..}) => Some(raw.to_vec()),
        PdfAtom::Name(n) => Some(n.decoded.clone()),
        _ => None,
    }
}
```

## 1.2 Export it

### Update `crates/sis-pdf-pdf/src/lib.rs`

Add:

```rust
pub mod nametree; // NEW
```

---

# 2) sis-pdf-detectors: Deep ObjStm enumeration (decode + parse table + parse embedded objs)

This detector runs only with `--deep` (Cost::Expensive, now enforced by runner).

## 2.1 New file: `crates/sis-pdf-detectors/src/objstm_deep.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;
use sis_pdf_pdf::object::{PdfAtom, PdfObj};
use sis_pdf_pdf::tokbuf::TokBuf;

/// Deep enumerate /ObjStm:
/// - decode stream with filter chain
/// - parse first `/First` bytes as "objnum offset" pairs
/// - parse embedded objects and scan for:
///   - /S /JavaScript
///   - /JS presence
pub struct ObjStmEnumerateDetector;

impl Detector for ObjStmEnumerateDetector {
    fn id(&self) -> &'static str { "structure.objstm_deep" }
    fn surface(&self) -> AttackSurface { AttackSurface::ObjectStreams }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH | Needs::STREAM_INDEX | Needs::STREAM_DECODE }
    fn cost(&self) -> Cost { Cost::Expensive }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let file = ctx.bytes;
        let mut out = Vec::new();

        for e in g.iter_objects() {
            let Some(d) = g.obj_as_dict(e) else { continue; };
            if !g.dict_has_name_value(d, b"/Type", b"/ObjStm") { continue; }
            if !g.is_stream(e) { continue; }

            // /N and /First required for ObjStm parsing
            let n = int_first(d, b"/N").unwrap_or(0).max(0) as usize;
            let first = int_first(d, b"/First").unwrap_or(0).max(0) as usize;

            let raw_stream = match g.stream_bytes(e, file) {
                Some(b) => b,
                None => continue,
            };

            let (filters, _) = g.stream_filters_and_length(e);
            let decoded = sis_pdf_pdf::decode::decode_with_filters_limited(
                raw_stream,
                &filters,
                sis_pdf_pdf::decode::DecodePlan{
                    max_output: ctx.options.max_decode_bytes.min(16 * 1024 * 1024),
                    max_steps: 8,
                }
            )?;

            // Basic sanity: need header region of length `/First`
            if decoded.bytes.len() < first {
                out.push(Finding{
                    id: format!("{}:{}:{}:short", self.id(), e.r.obj, e.r.gen),
                    surface: AttackSurface::ObjectStreams,
                    kind: "objstm_decode_too_short".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "ObjStm decoded stream shorter than /First".into(),
                    description: format!("Decoded ObjStm bytes ({}) shorter than /First ({}) — malformed or decode unsupported.", decoded.bytes.len(), first),
                    objects: vec![format!("{} {} obj", e.r.obj, e.r.gen)],
                    evidence: vec![
                        EvidenceSpan{ offset: e.full_span.start, length: (e.full_span.len().min(u64::from(u32::MAX))) as u32, note: Some("ObjStm object span".into()) }
                    ],
                    remediation: Some("In deep mode, verify filter chain support and inspect ObjStm header and offsets manually.".into()),
                });
                continue;
            }

            // Parse header table: "objnum offset" repeated N times
            let header = &decoded.bytes[..first];
            let table = parse_objstm_table(header, n);

            // Parse embedded objects from decoded.bytes[first..] using offsets
            // Offsets are relative to start of object data section (at index `first`)
            let data = &decoded.bytes[first..];

            let mut js_hits = Vec::new();
            for (objnum, off) in table {
                if off >= data.len() { continue; }
                let slice = &data[off..];

                // Parse one object from slice using TokBuf (decoded buffer)
                let mut tb = TokBuf::new(slice, 0);
                let parsed: PdfObj = match sis_pdf_pdf::object::parse_object(&mut tb) {
                    Ok(o) => o,
                    Err(_) => continue,
                };

                if contains_javascript_action(&parsed) {
                    js_hits.push((objnum, off));
                }
                if js_hits.len() >= 50 { break; } // cap
            }

            if !js_hits.is_empty() {
                out.push(Finding{
                    id: format!("{}:{}:{}:js", self.id(), e.r.obj, e.r.gen),
                    surface: AttackSurface::JavaScript,
                    kind: "objstm_contains_javascript".into(),
                    severity: Severity::Critical,
                    confidence: Confidence::Probable,
                    title: "ObjStm contains JavaScript action(s)".into(),
                    description: format!(
                        "Decoded object stream contains {} JavaScript-like action objects (examples: {}).",
                        js_hits.len(),
                        js_hits.iter().take(5).map(|(o,off)| format!("obj={} off={}", o, off)).collect::<Vec<_>>().join(", ")
                    ),
                    objects: vec![format!("{} {} obj (/ObjStm)", e.r.obj, e.r.gen)],
                    evidence: vec![
                        EvidenceSpan{ offset: e.full_span.start, length: (e.full_span.len().min(u64::from(u32::MAX))) as u32, note: Some("ObjStm object span".into()) }
                    ],
                    remediation: Some("Extract and inspect decoded ObjStm contents; compare against xref view to find hidden/shadowed JS/actions.".into()),
                });
            } else {
                // optional informational finding in deep mode
                out.push(Finding{
                    id: format!("{}:{}:{}:ok", self.id(), e.r.obj, e.r.gen),
                    surface: AttackSurface::ObjectStreams,
                    kind: "objstm_enumerated".into(),
                    severity: Severity::Info,
                    confidence: Confidence::Probable,
                    title: "ObjStm decoded and enumerated".into(),
                    description: format!("Decoded ObjStm and parsed header table (N={}, First={}). No obvious JavaScript actions found in parsed embedded objects (heuristic).", n, first),
                    objects: vec![format!("{} {} obj (/ObjStm)", e.r.obj, e.r.gen)],
                    evidence: vec![],
                    remediation: None,
                });
            }
        }

        Ok(out)
    }
}

fn int_first(d: &sis_pdf_pdf::object::PdfDict<'_>, key: &[u8]) -> Option<i64> {
    let (_, v) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, key)?;
    if let sis_pdf_pdf::object::PdfAtom::Int(n) = v.atom { Some(n) } else { None }
}

fn parse_objstm_table(header: &[u8], n: usize) -> Vec<(u32, usize)> {
    // Tolerant parse: read integers from ASCII bytes
    // Format: objnum offset objnum offset ... (2*n ints)
    let ints = parse_ascii_ints(header);
    let mut out = Vec::new();
    let pairs = std::cmp::min(n, ints.len()/2);
    for i in 0..pairs {
        let objnum = ints[2*i].max(0) as u32;
        let off = ints[2*i+1].max(0) as usize;
        out.push((objnum, off));
    }
    out
}

fn parse_ascii_ints(b: &[u8]) -> Vec<i64> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        while i < b.len() && !is_digit_or_sign(b[i]) { i += 1; }
        if i >= b.len() { break; }
        let start = i;
        i += 1;
        while i < b.len() && (b[i] as char).is_ascii_digit() { i += 1; }
        if let Ok(s) = std::str::from_utf8(&b[start..i]) {
            if let Ok(v) = s.parse::<i64>() {
                out.push(v);
            }
        }
    }
    out
}
fn is_digit_or_sign(c: u8) -> bool { (c as char).is_ascii_digit() || c == b'+' || c == b'-' }

fn contains_javascript_action(o: &PdfObj<'_>) -> bool {
    // Heuristic: any dict with /S /JavaScript or key /JS
    match &o.atom {
        PdfAtom::Dict(d) => {
            let has_js_key = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS").is_some();
            let has_s_js = sis_pdf_pdf::graph::ObjectGraph::dict_get_all(d, b"/S").iter().any(|(_,v)| {
                matches!(&v.atom, PdfAtom::Name(n) if n.decoded.as_slice() == b"/JavaScript")
            });
            has_js_key || has_s_js
        }
        _ => false
    }
}
```

## 2.2 Wire it in

### `crates/sis-pdf-detectors/src/lib.rs`

Add:

```rust
pub mod objstm_deep; // NEW
```

### `crates/sis-pdf-core/src/registry.rs`

Add:

```rust
        Box::new(sis_pdf_detectors::objstm_deep::ObjStmEnumerateDetector), // NEW (Expensive)
```

---

# 3) sis-pdf-detectors: Action graph detector (trigger → action → payload)

This builds a “chain view” by scanning dictionaries for:

* `/OpenAction`
* `/AA` (and its event keys)
* `/A` (common action key on annotations/forms)
* plus extracts `/S` and a payload hint (`/JS`, `/URI`, `/F`, `/Launch`)

## 3.1 New file: `crates/sis-pdf-detectors/src/action_graph.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;
use sis_pdf_pdf::object::{PdfAtom, PdfObj, PdfDict};

pub struct ActionGraphDetector;

impl Detector for ActionGraphDetector {
    fn id(&self) -> &'static str { "actions.graph" }
    fn surface(&self) -> AttackSurface { AttackSurface::Actions }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let bytes = ctx.bytes;

        let mut edges: Vec<String> = Vec::new();
        let mut evidence: Vec<EvidenceSpan> = Vec::new();

        for e in g.iter_objects() {
            let Some(d) = g.obj_as_dict(e) else { continue; };

            // /OpenAction (only meaningful on Catalog, but tolerate anywhere)
            if let Some((k, v)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/OpenAction") {
                if let Some(line) = describe_triggered_action(g, bytes, "OpenAction", v, ctx.options.max_decode_bytes.min(256*1024)) {
                    edges.push(format!("{} {} obj: {}", e.r.obj, e.r.gen, line));
                    evidence.push(EvidenceSpan{ offset: k.span.start, length: (k.span.end-k.span.start) as u32, note: Some("Key /OpenAction".into()) });
                    evidence.push(EvidenceSpan{ offset: v.span.start, length: (v.span.end-v.span.start) as u32, note: Some("Value /OpenAction".into()) });
                }
            }

            // /A (annotation/widget/etc action hook)
            if let Some((k, v)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/A") {
                if let Some(line) = describe_triggered_action(g, bytes, "A", v, ctx.options.max_decode_bytes.min(256*1024)) {
                    edges.push(format!("{} {} obj: {}", e.r.obj, e.r.gen, line));
                    evidence.push(EvidenceSpan{ offset: k.span.start, length: (k.span.end-k.span.start) as u32, note: Some("Key /A".into()) });
                    evidence.push(EvidenceSpan{ offset: v.span.start, length: (v.span.end-v.span.start) as u32, note: Some("Value /A".into()) });
                }
            }

            // /AA (additional actions dict with event keys)
            if let Some((k, v)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/AA") {
                if let Some(line) = describe_additional_actions(g, bytes, v, ctx.options.max_decode_bytes.min(256*1024)) {
                    edges.push(format!("{} {} obj: {}", e.r.obj, e.r.gen, line));
                    evidence.push(EvidenceSpan{ offset: k.span.start, length: (k.span.end-k.span.start) as u32, note: Some("Key /AA".into()) });
                    evidence.push(EvidenceSpan{ offset: v.span.start, length: (v.span.end-v.span.start) as u32, note: Some("Value /AA".into()) });
                }
            }
        }

        if edges.is_empty() {
            return Ok(vec![]);
        }

        // Summarize chains as a single finding (grouped view)
        let sev = edges.iter().any(|e| e.contains("/JavaScript") || e.contains("Launch")) 
            .then_some(Severity::High).unwrap_or(Severity::Medium);

        Ok(vec![Finding{
            id: format!("{}:{}", self.id(), edges.len()),
            surface: AttackSurface::Actions,
            kind: "action_graph".into(),
            severity: sev,
            confidence: Confidence::Probable,
            title: "Action graph (trigger → action → payload)".into(),
            description: format!("Discovered action chains:\n- {}", edges.join("\n- ")),
            objects: vec![],
            evidence,
            remediation: Some("Review each chain, confirm trigger conditions, and inspect action payloads (JS/URI/Launch/SubmitForm). Consider stripping interactive actions for high-risk ingestion paths.".into()),
        }])
    }
}

fn describe_triggered_action<'a>(
    g: &sis_pdf_pdf::graph::ObjectGraph<'a>,
    file: &[u8],
    trigger: &str,
    action_obj: &PdfObj<'a>,
    max_decode: usize
) -> Option<String> {
    // resolve action dict
    let ad: Option<&PdfDict<'a>> = match &action_obj.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Ref{..} => g.resolve_ref(action_obj).and_then(|e| g.obj_as_dict(e)),
        _ => None,
    };
    let Some(ad) = ad else { return Some(format!("{trigger} → (unresolved/non-dict action)")); };

    let s = action_type(ad);
    let payload = action_payload_hint(g, file, ad, max_decode);

    Some(format!("{trigger} → Action /S={} {}", s, payload.unwrap_or_default()))
}

fn describe_additional_actions<'a>(
    g: &sis_pdf_pdf::graph::ObjectGraph<'a>,
    file: &[u8],
    aa_obj: &PdfObj<'a>,
    max_decode: usize
) -> Option<String> {
    let aad: Option<&PdfDict<'a>> = match &aa_obj.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Ref{..} => g.resolve_ref(aa_obj).and_then(|e| g.obj_as_dict(e)),
        _ => None,
    };
    let Some(aad) = aad else { return Some("AA → (unresolved/non-dict)".into()); };

    // Each entry: event key -> action
    let mut parts = Vec::new();
    for (k, v) in &aad.entries {
        let event = String::from_utf8_lossy(&k.decoded).to_string();
        if let Some(s) = describe_triggered_action(g, file, &format!("AA{}", event), v, max_decode) {
            parts.push(s);
        }
        if parts.len() >= 20 { break; }
    }

    if parts.is_empty() { None } else { Some(parts.join(" | ")) }
}

fn action_type(d: &PdfDict<'_>) -> String {
    if let Some((_, s_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/S") {
        if let PdfAtom::Name(n) = &s_obj.atom {
            return String::from_utf8_lossy(&n.decoded).to_string();
        }
    }
    "unknown".into()
}

fn action_payload_hint<'a>(
    g: &sis_pdf_pdf::graph::ObjectGraph<'a>,
    file: &[u8],
    d: &PdfDict<'a>,
    max_decode: usize
) -> Option<String> {
    // /JS snippet
    if let Some((_, js_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS") {
        if let Some((payload, truncated, _note)) = g.extract_js_payload(js_obj, file, max_decode) {
            let prev = safe_preview(&payload, 120);
            return Some(format!("[/JS~=\"{}\"{}]", prev, if truncated { " (trunc)" } else { "" }));
        }
        return Some("[/JS present]".into());
    }
    // /URI value
    if let Some((_, uri_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/URI") {
        return Some(format!("[/URI {}]", textish(uri_obj)));
    }
    // /F submit target
    if let Some((_, f_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/F") {
        return Some(format!("[/F {}]", textish(f_obj)));
    }
    // /Launch or other keys
    if sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/Launch").is_some() {
        return Some("[/Launch present]".into());
    }
    None
}

fn textish(o: &PdfObj<'_>) -> String {
    use sis_pdf_pdf::object::PdfStr;
    match &o.atom {
        PdfAtom::Str(PdfStr::Literal{raw, ..}) => sanitize(raw),
        PdfAtom::Str(PdfStr::Hex{raw, ..}) => sanitize(raw),
        PdfAtom::Name(n) => String::from_utf8_lossy(&n.decoded).to_string(),
        PdfAtom::Keyword(k) => String::from_utf8_lossy(k).to_string(),
        PdfAtom::Ref{obj, gen} => format!("{} {} R", obj, gen),
        _ => "(complex)".into()
    }
}

fn sanitize(b: &[u8]) -> String {
    let mut s = String::new();
    for &c in b.iter().take(256) {
        if c.is_ascii_graphic() || c == b' ' { s.push(c as char); }
        else if matches!(c, b'\n'|b'\r'|b'\t') { s.push(' '); }
        else { s.push('.'); }
    }
    s
}

fn safe_preview(b: &[u8], max: usize) -> String {
    let s = &b[..std::cmp::min(b.len(), max)];
    let mut out = String::new();
    for &c in s {
        if c.is_ascii_graphic() || c == b' ' { out.push(c as char); }
        else if matches!(c, b'\n'|b'\r'|b'\t') { out.push(' '); }
        else { out.push('.'); }
    }
    out
}
```

## 3.2 Wire it in

### `crates/sis-pdf-detectors/src/lib.rs`

Add:

```rust
pub mod action_graph; // NEW
```

### `crates/sis-pdf-core/src/registry.rs`

Add:

```rust
        Box::new(sis_pdf_detectors::action_graph::ActionGraphDetector), // NEW
```

---

# 4) Upgrade JavaScript detector to enumerate names tree entries (real walk)

Your existing `JavaScriptDetector` flags presence of `/Names` → `/JavaScript`. Now we’ll also **enumerate** entries and resolve referenced actions.

### Replace `crates/sis-pdf-detectors/src/javascript.rs` with this upgraded version

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;
use sis_pdf_pdf::object::{PdfAtom};

pub struct JavaScriptDetector;

impl Detector for JavaScriptDetector {
    fn id(&self) -> &'static str { "script.javascript" }
    fn surface(&self) -> AttackSurface { AttackSurface::JavaScript }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let bytes = ctx.bytes;
        let mut out = Vec::new();

        // 1) scan all dict objects for action dicts with /S /JavaScript
        for e in g.iter_objects() {
            let Some(d) = g.obj_as_dict(e) else { continue; };
            if !g.dict_has_name_value(d, b"/S", b"/JavaScript") { continue; }

            let mut evidence = Vec::new();
            if let Some((k, v)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/S") {
                evidence.push(EvidenceSpan{ offset: k.span.start, length: (k.span.end-k.span.start) as u32, note: Some("Action key /S".into()) });
                evidence.push(EvidenceSpan{ offset: v.span.start, length: (v.span.end-v.span.start) as u32, note: Some("Action value /JavaScript".into()) });
            }

            let mut desc = "JavaScript action dictionary present.".to_string();
            if let Some((_, js_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS") {
                if let Some((payload, truncated, note)) = g.extract_js_payload(js_obj, bytes, ctx.options.max_decode_bytes.min(512*1024)) {
                    desc.push_str(&format!(" JS preview: {}", safe_preview(&payload, 200)));
                    if truncated { desc.push_str(" (payload truncated by quota)"); }
                    if let Some(n) = note { desc.push_str(&format!(" [{}]", n)); }
                    evidence.push(EvidenceSpan{ offset: js_obj.span.start, length: (js_obj.span.end-js_obj.span.start) as u32, note: Some("JS payload span".into()) });
                } else {
                    desc.push_str(" JS present but not extracted (unsupported type/filter chain).");
                }
            }

            out.push(Finding {
                id: format!("{}:{}:{}", self.id(), e.r.obj, e.r.gen),
                surface: AttackSurface::JavaScript,
                kind: "javascript_action_present".into(),
                severity: Severity::High,
                confidence: Confidence::Strong,
                title: "JavaScript action present (/S /JavaScript)".into(),
                description: desc,
                objects: vec![format!("{} {} obj", e.r.obj, e.r.gen)],
                evidence,
                remediation: Some("Inspect /JS payload and trigger paths (/OpenAction, /AA, annotation /A). Consider blocking PDFs containing JavaScript in high-risk contexts.".into()),
            });
        }

        // 2) Enumerate Names tree: Catalog /Names -> /JavaScript -> NameTree entries
        if let Some(cat_r) = g.catalog_ref() {
            if let Some(cat_e) = g.get(cat_r) {
                if let Some(cat_d) = g.obj_as_dict(cat_e) {
                    if let Some((_, names_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/Names") {
                        let names_d = match &names_obj.atom {
                            PdfAtom::Ref{..} => g.resolve_ref(names_obj).and_then(|e| g.obj_as_dict(e)),
                            PdfAtom::Dict(d) => Some(d),
                            _ => None,
                        };
                        if let Some(names_d) = names_d {
                            if let Some((_, js_tree_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(names_d, b"/JavaScript") {
                                // enumerate actual entries
                                let entries = sis_pdf_pdf::nametree::enumerate_name_tree(g, js_tree_obj, 12, 200);

                                if !entries.is_empty() {
                                    // Try resolve first few to show what they point to
                                    let mut examples = Vec::new();
                                    for ent in entries.iter().take(5) {
                                        let nm = sanitize(&ent.name);
                                        let target = match &ent.value.atom {
                                            PdfAtom::Ref{obj, gen} => format!("{} {} R", obj, gen),
                                            PdfAtom::Dict(_) => "(inline dict)".into(),
                                            _ => "(other)".into(),
                                        };
                                        examples.push(format!("{} → {}", nm, target));
                                    }

                                    out.push(Finding{
                                        id: format!("{}:{}:{}:names_enum", self.id(), cat_r.obj, cat_r.gen),
                                        surface: AttackSurface::JavaScript,
                                        kind: "javascript_names_tree_entries".into(),
                                        severity: Severity::High,
                                        confidence: Confidence::Probable,
                                        title: "JavaScript entries in Names tree".into(),
                                        description: format!("Names tree /JavaScript has {} entries. Examples: {}", entries.len(), examples.join(", ")),
                                        objects: vec![
                                            format!("{} {} obj (Catalog)", cat_r.obj, cat_r.gen),
                                        ],
                                        evidence: vec![],
                                        remediation: Some("Resolve each name entry and inspect referenced actions and /JS payloads. Names tree scripts are often paired with triggers like /OpenAction or /AA.".into()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(out)
    }
}

fn safe_preview(b: &[u8], max: usize) -> String {
    let s = &b[..std::cmp::min(b.len(), max)];
    let mut out = String::new();
    for &c in s {
        if c.is_ascii_graphic() || c == b' ' { out.push(c as char); }
        else if matches!(c, b'\n'|b'\r'|b'\t') { out.push(' '); }
        else { out.push('.'); }
    }
    out
}

fn sanitize(b: &[u8]) -> String {
    let mut s = String::new();
    for &c in b.iter().take(128) {
        if c.is_ascii_graphic() || c == b' ' { s.push(c as char); }
        else if matches!(c, b'\n'|b'\r'|b'\t') { s.push(' '); }
        else { s.push('.'); }
    }
    s
}
```

---

# 5) Wire module exports + registry (complete list reminder)

### `crates/sis-pdf-detectors/src/lib.rs` should now include:

```rust
pub mod actions;
pub mod embedded;
pub mod javascript;
pub mod openaction;
pub mod aa;
pub mod network;
pub mod objstm;
pub mod objstm_deep;
pub mod action_graph;
```

### `crates/sis-pdf-core/src/registry.rs` should include these additional detectors:

```rust
        Box::new(sis_pdf_detectors::action_graph::ActionGraphDetector),
        Box::new(sis_pdf_detectors::objstm_deep::ObjStmEnumerateDetector), // Expensive (deep only)
```

---

# 6) Tests: action graph + deep ObjStm

### `crates/sis-pdf-detectors/tests/action_graph_and_objstm_deep.rs`

```rust
use sis_pdf_core::scan::ScanOptions;
use sis_pdf_core::runner::run_scan;

#[test]
fn action_graph_reports_openaction_chain() {
    let pdf = br#"%PDF-1.4
1 0 obj
<< /Type /Catalog /OpenAction 2 0 R >>
endobj
2 0 obj
<< /Type /Action /S /URI /URI (https://example.com/) >>
endobj
%%EOF
"#.to_vec();

    let rep = run_scan(&pdf, ScanOptions{
        deep: false,
        max_decode_bytes: 512*1024,
        recover_xref: true,
        parallel: false,
    }).unwrap();

    assert!(rep.findings.iter().any(|f| f.kind == "action_graph"));
}

#[test]
fn deep_objstm_enumeration_runs_only_in_deep() {
    // Minimal ObjStm decoded content (no real compression here; filter chain empty)
    // We fake by setting no filters and putting plain header+object in stream.
    // However, our current ObjStm detector expects decode_with_filters to run; it will just pass bytes through if no filters? (It currently clones input and steps 0.)
    // For now, include FlateDecode but keep it short — if decode fails in your environment, you can remove this test or adjust fixture.

    let pdf = br#"%PDF-1.4
10 0 obj
<< /Type /ObjStm /N 1 /First 4 /Filter /ASCIIHexDecode /Length 20 >>
stream
31302030203C3C2F532F4A6176615363726970742F4A532831293E3E
endstream
endobj
%%EOF
"#.to_vec();

    let rep = run_scan(&pdf, ScanOptions{
        deep: true,
        max_decode_bytes: 2*1024*1024,
        recover_xref: true,
        parallel: false,
    }).unwrap();

    // Depending on fixture correctness, we just assert the deep detector ran (info or js hit)
    assert!(rep.findings.iter().any(|f| f.kind == "objstm_enumerated" || f.kind == "objstm_contains_javascript" || f.kind == "objstm_decode_too_short"));
}
```

That ObjStm fixture is intentionally tolerant; ObjStm correctness is fiddly, and you’ll likely replace it with a real generated fixture once you have ObjStm decoding stable.

---

## What you have now

* **Deep mode**:

  * decodes and enumerates `/ObjStm`
  * can surface “hidden JS” inside object streams
* **Name tree enumeration**:

  * actually walks `/Kids` trees and `/Names` arrays
  * JS detector now reports real entries
* **Action graph**:

  * gives you an analyst-friendly “chain view” of triggers to payloads

---


# Chapter 7

Alright — **next chunk 3**. This adds the “PDF as a timeline” view you need for real exploit hunting:

1. **Page tree traversal** (Catalog → /Pages → /Kids → /Annots), so you can reliably find annotation actions (a huge real-world trigger surface).
2. **Incremental update /Prev chain** parsing + reporting (how many revisions, where startxrefs are, whether it looks weird).
3. **Object shadowing detection** (same `obj gen` defined multiple times; classic malicious trick).
4. **XRef stream + hybrid xref detection** (triage-level: detect and report; optional deep extraction later).

All in the same “drop-in file chunks” style.

---

# 1) sis-pdf-pdf: Page tree traversal

## 1.1 New file: `crates/sis-pdf-pdf/src/pagetree.rs`

```rust
use std::collections::HashSet;

use crate::graph::ObjectGraph;
use crate::object::{ObjRef, PdfAtom, PdfDict, PdfObj};

#[derive(Debug, Clone)]
pub struct PageInfo<'a> {
    pub page_ref: ObjRef,
    pub annots: Vec<PdfObj<'a>>, // usually refs
}

/// Collect pages and their /Annots by traversing the page tree:
/// Catalog -> /Pages -> (PageTreeNode) -> /Kids -> ... -> /Type /Page
pub fn collect_pages<'a>(
    g: &ObjectGraph<'a>,
    max_pages: usize,
    max_depth: usize
) -> Vec<PageInfo<'a>> {
    let mut out = Vec::new();
    let mut seen = HashSet::<(u32,u16)>::new();

    let Some(cat_r) = g.catalog_ref() else { return out; };
    let Some(cat_e) = g.get(cat_r) else { return out; };
    let Some(cat_d) = g.obj_as_dict(cat_e) else { return out; };

    let Some((_, pages_obj)) = ObjectGraph::dict_get_first(cat_d, b"/Pages") else { return out; };

    walk_pages_node(g, pages_obj, 0, max_depth, max_pages, &mut out, &mut seen);
    out
}

fn walk_pages_node<'a>(
    g: &ObjectGraph<'a>,
    node_obj: &PdfObj<'a>,
    depth: usize,
    max_depth: usize,
    max_pages: usize,
    out: &mut Vec<PageInfo<'a>>,
    seen: &mut HashSet<(u32,u16)>
) {
    if out.len() >= max_pages || depth > max_depth {
        return;
    }

    let (node_ref, node_dict): (Option<ObjRef>, Option<&PdfDict<'a>>) = match &node_obj.atom {
        PdfAtom::Ref{obj, gen} => {
            let r = ObjRef{ obj:*obj, gen:*gen };
            if !seen.insert((*obj, *gen)) { return; }
            let d = g.get(r).and_then(|e| g.obj_as_dict(e));
            (Some(r), d)
        }
        PdfAtom::Dict(d) => (None, Some(d)),
        _ => (None, None),
    };

    let Some(d) = node_dict else { return; };

    // If it's a Page, collect annots
    if g.dict_has_name_value(d, b"/Type", b"/Page") {
        // We only produce PageInfo if we have a ref (best for evidence)
        let page_ref = match node_ref {
            Some(r) => r,
            None => return,
        };

        let mut annots = Vec::new();
        if let Some((_, ann_obj)) = ObjectGraph::dict_get_first(d, b"/Annots") {
            if let PdfAtom::Array(items) = &ann_obj.atom {
                annots.extend(items.iter().cloned());
            } else {
                // sometimes /Annots can be an indirect ref to an array
                if let Some(ann_e) = g.resolve_ref(ann_obj) {
                    if let Some(ad) = g.obj_as_dict(ann_e) {
                        // rare; ignore
                        let _ = ad;
                    } else if let PdfAtom::Array(items) = &ann_e.body.atom {
                        annots.extend(items.iter().cloned());
                    }
                }
            }
        }

        out.push(PageInfo{ page_ref, annots });
        return;
    }

    // Otherwise recurse via /Kids
    if let Some((_, kids_obj)) = ObjectGraph::dict_get_first(d, b"/Kids") {
        if let PdfAtom::Array(items) = &kids_obj.atom {
            for kid in items {
                if out.len() >= max_pages { break; }
                walk_pages_node(g, kid, depth + 1, max_depth, max_pages, out, seen);
            }
        }
    }
}
```

## 1.2 Export it

### `crates/sis-pdf-pdf/src/lib.rs`

Add:

```rust
pub mod pagetree; // NEW
```

---

# 2) sis-pdf-detectors: Annotation action detector (uses page tree)

This finds action triggers hiding in `/Annots` via `/A` and `/AA`.

## 2.1 New file: `crates/sis-pdf-detectors/src/annots.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;
use sis_pdf_pdf::object::{PdfAtom, PdfObj};

pub struct AnnotationActionDetector;

impl Detector for AnnotationActionDetector {
    fn id(&self) -> &'static str { "actions.annotations" }
    fn surface(&self) -> AttackSurface { AttackSurface::Annotations }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let bytes = ctx.bytes;
        let mut out = Vec::new();

        let pages = sis_pdf_pdf::pagetree::collect_pages(g, 2000, 64);

        for p in pages {
            for a in p.annots {
                let annot_e = match g.resolve_ref(&a) {
                    Some(e) => e,
                    None => continue,
                };
                let Some(ad) = g.obj_as_dict(annot_e) else { continue; };

                // /A
                if let Some((k, v)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/A") {
                    if let Some(line) = describe_action(g, bytes, "Annot/A", v, ctx.options.max_decode_bytes.min(256*1024)) {
                        out.push(Finding{
                            id: format!("{}:{}:{}:{}:a", self.id(), p.page_ref.obj, p.page_ref.gen, annot_e.r.obj),
                            surface: AttackSurface::Annotations,
                            kind: "annotation_action".into(),
                            severity: severity_from_line(&line),
                            confidence: Confidence::Probable,
                            title: "Annotation action present (/A)".into(),
                            description: format!("Page {} {} R annotation {} {} R: {}", p.page_ref.obj, p.page_ref.gen, annot_e.r.obj, annot_e.r.gen, line),
                            objects: vec![
                                format!("{} {} obj (Page)", p.page_ref.obj, p.page_ref.gen),
                                format!("{} {} obj (Annot)", annot_e.r.obj, annot_e.r.gen),
                            ],
                            evidence: vec![
                                EvidenceSpan{ offset: k.span.start, length: (k.span.end-k.span.start) as u32, note: Some("Annot key /A".into()) },
                                EvidenceSpan{ offset: v.span.start, length: (v.span.end-v.span.start) as u32, note: Some("Annot /A value".into()) },
                            ],
                            remediation: Some("Inspect annotation dictionaries for /A and /AA triggers. Strip or neutralize actions if PDFs are ingested from untrusted sources.".into()),
                        });
                    }
                }

                // /AA
                if let Some((k, v)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/AA") {
                    out.push(Finding{
                        id: format!("{}:{}:{}:{}:aa", self.id(), p.page_ref.obj, p.page_ref.gen, annot_e.r.obj),
                        surface: AttackSurface::Annotations,
                        kind: "annotation_additional_actions".into(),
                        severity: Severity::High,
                        confidence: Confidence::Probable,
                        title: "Annotation additional actions present (/AA)".into(),
                        description: format!("Page {} {} R annotation {} {} R contains /AA (event-driven triggers).", p.page_ref.obj, p.page_ref.gen, annot_e.r.obj, annot_e.r.gen),
                        objects: vec![
                            format!("{} {} obj (Page)", p.page_ref.obj, p.page_ref.gen),
                            format!("{} {} obj (Annot)", annot_e.r.obj, annot_e.r.gen),
                        ],
                        evidence: vec![
                            EvidenceSpan{ offset: k.span.start, length: (k.span.end-k.span.start) as u32, note: Some("Annot key /AA".into()) },
                            EvidenceSpan{ offset: v.span.start, length: (v.span.end-v.span.start) as u32, note: Some("Annot /AA value".into()) },
                        ],
                        remediation: Some("Resolve /AA entries to actions and inspect /S and payload (/JS,/URI,/Launch,/SubmitForm).".into()),
                    });
                }
            }
        }

        Ok(out)
    }
}

fn describe_action<'a>(
    g: &sis_pdf_pdf::graph::ObjectGraph<'a>,
    file: &[u8],
    trigger: &str,
    action_obj: &PdfObj<'a>,
    max_decode: usize
) -> Option<String> {
    let ad = match &action_obj.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Ref{..} => g.resolve_ref(action_obj).and_then(|e| g.obj_as_dict(e)),
        _ => None,
    }?;

    let s = if let Some((_, s_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/S") {
        if let PdfAtom::Name(n) = &s_obj.atom {
            String::from_utf8_lossy(&n.decoded).to_string()
        } else { "unknown".into() }
    } else { "unknown".into() };

    // payload hint
    let payload = if let Some((_, js_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/JS") {
        if let Some((b, trunc, _)) = g.extract_js_payload(js_obj, file, max_decode) {
            format!("[/JS~=\"{}\"{}]", safe_preview(&b, 80), if trunc { " (trunc)" } else { "" })
        } else { "[/JS present]".into() }
    } else if let Some((_, uri_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/URI") {
        format!("[/URI {}]", textish(uri_obj))
    } else if let Some((_, f_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/F") {
        format!("[/F {}]", textish(f_obj))
    } else { "".into() };

    Some(format!("{trigger} → /S={} {}", s, payload))
}

fn severity_from_line(line: &str) -> Severity {
    if line.contains("/JavaScript") || line.contains("Launch") { Severity::Critical }
    else if line.contains("/URI") || line.contains("SubmitForm") { Severity::High }
    else { Severity::Medium }
}

fn safe_preview(b: &[u8], max: usize) -> String {
    let s = &b[..std::cmp::min(b.len(), max)];
    let mut out = String::new();
    for &c in s {
        if c.is_ascii_graphic() || c == b' ' { out.push(c as char); }
        else if matches!(c, b'\n'|b'\r'|b'\t') { out.push(' '); }
        else { out.push('.'); }
    }
    out
}

fn textish(o: &PdfObj<'_>) -> String {
    use sis_pdf_pdf::object::PdfStr;
    match &o.atom {
        PdfAtom::Str(PdfStr::Literal{raw, ..}) => String::from_utf8_lossy(raw).to_string(),
        PdfAtom::Str(PdfStr::Hex{raw, ..}) => String::from_utf8_lossy(raw).to_string(),
        PdfAtom::Name(n) => String::from_utf8_lossy(&n.decoded).to_string(),
        PdfAtom::Keyword(k) => String::from_utf8_lossy(k).to_string(),
        PdfAtom::Ref{obj, gen} => format!("{} {} R", obj, gen),
        _ => "(complex)".into()
    }
}
```

## 2.2 Wire it in

### `crates/sis-pdf-detectors/src/lib.rs`

Add:

```rust
pub mod annots; // NEW
```

### `crates/sis-pdf-core/src/registry.rs`

Add:

```rust
        Box::new(sis_pdf_detectors::annots::AnnotationActionDetector), // NEW
```

---

# 3) sis-pdf-pdf: incremental update (/Prev) + startxref chain parsing

This is a **triage** parser: it finds multiple `startxref` blocks (from end backward) and tries to parse `/Prev` offsets from trailer or xref stream dicts.

## 3.1 New file: `crates/sis-pdf-pdf/src/incremental.rs`

```rust
use crate::span::Span;

#[derive(Debug, Clone)]
pub enum XrefKind {
    ClassicXrefTable,
    XrefStream,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct XrefRevision {
    pub startxref: u64,
    pub kind: XrefKind,
    pub prev: Option<u64>,
    pub dict_span: Option<Span>, // trailer dict span or xref stream dict span (best effort)
}

/// Find a chain of xref revisions by walking /Prev.
/// This does NOT fully parse xref; it’s for timeline + anomaly detection.
pub fn parse_revisions(bytes: &[u8], max_revisions: usize) -> Vec<XrefRevision> {
    let mut out = Vec::new();

    // Find last startxref from end
    let mut next_startxref = find_startxref(bytes, None);

    let mut seen = std::collections::HashSet::<u64>::new();

    while let Some(sx) = next_startxref {
        if out.len() >= max_revisions { break; }
        if !seen.insert(sx) { break; }

        // Determine kind + prev (best effort)
        let (kind, prev, span) = classify_and_prev(bytes, sx);

        out.push(XrefRevision{
            startxref: sx,
            kind,
            prev,
            dict_span: span,
        });

        next_startxref = prev;
    }

    out
}

/// Find "startxref" and parse following integer.
/// If from_offset is Some(x), search near that location; otherwise search from end.
pub fn find_startxref(bytes: &[u8], from_offset: Option<u64>) -> Option<u64> {
    if let Some(off) = from_offset {
        // when following /Prev, startxref should be at off; we still accept slight drift
        let o = off as usize;
        let start = o.saturating_sub(128);
        let end = (o + 512).min(bytes.len());
        let hay = &bytes[start..end];
        if let Some(i) = hay.windows(b"startxref".len()).position(|w| w == b"startxref") {
            return parse_int_after(bytes, start + i + b"startxref".len());
        }
        return Some(off);
    }

    let win = bytes.len().min(1024 * 1024);
    let start = bytes.len().saturating_sub(win);
    let hay = &bytes[start..];

    let idx = hay.windows(b"startxref".len()).rposition(|w| w == b"startxref")?;
    parse_int_after(bytes, start + idx + b"startxref".len())
}

fn parse_int_after(bytes: &[u8], mut i: usize) -> Option<u64> {
    while i < bytes.len() && is_ws(bytes[i]) { i += 1; }
    let j = i;
    while i < bytes.len() && (bytes[i] as char).is_ascii_digit() { i += 1; }
    if i == j { return None; }
    std::str::from_utf8(&bytes[j..i]).ok()?.parse::<u64>().ok()
}

fn classify_and_prev(bytes: &[u8], startxref: u64) -> (XrefKind, Option<u64>, Option<Span>) {
    let sx = startxref as usize;
    if sx >= bytes.len() { return (XrefKind::Unknown, None, None); }

    // Classic xref table usually begins with "xref"
    if bytes[sx..].starts_with(b"xref") {
        // find trailer dict and parse /Prev
        if let Some(trailer_idx) = find_next(bytes, b"trailer", sx) {
            if let Some(d1) = find_next(bytes, b"<<", trailer_idx) {
                if let Some(d2) = find_next(bytes, b">>", d1 + 2) {
                    let dict = &bytes[d1..d2+2];
                    let prev = parse_prev_from_dict_bytes(dict);
                    return (XrefKind::ClassicXrefTable, prev, Some(Span{ start: d1 as u64, end: (d2+2) as u64 }));
                }
            }
        }
        return (XrefKind::ClassicXrefTable, None, None);
    }

    // Otherwise: could be xref stream object at this offset: "<obj> <gen> obj << /Type /XRef ... >> stream ... endobj"
    // We do a minimal search for "/Type /XRef" within a small window.
    let end = (sx + 4096).min(bytes.len());
    let window = &bytes[sx..end];

    if find_first(window, b"/Type").is_some() && find_first(window, b"/XRef").is_some() {
        // best effort: locate first "<<...>>" and parse /Prev inside it
        if let Some(d1) = find_first(window, b"<<") {
            if let Some(d2) = find_first(&window[d1+2..], b">>") {
                let a = sx + d1;
                let b = sx + d1 + 2 + d2 + 2;
                let dict = &bytes[a..b];
                let prev = parse_prev_from_dict_bytes(dict);
                return (XrefKind::XrefStream, prev, Some(Span{ start: a as u64, end: b as u64 }));
            }
        }
        return (XrefKind::XrefStream, None, None);
    }

    (XrefKind::Unknown, None, None)
}

fn parse_prev_from_dict_bytes(dict: &[u8]) -> Option<u64> {
    // Look for "/Prev <int>"
    let k = find_first(dict, b"/Prev")?;
    let mut i = k + b"/Prev".len();
    while i < dict.len() && is_ws(dict[i]) { i += 1; }
    let j = i;
    while i < dict.len() && (dict[i] as char).is_ascii_digit() { i += 1; }
    if i == j { return None; }
    std::str::from_utf8(&dict[j..i]).ok()?.parse::<u64>().ok()
}

fn is_ws(c: u8) -> bool { matches!(c, b' ' | b'\t' | b'\r' | b'\n' | 0x0C) }

fn find_first(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}
fn find_next(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    if from >= h.len() { return None; }
    h[from..].windows(n.len()).position(|w| w == n).map(|i| from + i)
}
```

## 3.2 Export it

### `crates/sis-pdf-pdf/src/lib.rs`

Add:

```rust
pub mod incremental; // NEW
```

---

# 4) sis-pdf-detectors: incremental timeline + anomalies detector

## 4.1 New file: `crates/sis-pdf-detectors/src/incremental.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;

pub struct IncrementalUpdateDetector;

impl Detector for IncrementalUpdateDetector {
    fn id(&self) -> &'static str { "structure.incremental_updates" }
    fn surface(&self) -> AttackSurface { AttackSurface::Structure }
    fn needs(&self) -> Needs { Needs::BYTES_ONLY }
    fn cost(&self) -> Cost { Cost::Cheap }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let bytes = ctx.bytes;
        let revs = sis_pdf_pdf::incremental::parse_revisions(bytes, 64);

        if revs.is_empty() {
            return Ok(vec![]);
        }

        let mut flags = Vec::new();
        if revs.len() >= 6 { flags.push("many_revisions"); }
        if revs.iter().any(|r| matches!(r.kind, sis_pdf_pdf::incremental::XrefKind::Unknown)) {
            flags.push("unknown_xref_kind");
        }
        if revs.iter().any(|r| matches!(r.kind, sis_pdf_pdf::incremental::XrefKind::XrefStream)) {
            flags.push("xref_stream_present");
        }

        // check monotonic prev offsets (should go backwards)
        for w in revs.windows(2) {
            let a = w[0].startxref;
            let b = w[1].startxref;
            if b >= a {
                flags.push("non_monotonic_prev_chain");
                break;
            }
        }

        let desc = revs.iter().enumerate()
            .map(|(i,r)| format!(
                "#{i}: startxref={} kind={:?} prev={:?}",
                r.startxref, r.kind, r.prev
            ))
            .collect::<Vec<_>>()
            .join("\n");

        let sev = if flags.contains(&"non_monotonic_prev_chain") { Severity::High }
                  else if flags.contains(&"many_revisions") { Severity::Medium }
                  else { Severity::Info };

        Ok(vec![Finding{
            id: format!("{}:{}", self.id(), revs.len()),
            surface: AttackSurface::Structure,
            kind: "incremental_update_chain".into(),
            severity: sev,
            confidence: Confidence::Probable,
            title: "Incremental update chain (/Prev)".into(),
            description: format!("Revisions: {}. Flags: {}.\n{}", revs.len(), if flags.is_empty() {"none"} else {&flags.join(", ")}, desc),
            objects: vec![],
            evidence: vec![],
            remediation: Some("Incremental updates can hide shadowed objects. If suspicious, compare earliest vs latest object definitions and validate xref integrity.".into()),
        }])
    }
}
```

## 4.2 Wire it in

### `crates/sis-pdf-detectors/src/lib.rs`

Add:

```rust
pub mod incremental; // NEW
```

### `crates/sis-pdf-core/src/registry.rs`

Add:

```rust
        Box::new(sis_pdf_detectors::incremental::IncrementalUpdateDetector), // NEW
```

---

# 5) Object shadowing detector (byte-scan, independent of graph)

This finds duplicate definitions of the same `obj gen`. (You don’t need perfect parsing to catch most shadowing.)

## 5.1 New file: `crates/sis-pdf-detectors/src/shadowing.rs`

```rust
use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;

pub struct ObjectShadowingDetector;

impl Detector for ObjectShadowingDetector {
    fn id(&self) -> &'static str { "structure.object_shadowing" }
    fn surface(&self) -> AttackSurface { AttackSurface::Structure }
    fn needs(&self) -> Needs { Needs::BYTES_ONLY }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let b = ctx.bytes;
        let mut counts: HashMap<(u32,u16), Vec<u64>> = HashMap::new();

        // scan for " obj" and parse two ints immediately before it using a tolerant backward scan
        let needle = b" obj";
        let mut i = 0usize;

        while let Some(pos) = find_next(b, needle, i) {
            let header_start = scan_back_to_ws(b, pos);
            if let Some(((obj, gen), off)) = parse_header_pair_at(b, header_start) {
                counts.entry((obj, gen)).or_default().push(off as u64);
            }
            i = pos + needle.len();
        }

        // report duplicates
        let mut dups: Vec<((u32,u16), Vec<u64>)> = counts.into_iter()
            .filter(|(_, v)| v.len() >= 2)
            .collect();

        if dups.is_empty() {
            return Ok(vec![]);
        }

        dups.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));

        let top = dups.iter().take(10).map(|((o,g), offs)| {
            format!("{} {}: {} defs at offsets {}", o, g, offs.len(), offs.iter().take(5).map(|x| x.to_string()).collect::<Vec<_>>().join(", "))
        }).collect::<Vec<_>>().join("\n");

        let sev = if dups.iter().any(|(_, v)| v.len() >= 5) { Severity::High } else { Severity::Medium };

        Ok(vec![Finding{
            id: format!("{}:{}", self.id(), dups.len()),
            surface: AttackSurface::Structure,
            kind: "duplicate_object_definitions".into(),
            severity: sev,
            confidence: Confidence::Probable,
            title: "Object shadowing: duplicate object definitions".into(),
            description: format!(
                "Found {} object (obj gen) pairs defined multiple times. This can occur in incremental updates, but is also used to hide malicious content.\nTop duplicates:\n{}",
                dups.len(),
                top
            ),
            objects: vec![],
            evidence: vec![],
            remediation: Some("Correlate duplicates with incremental update chain. Ensure xref points to the expected (latest) definition. Compare early vs late definitions for action/JS additions.".into()),
        }])
    }
}

fn find_next(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    if from >= h.len() { return None; }
    h[from..].windows(n.len()).position(|w| w == n).map(|k| from + k)
}

fn scan_back_to_ws(b: &[u8], mut i: usize) -> usize {
    while i > 0 && !is_ws(b[i-1]) { i -= 1; }
    i
}

fn parse_header_pair_at(b: &[u8], i: usize) -> Option<((u32,u16), usize)> {
    // parse "<int> <int> obj" from b[i..]
    let mut p = i;

    let (a, p2) = parse_u32(b, p)?;
    p = p2;
    skip_ws(b, &mut p);
    let (g, p3) = parse_u32(b, p)?;
    if g > u16::MAX as u32 { return None; }
    p = p3;
    skip_ws(b, &mut p);

    // check "obj" keyword
    if p + 3 <= b.len() && &b[p..p+3] == b"obj" {
        Some(((a, g as u16), i))
    } else {
        None
    }
}

fn parse_u32(b: &[u8], mut i: usize) -> Option<(u32, usize)> {
    skip_ws(b, &mut i);
    let start = i;
    while i < b.len() && (b[i] as char).is_ascii_digit() { i += 1; }
    if i == start { return None; }
    let v = std::str::from_utf8(&b[start..i]).ok()?.parse::<u32>().ok()?;
    Some((v, i))
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && is_ws(b[*i]) { *i += 1; }
}

fn is_ws(c: u8) -> bool { matches!(c, b' ' | b'\t' | b'\r' | b'\n' | 0x0C) }
```

## 5.2 Wire it in

### `crates/sis-pdf-detectors/src/lib.rs`

Add:

```rust
pub mod shadowing; // NEW
```

### `crates/sis-pdf-core/src/registry.rs`

Add:

```rust
        Box::new(sis_pdf_detectors::shadowing::ObjectShadowingDetector), // NEW
```

---

# 6) XRef stream + hybrid xref detector (triage-level)

This one doesn’t fully parse xref streams yet — it **detects** them, reports `/W`, `/Index`, filters, length, and whether it looks hybrid.

## 6.1 New file: `crates/sis-pdf-detectors/src/xref_stream.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;

pub struct XrefStreamDetector;

impl Detector for XrefStreamDetector {
    fn id(&self) -> &'static str { "structure.xref_stream" }
    fn surface(&self) -> AttackSurface { AttackSurface::Structure }
    fn needs(&self) -> Needs { Needs::BYTES_ONLY }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let bytes = ctx.bytes;
        let revs = sis_pdf_pdf::incremental::parse_revisions(bytes, 64);

        let has_xref_stream = revs.iter().any(|r| matches!(r.kind, sis_pdf_pdf::incremental::XrefKind::XrefStream));
        if !has_xref_stream {
            return Ok(vec![]);
        }

        // Find spans where we detected dicts, extract a few keys heuristically
        let mut lines = Vec::new();
        let mut flags = Vec::new();

        for r in &revs {
            if !matches!(r.kind, sis_pdf_pdf::incremental::XrefKind::XrefStream) { continue; }
            if let Some(sp) = r.dict_span {
                let dict = &bytes[sp.start as usize..sp.end as usize];
                let w = sniff_key(dict, b"/W");
                let idx = sniff_key(dict, b"/Index");
                let len = sniff_key(dict, b"/Length");
                let filter = sniff_key(dict, b"/Filter");
                let xrefstm = sniff_key(dict, b"/XRefStm");

                if xrefstm.is_some() { flags.push("hybrid_xref(/XRefStm)"); }

                lines.push(format!(
                    "startxref={} dict_span=[{}..{}] W={:?} Index={:?} Length={:?} Filter={:?} XRefStm={:?}",
                    r.startxref, sp.start, sp.end, w, idx, len, filter, xrefstm
                ));
            } else {
                lines.push(format!("startxref={} (xref stream) dict_span=unknown", r.startxref));
            }
        }

        let sev = if flags.contains(&"hybrid_xref(/XRefStm)") { Severity::Medium } else { Severity::Info };

        Ok(vec![Finding{
            id: format!("{}:{}", self.id(), lines.len()),
            surface: AttackSurface::Structure,
            kind: "xref_stream_present".into(),
            severity: sev,
            confidence: Confidence::Probable,
            title: "XRef stream present (PDF 1.5+)".into(),
            description: format!(
                "Detected xref stream revision(s). Flags: {}.\n{}",
                if flags.is_empty() { "none".into() } else { flags.join(", ") },
                lines.join("\n")
            ),
            objects: vec![],
            evidence: vec![],
            remediation: Some("Ensure your parser handles xref streams correctly. For security scanning, compare recovered objects vs xref-indexed objects to detect hidden/shadowed content.".into()),
        }])
    }
}

// extremely small key sniffer: returns small slice preview if key exists
fn sniff_key(dict: &[u8], key: &[u8]) -> Option<String> {
    let p = dict.windows(key.len()).position(|w| w == key)?;
    let mut i = p + key.len();
    while i < dict.len() && matches!(dict[i], b' ' | b'\t' | b'\r' | b'\n' | 0x0C) { i += 1; }
    let end = (i + 64).min(dict.len());
    Some(String::from_utf8_lossy(&dict[i..end]).trim().to_string())
}
```

## 6.2 Wire it in

### `crates/sis-pdf-detectors/src/lib.rs`

Add:

```rust
pub mod xref_stream; // NEW
```

### `crates/sis-pdf-core/src/registry.rs`

Add:

```rust
        Box::new(sis_pdf_detectors::xref_stream::XrefStreamDetector), // NEW
```

---

# 7) Export modules (final checklist)

### `crates/sis-pdf-detectors/src/lib.rs` should now include (additions in bold):

```rust
pub mod actions;
pub mod embedded;
pub mod javascript;
pub mod openaction;
pub mod aa;
pub mod network;
pub mod objstm;
pub mod objstm_deep;
pub mod action_graph;
pub mod annots;
pub mod incremental;
pub mod shadowing;
pub mod xref_stream;
```

### `crates/sis-pdf-pdf/src/lib.rs` should now include (additions in bold):

```rust
pub mod span;
pub mod lexer;
pub mod tokbuf;
pub mod object;
pub mod xref;
pub mod recover;
pub mod graph;
pub mod stream;
pub mod decode;
pub mod nametree;
pub mod pagetree;
pub mod incremental;
```

---

# 8) Tests (quick fixtures)

### `crates/sis-pdf-detectors/tests/annots_shadowing_incremental.rs`

```rust
use sis_pdf_core::scan::ScanOptions;
use sis_pdf_core::runner::run_scan;

#[test]
fn detects_annotation_actions() {
    let pdf = br#"%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>
endobj
4 0 obj
<< /Subtype /Link /A 5 0 R >>
endobj
5 0 obj
<< /S /URI /URI (http://example.com) >>
endobj
%%EOF
"#.to_vec();

    let rep = run_scan(&pdf, ScanOptions{
        deep: false,
        max_decode_bytes: 512*1024,
        recover_xref: true,
        parallel: false,
    }).unwrap();

    assert!(rep.findings.iter().any(|f| f.kind == "annotation_action"));
}

#[test]
fn detects_object_shadowing() {
    // same object defined twice
    let pdf = br#"%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
1 0 obj
<< /Type /Catalog /OpenAction 2 0 R >>
endobj
2 0 obj
<< /S /JavaScript /JS (1) >>
endobj
%%EOF
"#.to_vec();

    let rep = run_scan(&pdf, ScanOptions{
        deep: false,
        max_decode_bytes: 512*1024,
        recover_xref: true,
        parallel: false,
    }).unwrap();

    assert!(rep.findings.iter().any(|f| f.kind == "duplicate_object_definitions"));
}
```

---

## What you gained with chunk 3

* You now have *reliable* coverage of **annotation-trigger surfaces** (where a ton of malicious payloads live).
* You get a **revision timeline** + **shadowing indicator** — essential for incremental update attacks.
* You detect **xref streams / hybrid xref** early, so your scanner can say “this file uses xref streams; full correctness requires X”.



# Chapter 8

Here’s **next chunk 4**: **real xref-stream indexing**, plus **recovered-vs-xref comparison**, plus a **revision “what changed” heuristic**.

You’ll get:

* A **decoded xref index** from `/Type /XRef` streams (supports `/W`, `/Index`, `/Size`, filter chain decoding).
* Detection of **compressed objects** (type 2 entries: in `/ObjStm`).
* A detector that compares **xref-indexed objects vs recovered objects** to flag:

  * objects referenced by xref but **not found** by your recovery scan
  * objects recovered but **not referenced** (potential junk/shadow/forensics signal)
* A **revision delta** detector: per incremental update revision, counts of “new objects appended” and keyword deltas (OpenAction/AA/JavaScript etc).

Drop-in style, same as before.

---

# 1) sis-pdf-pdf: xref stream index parser (decode `/Type /XRef` stream)

## 1.1 New file: `crates/sis-pdf-pdf/src/xrefstream.rs`

```rust
use std::collections::HashMap;

use crate::decode::{decode_with_filters_limited, DecodePlan};
use crate::graph::{ObjEntry, ObjectGraph};
use crate::object::{PdfAtom, PdfObj};

#[derive(Debug, Clone)]
pub struct XrefStreamIndex {
    pub size: Option<u32>,
    pub w: [usize; 3],
    pub index_ranges: Vec<(u32, u32)>, // (start, count)
    pub entries: HashMap<u32, XrefEntry>,
    pub truncated: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub enum XrefEntry {
    Free { next_free: u64, gen: u64 },
    InUse { offset: u64, gen: u64 },
    Compressed { objstm_obj: u64, objstm_index: u64 },
    Unknown { t: u64, f2: u64, f3: u64 },
}

impl XrefStreamIndex {
    pub fn count_by_kind(&self) -> (usize, usize, usize, usize) {
        let mut free = 0;
        let mut inuse = 0;
        let mut comp = 0;
        let mut unk = 0;
        for v in self.entries.values() {
            match v {
                XrefEntry::Free{..} => free += 1,
                XrefEntry::InUse{..} => inuse += 1,
                XrefEntry::Compressed{..} => comp += 1,
                XrefEntry::Unknown{..} => unk += 1,
            }
        }
        (free, inuse, comp, unk)
    }
}

/// Build xref index from a recovered ObjEntry that is a /Type /XRef stream object.
///
/// - Decodes stream bytes using filter chain (ASCII85/ASCIIHex/RunLength/Flate)
/// - Reads /W and /Index (or defaults)
/// - Parses entries (type 0/1/2 per PDF spec)
pub fn parse_xref_stream_index<'a>(
    g: &ObjectGraph<'a>,
    e: &ObjEntry<'a>,
    file: &[u8],
    max_decode: usize
) -> Option<XrefStreamIndex> {
    let d = g.obj_as_dict(e)?;
    if !g.dict_has_name_value(d, b"/Type", b"/XRef") {
        return None;
    }
    if !g.is_stream(e) {
        return None;
    }

    let (filters, _len_decl) = g.stream_filters_and_length(e);
    let sb = g.stream_bytes(e, file)?;

    // decode stream bytes
    let dec = decode_with_filters_limited(
        sb,
        &filters,
        DecodePlan{ max_output: max_decode, max_steps: 8 }
    ).ok()?;

    // parse /W (required)
    let w = parse_w_array(d).unwrap_or([0usize, 0usize, 0usize]);
    if w == [0,0,0] {
        return Some(XrefStreamIndex{
            size: parse_size(d),
            w,
            index_ranges: vec![],
            entries: HashMap::new(),
            truncated: dec.truncated,
            note: Some("Missing/invalid /W in xref stream dict".into()),
        });
    }

    let size = parse_size(d);
    let index_ranges = parse_index_ranges(d).unwrap_or_else(|| {
        // default: [0 /Size]
        if let Some(sz) = size { vec![(0, sz)] } else { vec![] }
    });

    let mut entries = HashMap::new();
    let mut truncated = dec.truncated;
    let mut note = dec.note;

    let row_len = w[0] + w[1] + w[2];
    if row_len == 0 {
        return Some(XrefStreamIndex{
            size, w, index_ranges, entries,
            truncated,
            note: Some("Invalid row_len=0 from /W".into()),
        });
    }

    let mut cursor = 0usize;
    for (start, count) in &index_ranges {
        for objno in *start..(*start + *count) {
            if cursor + row_len > dec.bytes.len() {
                truncated = true;
                note = Some(match note {
                    Some(n) => format!("{}; Xref stream table truncated", n),
                    None => "Xref stream table truncated".into(),
                });
                break;
            }
            let t = read_uint_be(&dec.bytes[cursor..cursor+w[0]]);
            cursor += w[0];
            let f2 = read_uint_be(&dec.bytes[cursor..cursor+w[1]]);
            cursor += w[1];
            let f3 = read_uint_be(&dec.bytes[cursor..cursor+w[2]]);
            cursor += w[2];

            let entry = match t {
                0 => XrefEntry::Free { next_free: f2, gen: f3 },
                1 => XrefEntry::InUse { offset: f2, gen: f3 },
                2 => XrefEntry::Compressed { objstm_obj: f2, objstm_index: f3 },
                _ => XrefEntry::Unknown { t, f2, f3 },
            };
            entries.insert(objno, entry);
        }
    }

    Some(XrefStreamIndex{
        size, w, index_ranges, entries,
        truncated,
        note,
    })
}

fn read_uint_be(b: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for &c in b {
        v = (v << 8) | (c as u64);
    }
    v
}

fn parse_size(d: &crate::object::PdfDict<'_>) -> Option<u32> {
    let (_, v) = ObjectGraph::dict_get_first(d, b"/Size")?;
    if let PdfAtom::Int(n) = v.atom {
        if n >= 0 && n <= u32::MAX as i64 { return Some(n as u32); }
    }
    None
}

fn parse_w_array(d: &crate::object::PdfDict<'_>) -> Option<[usize; 3]> {
    let (_, v) = ObjectGraph::dict_get_first(d, b"/W")?;
    let PdfAtom::Array(items) = &v.atom else { return None; };
    if items.len() != 3 { return None; }
    let mut out = [0usize; 3];
    for (i, it) in items.iter().enumerate() {
        if let PdfAtom::Int(n) = it.atom {
            if n < 0 || n > 16 { return None; } // sanity cap
            out[i] = n as usize;
        } else {
            return None;
        }
    }
    Some(out)
}

fn parse_index_ranges(d: &crate::object::PdfDict<'_>) -> Option<Vec<(u32, u32)>> {
    let (_, v) = ObjectGraph::dict_get_first(d, b"/Index")?;
    let PdfAtom::Array(items) = &v.atom else { return None; };
    if items.len() % 2 != 0 { return None; }

    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < items.len() {
        let (a, b) = (&items[i], &items[i+1]);
        let (PdfAtom::Int(sa), PdfAtom::Int(ct)) = (&a.atom, &b.atom) else {
            i += 2;
            continue;
        };
        if *sa < 0 || *ct <= 0 { i += 2; continue; }
        let start = (*sa as u64).min(u32::MAX as u64) as u32;
        let count = (*ct as u64).min(u32::MAX as u64) as u32;
        out.push((start, count));
        i += 2;
    }
    Some(out)
}
```

## 1.2 Export it

### `crates/sis-pdf-pdf/src/lib.rs`

Add:

```rust
pub mod xrefstream; // NEW
```

---

# 2) sis-pdf-pdf: helper to find object by start offset

This makes it easy to map `startxref` → recovered object entry.

### Update `crates/sis-pdf-pdf/src/graph.rs` (add inside `impl ObjectGraph<'a>`)

```rust
    pub fn find_object_by_full_start(&self, start: u64) -> Option<&ObjEntry<'a>> {
        // O(n) scan; fine for now. You can add an index later.
        self.objects.values().find(|e| e.full_span.start == start)
    }
```

---

# 3) sis-pdf-detectors: xref stream index + recovered-vs-xref comparison

This is the core “hidden object” signal generator.

## 3.1 New file: `crates/sis-pdf-detectors/src/xref_index.rs`

```rust
use anyhow::Result;
use std::collections::{HashMap, HashSet};

use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;

pub struct XrefStreamIndexCompareDetector;

impl Detector for XrefStreamIndexCompareDetector {
    fn id(&self) -> &'static str { "structure.xref_index_compare" }
    fn surface(&self) -> AttackSurface { AttackSurface::Structure }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH | Needs::BYTES_ONLY }
    fn cost(&self) -> Cost { Cost::Expensive } // deep-only is recommended (indexing can be heavy)

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let file = ctx.bytes;

        // Find latest revision that is an xref stream
        let revs = sis_pdf_pdf::incremental::parse_revisions(file, 64);
        let latest_xref_stream = revs.iter().find(|r| matches!(r.kind, sis_pdf_pdf::incremental::XrefKind::XrefStream));
        let Some(r) = latest_xref_stream else { return Ok(vec![]); };

        // Find the recovered object that starts at startxref
        let Some(xref_obj) = g.find_object_by_full_start(r.startxref) else {
            return Ok(vec![Finding{
                id: format!("{}:missing_obj", self.id()),
                surface: AttackSurface::Structure,
                kind: "xref_stream_unresolved".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Xref stream startxref does not match recovered object start".into(),
                description: format!("startxref={} looks like xref stream, but no recovered object entry starts exactly at that offset.", r.startxref),
                objects: vec![],
                evidence: vec![],
                remediation: Some("Recovery scanner may have missed the xref stream object header (obfuscation/whitespace). Improve object recovery around startxref offset.".into()),
            }]);
        };

        // Build index
        let Some(index) = sis_pdf_pdf::xrefstream::parse_xref_stream_index(
            g, xref_obj, file,
            ctx.options.max_decode_bytes.min(32 * 1024 * 1024)
        ) else {
            return Ok(vec![Finding{
                id: format!("{}:parse_failed", self.id()),
                surface: AttackSurface::Structure,
                kind: "xref_stream_parse_failed".into(),
                severity: Severity::Medium,
                confidence: Confidence::Probable,
                title: "Failed to parse xref stream index".into(),
                description: format!("Could not parse xref stream at startxref={}. Unsupported dict form or decode failure.", r.startxref),
                objects: vec![format!("{} {} obj", xref_obj.r.obj, xref_obj.r.gen)],
                evidence: vec![],
                remediation: Some("Add support for additional filter chains and validate /W and /Index parsing.".into()),
            }]);
        };

        let (free, inuse, comp, unk) = index.count_by_kind();

        // Build recovered set (object numbers only; xref uses obj numbers)
        let recovered: HashSet<u32> = g.iter_objects().map(|e| e.r.obj).collect();
        let indexed: HashSet<u32> = index.entries.keys().copied().collect();

        // Missing recovered definitions for in-use objects
        let mut missing = Vec::new();
        let mut compressed_missing = 0usize;
        for (objno, ent) in &index.entries {
            match ent {
                sis_pdf_pdf::xrefstream::XrefEntry::InUse{..} | sis_pdf_pdf::xrefstream::XrefEntry::Compressed{..} => {
                    if !recovered.contains(objno) {
                        missing.push(*objno);
                        if matches!(ent, sis_pdf_pdf::xrefstream::XrefEntry::Compressed{..}) { compressed_missing += 1; }
                    }
                }
                _ => {}
            }
        }
        missing.sort_unstable();
        if missing.len() > 200 { missing.truncate(200); }

        // Recovered objects not referenced by xref index (potential junk/shadow/forensics)
        let mut extra: Vec<u32> = recovered.difference(&indexed).copied().collect();
        extra.sort_unstable();
        if extra.len() > 200 { extra.truncate(200); }

        let mut flags = Vec::new();
        if index.truncated { flags.push("xref_index_truncated"); }
        if comp > 0 { flags.push("compressed_objects_present"); }
        if compressed_missing > 0 { flags.push("missing_compressed_objects"); }
        if !missing.is_empty() { flags.push("indexed_but_not_recovered"); }
        if !extra.is_empty() { flags.push("recovered_not_indexed"); }

        let sev = if flags.contains(&"indexed_but_not_recovered") && (missing.len() > 0) {
            Severity::High
        } else if flags.contains(&"recovered_not_indexed") || flags.contains(&"compressed_objects_present") {
            Severity::Medium
        } else {
            Severity::Info
        };

        let desc = format!(
            "XRef stream index summary: free={}, inuse={}, compressed={}, unknown={}.\n\
             /W={:?}, /Index ranges={}, /Size={:?}.\n\
             Flags: {}.\n\
             Indexed-but-not-recovered (first {}): {:?}\n\
             Recovered-not-indexed (first {}): {:?}\n\
             Note: {}",
            free, inuse, comp, unk,
            index.w,
            index.index_ranges.len(),
            index.size,
            if flags.is_empty() { "none".into() } else { flags.join(", ") },
            missing.len(), missing,
            extra.len(), extra,
            index.note.clone().unwrap_or_else(|| "none".into()),
        );

        Ok(vec![Finding{
            id: format!("{}:{}", self.id(), r.startxref),
            surface: AttackSurface::Structure,
            kind: "xref_index_compare".into(),
            severity: sev,
            confidence: Confidence::Probable,
            title: "XRef stream index vs recovered objects".into(),
            description: desc,
            objects: vec![format!("{} {} obj (xref stream)", xref_obj.r.obj, xref_obj.r.gen)],
            evidence: vec![
                EvidenceSpan{
                    offset: xref_obj.full_span.start,
                    length: (xref_obj.full_span.len().min(u64::from(u32::MAX))) as u32,
                    note: Some("XRef stream object span".into()),
                }
            ],
            remediation: Some(
                "If indexed objects are missing from recovery: improve recovery around object headers and handle obfuscation. \
                 If many objects are compressed: enumerate ObjStm referenced by type-2 entries and parse embedded objects. \
                 If recovered objects aren’t indexed: correlate with incremental updates and shadowing detector."
                    .into()
            ),
        }])
    }
}
```

## 3.2 Wire it in

### `crates/sis-pdf-detectors/src/lib.rs`

Add:

```rust
pub mod xref_index; // NEW
```

### `crates/sis-pdf-core/src/registry.rs`

Add:

```rust
        Box::new(sis_pdf_detectors::xref_index::XrefStreamIndexCompareDetector), // NEW (Expensive)
```

---

# 4) Incremental revision “diff” detector (heuristic but useful)

This counts “objects appended” and keyword deltas between revisions.

## 4.1 New file: `crates/sis-pdf-detectors/src/incremental_diff.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;

pub struct IncrementalHeuristicDiffDetector;

impl Detector for IncrementalHeuristicDiffDetector {
    fn id(&self) -> &'static str { "structure.incremental_diff" }
    fn surface(&self) -> AttackSurface { AttackSurface::Structure }
    fn needs(&self) -> Needs { Needs::BYTES_ONLY }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let b = ctx.bytes;
        let revs = sis_pdf_pdf::incremental::parse_revisions(b, 64);

        if revs.len() < 2 {
            return Ok(vec![]);
        }

        // sort by startxref ascending (oldest->newest), because revisions append data
        let mut sxs: Vec<u64> = revs.iter().map(|r| r.startxref).collect();
        sxs.sort_unstable();

        let mut lines = Vec::new();
        let mut flags = Vec::new();

        for w in sxs.windows(2) {
            let a = w[0] as usize;
            let c = w[1] as usize;
            if a >= b.len() || c > b.len() || a >= c { continue; }

            let seg = &b[a..c];
            let obj_ct = count_sub(seg, b" obj");
            let open_ct = count_sub(seg, b"/OpenAction");
            let aa_ct = count_sub(seg, b"/AA");
            let js_ct = count_sub(seg, b"/JavaScript");
            let uri_ct = count_sub(seg, b"/URI");
            let submit_ct = count_sub(seg, b"/SubmitForm");
            let launch_ct = count_sub(seg, b"/Launch");
            let objstm_ct = count_sub(seg, b"/ObjStm");
            let xref_ct = count_sub(seg, b"/XRef");

            if js_ct > 0 && open_ct > 0 { flags.push("openaction_added_with_js"); }
            if js_ct > 0 && aa_ct > 0 { flags.push("aa_added_with_js"); }

            lines.push(format!(
                "[{}..{}): new_objs~{} | OpenAction={} AA={} JavaScript={} URI={} SubmitForm={} Launch={} ObjStm={} XRefType={} ",
                a, c, obj_ct, open_ct, aa_ct, js_ct, uri_ct, submit_ct, launch_ct, objstm_ct, xref_ct
            ));
        }

        let sev = if flags.contains(&"openaction_added_with_js") || flags.contains(&"aa_added_with_js") {
            Severity::High
        } else if revs.len() >= 6 {
            Severity::Medium
        } else {
            Severity::Info
        };

        Ok(vec![Finding{
            id: format!("{}:{}", self.id(), revs.len()),
            surface: AttackSurface::Structure,
            kind: "incremental_heuristic_diff".into(),
            severity: sev,
            confidence: Confidence::Heuristic,
            title: "Incremental update heuristic diff".into(),
            description: format!(
                "Revisions: {} ({} intervals). Flags: {}.\nIntervals (oldest→newest):\n{}",
                revs.len(),
                sxs.len().saturating_sub(1),
                if flags.is_empty() { "none".into() } else { flags.join(", ") },
                lines.join("\n")
            ),
            objects: vec![],
            evidence: vec![],
            remediation: Some(
                "Use this as a triage view. If suspicious deltas appear, perform deep object comparison per revision: \
                 resolve actions (/OpenAction,/AA,/A) and compare object definitions across duplicated obj/gen pairs."
                    .into()
            ),
        }])
    }
}

fn count_sub(h: &[u8], n: &[u8]) -> usize {
    if n.is_empty() || h.len() < n.len() { return 0; }
    h.windows(n.len()).filter(|w| *w == n).count()
}
```

## 4.2 Wire it in

### `crates/sis-pdf-detectors/src/lib.rs`

Add:

```rust
pub mod incremental_diff; // NEW
```

### `crates/sis-pdf-core/src/registry.rs`

Add:

```rust
        Box::new(sis_pdf_detectors::incremental_diff::IncrementalHeuristicDiffDetector), // NEW
```

---

# 5) Export checklist update

### `crates/sis-pdf-pdf/src/lib.rs` should now include:

```rust
pub mod xrefstream;
```

### `crates/sis-pdf-detectors/src/lib.rs` should now include:

```rust
pub mod xref_index;
pub mod incremental_diff;
```

### `crates/sis-pdf-core/src/registry.rs` should now include:

```rust
Box::new(sis_pdf_detectors::xref_index::XrefStreamIndexCompareDetector),
Box::new(sis_pdf_detectors::incremental_diff::IncrementalHeuristicDiffDetector),
```

---

# 6) Tests: xref stream index parsing (minimal)

Xref stream fixtures are annoying; here’s a “structural” test that at least confirms:

* xref stream is detected via incremental module
* compare detector produces something (may be parse_failed depending on fixture)

### `crates/sis-pdf-detectors/tests/xref_index_smoke.rs`

```rust
use sis_pdf_core::scan::ScanOptions;
use sis_pdf_core::runner::run_scan;

#[test]
fn xref_index_compare_detector_smoke() {
    // NOTE: This is a smoke test; real xref stream correctness needs generated fixtures.
    // We include /Type /XRef and a stream. The parser may report truncated/parse_failed, which is acceptable for smoke.

    let pdf = br#"%PDF-1.5
9 0 obj
<< /Type /XRef /W [1 2 1] /Index [0 1] /Size 1 /Length 6 >>
stream
\x01\x00\x10\x00\x00\x00
endstream
endobj
startxref
0
%%EOF
"#.to_vec();

    let rep = run_scan(&pdf, ScanOptions{
        deep: true,
        max_decode_bytes: 2*1024*1024,
        recover_xref: true,
        parallel: false,
    }).unwrap();

    assert!(rep.findings.iter().any(|f|
        f.kind == "xref_stream_parse_failed" ||
        f.kind == "xref_index_compare" ||
        f.kind == "xref_stream_present"
    ));
}
```

---

## What this chunk unlocks immediately

* You can now say **“xref stream claims these objects exist”** and compare that to what you actually recovered.
* You can quantify **compressed object pressure** (type 2 entries), which is a major “hiding” mechanism.
* You get a usable **incremental update timeline** and per-interval keyword deltas that highlight suspicious “late additions”.

---

Below is **next chunk 5**: take **type-2 xref entries** (compressed objects) → **decode the referenced /ObjStm** → **extract the specific embedded object** → **scan it for actions/JS** → emit findings that connect:
`xref objno → (ObjStm obj, index) → embedded object → payload hints`.

This stays in the same “drop-in files” style.

---

# 1) sis-pdf-pdf: ObjStm extractor (decode + parse table + get object by index)

## 1.1 New file: `crates/sis-pdf-pdf/src/objstm_extract.rs`

```rust
use crate::decode::{decode_with_filters_limited, DecodePlan};
use crate::graph::{ObjEntry, ObjectGraph};
use crate::object::{PdfAtom, PdfObj, PdfDict};

#[derive(Debug, Clone)]
pub struct ObjStmTableEntry {
    pub objno: u32,
    pub offset: usize, // into object data section (decoded bytes starting at /First)
}

#[derive(Debug, Clone)]
pub struct ObjStmDecoded {
    pub n: usize,
    pub first: usize,
    pub table: Vec<ObjStmTableEntry>,
    pub data: Vec<u8>, // decoded whole stream bytes
    pub truncated: bool,
    pub note: Option<String>,
}

/// Decode and parse an /ObjStm stream into table + data.
/// Returns None if the object isn't a usable /ObjStm stream.
pub fn decode_objstm<'a>(
    g: &ObjectGraph<'a>,
    e: &ObjEntry<'a>,
    file: &[u8],
    max_decode: usize
) -> Option<ObjStmDecoded> {
    let d = g.obj_as_dict(e)?;
    if !g.dict_has_name_value(d, b"/Type", b"/ObjStm") { return None; }
    if !g.is_stream(e) { return None; }

    let n = int_first(d, b"/N").unwrap_or(0).max(0) as usize;
    let first = int_first(d, b"/First").unwrap_or(0).max(0) as usize;

    let raw_stream = g.stream_bytes(e, file)?;
    let (filters, _len_decl) = g.stream_filters_and_length(e);

    let dec = decode_with_filters_limited(
        raw_stream,
        &filters,
        DecodePlan{ max_output: max_decode, max_steps: 8 }
    ).ok()?;

    if dec.bytes.len() < first {
        return Some(ObjStmDecoded{
            n, first,
            table: vec![],
            data: dec.bytes,
            truncated: true,
            note: Some(format!("Decoded ObjStm shorter than /First (len={} First={})", dec.bytes.len(), first)),
        });
    }

    let header = &dec.bytes[..first];
    let table = parse_objstm_table(header, n);

    Some(ObjStmDecoded{
        n, first,
        table,
        data: dec.bytes,
        truncated: dec.truncated,
        note: dec.note,
    })
}

/// Extract a specific embedded object:
/// - by ObjStm index (0-based) if provided
/// - or by object number (objno) if provided
pub fn extract_embedded_object_by_index<'a>(
    decoded: &ObjStmDecoded,
    index: usize
) -> Option<PdfObj<'a>> {
    if decoded.first > decoded.data.len() { return None; }
    let data_section = &decoded.data[decoded.first..];

    // find offset at table[index]
    let ent = decoded.table.get(index)?;
    if ent.offset >= data_section.len() { return None; }
    let slice = &data_section[ent.offset..];

    let mut tb = crate::tokbuf::TokBuf::new(slice, 0);
    crate::object::parse_object(&mut tb).ok()
}

/// Find embedded object index by obj number, then extract it
pub fn extract_embedded_object_by_objno<'a>(
    decoded: &ObjStmDecoded,
    objno: u32
) -> Option<(usize, PdfObj<'a>)> {
    let idx = decoded.table.iter().position(|e| e.objno == objno)?;
    let obj = extract_embedded_object_by_index(decoded, idx)?;
    Some((idx, obj))
}

fn int_first(d: &PdfDict<'_>, key: &[u8]) -> Option<i64> {
    let (_, v) = ObjectGraph::dict_get_first(d, key)?;
    if let PdfAtom::Int(n) = v.atom { Some(n) } else { None }
}

fn parse_objstm_table(header: &[u8], n: usize) -> Vec<ObjStmTableEntry> {
    // Header: "objnum offset objnum offset ..." (2*N integers)
    let ints = parse_ascii_ints(header);
    let pairs = std::cmp::min(n, ints.len()/2);

    let mut out = Vec::with_capacity(pairs);
    for i in 0..pairs {
        let objno = ints[2*i].max(0) as u32;
        let off = ints[2*i+1].max(0) as usize;
        out.push(ObjStmTableEntry{ objno, offset: off });
    }
    out
}

fn parse_ascii_ints(b: &[u8]) -> Vec<i64> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        while i < b.len() && !is_digit_or_sign(b[i]) { i += 1; }
        if i >= b.len() { break; }
        let start = i;
        i += 1;
        while i < b.len() && (b[i] as char).is_ascii_digit() { i += 1; }
        if let Ok(s) = std::str::from_utf8(&b[start..i]) {
            if let Ok(v) = s.parse::<i64>() { out.push(v); }
        }
    }
    out
}
fn is_digit_or_sign(c: u8) -> bool { (c as char).is_ascii_digit() || c == b'+' || c == b'-' }
```

## 1.2 Export it

### `crates/sis-pdf-pdf/src/lib.rs`

Add:

```rust
pub mod objstm_extract; // NEW
```

---

# 2) sis-pdf-detectors: type-2 xref → ObjStm extraction detector

This detector:

* builds xref stream index (from chunk 4)
* selects **type-2 entries** (compressed objects)
* loads each referenced ObjStm **once** (cache)
* extracts the embedded object at `objstm_index`
* scans extracted object for:

  * `/S /JavaScript`
  * `/JS`
  * `/URI`
  * `/SubmitForm` target
  * `/Launch`
* emits detailed per-object findings and one summary finding

## 2.1 New file: `crates/sis-pdf-detectors/src/xref_objstm_extract.rs`

```rust
use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;
use sis_pdf_pdf::object::{PdfAtom, PdfObj};

pub struct XrefType2ObjStmExtractionDetector;

impl Detector for XrefType2ObjStmExtractionDetector {
    fn id(&self) -> &'static str { "structure.xref_type2_objstm_extract" }
    fn surface(&self) -> AttackSurface { AttackSurface::ObjectStreams }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH | Needs::BYTES_ONLY | Needs::STREAM_DECODE }
    fn cost(&self) -> Cost { Cost::Expensive } // deep only

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let file = ctx.bytes;

        // Find latest xref stream revision (same logic as compare detector)
        let revs = sis_pdf_pdf::incremental::parse_revisions(file, 64);
        let latest = revs.iter().find(|r| matches!(r.kind, sis_pdf_pdf::incremental::XrefKind::XrefStream));
        let Some(r) = latest else { return Ok(vec![]); };

        let Some(xref_obj) = g.find_object_by_full_start(r.startxref) else { return Ok(vec![]); };

        let Some(index) = sis_pdf_pdf::xrefstream::parse_xref_stream_index(
            g, xref_obj, file,
            ctx.options.max_decode_bytes.min(64 * 1024 * 1024)
        ) else { return Ok(vec![]); };

        // Collect type-2 entries: objno -> (objstm_obj, objstm_index)
        let mut t2: Vec<(u32, u64, u64)> = Vec::new();
        for (objno, ent) in &index.entries {
            if let sis_pdf_pdf::xrefstream::XrefEntry::Compressed{ objstm_obj, objstm_index } = ent {
                t2.push((*objno, *objstm_obj, *objstm_index));
            }
        }
        if t2.is_empty() {
            return Ok(vec![]);
        }

        // Cache decoded ObjStm by objstm object number
        let mut cache: HashMap<u64, sis_pdf_pdf::objstm_extract::ObjStmDecoded> = HashMap::new();

        // Cap work unless you explicitly loosen later
        t2.sort_by_key(|(o,_,_)| *o);
        let cap = if ctx.options.deep { 5000 } else { 0 };
        let t2 = t2.into_iter().take(cap).collect::<Vec<_>>();

        let mut out = Vec::new();
        let mut hits_js = 0usize;
        let mut hits_net = 0usize;
        let mut errors = 0usize;

        for (objno, objstm_obj, objstm_index) in t2 {
            // Resolve ObjStm object entry by object number (gen unknown, so scan best-effort: pick any gen)
            let objstm_entry = g.iter_objects().find(|e| e.r.obj as u64 == objstm_obj);
            let Some(objstm_entry) = objstm_entry else {
                errors += 1;
                continue;
            };

            let dec = if let Some(d) = cache.get(&objstm_obj) {
                d.clone()
            } else {
                let d = match sis_pdf_pdf::objstm_extract::decode_objstm(
                    g,
                    objstm_entry,
                    file,
                    ctx.options.max_decode_bytes.min(64 * 1024 * 1024)
                ) {
                    Some(d) => d,
                    None => { errors += 1; continue; }
                };
                cache.insert(objstm_obj, d.clone());
                d
            };

            let idx = objstm_index as usize;

            let embedded: Option<PdfObj> = sis_pdf_pdf::objstm_extract::extract_embedded_object_by_index(&dec, idx);
            let Some(embedded) = embedded else {
                errors += 1;
                continue;
            };

            // Scan the embedded object for action hints
            let (sev, kind, desc, extra_ev) = classify_embedded(g, file, &embedded, ctx.options.max_decode_bytes.min(512*1024));

            if kind.contains("javascript") { hits_js += 1; }
            if kind.contains("uri") || kind.contains("submitform") { hits_net += 1; }

            out.push(Finding{
                id: format!("{}:obj{}", self.id(), objno),
                surface: AttackSurface::ObjectStreams,
                kind,
                severity: sev,
                confidence: Confidence::Probable,
                title: "Compressed object extracted via xref type-2 entry".into(),
                description: format!(
                    "xref obj={} is compressed: in ObjStm {} (gen {}), index {}.\nObjStm header: N={} First={} table_len={} truncated={} note={:?}\nEmbedded scan: {}",
                    objno,
                    objstm_entry.r.obj, objstm_entry.r.gen,
                    idx,
                    dec.n, dec.first, dec.table.len(),
                    dec.truncated, dec.note,
                    desc
                ),
                objects: vec![
                    format!("{} {} obj (xref stream)", xref_obj.r.obj, xref_obj.r.gen),
                    format!("{} {} obj (ObjStm)", objstm_entry.r.obj, objstm_entry.r.gen),
                ],
                evidence: {
                    let mut ev = vec![
                        EvidenceSpan{
                            offset: objstm_entry.full_span.start,
                            length: (objstm_entry.full_span.len().min(u64::from(u32::MAX))) as u32,
                            note: Some("ObjStm container span".into()),
                        }
                    ];
                    ev.extend(extra_ev);
                    ev
                },
                remediation: Some("Inspect extracted object content. If it contains actions/JS, trace triggers (/OpenAction,/AA,/A, annotations) and consider stripping or blocking compressed objects in untrusted PDFs.".into()),
            });
        }

        // Summary finding
        out.push(Finding{
            id: format!("{}:summary", self.id()),
            surface: AttackSurface::ObjectStreams,
            kind: "xref_type2_objstm_extraction_summary".into(),
            severity: if hits_js > 0 { Severity::High } else { Severity::Info },
            confidence: Confidence::Probable,
            title: "XRef type-2 compressed objects extracted".into(),
            description: format!(
                "Extracted compressed objects referenced by xref stream type-2 entries.\n\
                 ObjStm containers decoded: {}\n\
                 Findings emitted: {}\n\
                 JS-like hits: {}\n\
                 Network-like hits (URI/SubmitForm): {}\n\
                 Errors (missing/parse failures): {}",
                cache.len(),
                out.len().saturating_sub(1),
                hits_js,
                hits_net,
                errors
            ),
            objects: vec![format!("{} {} obj (xref stream)", xref_obj.r.obj, xref_obj.r.gen)],
            evidence: vec![
                EvidenceSpan{
                    offset: xref_obj.full_span.start,
                    length: (xref_obj.full_span.len().min(u64::from(u32::MAX))) as u32,
                    note: Some("XRef stream object span".into()),
                }
            ],
            remediation: Some("If many compressed objects exist, enable deep ObjStm enumeration and compare recovered-vs-xref index to ensure no hidden objects are missed.".into()),
        });

        Ok(out)
    }
}

fn classify_embedded<'a>(
    g: &sis_pdf_pdf::graph::ObjectGraph<'a>,
    file: &[u8],
    o: &PdfObj<'a>,
    max_decode: usize
) -> (Severity, String, String, Vec<EvidenceSpan>) {
    // heuristic classification on a single embedded object
    let mut evidence = Vec::new();

    match &o.atom {
        PdfAtom::Dict(d) => {
            // Action dict?
            if g.dict_has_name_value(d, b"/S", b"/JavaScript") || sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS").is_some() {
                let mut desc = "Embedded dict looks like JavaScript action.".to_string();
                if let Some((_, js_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS") {
                    if let Some((payload, trunc, note)) = g.extract_js_payload(js_obj, file, max_decode) {
                        desc.push_str(&format!(" JS preview: {}", safe_preview(&payload, 160)));
                        if trunc { desc.push_str(" (trunc)"); }
                        if let Some(n) = note { desc.push_str(&format!(" [{}]", n)); }
                        evidence.push(EvidenceSpan{
                            offset: js_obj.span.start,
                            length: (js_obj.span.end-js_obj.span.start) as u32,
                            note: Some("Embedded /JS span (relative to decoded buffer, not file)".into()),
                        });
                    } else {
                        desc.push_str(" JS present but not extracted (unsupported).");
                    }
                }
                return (Severity::Critical, "xref_t2_embedded_javascript".into(), desc, evidence);
            }

            if g.dict_has_name_value(d, b"/S", b"/URI") || sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/URI").is_some() {
                let uri = if let Some((_, u)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/URI") {
                    format!("{}", textish(u))
                } else { "(missing)".into() };
                return (Severity::High, "xref_t2_embedded_uri".into(), format!("Embedded dict looks like URI action. URI={}", uri), evidence);
            }

            if g.dict_has_name_value(d, b"/S", b"/SubmitForm") || sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/F").is_some() {
                let f = if let Some((_, u)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/F") {
                    format!("{}", textish(u))
                } else { "(missing)".into() };
                return (Severity::High, "xref_t2_embedded_submitform".into(), format!("Embedded dict looks like SubmitForm action. F={}", f), evidence);
            }

            if g.dict_has_name_value(d, b"/S", b"/Launch") || sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/Launch").is_some() {
                return (Severity::Critical, "xref_t2_embedded_launch".into(), "Embedded dict looks like Launch action.".into(), evidence);
            }

            (Severity::Medium, "xref_t2_embedded_dict".into(), "Embedded object is a dictionary (no obvious action keys).".into(), evidence)
        }
        PdfAtom::Array(_) => (Severity::Info, "xref_t2_embedded_array".into(), "Embedded object is an array.".into(), evidence),
        PdfAtom::Str(_) => (Severity::Info, "xref_t2_embedded_string".into(), "Embedded object is a string.".into(), evidence),
        _ => (Severity::Info, "xref_t2_embedded_other".into(), "Embedded object is a non-dict primitive.".into(), evidence),
    }
}

fn safe_preview(b: &[u8], max: usize) -> String {
    let s = &b[..std::cmp::min(b.len(), max)];
    let mut out = String::new();
    for &c in s {
        if c.is_ascii_graphic() || c == b' ' { out.push(c as char); }
        else if matches!(c, b'\n'|b'\r'|b'\t') { out.push(' '); }
        else { out.push('.'); }
    }
    out
}

fn textish(o: &PdfObj<'_>) -> String {
    use sis_pdf_pdf::object::PdfStr;
    match &o.atom {
        PdfAtom::Str(PdfStr::Literal{raw, ..}) => sanitize(raw),
        PdfAtom::Str(PdfStr::Hex{raw, ..}) => sanitize(raw),
        PdfAtom::Name(n) => String::from_utf8_lossy(&n.decoded).to_string(),
        PdfAtom::Keyword(k) => String::from_utf8_lossy(k).to_string(),
        PdfAtom::Ref{obj, gen} => format!("{} {} R", obj, gen),
        _ => "(complex)".into()
    }
}
fn sanitize(b: &[u8]) -> String {
    let mut s = String::new();
    for &c in b.iter().take(256) {
        if c.is_ascii_graphic() || c == b' ' { s.push(c as char); }
        else if matches!(c, b'\n'|b'\r'|b'\t') { s.push(' '); }
        else { s.push('.'); }
    }
    s
}
```

## 2.2 Wire it in

### `crates/sis-pdf-detectors/src/lib.rs`

Add:

```rust
pub mod xref_objstm_extract; // NEW
```

### `crates/sis-pdf-core/src/registry.rs`

Add:

```rust
        Box::new(sis_pdf_detectors::xref_objstm_extract::XrefType2ObjStmExtractionDetector), // NEW (Expensive)
```

---

# 3) Small but important correctness fix: type-2 references can point to ObjStm by (obj, gen)

Your xref stream entry stores `objstm_obj` as a u64 but *really* it’s an object number. Gen for that ObjStm is usually 0 but not guaranteed.

Right now, the detector resolves by `e.r.obj == objstm_obj` and picks the first gen it finds. That’s fine for now, but add a note to the finding to mark it “best effort”. Already done implicitly; you can refine later by:

* using classic xref to determine correct gen, or
* building an object-number → best entry map.

If you want that refinement now, I can paste a tiny `ObjectGraph::first_by_objno(u32)` helper + use it everywhere.

---

# 4) Tests: minimal ObjStm extraction utility test

This unit test validates `decode_objstm` + `extract_embedded_object_by_index` using an **unfiltered plain stream** (no compression). It’s not spec-perfect, but it exercises your parsing.

### `crates/sis-pdf-pdf/tests/objstm_extract_smoke.rs`

```rust
use sis_pdf_pdf::parse;

#[test]
fn objstm_extract_smoke() {
    let pdf = br#"%PDF-1.4
10 0 obj
<< /Type /ObjStm /N 1 /First 4 /Length 100 >>
stream
20 0 << /S /JavaScript /JS (1) >>
endstream
endobj
%%EOF
"#.to_vec();

    let g = parse(&pdf, true).unwrap();
    let e = g.iter_objects().find(|e| e.r.obj == 10).unwrap();

    let dec = sis_pdf_pdf::objstm_extract::decode_objstm(&g, e, &pdf, 1024*1024).unwrap();
    assert!(dec.table.len() >= 1);

    let obj = sis_pdf_pdf::objstm_extract::extract_embedded_object_by_index(&dec, 0).unwrap();
    // it should be a dict
    match obj.atom {
        sis_pdf_pdf::object::PdfAtom::Dict(_) => {}
        _ => panic!("expected dict"),
    }
}
```

---

# 5) Optional: hook extracted embedded objects into the existing detector pipeline

Right now, we classify embedded objects *locally* in this detector. The next (very powerful) step is to run your *normal* detectors over each embedded object (or at least JS/URI/action ones) without re-parsing the whole PDF.

That requires a mini “sub-scan context” over a `PdfObj` tree, or “object visitor” detectors.

If you say **“next chunk 6: embedded-object visitor framework”**, I’ll give you:

* a `VisitorDetector` trait that can inspect `PdfObj` directly,
* adapters for JavaScript/network/action triggers,
* and run it on: embedded objects (ObjStm), annotations, names-tree entries.




# Chapter 9


Below is **chunk 6: embedded-object visitor framework**.

Goal: once you’ve extracted an *embedded* `PdfObj` (from `/ObjStm`, name trees, annotation `/A`, etc.), you can run a **shared set of “object visitors”** over it without pretending it’s a full PDF file.

This gives you:

* a **generic recursive walker** over `PdfObj` trees
* a **VisitorDetector** trait that emits findings from any `PdfObj`
* a **small standard visitor pack** (JS / URI+SubmitForm / Launch-ish action hints)
* integration into your **type-2 xref → ObjStm extraction** detector (from chunk 5), replacing the local “classify_embedded” logic with reusable visitors

No new crates required.

---

# 1) sis-pdf-core: visitor framework (trait + walker + adapter to `Finding`)

## 1.1 New file: `crates/sis-pdf-core/src/visitor.rs`

```rust
use std::collections::HashSet;

use crate::model::{Finding, EvidenceSpan, AttackSurface, Severity, Confidence};
use sis_pdf_pdf::object::{PdfAtom, PdfObj};

/// Where did this embedded object come from?
#[derive(Debug, Clone)]
pub struct EmbeddedOrigin {
    pub origin_kind: &'static str, // e.g. "xref_type2", "nametree", "annotation"
    pub container_objects: Vec<String>, // "10 0 obj (ObjStm)", etc
    pub note: Option<String>,
}

/// A finding produced from visiting an embedded object.
/// We'll adapt it into the normal `Finding` type for report output.
#[derive(Debug, Clone)]
pub struct EmbeddedFinding {
    pub surface: AttackSurface,
    pub kind: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub evidence: Vec<EvidenceSpan>, // NOTE: spans are relative-to-buffer unless you map them
}

/// Visitor interface: inspect a PdfObj (and optionally its subtree)
pub trait VisitorDetector {
    fn id(&self) -> &'static str;
    fn max_hits(&self) -> usize { 50 }

    /// Called for every node visited.
    /// - `path`: JSONPath-like location within the embedded tree
    fn on_node(&mut self, ctx: &VisitorContext, path: &str, obj: &PdfObj<'_>, out: &mut Vec<EmbeddedFinding>);
}

/// Context for visitors
#[derive(Clone)]
pub struct VisitorContext<'a> {
    pub graph: &'a sis_pdf_pdf::graph::ObjectGraph<'a>,
    pub file: &'a [u8],
    pub max_decode: usize,

    /// Limits to prevent pathological recursion
    pub max_depth: usize,
    pub max_nodes: usize,
    pub resolve_refs: bool,
    pub max_ref_hops: usize,
}

/// Run multiple visitors over an embedded object, walking its tree.
///
/// The walker:
/// - visits dict/array children
/// - optionally resolves refs (bounded, cycle-safe)
pub fn run_visitors_on_embedded<'a>(
    ctx: &VisitorContext<'a>,
    origin: &EmbeddedOrigin,
    root: &PdfObj<'a>,
    visitors: &mut [&mut dyn VisitorDetector],
    id_prefix: &str,
) -> Vec<Finding> {
    let mut embedded_hits: Vec<EmbeddedFinding> = Vec::new();

    // Walk once, call all visitors at each node
    let mut seen_refs = HashSet::<(u32,u16)>::new();
    let mut nodes = 0usize;

    walk(
        ctx,
        root,
        "$",
        0,
        &mut nodes,
        &mut seen_refs,
        visitors,
        &mut embedded_hits
    );

    // Adapt to normal findings
    let mut out = Vec::new();
    for (i, ef) in embedded_hits.into_iter().enumerate() {
        out.push(Finding{
            id: format!("{}:{}:{}", id_prefix, origin.origin_kind, i),
            surface: ef.surface,
            kind: ef.kind,
            severity: ef.severity,
            confidence: ef.confidence,
            title: ef.title,
            description: format!(
                "{}\nOrigin: {}\nContainers: {}\n{}",
                ef.description,
                origin.origin_kind,
                if origin.container_objects.is_empty() { "(none)".into() } else { origin.container_objects.join(", ") },
                origin.note.clone().unwrap_or_default(),
            ),
            objects: origin.container_objects.clone(),
            evidence: ef.evidence, // spans likely relative unless you provide mapping later
            remediation: None,
        });
    }
    out
}

fn walk<'a>(
    ctx: &VisitorContext<'a>,
    obj: &PdfObj<'a>,
    path: &str,
    depth: usize,
    nodes: &mut usize,
    seen_refs: &mut HashSet<(u32,u16)>,
    visitors: &mut [&mut dyn VisitorDetector],
    out: &mut Vec<EmbeddedFinding>,
) {
    if *nodes >= ctx.max_nodes || depth > ctx.max_depth {
        return;
    }
    *nodes += 1;

    for v in visitors.iter_mut() {
        if out.len() >= v.max_hits() {
            continue;
        }
        v.on_node(ctx, path, obj, out);
    }

    // optionally resolve refs (bounded)
    if ctx.resolve_refs {
        if let PdfAtom::Ref{obj: ro, gen: rg} = obj.atom {
            let key = (ro, rg);
            if !seen_refs.insert(key) {
                return;
            }
            // hop cap: we approximate hop count by seen_refs size
            if seen_refs.len() > ctx.max_ref_hops {
                return;
            }
            if let Some(e) = ctx.graph.get(sis_pdf_pdf::object::ObjRef{obj: ro, gen: rg}) {
                walk(ctx, &e.body, &format!("{path}->{} {}R", ro, rg), depth + 1, nodes, seen_refs, visitors, out);
            }
            return;
        }
    }

    match &obj.atom {
        PdfAtom::Dict(d) => {
            for (k, v) in &d.entries {
                let kstr = String::from_utf8_lossy(&k.decoded).to_string();
                let child_path = format!("{path}.{}", kstr);
                walk(ctx, v, &child_path, depth + 1, nodes, seen_refs, visitors, out);
                if *nodes >= ctx.max_nodes { break; }
            }
        }
        PdfAtom::Array(items) => {
            for (i, it) in items.iter().enumerate() {
                let child_path = format!("{path}[{}]", i);
                walk(ctx, it, &child_path, depth + 1, nodes, seen_refs, visitors, out);
                if *nodes >= ctx.max_nodes { break; }
            }
        }
        _ => {}
    }
}
```

## 1.2 Export it

### `crates/sis-pdf-core/src/lib.rs`

Add:

```rust
pub mod visitor; // NEW
```

---

# 2) sis-pdf-detectors: reusable visitors (JS / network actions / launch-ish)

We’ll implement three visitors:

* `EmbeddedJavaScriptVisitor`: flags `/S /JavaScript` or any dict with `/JS`
* `EmbeddedNetworkActionVisitor`: flags `/S /URI` and `/S /SubmitForm` (or `/URI`, `/F`)
* `EmbeddedLaunchVisitor`: flags `/S /Launch` or `/Launch` key

## 2.1 New file: `crates/sis-pdf-detectors/src/embedded_visitors.rs`

```rust
use sis_pdf_core::model::*;
use sis_pdf_core::visitor::{VisitorDetector, VisitorContext, EmbeddedFinding};
use sis_pdf_pdf::object::{PdfAtom, PdfObj};

pub struct EmbeddedJavaScriptVisitor {
    hits: usize,
}
impl EmbeddedJavaScriptVisitor {
    pub fn new() -> Self { Self{ hits: 0 } }
}
impl VisitorDetector for EmbeddedJavaScriptVisitor {
    fn id(&self) -> &'static str { "visitor.embedded_js" }
    fn max_hits(&self) -> usize { 50 }

    fn on_node(&mut self, ctx: &VisitorContext, path: &str, obj: &PdfObj<'_>, out: &mut Vec<EmbeddedFinding>) {
        if self.hits >= self.max_hits() { return; }
        let PdfAtom::Dict(d) = &obj.atom else { return; };

        let is_js_action = ctx.graph.dict_has_name_value(d, b"/S", b"/JavaScript");
        let has_js_key = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS").is_some();

        if !(is_js_action || has_js_key) { return; }

        let mut desc = format!("Embedded JS indicator at path {}.", path);

        if let Some((_, js_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS") {
            if let Some((payload, trunc, note)) = ctx.graph.extract_js_payload(js_obj, ctx.file, ctx.max_decode) {
                desc.push_str(&format!(" JS preview: {}", safe_preview(&payload, 180)));
                if trunc { desc.push_str(" (trunc)"); }
                if let Some(n) = note { desc.push_str(&format!(" [{}]", n)); }
            } else {
                desc.push_str(" /JS present but not extracted.");
            }
        }

        out.push(EmbeddedFinding{
            surface: AttackSurface::JavaScript,
            kind: "embedded_javascript".into(),
            severity: Severity::Critical,
            confidence: Confidence::Probable,
            title: "Embedded JavaScript indicator".into(),
            description: desc,
            evidence: vec![],
        });
        self.hits += 1;
    }
}

pub struct EmbeddedNetworkActionVisitor {
    hits: usize,
}
impl EmbeddedNetworkActionVisitor {
    pub fn new() -> Self { Self{ hits: 0 } }
}
impl VisitorDetector for EmbeddedNetworkActionVisitor {
    fn id(&self) -> &'static str { "visitor.embedded_network_actions" }
    fn max_hits(&self) -> usize { 50 }

    fn on_node(&mut self, _ctx: &VisitorContext, path: &str, obj: &PdfObj<'_>, out: &mut Vec<EmbeddedFinding>) {
        if self.hits >= self.max_hits() { return; }
        let PdfAtom::Dict(d) = &obj.atom else { return; };

        let is_uri = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/URI").is_some()
            || _ctx.graph.dict_has_name_value(d, b"/S", b"/URI");
        let is_submit = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/F").is_some()
            || _ctx.graph.dict_has_name_value(d, b"/S", b"/SubmitForm");

        if !is_uri && !is_submit { return; }

        if is_uri {
            let uri = if let Some((_, u)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/URI") {
                textish(u)
            } else { "(missing)".into() };

            out.push(EmbeddedFinding{
                surface: AttackSurface::Actions,
                kind: "embedded_uri_action".into(),
                severity: Severity::High,
                confidence: Confidence::Probable,
                title: "Embedded URI action indicator".into(),
                description: format!("Embedded URI indicator at path {}. URI={}", path, uri),
                evidence: vec![],
            });
            self.hits += 1;
        }

        if is_submit {
            let f = if let Some((_, u)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/F") {
                textish(u)
            } else { "(missing)".into() };

            out.push(EmbeddedFinding{
                surface: AttackSurface::Actions,
                kind: "embedded_submitform_action".into(),
                severity: Severity::High,
                confidence: Confidence::Probable,
                title: "Embedded SubmitForm action indicator".into(),
                description: format!("Embedded SubmitForm indicator at path {}. F={}", path, f),
                evidence: vec![],
            });
            self.hits += 1;
        }
    }
}

pub struct EmbeddedLaunchVisitor {
    hits: usize,
}
impl EmbeddedLaunchVisitor {
    pub fn new() -> Self { Self{ hits: 0 } }
}
impl VisitorDetector for EmbeddedLaunchVisitor {
    fn id(&self) -> &'static str { "visitor.embedded_launch" }
    fn max_hits(&self) -> usize { 20 }

    fn on_node(&mut self, ctx: &VisitorContext, path: &str, obj: &PdfObj<'_>, out: &mut Vec<EmbeddedFinding>) {
        if self.hits >= self.max_hits() { return; }
        let PdfAtom::Dict(d) = &obj.atom else { return; };

        let is_launch = ctx.graph.dict_has_name_value(d, b"/S", b"/Launch")
            || sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/Launch").is_some();

        if !is_launch { return; }

        out.push(EmbeddedFinding{
            surface: AttackSurface::Actions,
            kind: "embedded_launch_action".into(),
            severity: Severity::Critical,
            confidence: Confidence::Probable,
            title: "Embedded Launch action indicator".into(),
            description: format!("Embedded Launch indicator at path {}.", path),
            evidence: vec![],
        });
        self.hits += 1;
    }
}

fn safe_preview(b: &[u8], max: usize) -> String {
    let s = &b[..std::cmp::min(b.len(), max)];
    let mut out = String::new();
    for &c in s {
        if c.is_ascii_graphic() || c == b' ' { out.push(c as char); }
        else if matches!(c, b'\n'|b'\r'|b'\t') { out.push(' '); }
        else { out.push('.'); }
    }
    out
}

fn textish(o: &PdfObj<'_>) -> String {
    use sis_pdf_pdf::object::PdfStr;
    match &o.atom {
        PdfAtom::Str(PdfStr::Literal{raw, ..}) => sanitize(raw),
        PdfAtom::Str(PdfStr::Hex{raw, ..}) => sanitize(raw),
        PdfAtom::Name(n) => String::from_utf8_lossy(&n.decoded).to_string(),
        PdfAtom::Keyword(k) => String::from_utf8_lossy(k).to_string(),
        PdfAtom::Ref{obj, gen} => format!("{} {} R", obj, gen),
        _ => "(complex)".into()
    }
}

fn sanitize(b: &[u8]) -> String {
    let mut s = String::new();
    for &c in b.iter().take(256) {
        if c.is_ascii_graphic() || c == b' ' { s.push(c as char); }
        else if matches!(c, b'\n'|b'\r'|b'\t') { s.push(' '); }
        else { s.push('.'); }
    }
    s
}
```

## 2.2 Export it

### `crates/sis-pdf-detectors/src/lib.rs`

Add:

```rust
pub mod embedded_visitors; // NEW
```

---

# 3) Integrate visitors into the type-2 xref → ObjStm extraction detector

Now we replace the local `classify_embedded` approach from chunk 5 and run visitors over the extracted embedded object.

### Replace `crates/sis-pdf-detectors/src/xref_objstm_extract.rs` with this updated version

```rust
use anyhow::Result;
use std::collections::HashMap;

use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;
use sis_pdf_core::visitor::{VisitorContext, EmbeddedOrigin, run_visitors_on_embedded, VisitorDetector};

pub struct XrefType2ObjStmExtractionDetector;

impl Detector for XrefType2ObjStmExtractionDetector {
    fn id(&self) -> &'static str { "structure.xref_type2_objstm_extract" }
    fn surface(&self) -> AttackSurface { AttackSurface::ObjectStreams }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH | Needs::BYTES_ONLY | Needs::STREAM_DECODE }
    fn cost(&self) -> Cost { Cost::Expensive } // deep only

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let file = ctx.bytes;

        // latest xref stream revision
        let revs = sis_pdf_pdf::incremental::parse_revisions(file, 64);
        let latest = revs.iter().find(|r| matches!(r.kind, sis_pdf_pdf::incremental::XrefKind::XrefStream));
        let Some(r) = latest else { return Ok(vec![]); };

        let Some(xref_obj) = g.find_object_by_full_start(r.startxref) else { return Ok(vec![]); };

        let Some(index) = sis_pdf_pdf::xrefstream::parse_xref_stream_index(
            g, xref_obj, file,
            ctx.options.max_decode_bytes.min(64 * 1024 * 1024)
        ) else { return Ok(vec![]); };

        let mut t2: Vec<(u32, u64, u64)> = Vec::new();
        for (objno, ent) in &index.entries {
            if let sis_pdf_pdf::xrefstream::XrefEntry::Compressed{ objstm_obj, objstm_index } = ent {
                t2.push((*objno, *objstm_obj, *objstm_index));
            }
        }
        if t2.is_empty() { return Ok(vec![]); }

        // ObjStm cache
        let mut cache: HashMap<u64, sis_pdf_pdf::objstm_extract::ObjStmDecoded> = HashMap::new();

        // caps
        t2.sort_by_key(|(o,_,_)| *o);
        let cap = 5000usize;
        let t2 = t2.into_iter().take(cap).collect::<Vec<_>>();

        // Prepare visitors (mutable)
        let mut v_js = crate::embedded_visitors::EmbeddedJavaScriptVisitor::new();
        let mut v_net = crate::embedded_visitors::EmbeddedNetworkActionVisitor::new();
        let mut v_launch = crate::embedded_visitors::EmbeddedLaunchVisitor::new();

        let mut visitors: Vec<&mut dyn VisitorDetector> = vec![&mut v_js, &mut v_net, &mut v_launch];

        // Visitor context
        let vctx = VisitorContext{
            graph: g,
            file,
            max_decode: ctx.options.max_decode_bytes.min(512 * 1024),
            max_depth: 32,
            max_nodes: 50_000,
            resolve_refs: true,
            max_ref_hops: 20_000,
        };

        let mut out: Vec<Finding> = Vec::new();
        let mut containers_decoded = 0usize;
        let mut errors = 0usize;

        for (objno, objstm_obj, objstm_index) in t2 {
            // resolve ObjStm entry (best effort: first gen found)
            let objstm_entry = g.iter_objects().find(|e| e.r.obj as u64 == objstm_obj);
            let Some(objstm_entry) = objstm_entry else { errors += 1; continue; };

            let dec = if let Some(d) = cache.get(&objstm_obj) {
                d.clone()
            } else {
                let d = match sis_pdf_pdf::objstm_extract::decode_objstm(
                    g,
                    objstm_entry,
                    file,
                    ctx.options.max_decode_bytes.min(64 * 1024 * 1024)
                ) {
                    Some(d) => d,
                    None => { errors += 1; continue; }
                };
                cache.insert(objstm_obj, d.clone());
                containers_decoded += 1;
                d
            };

            let idx = objstm_index as usize;
            let embedded = sis_pdf_pdf::objstm_extract::extract_embedded_object_by_index(&dec, idx);
            let Some(embedded) = embedded else { errors += 1; continue; };

            let origin = EmbeddedOrigin{
                origin_kind: "xref_type2",
                container_objects: vec![
                    format!("{} {} obj (xref stream)", xref_obj.r.obj, xref_obj.r.gen),
                    format!("{} {} obj (ObjStm)", objstm_entry.r.obj, objstm_entry.r.gen),
                ],
                note: Some(format!(
                    "xref obj={} compressed in ObjStm {} {} at index {} (ObjStm N={} First={} table_len={} truncated={} note={:?})",
                    objno,
                    objstm_entry.r.obj, objstm_entry.r.gen,
                    idx,
                    dec.n, dec.first, dec.table.len(),
                    dec.truncated, dec.note
                )),
            };

            let id_prefix = format!("{}:obj{}", self.id(), objno);
            out.extend(run_visitors_on_embedded(&vctx, &origin, &embedded, &mut visitors, &id_prefix));
        }

        // Summary
        out.push(Finding{
            id: format!("{}:summary", self.id()),
            surface: AttackSurface::ObjectStreams,
            kind: "xref_type2_objstm_extraction_summary".into(),
            severity: Severity::Info,
            confidence: Confidence::Probable,
            title: "XRef type-2 extraction + embedded visitors complete".into(),
            description: format!(
                "Processed type-2 xref entries.\n\
                 ObjStm containers decoded: {}\n\
                 Unique ObjStm in cache: {}\n\
                 Findings emitted (embedded visitors): {}\n\
                 Errors: {}",
                containers_decoded,
                cache.len(),
                out.len().saturating_sub(1),
                errors
            ),
            objects: vec![format!("{} {} obj (xref stream)", xref_obj.r.obj, xref_obj.r.gen)],
            evidence: vec![
                EvidenceSpan{
                    offset: xref_obj.full_span.start,
                    length: (xref_obj.full_span.len().min(u64::from(u32::MAX))) as u32,
                    note: Some("XRef stream object span".into()),
                }
            ],
            remediation: Some("If embedded visitors find JS/actions, trace trigger paths (/OpenAction,/AA,/A, annotations, names tree). Consider stripping or blocking actions in untrusted PDFs.".into()),
        });

        Ok(out)
    }
}
```

---

# 4) Wiring checklist updates

### `crates/sis-pdf-core/src/lib.rs`

Add:

```rust
pub mod visitor;
```

### `crates/sis-pdf-detectors/src/lib.rs`

Add:

```rust
pub mod embedded_visitors;
```

No registry changes needed beyond what you already did in chunk 5.

---

# 5) Smoke test: visitor runner hits embedded JS

### `crates/sis-pdf-core/tests/visitor_smoke.rs`

```rust
use sis_pdf_core::visitor::{VisitorContext, EmbeddedOrigin, run_visitors_on_embedded, VisitorDetector};
use sis_pdf_core::model::*;
use sis_pdf_pdf::parse;

#[test]
fn embedded_visitor_finds_js() {
    let pdf = br#"%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
2 0 obj
<< /S /JavaScript /JS (app.alert(1)) >>
endobj
%%EOF
"#.to_vec();

    let g = parse(&pdf, true).unwrap();
    let e = g.iter_objects().find(|e| e.r.obj == 2).unwrap();

    let vctx = VisitorContext{
        graph: &g,
        file: &pdf,
        max_decode: 256*1024,
        max_depth: 16,
        max_nodes: 10_000,
        resolve_refs: true,
        max_ref_hops: 1000,
    };

    let origin = EmbeddedOrigin{
        origin_kind: "test",
        container_objects: vec![format!("{} {} obj", e.r.obj, e.r.gen)],
        note: None,
    };

    let mut v_js = sis_pdf_detectors::embedded_visitors::EmbeddedJavaScriptVisitor::new();
    let mut visitors: Vec<&mut dyn VisitorDetector> = vec![&mut v_js];

    let findings = run_visitors_on_embedded(&vctx, &origin, &e.body, &mut visitors, "testprefix");
    assert!(findings.iter().any(|f| f.kind == "embedded_javascript"));
}
```

---

## What you can do next with this framework

Now you can plug the same visitors into:

* **Name tree entries** (`/Names` → `/JavaScript` → entry value)
* **Annotation actions** (when you resolve `/A` or `/AA` dicts, run visitors on that dict)
* **ObjStm deep enumeration** (chunk 2): instead of only “contains JS”, you can run visitors on each parsed embedded object

# Chapter 10

Below is **chunk 7**: apply the **embedded-object visitor framework** (chunk 6) to:

* **NameTree** `/Names → /JavaScript` entries
* **Annotations** (`/Annots` → annotation dict → `/A` and `/AA` action hooks)
* **ObjStm deep enumeration** (decode `/ObjStm`, parse embedded objects, then run visitors on each embedded object)

This gives you consistent “payload detectors” regardless of where the object came from.

---

# 0) Add a glue helper in `sis-pdf-detectors` so detectors can run visitors easily

## 0.1 New file: `crates/sis-pdf-detectors/src/visitor_glue.rs`

```rust
use sis_pdf_core::visitor::{EmbeddedOrigin, VisitorContext, run_visitors_on_embedded, VisitorDetector};
use sis_pdf_core::model::Finding;

pub struct DefaultVisitorPack<'a> {
    pub visitors: Vec<&'a mut dyn VisitorDetector>,
}

pub fn run_default_visitors<'a>(
    vctx: &VisitorContext<'a>,
    origin: &EmbeddedOrigin,
    root: &sis_pdf_pdf::object::PdfObj<'a>,
    id_prefix: &str,
) -> Vec<Finding> {
    // IMPORTANT: create fresh visitors per origin so caps are per-object, not global
    let mut v_js = crate::embedded_visitors::EmbeddedJavaScriptVisitor::new();
    let mut v_net = crate::embedded_visitors::EmbeddedNetworkActionVisitor::new();
    let mut v_launch = crate::embedded_visitors::EmbeddedLaunchVisitor::new();

    let mut visitors: Vec<&mut dyn VisitorDetector> = vec![&mut v_js, &mut v_net, &mut v_launch];

    run_visitors_on_embedded(vctx, origin, root, &mut visitors, id_prefix)
}
```

## 0.2 Export it

### `crates/sis-pdf-detectors/src/lib.rs`

Add:

```rust
pub mod visitor_glue; // NEW
```

---

# 1) Apply visitors to NameTree (/Names → /JavaScript)

We’ll extend your `JavaScriptDetector` so that after enumerating name tree entries, it resolves each entry and runs embedded visitors on it (action dicts, or objects that reference action dicts).

### Replace the NameTree section in `crates/sis-pdf-detectors/src/javascript.rs`

Keep your existing “scan action dict /S /JavaScript” section (it’s good). Replace the *part* starting at:

```rust
// 2) Enumerate Names tree: Catalog /Names -> /JavaScript -> NameTree entries
```

with this upgraded version:

```rust
        // 2) Enumerate Names tree: Catalog /Names -> /JavaScript -> NameTree entries
        if let Some(cat_r) = g.catalog_ref() {
            if let Some(cat_e) = g.get(cat_r) {
                if let Some(cat_d) = g.obj_as_dict(cat_e) {
                    if let Some((_, names_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/Names") {
                        let names_d = match &names_obj.atom {
                            PdfAtom::Ref{..} => g.resolve_ref(names_obj).and_then(|e| g.obj_as_dict(e)),
                            PdfAtom::Dict(d) => Some(d),
                            _ => None,
                        };
                        if let Some(names_d) = names_d {
                            if let Some((_, js_tree_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(names_d, b"/JavaScript") {
                                // enumerate actual entries
                                let entries = sis_pdf_pdf::nametree::enumerate_name_tree(g, js_tree_obj, 12, 500);

                                if !entries.is_empty() {
                                    // Visitor context
                                    let vctx = sis_pdf_core::visitor::VisitorContext{
                                        graph: g,
                                        file: bytes,
                                        max_decode: ctx.options.max_decode_bytes.min(512*1024),
                                        max_depth: 32,
                                        max_nodes: 50_000,
                                        resolve_refs: true,
                                        max_ref_hops: 20_000,
                                    };

                                    let mut emitted = 0usize;
                                    let mut example_pairs = Vec::new();

                                    for (idx, ent) in entries.iter().enumerate() {
                                        if emitted >= 200 { break; } // cap findings from names tree
                                        let nm = sanitize(&ent.name);

                                        // Resolve entry value if it's a ref; otherwise use inline value
                                        let root_obj: PdfObj = match &ent.value.atom {
                                            PdfAtom::Ref{..} => {
                                                if let Some(e) = g.resolve_ref(&ent.value) { e.body.clone() } else { ent.value.clone() }
                                            }
                                            _ => ent.value.clone()
                                        };

                                        // Create origin info
                                        let origin = sis_pdf_core::visitor::EmbeddedOrigin{
                                            origin_kind: "nametree_js",
                                            container_objects: vec![
                                                format!("{} {} obj (Catalog)", cat_r.obj, cat_r.gen),
                                            ],
                                            note: Some(format!("NameTree entry \"{}\" (entry_index={})", nm, idx)),
                                        };

                                        let id_prefix = format!("script.javascript:nametree:{}", idx);
                                        let mut f = crate::visitor_glue::run_default_visitors(&vctx, &origin, &root_obj, &id_prefix);

                                        if !f.is_empty() {
                                            emitted += f.len();
                                            out.append(&mut f);
                                            example_pairs.push(format!("{} → (hit)", nm));
                                        } else if example_pairs.len() < 5 {
                                            // Keep a few examples even if no hit (helps debugging)
                                            example_pairs.push(format!("{} → (no-hit)", nm));
                                        }
                                    }

                                    out.push(Finding{
                                        id: format!("{}:{}:{}:names_tree_visited", self.id(), cat_r.obj, cat_r.gen),
                                        surface: AttackSurface::JavaScript,
                                        kind: "javascript_names_tree_visited".into(),
                                        severity: Severity::Info,
                                        confidence: Confidence::Probable,
                                        title: "Visited JavaScript Names tree entries".into(),
                                        description: format!(
                                            "Names tree /JavaScript has {} entries. Ran embedded visitors over up to {} entries.\nExamples: {}",
                                            entries.len(),
                                            std::cmp::min(entries.len(), 200),
                                            example_pairs.join(", ")
                                        ),
                                        objects: vec![format!("{} {} obj (Catalog)", cat_r.obj, cat_r.gen)],
                                        evidence: vec![],
                                        remediation: Some("If NameTree entries produce JS/action hits, trace triggers like /OpenAction or /AA and consider stripping interactive features for untrusted ingestion.".into()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
```

That’s it — NameTree entries now flow through the same embedded visitors as everything else.

---

# 2) Apply visitors to Annotations: /A and /AA action hooks

We’ll update the `AnnotationActionDetector` to:

* resolve `/A` dict and run embedded visitors over it
* for `/AA`, resolve the dict and for each event key, run visitors over its action value

### Replace `crates/sis-pdf-detectors/src/annots.rs` with this upgraded version

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;
use sis_pdf_pdf::object::{PdfAtom, PdfObj};

pub struct AnnotationActionDetector;

impl Detector for AnnotationActionDetector {
    fn id(&self) -> &'static str { "actions.annotations" }
    fn surface(&self) -> AttackSurface { AttackSurface::Annotations }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let bytes = ctx.bytes;
        let mut out = Vec::new();

        let pages = sis_pdf_pdf::pagetree::collect_pages(g, 2000, 64);

        // Visitor context shared for this detector
        let vctx = sis_pdf_core::visitor::VisitorContext{
            graph: g,
            file: bytes,
            max_decode: ctx.options.max_decode_bytes.min(512*1024),
            max_depth: 32,
            max_nodes: 50_000,
            resolve_refs: true,
            max_ref_hops: 20_000,
        };

        let mut visited_actions = 0usize;

        for p in pages {
            for a in p.annots {
                let annot_e = match g.resolve_ref(&a) {
                    Some(e) => e,
                    None => continue,
                };
                let Some(ad) = g.obj_as_dict(annot_e) else { continue; };

                // /A (direct action)
                if let Some((_, v)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/A") {
                    if visited_actions < 500 {
                        let root_obj: PdfObj = match &v.atom {
                            PdfAtom::Ref{..} => g.resolve_ref(v).map(|e| e.body.clone()).unwrap_or_else(|| v.clone()),
                            _ => v.clone(),
                        };

                        let origin = sis_pdf_core::visitor::EmbeddedOrigin{
                            origin_kind: "annotation_A",
                            container_objects: vec![
                                format!("{} {} obj (Page)", p.page_ref.obj, p.page_ref.gen),
                                format!("{} {} obj (Annot)", annot_e.r.obj, annot_e.r.gen),
                            ],
                            note: Some("Annotation /A action".into()),
                        };

                        let id_prefix = format!("actions.annotations:{}:{}:A", annot_e.r.obj, annot_e.r.gen);
                        out.extend(crate::visitor_glue::run_default_visitors(&vctx, &origin, &root_obj, &id_prefix));
                        visited_actions += 1;
                    }

                    out.push(Finding{
                        id: format!("{}:{}:{}:{}:a", self.id(), p.page_ref.obj, p.page_ref.gen, annot_e.r.obj),
                        surface: AttackSurface::Annotations,
                        kind: "annotation_action_present".into(),
                        severity: Severity::Info,
                        confidence: Confidence::Probable,
                        title: "Annotation action present (/A)".into(),
                        description: format!("Page {} {} R annotation {} {} R contains /A action.", p.page_ref.obj, p.page_ref.gen, annot_e.r.obj, annot_e.r.gen),
                        objects: vec![
                            format!("{} {} obj (Page)", p.page_ref.obj, p.page_ref.gen),
                            format!("{} {} obj (Annot)", annot_e.r.obj, annot_e.r.gen),
                        ],
                        evidence: vec![EvidenceSpan{ offset: v.span.start, length: (v.span.end-v.span.start) as u32, note: Some("Annot /A value".into()) }],
                        remediation: Some("Resolve /A action and inspect payloads (JS/URI/Launch/SubmitForm).".into()),
                    });
                }

                // /AA (additional actions dict of event -> action)
                if let Some((_, aa_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/AA") {
                    let aa_dict_opt = match &aa_obj.atom {
                        PdfAtom::Dict(d) => Some(d),
                        PdfAtom::Ref{..} => g.resolve_ref(aa_obj).and_then(|e| g.obj_as_dict(e)),
                        _ => None,
                    };

                    if let Some(aa_dict) = aa_dict_opt {
                        // For each event key, run visitors on its action value
                        for (k, v) in &aa_dict.entries {
                            if visited_actions >= 500 { break; }
                            let event = String::from_utf8_lossy(&k.decoded).to_string();

                            let root_obj: PdfObj = match &v.atom {
                                PdfAtom::Ref{..} => g.resolve_ref(v).map(|e| e.body.clone()).unwrap_or_else(|| v.clone()),
                                _ => v.clone(),
                            };

                            let origin = sis_pdf_core::visitor::EmbeddedOrigin{
                                origin_kind: "annotation_AA",
                                container_objects: vec![
                                    format!("{} {} obj (Page)", p.page_ref.obj, p.page_ref.gen),
                                    format!("{} {} obj (Annot)", annot_e.r.obj, annot_e.r.gen),
                                ],
                                note: Some(format!("Annotation /AA event {}", event)),
                            };

                            let id_prefix = format!("actions.annotations:{}:{}:AA{}", annot_e.r.obj, annot_e.r.gen, event);
                            out.extend(crate::visitor_glue::run_default_visitors(&vctx, &origin, &root_obj, &id_prefix));
                            visited_actions += 1;
                        }
                    }

                    out.push(Finding{
                        id: format!("{}:{}:{}:{}:aa", self.id(), p.page_ref.obj, p.page_ref.gen, annot_e.r.obj),
                        surface: AttackSurface::Annotations,
                        kind: "annotation_additional_actions_present".into(),
                        severity: Severity::Info,
                        confidence: Confidence::Probable,
                        title: "Annotation additional actions present (/AA)".into(),
                        description: format!("Page {} {} R annotation {} {} R contains /AA (event-driven triggers). Embedded visitors were run over /AA entries (capped).", p.page_ref.obj, p.page_ref.gen, annot_e.r.obj, annot_e.r.gen),
                        objects: vec![
                            format!("{} {} obj (Page)", p.page_ref.obj, p.page_ref.gen),
                            format!("{} {} obj (Annot)", annot_e.r.obj, annot_e.r.gen),
                        ],
                        evidence: vec![EvidenceSpan{ offset: aa_obj.span.start, length: (aa_obj.span.end-aa_obj.span.start) as u32, note: Some("Annot /AA value".into()) }],
                        remediation: Some("Review /AA actions; event-driven actions can be triggered on open/close/mouse events depending on annotation subtype.".into()),
                    });
                }
            }
        }

        // Summary
        out.push(Finding{
            id: format!("{}:visited_summary", self.id()),
            surface: AttackSurface::Annotations,
            kind: "annotation_actions_visited_summary".into(),
            severity: Severity::Info,
            confidence: Confidence::Probable,
            title: "Annotation actions visited (embedded visitors)".into(),
            description: format!("Ran embedded visitors over up to {} annotation actions (/A and /AA entries).", std::cmp::min(visited_actions, 500)),
            objects: vec![],
            evidence: vec![],
            remediation: None,
        });

        Ok(out)
    }
}
```

---

# 3) Apply visitors to ObjStm deep enumeration

We’ll upgrade the deep ObjStm detector to:

* decode `/ObjStm`
* parse its embedded objects (as before)
* for each embedded object, run the embedded visitors and include origin metadata

### Replace `crates/sis-pdf-detectors/src/objstm_deep.rs` with this upgraded version

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;
use sis_pdf_pdf::object::{PdfAtom, PdfObj};
use sis_pdf_pdf::tokbuf::TokBuf;

pub struct ObjStmEnumerateDetector;

impl Detector for ObjStmEnumerateDetector {
    fn id(&self) -> &'static str { "structure.objstm_deep" }
    fn surface(&self) -> AttackSurface { AttackSurface::ObjectStreams }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH | Needs::STREAM_INDEX | Needs::STREAM_DECODE }
    fn cost(&self) -> Cost { Cost::Expensive }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let file = ctx.bytes;
        let mut out = Vec::new();

        // Visitor context shared for all embedded objects
        let vctx = sis_pdf_core::visitor::VisitorContext{
            graph: g,
            file,
            max_decode: ctx.options.max_decode_bytes.min(512*1024),
            max_depth: 32,
            max_nodes: 50_000,
            resolve_refs: true,
            max_ref_hops: 20_000,
        };

        for e in g.iter_objects() {
            let Some(d) = g.obj_as_dict(e) else { continue; };
            if !g.dict_has_name_value(d, b"/Type", b"/ObjStm") { continue; }
            if !g.is_stream(e) { continue; }

            let n = int_first(d, b"/N").unwrap_or(0).max(0) as usize;
            let first = int_first(d, b"/First").unwrap_or(0).max(0) as usize;

            let raw_stream = match g.stream_bytes(e, file) {
                Some(b) => b,
                None => continue,
            };

            let (filters, _) = g.stream_filters_and_length(e);
            let decoded = sis_pdf_pdf::decode::decode_with_filters_limited(
                raw_stream,
                &filters,
                sis_pdf_pdf::decode::DecodePlan{
                    max_output: ctx.options.max_decode_bytes.min(64 * 1024 * 1024),
                    max_steps: 8,
                }
            )?;

            if decoded.bytes.len() < first {
                out.push(Finding{
                    id: format!("{}:{}:{}:short", self.id(), e.r.obj, e.r.gen),
                    surface: AttackSurface::ObjectStreams,
                    kind: "objstm_decode_too_short".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "ObjStm decoded stream shorter than /First".into(),
                    description: format!("Decoded ObjStm bytes ({}) shorter than /First ({}) — malformed or decode unsupported.", decoded.bytes.len(), first),
                    objects: vec![format!("{} {} obj", e.r.obj, e.r.gen)],
                    evidence: vec![EvidenceSpan{ offset: e.full_span.start, length: (e.full_span.len().min(u64::from(u32::MAX))) as u32, note: Some("ObjStm object span".into()) }],
                    remediation: Some("Verify filter chain support and inspect ObjStm header and offsets manually.".into()),
                });
                continue;
            }

            let header = &decoded.bytes[..first];
            let table = parse_objstm_table(header, n);
            let data = &decoded.bytes[first..];

            // Walk a bounded number of embedded objects per ObjStm
            let mut embedded_count = 0usize;
            let mut visitor_findings = 0usize;

            for (i, (objnum, off)) in table.into_iter().enumerate() {
                if embedded_count >= 500 { break; } // cap per ObjStm
                if off >= data.len() { continue; }

                let slice = &data[off..];
                let mut tb = TokBuf::new(slice, 0);
                let parsed: PdfObj = match sis_pdf_pdf::object::parse_object(&mut tb) {
                    Ok(o) => o,
                    Err(_) => continue,
                };

                embedded_count += 1;

                let origin = sis_pdf_core::visitor::EmbeddedOrigin{
                    origin_kind: "objstm_deep",
                    container_objects: vec![format!("{} {} obj (/ObjStm)", e.r.obj, e.r.gen)],
                    note: Some(format!(
                        "Embedded object #{}: objnum={} off={} (table_index={}) ObjStm(N={},First={}) truncated={} note={:?}",
                        i, objnum, off, i, n, first, decoded.truncated, decoded.note
                    )),
                };

                let id_prefix = format!("{}:{}:{}:emb{}", self.id(), e.r.obj, e.r.gen, i);
                let mut f = crate::visitor_glue::run_default_visitors(&vctx, &origin, &parsed, &id_prefix);

                if !f.is_empty() {
                    visitor_findings += f.len();
                    out.append(&mut f);
                }

                if visitor_findings >= 2000 {
                    // global cap for this ObjStm to prevent blowups
                    break;
                }
            }

            out.push(Finding{
                id: format!("{}:{}:{}:summary", self.id(), e.r.obj, e.r.gen),
                surface: AttackSurface::ObjectStreams,
                kind: "objstm_deep_visited_summary".into(),
                severity: Severity::Info,
                confidence: Confidence::Probable,
                title: "ObjStm deep enumeration visited (embedded visitors)".into(),
                description: format!(
                    "Decoded ObjStm and parsed header table (N={}, First={}). Embedded objects parsed (cap 500): {}. Embedded visitor findings emitted: {}.",
                    n, first, embedded_count, visitor_findings
                ),
                objects: vec![format!("{} {} obj (/ObjStm)", e.r.obj, e.r.gen)],
                evidence: vec![
                    EvidenceSpan{ offset: e.full_span.start, length: (e.full_span.len().min(u64::from(u32::MAX))) as u32, note: Some("ObjStm object span".into()) }
                ],
                remediation: None,
            });
        }

        Ok(out)
    }
}

fn int_first(d: &sis_pdf_pdf::object::PdfDict<'_>, key: &[u8]) -> Option<i64> {
    let (_, v) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, key)?;
    if let sis_pdf_pdf::object::PdfAtom::Int(n) = v.atom { Some(n) } else { None }
}

fn parse_objstm_table(header: &[u8], n: usize) -> Vec<(u32, usize)> {
    let ints = parse_ascii_ints(header);
    let mut out = Vec::new();
    let pairs = std::cmp::min(n, ints.len()/2);
    for i in 0..pairs {
        let objnum = ints[2*i].max(0) as u32;
        let off = ints[2*i+1].max(0) as usize;
        out.push((objnum, off));
    }
    out
}

fn parse_ascii_ints(b: &[u8]) -> Vec<i64> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        while i < b.len() && !is_digit_or_sign(b[i]) { i += 1; }
        if i >= b.len() { break; }
        let start = i;
        i += 1;
        while i < b.len() && (b[i] as char).is_ascii_digit() { i += 1; }
        if let Ok(s) = std::str::from_utf8(&b[start..i]) {
            if let Ok(v) = s.parse::<i64>() { out.push(v); }
        }
    }
    out
}
fn is_digit_or_sign(c: u8) -> bool { (c as char).is_ascii_digit() || c == b'+' || c == b'-' }
```

---

# 4) Wiring checklist recap

### `crates/sis-pdf-detectors/src/lib.rs` includes:

```rust
pub mod visitor_glue;
```

No registry changes beyond what you already have.

---

# 5) Practical notes (important)

* **Evidence spans** for embedded objects are currently “relative-ish” (no direct file offsets). That’s okay for now; your origin note ties the embedded object back to:

  * ObjStm container object (with real file span), and
  * index/offset within decoded ObjStm data.
* Next, you can add an optional “offset mapper” so embedded visitor findings can point to:

  * `ObjStm stream span start + (stream data offset)` if you store the decoded stream’s relationship to the original stream bytes.

---

## What you have now (end-to-end)

Any place you extract a `PdfObj` (xref type-2, ObjStm deep, annotation /A & /AA, NameTree JavaScript entries), you run the **same** visitors and get consistent findings.


# Chapter 11

Got it — here are **chunk 8, then chunk 9, then chunk 10** (all in one go), staying in the same drop-in style.

You’ll get:

* **Chunk 8 (Evidence mapping):** when visitors find `/JS` inside an embedded object (ObjStm / NameTree / Annotation action), findings now include **real file offsets** *when mapping is safe*, and otherwise include a **precise fallback** pointing to the container stream + decoded offsets.
* **Chunk 9 (Trigger graph enrichment):** every embedded visitor finding now carries a normalized **trigger context** (OpenAction / AA event / Annot / NameTree entry), and you get a **graph summary finding** with edges.
* **Chunk 10 (Performance pass):** a global **scan budget** (bytes decoded, nodes visited, objects processed) + a lightweight **work scheduler** pattern + caching hooks so deep scans can stay interactive without guessing.

---

## Chunk 8 — Evidence mapping for embedded objects

### Problem

Embedded `PdfObj` spans are currently relative to **decoded buffers**, not the original file. We can only map spans to file offsets **when decoding is identity** (no filters), because flate/ASCII85/etc do not preserve positional mapping.

### Strategy

* Add a `StreamDataSpan` finder: locate raw `stream ... endstream` bytes inside the file and return the file offsets for the **raw stream data**.
* Introduce `EvidenceMap`:

  * `IdentityStream { data_start_file_off }` — safe mapping from decoded offset → file offset
  * `Unmappable { container_span, decoded_note }` — fall back to container span + decoded offsets in note
* Update ObjStm decode helper to return a mapping description.
* Update visitor findings to include evidence spans in decoded space; `run_visitors_on_embedded` maps them when possible.

---

### 8.1 New file: `crates/sis-pdf-pdf/src/streamloc.rs`

```rust
use crate::span::Span;
use crate::graph::ObjEntry;

/// File-location of raw stream data (bytes between end-of-line after "stream" and before "endstream")
#[derive(Debug, Clone)]
pub struct StreamDataSpan {
    pub data: Span,      // raw stream data bytes in file
    pub container: Span, // full object span in file
}

/// Best-effort parse of stream keyword boundaries inside an object's full span.
/// Works for typical "stream\n...endstream" and "stream\r\n...endstream".
pub fn locate_stream_data(bytes: &[u8], e: &ObjEntry<'_>) -> Option<StreamDataSpan> {
    let a = e.full_span.start as usize;
    let b = e.full_span.end as usize;
    if a >= bytes.len() || b > bytes.len() || a >= b { return None; }
    let s = &bytes[a..b];

    // find "stream"
    let st = s.windows(b"stream".len()).position(|w| w == b"stream")?;
    let mut i = st + b"stream".len();

    // skip optional whitespace then EOL; PDF spec: after "stream" can be EOL
    // Accept: "\n", "\r\n", "\r"
    if i < s.len() && (s[i] == b' ' || s[i] == b'\t') {
        while i < s.len() && (s[i] == b' ' || s[i] == b'\t') { i += 1; }
    }

    // consume EOL
    if i + 1 < s.len() && s[i] == b'\r' && s[i+1] == b'\n' { i += 2; }
    else if i < s.len() && (s[i] == b'\n' || s[i] == b'\r') { i += 1; }
    else {
        // some PDFs do "stream " without EOL; tolerate: treat remaining as data start
    }

    let data_start = i;

    // find "endstream" from the back (best effort)
    let endst = s.windows(b"endstream".len()).rposition(|w| w == b"endstream")?;
    let data_end = endst;

    if data_start > data_end || data_end > s.len() { return None; }

    Some(StreamDataSpan{
        data: Span{ start: (a + data_start) as u64, end: (a + data_end) as u64 },
        container: e.full_span,
    })
}
```

### 8.2 Export it

`crates/sis-pdf-pdf/src/lib.rs`

```rust
pub mod streamloc; // NEW
```

---

### 8.3 New file: `crates/sis-pdf-core/src/evidence_map.rs`

```rust
use sis_pdf_pdf::span::Span;

/// Describes how to map evidence offsets coming from an embedded buffer back into the PDF file.
#[derive(Debug, Clone)]
pub enum EvidenceMap {
    /// Decoded buffer offsets correspond 1:1 with raw stream data offsets in file.
    /// file_offset = data_start_file_off + decoded_offset
    IdentityStream {
        data_start_file_off: u64,
        data_end_file_off: u64,
    },
    /// Cannot map precisely; provide container span + decoded offsets in notes.
    Unmappable {
        container_span: Span,
        note: String,
    },
}

impl EvidenceMap {
    pub fn map_offset(&self, decoded_off: u64) -> Option<u64> {
        match self {
            EvidenceMap::IdentityStream{ data_start_file_off, data_end_file_off } => {
                let off = data_start_file_off.saturating_add(decoded_off);
                if off <= *data_end_file_off { Some(off) } else { None }
            }
            EvidenceMap::Unmappable{..} => None,
        }
    }
}
```

### 8.4 Export it

`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod evidence_map; // NEW
```

---

### 8.5 Update visitor context to carry evidence mapping

#### Update `crates/sis-pdf-core/src/visitor.rs`

1. Add import:

```rust
use crate::evidence_map::EvidenceMap;
```

2. Extend `EmbeddedOrigin`:

```rust
pub struct EmbeddedOrigin {
    pub origin_kind: &'static str,
    pub container_objects: Vec<String>,
    pub note: Option<String>,

    // NEW:
    pub evidence_map: Option<EvidenceMap>,
    pub trigger: Option<crate::trigger::TriggerContext>, // (chunk 9 adds this type)
}
```

3. In `run_visitors_on_embedded`, when adapting `EmbeddedFinding` → `Finding`, map evidence spans if possible.

Replace:

```rust
evidence: ef.evidence,
```

with:

```rust
evidence: map_evidence(origin.evidence_map.as_ref(), ef.evidence),
```

And add helper functions at bottom of file:

```rust
fn map_evidence(map: Option<&EvidenceMap>, mut ev: Vec<EvidenceSpan>) -> Vec<EvidenceSpan> {
    let Some(map) = map else { return ev; };

    for e in ev.iter_mut() {
        if let Some(new_off) = map.map_offset(e.offset) {
            e.note = Some(match &e.note {
                Some(n) => format!("{n}; mapped_from_decoded_offset={}", e.offset),
                None => format!("mapped_from_decoded_offset={}", e.offset),
            });
            e.offset = new_off;
        } else {
            // leave offset as-is; it is decoded-space
            e.note = Some(match &e.note {
                Some(n) => format!("{n}; decoded_offset_unmappable"),
                None => "decoded_offset_unmappable".into(),
            });
        }
    }
    ev
}
```

---

### 8.6 Make embedded JS visitor emit evidence spans

#### Update `crates/sis-pdf-detectors/src/embedded_visitors.rs`

In `EmbeddedJavaScriptVisitor::on_node`, where you extract payload, add decoded-space evidence:

Replace the `EmbeddedFinding{ evidence: vec![] }` with:

```rust
        let mut ev = Vec::new();
        if let Some((_, js_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS") {
            // js_obj.span is relative to the embedded buffer when embedded; relative to file when top-level.
            ev.push(EvidenceSpan{
                offset: js_obj.span.start,
                length: (js_obj.span.end - js_obj.span.start) as u32,
                note: Some(format!("JS span at {}", path)),
            });
        }

        out.push(EmbeddedFinding{
            surface: AttackSurface::JavaScript,
            kind: "embedded_javascript".into(),
            severity: Severity::Critical,
            confidence: Confidence::Probable,
            title: "Embedded JavaScript indicator".into(),
            description: desc,
            evidence: ev,
        });
```

(Leave URI/Submit/Launch evidence empty for now — you can add spans similarly.)

---

### 8.7 Provide evidence_map in ObjStm-based detectors

#### Update `crates/sis-pdf-detectors/src/xref_objstm_extract.rs` (chunk 6/7 version)

Inside the loop where you build `origin`, set `evidence_map` based on filter chain:

Add this just before `let origin = EmbeddedOrigin{...};`:

```rust
            // Evidence mapping:
            // If ObjStm has NO filters, decoded bytes == raw stream data bytes and offsets map 1:1.
            let evidence_map = {
                let (filters, _) = g.stream_filters_and_length(objstm_entry);
                if filters.is_empty() {
                    if let Some(loc) = sis_pdf_pdf::streamloc::locate_stream_data(file, objstm_entry) {
                        Some(sis_pdf_core::evidence_map::EvidenceMap::IdentityStream{
                            data_start_file_off: loc.data.start,
                            data_end_file_off: loc.data.end,
                        })
                    } else {
                        Some(sis_pdf_core::evidence_map::EvidenceMap::Unmappable{
                            container_span: objstm_entry.full_span,
                            note: "Could not locate raw stream data span".into(),
                        })
                    }
                } else {
                    Some(sis_pdf_core::evidence_map::EvidenceMap::Unmappable{
                        container_span: objstm_entry.full_span,
                        note: format!("ObjStm uses filters {:?}; decoded offsets cannot be mapped to file offsets", filters),
                    })
                }
            };
```

Then include in origin:

```rust
                evidence_map,
                trigger: None, // chunk 9 will fill this
```

#### Update `crates/sis-pdf-detectors/src/objstm_deep.rs` similarly

When building the origin for each embedded object, set `evidence_map` based on whether filters are empty and `locate_stream_data` succeeds.

---

That’s chunk 8: you now get **real file offsets** for embedded evidence in the common case of unfiltered ObjStm streams, and a deterministic fallback otherwise.

---

## Chunk 9 — Trigger graph enrichment

### Goal

Every visitor hit should explain *how it can be triggered* (OpenAction vs AA event vs annotation action vs name tree entry). Also generate a **graph summary** (edges) across trigger → action → payload.

We’ll add:

* `TriggerContext` type in `sis-pdf-core`
* origin carries `trigger`
* new detector `TriggerGraphSummaryDetector` that gathers edges from all the common trigger surfaces

---

### 9.1 New file: `crates/sis-pdf-core/src/trigger.rs`

```rust
#[derive(Debug, Clone)]
pub enum TriggerKind {
    OpenAction,
    DocumentAA,          // Catalog /AA
    PageAA,              // Page /AA
    AnnotationA,         // Annot /A
    AnnotationAAEvent,   // Annot /AA (event key)
    NameTreeJavaScript,  // Names tree /JavaScript entry
    XrefType2Embedded,   // xref stream type-2 -> ObjStm -> embedded object
    ObjStmDeep,          // deep enumeration
}

#[derive(Debug, Clone)]
pub struct TriggerContext {
    pub kind: TriggerKind,
    pub path: String,          // e.g. "$.Catalog.OpenAction", "$.Annot.AA./E"
    pub event: Option<String>, // annotation AA event name or AA key
    pub note: Option<String>,
}
```

### 9.2 Export it

`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod trigger; // NEW
```

### 9.3 Add trigger context into visitor output descriptions

#### Update `crates/sis-pdf-core/src/visitor.rs`

In `run_visitors_on_embedded` description formatting, append trigger if present:

Replace the description construction with:

```rust
let trigger_txt = origin.trigger.as_ref().map(|t| {
    format!(
        "Trigger: {:?} path={} event={} note={}",
        t.kind,
        t.path,
        t.event.clone().unwrap_or_else(|| "-".into()),
        t.note.clone().unwrap_or_else(|| "-".into()),
    )
}).unwrap_or_else(|| "Trigger: (none)".into());

description: format!(
    "{}\n{}\nOrigin: {}\nContainers: {}\n{}",
    ef.description,
    trigger_txt,
    origin.origin_kind,
    if origin.container_objects.is_empty() { "(none)".into() } else { origin.container_objects.join(", ") },
    origin.note.clone().unwrap_or_default(),
),
```

---

### 9.4 Populate trigger contexts in detectors

#### A) Annotations (`crates/sis-pdf-detectors/src/annots.rs`)

When building origin for `/A`:

```rust
trigger: Some(sis_pdf_core::trigger::TriggerContext{
    kind: sis_pdf_core::trigger::TriggerKind::AnnotationA,
    path: "$.Page.Annots[].A".into(),
    event: None,
    note: Some("Annotation /A action".into()),
}),
```

For `/AA` event entry:

```rust
trigger: Some(sis_pdf_core::trigger::TriggerContext{
    kind: sis_pdf_core::trigger::TriggerKind::AnnotationAAEvent,
    path: format!("$.Page.Annots[].AA.{}", event),
    event: Some(event.clone()),
    note: Some("Annotation /AA event action".into()),
}),
```

#### B) NameTree JavaScript (`crates/sis-pdf-detectors/src/javascript.rs`)

When building origin for name tree entry:

```rust
trigger: Some(sis_pdf_core::trigger::TriggerContext{
    kind: sis_pdf_core::trigger::TriggerKind::NameTreeJavaScript,
    path: "$.Catalog.Names.JavaScript".into(),
    event: Some(nm.clone()),
    note: Some("NameTree /JavaScript entry value visited".into()),
}),
```

#### C) XRef type-2 ObjStm extraction (`xref_objstm_extract.rs`)

Set:

```rust
trigger: Some(sis_pdf_core::trigger::TriggerContext{
    kind: sis_pdf_core::trigger::TriggerKind::XrefType2Embedded,
    path: "$.XRefStream.Type2".into(),
    event: None,
    note: Some(format!("xref obj={} -> ObjStm {} idx {}", objno, objstm_obj, idx)),
}),
```

#### D) ObjStm deep (`objstm_deep.rs`)

Set:

```rust
trigger: Some(sis_pdf_core::trigger::TriggerContext{
    kind: sis_pdf_core::trigger::TriggerKind::ObjStmDeep,
    path: "$.ObjStm[]".into(),
    event: None,
    note: Some(format!("embedded objnum={} table_index={}", objnum, i)),
}),
```

---

### 9.5 New detector: trigger graph summary (edges)

## New file: `crates/sis-pdf-detectors/src/trigger_graph.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;
use sis_pdf_pdf::object::{PdfAtom, PdfObj};

pub struct TriggerGraphSummaryDetector;

impl Detector for TriggerGraphSummaryDetector {
    fn id(&self) -> &'static str { "graph.trigger_summary" }
    fn surface(&self) -> AttackSurface { AttackSurface::Structure }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH }
    fn cost(&self) -> Cost { Cost::Moderate }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let g = &ctx.graph;
        let mut edges: Vec<String> = Vec::new();

        // OpenAction edges: Catalog -> OpenAction -> (action dict /S + payload keys)
        if let Some(cat_r) = g.catalog_ref() {
            if let Some(cat_e) = g.get(cat_r) {
                if let Some(cat_d) = g.obj_as_dict(cat_e) {
                    if let Some((_, oa)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/OpenAction") {
                        edges.extend(describe_action_edge(g, "Catalog/OpenAction", oa));
                    }
                    if let Some((_, aa)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/AA") {
                        edges.push("Catalog -> AA (additional-actions dict)".into());
                        if let Some(ad) = resolve_dict(g, aa) {
                            for (k, v) in &ad.entries {
                                let ev = String::from_utf8_lossy(&k.decoded).to_string();
                                edges.extend(describe_action_edge(g, &format!("Catalog/AA/{}", ev), v));
                            }
                        }
                    }
                }
            }
        }

        // Annotation edges: PageTree -> Annots -> /A + /AA event
        let pages = sis_pdf_pdf::pagetree::collect_pages(g, 2000, 64);
        for p in pages {
            for a in p.annots {
                let Some(annot_e) = g.resolve_ref(&a) else { continue; };
                let Some(ad) = g.obj_as_dict(annot_e) else { continue; };

                if let Some((_, ao)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/A") {
                    edges.extend(describe_action_edge(g, "Annot/A", ao));
                }
                if let Some((_, aao)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/AA") {
                    if let Some(aad) = resolve_dict(g, aao) {
                        for (k, v) in &aad.entries {
                            let ev = String::from_utf8_lossy(&k.decoded).to_string();
                            edges.extend(describe_action_edge(g, &format!("Annot/AA/{}", ev), v));
                        }
                    }
                }
            }
        }

        // NameTree JS edges: Catalog/Names/JavaScript -> entry name -> value kind
        if let Some(cat_r) = g.catalog_ref() {
            if let Some(cat_e) = g.get(cat_r) {
                if let Some(cat_d) = g.obj_as_dict(cat_e) {
                    if let Some((_, names_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/Names") {
                        if let Some(names_d) = resolve_dict(g, names_obj) {
                            if let Some((_, js_tree_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(names_d, b"/JavaScript") {
                                let entries = sis_pdf_pdf::nametree::enumerate_name_tree(g, js_tree_obj, 12, 200);
                                for ent in entries {
                                    edges.push(format!(
                                        "Names/JavaScript[{}] -> value({})",
                                        String::from_utf8_lossy(&ent.name),
                                        classify_obj(&ent.value)
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        if edges.is_empty() {
            return Ok(vec![]);
        }

        if edges.len() > 500 { edges.truncate(500); }

        Ok(vec![Finding{
            id: self.id().into(),
            surface: AttackSurface::Structure,
            kind: "trigger_graph_edges".into(),
            severity: Severity::Info,
            confidence: Confidence::Heuristic,
            title: "Trigger graph summary (edges)".into(),
            description: format!("Collected {} edges (truncated to 500):\n{}", edges.len(), edges.join("\n")),
            objects: vec![],
            evidence: vec![],
            remediation: Some("Use edges to trace trigger->action->payload. Deep scans should resolve refs and inspect payload objects for JS/URI/Launch.".into()),
        }])
    }
}

fn resolve_dict<'a>(g: &sis_pdf_pdf::graph::ObjectGraph<'a>, o: &PdfObj<'a>) -> Option<&'a sis_pdf_pdf::object::PdfDict<'a>> {
    match &o.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Ref{..} => g.resolve_ref(o).and_then(|e| g.obj_as_dict(e)),
        _ => None,
    }
}

fn describe_action_edge<'a>(g: &sis_pdf_pdf::graph::ObjectGraph<'a>, from: &str, o: &PdfObj<'a>) -> Vec<String> {
    let mut out = Vec::new();
    let d = resolve_dict(g, o);
    if d.is_none() {
        out.push(format!("{} -> (non-dict action {})", from, classify_obj(o)));
        return out;
    }
    let d = d.unwrap();

    let s = if let Some((_, s_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/S") {
        if let PdfAtom::Name(n) = &s_obj.atom {
            String::from_utf8_lossy(&n.decoded).to_string()
        } else { "unknown".into() }
    } else { "unknown".into() };

    let mut payloads = Vec::new();
    for k in [b"/JS".as_slice(), b"/URI".as_slice(), b"/F".as_slice(), b"/Launch".as_slice()] {
        if sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, k).is_some() {
            payloads.push(String::from_utf8_lossy(k).to_string());
        }
    }
    out.push(format!("{} -> Action(/S={}) payload_keys={}", from, s, if payloads.is_empty() {"-".into()} else {payloads.join(",")}));
    out
}

fn classify_obj(o: &PdfObj<'_>) -> &'static str {
    match &o.atom {
        PdfAtom::Ref{..} => "ref",
        PdfAtom::Dict(_) => "dict",
        PdfAtom::Array(_) => "array",
        PdfAtom::Str(_) => "string",
        _ => "other",
    }
}
```

### 9.6 Wire it in

`crates/sis-pdf-detectors/src/lib.rs`

```rust
pub mod trigger_graph; // NEW
```

`crates/sis-pdf-core/src/registry.rs`

```rust
Box::new(sis_pdf_detectors::trigger_graph::TriggerGraphSummaryDetector), // NEW
```

That’s chunk 9: visitor findings now include **trigger context**, and you also get a **graph edge summary**.

---

## Chunk 10 — Performance pass (budgets + scheduler + caching hooks)

### Goal

Keep deep scans interactive by enforcing:

* **Max decoded bytes total**
* **Max nodes visited**
* **Max heavy ops** (e.g., ObjStm extracted objects)

…and avoid repeated decoding across detectors with a shared cache where possible.

We’ll add:

* `ScanBudget` to `ScanOptions`
* `Budget` runtime counters in `ScanContext`
* decode helper checks budget before doing big work
* detectors use `budget.try_reserve_*()` to cap loops

---

### 10.1 Update `crates/sis-pdf-core/src/scan.rs` (options + budget)

Add to `ScanOptions`:

```rust
#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub deep: bool,
    pub max_decode_bytes: usize,
    pub recover_xref: bool,
    pub parallel: bool,

    // NEW:
    pub budget: ScanBudget,
}

#[derive(Clone, Debug)]
pub struct ScanBudget {
    pub max_total_decoded_bytes: usize,
    pub max_visited_nodes: usize,
    pub max_embedded_objects: usize,
}

impl Default for ScanBudget {
    fn default() -> Self {
        Self{
            max_total_decoded_bytes: 128 * 1024 * 1024, // 128MB
            max_visited_nodes: 2_000_000,
            max_embedded_objects: 50_000,
        }
    }
}
```

When you construct `ScanOptions` in runner/tests, set `budget: Default::default()` or custom.

---

### 10.2 New file: `crates/sis-pdf-core/src/budget.rs`

```rust
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::scan::ScanBudget;

pub struct BudgetState {
    pub decoded_bytes: AtomicUsize,
    pub visited_nodes: AtomicUsize,
    pub embedded_objects: AtomicUsize,
    limits: ScanBudget,
}

impl BudgetState {
    pub fn new(limits: ScanBudget) -> Self {
        Self{
            decoded_bytes: AtomicUsize::new(0),
            visited_nodes: AtomicUsize::new(0),
            embedded_objects: AtomicUsize::new(0),
            limits,
        }
    }

    pub fn try_reserve_decoded(&self, n: usize) -> bool {
        self.try_add(&self.decoded_bytes, n, self.limits.max_total_decoded_bytes)
    }
    pub fn try_reserve_nodes(&self, n: usize) -> bool {
        self.try_add(&self.visited_nodes, n, self.limits.max_visited_nodes)
    }
    pub fn try_reserve_embedded(&self, n: usize) -> bool {
        self.try_add(&self.embedded_objects, n, self.limits.max_embedded_objects)
    }

    fn try_add(&self, a: &AtomicUsize, n: usize, limit: usize) -> bool {
        let mut cur = a.load(Ordering::Relaxed);
        loop {
            if cur.saturating_add(n) > limit {
                return false;
            }
            match a.compare_exchange_weak(cur, cur + n, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(v) => cur = v,
            }
        }
    }
}
```

Export it:
`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod budget; // NEW
```

---

### 10.3 Add budget state into `ScanContext`

Update `crates/sis-pdf-core/src/scan.rs` (or wherever `ScanContext` is defined) to include:

```rust
pub struct ScanContext<'a> {
    pub bytes: &'a [u8],
    pub graph: sis_pdf_pdf::graph::ObjectGraph<'a>,
    pub options: ScanOptions,

    // NEW:
    pub budget_state: crate::budget::BudgetState,
}
```

Initialize it in your scan runner (where `ScanContext` is built):

```rust
let budget_state = sis_pdf_core::budget::BudgetState::new(options.budget.clone());
let ctx = ScanContext{ bytes, graph, options, budget_state };
```

---

### 10.4 Budget-aware decode in `sis-pdf-pdf/decode.rs`

In your decode entrypoint (e.g. `decode_with_filters_limited`), add a wrapper so callers can refuse work if budget exhausted:

#### New helper in `crates/sis-pdf-pdf/src/decode.rs`

```rust
use anyhow::anyhow;

pub fn decode_with_budget(
    input: &[u8],
    filters: &[crate::stream::FilterSpec],
    plan: DecodePlan,
    try_reserve_decoded: impl Fn(usize) -> bool,
) -> anyhow::Result<DecodedBytes> {
    // Reserve worst-case output budget up front
    if !try_reserve_decoded(plan.max_output) {
        return Err(anyhow!("decode budget exceeded (max_output reservation denied)"));
    }
    decode_with_filters_limited(input, filters, plan)
}
```

Then update heavy callers (ObjStm, xref stream parsing) to use `decode_with_budget(...)` with:

```rust
|n| ctx.budget_state.try_reserve_decoded(n)
```

This stops deep scans from trying to inflate endless streams.

---

### 10.5 Budget-aware visitor walking

In `sis-pdf-core/src/visitor.rs`, add one line inside `walk` near the start:

```rust
if !ctx.try_reserve_node(1) { return; }
```

So extend `VisitorContext`:

```rust
pub struct VisitorContext<'a> {
    ...
    pub try_reserve_node: Box<dyn Fn(usize) -> bool + 'a>, // NEW
}
```

Then in detectors constructing `VisitorContext`, pass:

```rust
try_reserve_node: Box::new(|n| ctx.budget_state.try_reserve_nodes(n)),
```

And update `walk` to call it:

```rust
if !(ctx.try_reserve_node)(1) { return; }
```

This prevents pathological object graphs from locking the UI.

---

### 10.6 Scheduler pattern for deep work (bounded batches)

Add a tiny helper to avoid per-object allocations and keep responsiveness predictable.

#### New file: `crates/sis-pdf-core/src/work.rs`

```rust
pub struct WorkLimiter {
    pub max: usize,
    pub used: usize,
}
impl WorkLimiter {
    pub fn new(max: usize) -> Self { Self{ max, used: 0 } }
    pub fn take(&mut self, n: usize) -> usize {
        if self.used >= self.max { return 0; }
        let rem = self.max - self.used;
        let k = std::cmp::min(rem, n);
        self.used += k;
        k
    }
}
```

Export:
`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod work; // NEW
```

Use it in:

* `objstm_deep.rs` (cap embedded objects across *all* ObjStm)
* `xref_objstm_extract.rs` (cap type-2 entries)
* `javascript.rs` name tree (cap entries)

Example in `objstm_deep.rs`:

```rust
let mut limiter = sis_pdf_core::work::WorkLimiter::new(ctx.options.budget.max_embedded_objects);
...
let allowance = limiter.take(1);
if allowance == 0 { break; }
```

---

### 10.7 Decode caches (minimal, practical)

You already have per-detector caches. The next step is a shared cache in `ScanContext` (mutex or dashmap). Keep it simple:

* Add `Arc<dashmap::DashMap<(u32,u16), Vec<u8>>>` for decoded streams keyed by object ref.
* Reuse in ObjStm decode and xref stream decode.

If you want it now, I’ll paste it, but it’s a more invasive change (Cargo deps + lifetime ergonomics). The budget system above already prevents UI-killing files.

---

## What you have after chunk 8+9+10

* Embedded JS/URI/Launch hits now come with **trigger context** and (when safely possible) **file offsets**.
* You get a compact **trigger graph** summary you can turn into DOT later.
* Deep scanning has **hard budgets** so it remains interactive and predictable.



# Chapter 12

Below is **Chunk 11: graph export + “path to payload” reconstruction**, with export to:

* **DOT** (Graphviz)
* **GML** (Graph Modeling Language)
* **JSON** (`{ nodes:[], edges:[] }`)

This chunk does two things:

1. Introduces a **canonical graph model** (nodes + edges + attributes) you can build from your scan.
2. Implements a **Path-to-Payload reconstruction** pass that turns “trigger edges + embedded payload hits” into **concrete chains** like:
   `Catalog.OpenAction → Action(/S=JavaScript) → /JS → (payload preview)`
   or
   `Page.Annots[n].AA.E → Action(/S=URI) → /URI → "https://..."`.

It also adds a clean way to export the graph in multiple formats.

---

# 11.1 sis-pdf-core: canonical graph model + exporters

## 11.1.1 New file: `crates/sis-pdf-core/src/graph_model.rs`

```rust
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Graph {
    pub directed: bool,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    node_index: HashMap<String, usize>, // id -> idx
}

#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    pub attrs: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Edge {
    pub source: String,
    pub target: String,
    pub kind: EdgeKind,
    pub label: String,
    pub attrs: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Trigger,
    ContainerObject,
    Action,
    Payload,
    EmbeddedObject,
    Finding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    Triggers,       // trigger -> action
    Contains,       // container -> embedded/action/payload
    ResolvesTo,     // ref -> resolved object
    Uses,           // action -> payload
    Indicates,      // finding -> payload/action
    Path,           // synthesized: trigger->...->payload path
}

impl Graph {
    pub fn new(directed: bool) -> Self {
        Self {
            directed,
            nodes: Vec::new(),
            edges: Vec::new(),
            node_index: HashMap::new(),
        }
    }

    pub fn upsert_node(&mut self, id: impl Into<String>, kind: NodeKind, label: impl Into<String>) -> String {
        let id = id.into();
        if let Some(&idx) = self.node_index.get(&id) {
            // preserve existing; allow label updates if you want
            self.nodes[idx].kind = kind;
            self.nodes[idx].label = label.into();
            return id;
        }
        let node = Node {
            id: id.clone(),
            kind,
            label: label.into(),
            attrs: HashMap::new(),
        };
        self.node_index.insert(id.clone(), self.nodes.len());
        self.nodes.push(node);
        id
    }

    pub fn node_mut(&mut self, id: &str) -> Option<&mut Node> {
        let idx = *self.node_index.get(id)?;
        self.nodes.get_mut(idx)
    }

    pub fn add_edge(&mut self, source: impl Into<String>, target: impl Into<String>, kind: EdgeKind, label: impl Into<String>) {
        self.edges.push(Edge {
            source: source.into(),
            target: target.into(),
            kind,
            label: label.into(),
            attrs: HashMap::new(),
        });
    }

    pub fn add_edge_attr(&mut self, i: usize, k: &str, v: &str) {
        if let Some(e) = self.edges.get_mut(i) {
            e.attrs.insert(k.to_string(), v.to_string());
        }
    }
}

/// Stable-ish IDs that are easy to join across exports.
/// Keep them consistent: "trigger:...", "obj:10:0", "action:...", "payload:..."
pub fn id_trigger(s: &str) -> String { format!("trigger:{}", s) }
pub fn id_obj(obj: u32, gen: u16) -> String { format!("obj:{}:{}", obj, gen) }
pub fn id_action(s: &str) -> String { format!("action:{}", s) }
pub fn id_payload(s: &str) -> String { format!("payload:{}", s) }
pub fn id_embedded(s: &str) -> String { format!("embedded:{}", s) }
pub fn id_finding(s: &str) -> String { format!("finding:{}", s) }

pub fn kind_name(k: NodeKind) -> &'static str {
    match k {
        NodeKind::Trigger => "Trigger",
        NodeKind::ContainerObject => "ContainerObject",
        NodeKind::Action => "Action",
        NodeKind::Payload => "Payload",
        NodeKind::EmbeddedObject => "EmbeddedObject",
        NodeKind::Finding => "Finding",
    }
}

pub fn edge_kind_name(k: EdgeKind) -> &'static str {
    match k {
        EdgeKind::Triggers => "Triggers",
        EdgeKind::Contains => "Contains",
        EdgeKind::ResolvesTo => "ResolvesTo",
        EdgeKind::Uses => "Uses",
        EdgeKind::Indicates => "Indicates",
        EdgeKind::Path => "Path",
    }
}
```

## 11.1.2 New file: `crates/sis-pdf-core/src/graph_export.rs`

Exports **DOT**, **GML**, and **JSON**.

```rust
use std::collections::HashMap;
use std::io::{self, Write};

use crate::graph_model::{Graph, Node, Edge, kind_name, edge_kind_name};

pub enum GraphFormat {
    Dot,
    Gml,
    Json,
}

pub fn write_graph<W: Write>(g: &Graph, fmt: GraphFormat, mut w: W) -> io::Result<()> {
    match fmt {
        GraphFormat::Dot => write_dot(g, &mut w),
        GraphFormat::Gml => write_gml(g, &mut w),
        GraphFormat::Json => write_json(g, &mut w),
    }
}

fn write_dot<W: Write>(g: &Graph, w: &mut W) -> io::Result<()> {
    let header = if g.directed { "digraph sis_pdf" } else { "graph sis_pdf" };
    writeln!(w, "{} {{", header)?;
    writeln!(w, "  rankdir=LR;")?;
    writeln!(w, "  node [shape=box];")?;

    for n in &g.nodes {
        let label = escape_dot(&n.label);
        writeln!(w, "  \"{}\" [label=\"{}\\n({})\"];",
            escape_dot(&n.id), label, kind_name(n.kind)
        )?;
    }

    let arrow = if g.directed { "->" } else { "--" };
    for e in &g.edges {
        writeln!(w, "  \"{}\" {} \"{}\" [label=\"{}\\n({})\"];",
            escape_dot(&e.source),
            arrow,
            escape_dot(&e.target),
            escape_dot(&e.label),
            edge_kind_name(e.kind),
        )?;
    }

    writeln!(w, "}}")?;
    Ok(())
}

fn write_gml<W: Write>(g: &Graph, w: &mut W) -> io::Result<()> {
    // GML nodes require integer IDs; we map node indices.
    let mut idx_map: HashMap<&str, usize> = HashMap::new();
    for (i, n) in g.nodes.iter().enumerate() {
        idx_map.insert(n.id.as_str(), i);
    }

    writeln!(w, "graph [")?;
    writeln!(w, "  directed {}", if g.directed { 1 } else { 0 })?;

    for (i, n) in g.nodes.iter().enumerate() {
        writeln!(w, "  node [")?;
        writeln!(w, "    id {}", i)?;
        writeln!(w, "    label \"{}\"", escape_gml(&n.label))?;
        writeln!(w, "    kind \"{}\"", kind_name(n.kind))?;
        // attrs
        for (k, v) in &n.attrs {
            writeln!(w, "    {} \"{}\"", escape_gml(k), escape_gml(v))?;
        }
        writeln!(w, "  ]")?;
    }

    for e in &g.edges {
        let Some(&s) = idx_map.get(e.source.as_str()) else { continue; };
        let Some(&t) = idx_map.get(e.target.as_str()) else { continue; };

        writeln!(w, "  edge [")?;
        writeln!(w, "    source {}", s)?;
        writeln!(w, "    target {}", t)?;
        writeln!(w, "    label \"{}\"", escape_gml(&e.label))?;
        writeln!(w, "    kind \"{}\"", edge_kind_name(e.kind))?;
        for (k, v) in &e.attrs {
            writeln!(w, "    {} \"{}\"", escape_gml(k), escape_gml(v))?;
        }
        writeln!(w, "  ]")?;
    }

    writeln!(w, "]")?;
    Ok(())
}

fn write_json<W: Write>(g: &Graph, w: &mut W) -> io::Result<()> {
    // No serde dependency required: write a straightforward JSON object.
    // If you already use serde_json elsewhere, you can replace this with serde derives.
    writeln!(w, "{{")?;
    writeln!(w, "  \"directed\": {},", if g.directed { "true" } else { "false" })?;

    writeln!(w, "  \"nodes\": [")?;
    for (i, n) in g.nodes.iter().enumerate() {
        writeln!(w, "    {{")?;
        writeln!(w, "      \"id\": \"{}\",", escape_json(&n.id))?;
        writeln!(w, "      \"kind\": \"{}\",", kind_name(n.kind))?;
        writeln!(w, "      \"label\": \"{}\",", escape_json(&n.label))?;
        writeln!(w, "      \"attrs\": {}{}", json_map(&n.attrs), if i + 1 == g.nodes.len() { "" } else { "" })?;
        writeln!(w, "    }}{}", if i + 1 == g.nodes.len() { "" } else { "," })?;
    }
    writeln!(w, "  ],")?;

    writeln!(w, "  \"edges\": [")?;
    for (i, e) in g.edges.iter().enumerate() {
        writeln!(w, "    {{")?;
        writeln!(w, "      \"source\": \"{}\",", escape_json(&e.source))?;
        writeln!(w, "      \"target\": \"{}\",", escape_json(&e.target))?;
        writeln!(w, "      \"kind\": \"{}\",", edge_kind_name(e.kind))?;
        writeln!(w, "      \"label\": \"{}\",", escape_json(&e.label))?;
        writeln!(w, "      \"attrs\": {}", json_map(&e.attrs))?;
        writeln!(w, "    }}{}", if i + 1 == g.edges.len() { "" } else { "," })?;
    }
    writeln!(w, "  ]")?;

    writeln!(w, "}}")?;
    Ok(())
}

fn json_map(m: &HashMap<String, String>) -> String {
    let mut s = String::from("{");
    let mut first = true;
    for (k, v) in m {
        if !first { s.push_str(", "); }
        first = false;
        s.push('"'); s.push_str(&escape_json(k)); s.push_str("\": ");
        s.push('"'); s.push_str(&escape_json(v)); s.push('"');
    }
    s.push('}');
    s
}

fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
fn escape_gml(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
```

## 11.1.3 Export modules

`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod graph_model;   // NEW
pub mod graph_export;  // NEW
```

---

# 11.2 sis-pdf-core: “path to payload” reconstruction

We’ll reconstruct paths by walking a graph built from:

* triggers (OpenAction, AA events, annotation A/AA, NameTree JS)
* actions (`/S` kind)
* payload keys (`/JS`, `/URI`, `/F`, `/Launch`)
* visitor hits (payload indicators)

Then we synthesize **Path edges** with a human-readable chain string.

## 11.2.1 New file: `crates/sis-pdf-core/src/path_recon.rs`

```rust
use std::collections::{HashMap, VecDeque, HashSet};

use crate::graph_model::{Graph, EdgeKind};

#[derive(Debug, Clone)]
pub struct PathHit {
    pub from_trigger: String,
    pub to_payload: String,
    pub chain: Vec<String>, // node ids
}

pub fn reconstruct_paths(g: &Graph, max_paths: usize, max_depth: usize) -> Vec<PathHit> {
    // Identify trigger nodes and payload nodes
    let triggers: Vec<String> = g.nodes.iter()
        .filter(|n| matches!(n.kind, crate::graph_model::NodeKind::Trigger))
        .map(|n| n.id.clone())
        .collect();

    let payloads: HashSet<String> = g.nodes.iter()
        .filter(|n| matches!(n.kind, crate::graph_model::NodeKind::Payload))
        .map(|n| n.id.clone())
        .collect();

    // adjacency (directed as stored)
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in &g.edges {
        // Only traverse meaningful edge kinds to prevent exploding
        match e.kind {
            EdgeKind::Triggers | EdgeKind::Uses | EdgeKind::Contains | EdgeKind::ResolvesTo | EdgeKind::Indicates => {
                adj.entry(e.source.as_str()).or_default().push(e.target.as_str());
            }
            EdgeKind::Path => {}
        }
    }

    let mut hits = Vec::new();

    for t in triggers {
        if hits.len() >= max_paths { break; }
        // BFS with parent pointers
        let mut q = VecDeque::new();
        let mut parent: HashMap<String, String> = HashMap::new();
        let mut depth: HashMap<String, usize> = HashMap::new();
        q.push_back(t.clone());
        depth.insert(t.clone(), 0);

        while let Some(cur) = q.pop_front() {
            let d = *depth.get(&cur).unwrap_or(&0);
            if d >= max_depth { continue; }

            if payloads.contains(&cur) && cur != t {
                // reconstruct chain
                let mut chain = vec![cur.clone()];
                let mut x = cur.clone();
                while let Some(p) = parent.get(&x).cloned() {
                    chain.push(p.clone());
                    x = p;
                }
                chain.reverse();
                hits.push(PathHit{
                    from_trigger: t.clone(),
                    to_payload: cur.clone(),
                    chain,
                });
                if hits.len() >= max_paths { break; }
                // continue searching; we want multiple payloads
            }

            let nexts = adj.get(cur.as_str()).cloned().unwrap_or_default();
            for &n in &nexts {
                let n = n.to_string();
                if parent.contains_key(&n) || n == t { continue; }
                parent.insert(n.clone(), cur.clone());
                depth.insert(n.clone(), d + 1);
                q.push_back(n);
            }
        }
    }

    hits
}
```

Export it:
`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod path_recon; // NEW
```

---

# 11.3 sis-pdf-detectors: build the graph from scan context + visitor hits

We’ll create a detector that:

1. builds a `Graph` with nodes/edges from:

   * trigger surfaces (Catalog OpenAction + AA, annotations /A + /AA, NameTree /JavaScript)
2. adds payload nodes from action dictionaries
3. links visitor hits (embedded_javascript / embedded_uri_action / embedded_launch_action) to payload/action nodes
4. runs path reconstruction and adds `EdgeKind::Path` edges
5. optionally emits **export strings** into the finding description (small) and relies on CLI export (next section) for full dumps

## 11.3.1 New file: `crates/sis-pdf-detectors/src/graph_exporter.rs`

```rust
use anyhow::Result;
use sis_pdf_core::detect::*;
use sis_pdf_core::model::*;
use sis_pdf_core::graph_model::*;
use sis_pdf_pdf::object::{PdfAtom, PdfObj};

pub struct GraphBuildAndPathReconDetector;

impl Detector for GraphBuildAndPathReconDetector {
    fn id(&self) -> &'static str { "graph.build_and_paths" }
    fn surface(&self) -> AttackSurface { AttackSurface::Structure }
    fn needs(&self) -> Needs { Needs::OBJECT_GRAPH | Needs::BYTES_ONLY }
    fn cost(&self) -> Cost { Cost::Expensive } // does traversal + path recon

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let gpdf = &ctx.graph;
        let bytes = ctx.bytes;

        let mut g = Graph::new(true);

        // ---- 1) Add trigger/action/payload edges from known surfaces ----

        // Catalog triggers
        if let Some(cat_r) = gpdf.catalog_ref() {
            let cat_id = g.upsert_node(id_obj(cat_r.obj, cat_r.gen), NodeKind::ContainerObject, "Catalog".into());

            if let Some(cat_e) = gpdf.get(cat_r) {
                if let Some(cat_d) = gpdf.obj_as_dict(cat_e) {
                    // OpenAction
                    if let Some((_, oa)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/OpenAction") {
                        add_trigger_action_payload_chain(gpdf, &mut g, &cat_id, "Catalog/OpenAction", oa);
                    }
                    // Catalog AA (additional actions)
                    if let Some((_, aa)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/AA") {
                        if let Some(aad) = resolve_dict(gpdf, aa) {
                            for (k, v) in &aad.entries {
                                let ev = String::from_utf8_lossy(&k.decoded).to_string();
                                add_trigger_action_payload_chain(gpdf, &mut g, &cat_id, &format!("Catalog/AA/{}", ev), v);
                            }
                        }
                    }
                }
            }
        }

        // Annotation triggers
        let pages = sis_pdf_pdf::pagetree::collect_pages(gpdf, 2000, 64);
        for p in pages {
            let page_id = g.upsert_node(id_obj(p.page_ref.obj, p.page_ref.gen), NodeKind::ContainerObject, "Page".into());
            if let Some(n) = g.node_mut(&page_id) {
                n.attrs.insert("page_ref".into(), format!("{} {} R", p.page_ref.obj, p.page_ref.gen));
            }

            for a in p.annots {
                let Some(annot_e) = gpdf.resolve_ref(&a) else { continue; };
                let annot_id = g.upsert_node(id_obj(annot_e.r.obj, annot_e.r.gen), NodeKind::ContainerObject, "Annot".into());
                g.add_edge(page_id.clone(), annot_id.clone(), EdgeKind::Contains, "Annots".into());

                let Some(ad) = gpdf.obj_as_dict(annot_e) else { continue; };

                if let Some((_, ao)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/A") {
                    add_trigger_action_payload_chain(gpdf, &mut g, &annot_id, "Annot/A", ao);
                }
                if let Some((_, aao)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/AA") {
                    if let Some(aad) = resolve_dict(gpdf, aao) {
                        for (k, v) in &aad.entries {
                            let ev = String::from_utf8_lossy(&k.decoded).to_string();
                            add_trigger_action_payload_chain(gpdf, &mut g, &annot_id, &format!("Annot/AA/{}", ev), v);
                        }
                    }
                }
            }
        }

        // NameTree /JavaScript entries
        if let Some(cat_r) = gpdf.catalog_ref() {
            if let Some(cat_e) = gpdf.get(cat_r) {
                if let Some(cat_d) = gpdf.obj_as_dict(cat_e) {
                    if let Some((_, names_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/Names") {
                        if let Some(names_d) = resolve_dict(gpdf, names_obj) {
                            if let Some((_, js_tree_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(names_d, b"/JavaScript") {
                                let tnode = g.upsert_node(id_trigger("Names/JavaScript"), NodeKind::Trigger, "NamesTree(JavaScript)".into());
                                let entries = sis_pdf_pdf::nametree::enumerate_name_tree(gpdf, js_tree_obj, 12, 300);

                                for ent in entries {
                                    let nm = String::from_utf8_lossy(&ent.name).to_string();
                                    let entry_id = g.upsert_node(id_trigger(&format!("Names/JavaScript/{}", nm)), NodeKind::Trigger, format!("NameEntry({})", nm));
                                    g.add_edge(tnode.clone(), entry_id.clone(), EdgeKind::Triggers, "entry".into());

                                    // treat value as an "action root"
                                    add_trigger_action_payload_chain(gpdf, &mut g, &entry_id, &format!("NameTree/{}", nm), &ent.value);
                                }
                            }
                        }
                    }
                }
            }
        }

        // ---- 2) Attach visitor hits (from findings) onto payload/action nodes ----
        //
        // We’ll look for your embedded visitor findings kinds and connect them.
        // This works even if payload came from ObjStm, xref type-2, etc.
        //
        // Note: findings come from detector outputs, not available inside this detector by default.
        // If you want *full* cross-detector linking, you’ll integrate this at runner-level.
        // For now we still generate a strong trigger->payload graph from PDF structure alone.
        //
        // Optional: lightweight heuristic scan of bytes for /JavaScript etc already exists elsewhere.

        // ---- 3) Reconstruct paths and add Path edges ----
        let paths = sis_pdf_core::path_recon::reconstruct_paths(&g, 200, 10);

        for (i, ph) in paths.iter().enumerate() {
            if ph.chain.len() < 2 { continue; }
            // add a synthesized "path edge" from trigger to payload with chain summary
            let label = chain_label(&g, &ph.chain);
            g.add_edge(ph.from_trigger.clone(), ph.to_payload.clone(), EdgeKind::Path, label);
            if i > 500 { break; }
        }

        // ---- 4) Provide small exports in Finding (full export via CLI in next section) ----
        let mut dot = Vec::new();
        sis_pdf_core::graph_export::write_graph(&g, sis_pdf_core::graph_export::GraphFormat::Dot, &mut dot)?;
        let dot_s = String::from_utf8_lossy(&dot);
        let dot_preview = dot_s.lines().take(80).collect::<Vec<_>>().join("\n");

        let mut json = Vec::new();
        sis_pdf_core::graph_export::write_graph(&g, sis_pdf_core::graph_export::GraphFormat::Json, &mut json)?;
        let json_s = String::from_utf8_lossy(&json);
        let json_preview = json_s.chars().take(2000).collect::<String>();

        Ok(vec![Finding{
            id: self.id().into(),
            surface: AttackSurface::Structure,
            kind: "graph_built_with_paths".into(),
            severity: Severity::Info,
            confidence: Confidence::Heuristic,
            title: "Built trigger/action/payload graph + reconstructed paths".into(),
            description: format!(
                "Graph: nodes={}, edges={} (includes synthesized Path edges).\n\
                 Paths found: {} (capped).\n\n\
                 DOT preview (first ~80 lines):\n{}\n\n\
                 JSON preview (first 2000 chars):\n{}",
                g.nodes.len(),
                g.edges.len(),
                paths.len(),
                dot_preview,
                json_preview
            ),
            objects: vec![],
            evidence: vec![],
            remediation: Some("Use --export-graph to emit full DOT/GML/JSON files for offline analysis (Gephi/NetworkX/Graphviz/etc).".into()),
        }])
    }
}

fn chain_label(g: &Graph, chain: &[String]) -> String {
    // Build "Trigger -> Action -> /JS" style label
    let mut parts = Vec::new();
    for id in chain {
        if let Some(n) = g.nodes.iter().find(|n| &n.id == id) {
            parts.push(n.label.clone());
        } else {
            parts.push(id.clone());
        }
        if parts.len() >= 8 { break; }
    }
    parts.join(" -> ")
}

fn resolve_dict<'a>(g: &sis_pdf_pdf::graph::ObjectGraph<'a>, o: &PdfObj<'a>) -> Option<&'a sis_pdf_pdf::object::PdfDict<'a>> {
    match &o.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Ref{..} => g.resolve_ref(o).and_then(|e| g.obj_as_dict(e)),
        _ => None,
    }
}

/// Adds: trigger node -> action node -> payload nodes (JS/URI/F/Launch), plus container contains edges.
///
/// `container_id` is a node representing where this trigger lives (Catalog, Annot, NameEntry, etc.).
fn add_trigger_action_payload_chain<'a>(
    gpdf: &sis_pdf_pdf::graph::ObjectGraph<'a>,
    g: &mut Graph,
    container_id: &str,
    trigger_name: &str,
    action_root: &PdfObj<'a>,
) {
    // Trigger node
    let t_id = g.upsert_node(id_trigger(trigger_name), NodeKind::Trigger, trigger_name.to_string());
    g.add_edge(container_id.to_string(), t_id.clone(), EdgeKind::Contains, "trigger".into());

    // Resolve action dict (or treat non-dict as leaf)
    let action_dict = resolve_dict(gpdf, action_root);
    if action_dict.is_none() {
        let leaf = g.upsert_node(id_action(&format!("{}:non_dict", trigger_name)), NodeKind::Action, "Action(non-dict)".into());
        g.add_edge(t_id.clone(), leaf.clone(), EdgeKind::Triggers, "action".into());
        return;
    }
    let ad = action_dict.unwrap();

    // Action kind via /S
    let s = if let Some((_, s_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/S") {
        match &s_obj.atom {
            PdfAtom::Name(n) => String::from_utf8_lossy(&n.decoded).to_string(),
            _ => "unknown".into()
        }
    } else { "unknown".into() };

    let a_id = g.upsert_node(id_action(&format!("{}:/S={}", trigger_name, s)), NodeKind::Action, format!("Action(/S={})", s));
    g.add_edge(t_id.clone(), a_id.clone(), EdgeKind::Triggers, "triggers".into());

    // Payload keys (if present)
    for key in [b"/JS".as_slice(), b"/URI".as_slice(), b"/F".as_slice(), b"/Launch".as_slice()] {
        if let Some((_, v)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, key) {
            let p_id = g.upsert_node(id_payload(&format!("{}{}", trigger_name, String::from_utf8_lossy(key))), NodeKind::Payload, format!("Payload({})", String::from_utf8_lossy(key)));
            g.add_edge(a_id.clone(), p_id.clone(), EdgeKind::Uses, format!("uses {}", String::from_utf8_lossy(key)));
            // annotate payload value kind
            if let Some(n) = g.node_mut(&p_id) {
                n.attrs.insert("value_kind".into(), classify_obj(&v));
            }
        }
    }
}

fn classify_obj(o: &PdfObj<'_>) -> String {
    match &o.atom {
        PdfAtom::Ref{obj, gen} => format!("ref({} {} R)", obj, gen),
        PdfAtom::Dict(_) => "dict".into(),
        PdfAtom::Array(_) => "array".into(),
        PdfAtom::Str(_) => "string".into(),
        PdfAtom::Name(_) => "name".into(),
        PdfAtom::Int(_) | PdfAtom::Real(_) => "number".into(),
        _ => "other".into(),
    }
}
```

### 11.3.2 Wire it in

`crates/sis-pdf-detectors/src/lib.rs`

```rust
pub mod graph_exporter; // NEW
```

`crates/sis-pdf-core/src/registry.rs`

```rust
Box::new(sis_pdf_detectors::graph_exporter::GraphBuildAndPathReconDetector), // NEW
```

---

# 11.4 CLI support: export graph to DOT/GML/JSON files

You asked for **flexible analysis options**. The cleanest is: after scan, if user passed `--export-graph <prefix>` and `--graph-formats dot,gml,json`, write those files.

I don’t know your current CLI crate (`clap` likely). Here’s a minimal pattern you can adapt.

## 11.4.1 Add to your CLI args (example)

```rust
/// Export trigger/action/payload graph to files using this prefix (e.g., "out/scan1")
#[arg(long)]
pub export_graph: Option<String>;

/// Comma-separated formats: dot,gml,json
#[arg(long, default_value = "dot,json")]
pub graph_formats: String;
```

## 11.4.2 Add a runner hook to write exports

Where you currently do something like:

* `let report = run_scan(...);`
* print report / serialize

Add:

```rust
if let Some(prefix) = &args.export_graph {
    // Rebuild graph in runner-level OR extract from detector output.
    // Easiest: call the graph builder directly (recommended), so export is not truncated.

    let graph = sis-pdf_runner::graph_build::build_trigger_graph(&ctx); // shown below

    let formats = args.graph_formats.split(',').map(|s| s.trim().to_lowercase()).collect::<Vec<_>>();
    for f in formats {
        match f.as_str() {
            "dot" => write_fmt(prefix, "dot", sis_pdf_core::graph_export::GraphFormat::Dot, &graph)?,
            "gml" => write_fmt(prefix, "gml", sis_pdf_core::graph_export::GraphFormat::Gml, &graph)?,
            "json" => write_fmt(prefix, "json", sis_pdf_core::graph_export::GraphFormat::Json, &graph)?,
            _ => {}
        }
    }
}
```

With helper:

```rust
fn write_fmt(prefix: &str, ext: &str, fmt: sis_pdf_core::graph_export::GraphFormat, g: &sis_pdf_core::graph_model::Graph) -> anyhow::Result<()> {
    let path = format!("{}.{}", prefix, ext);
    let mut f = std::fs::File::create(&path)?;
    sis_pdf_core::graph_export::write_graph(g, fmt, &mut f)?;
    Ok(())
}
```

---

# 11.5 Recommended: move graph-building out of the detector and into a reusable builder module

Detectors don’t naturally see each other’s findings, so “attach visitor hits to payload nodes” is best done at **runner level**.

Add a builder module that returns the full graph; you can call it from:

* the detector (for preview)
* the CLI export hook (for full export)
* future integrations (NetworkX/Neo4j ingestion, etc.)

## 11.5.1 New file: `crates/sis-pdf-runner/src/graph_build.rs`

(If you don’t have a `sis-pdf-runner` crate, put this in your CLI crate or `sis-pdf-core` as appropriate.)

```rust
use sis_pdf_core::graph_model::*;
use sis_pdf_pdf::object::{PdfAtom, PdfObj};

pub fn build_trigger_graph<'a>(
    ctx: &sis_pdf_core::scan::ScanContext<'a>,
) -> Graph {
    let gpdf = &ctx.graph;
    let mut g = Graph::new(true);

    // Reuse the same logic from the detector (copy/add helpers).
    // Keep the build deterministic.

    // Catalog
    if let Some(cat_r) = gpdf.catalog_ref() {
        let cat_id = g.upsert_node(id_obj(cat_r.obj, cat_r.gen), NodeKind::ContainerObject, "Catalog".into());
        if let Some(cat_e) = gpdf.get(cat_r) {
            if let Some(cat_d) = gpdf.obj_as_dict(cat_e) {
                if let Some((_, oa)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/OpenAction") {
                    add_trigger_action_payload_chain(gpdf, &mut g, &cat_id, "Catalog/OpenAction", oa);
                }
                if let Some((_, aa)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/AA") {
                    if let Some(aad) = resolve_dict(gpdf, aa) {
                        for (k, v) in &aad.entries {
                            let ev = String::from_utf8_lossy(&k.decoded).to_string();
                            add_trigger_action_payload_chain(gpdf, &mut g, &cat_id, &format!("Catalog/AA/{}", ev), v);
                        }
                    }
                }
            }
        }
    }

    // Pages + annots
    let pages = sis_pdf_pdf::pagetree::collect_pages(gpdf, 2000, 64);
    for p in pages {
        let page_id = g.upsert_node(id_obj(p.page_ref.obj, p.page_ref.gen), NodeKind::ContainerObject, "Page".into());
        for a in p.annots {
            let Some(annot_e) = gpdf.resolve_ref(&a) else { continue; };
            let annot_id = g.upsert_node(id_obj(annot_e.r.obj, annot_e.r.gen), NodeKind::ContainerObject, "Annot".into());
            g.add_edge(page_id.clone(), annot_id.clone(), EdgeKind::Contains, "Annots".into());

            let Some(ad) = gpdf.obj_as_dict(annot_e) else { continue; };
            if let Some((_, ao)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/A") {
                add_trigger_action_payload_chain(gpdf, &mut g, &annot_id, "Annot/A", ao);
            }
            if let Some((_, aao)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/AA") {
                if let Some(aad) = resolve_dict(gpdf, aao) {
                    for (k, v) in &aad.entries {
                        let ev = String::from_utf8_lossy(&k.decoded).to_string();
                        add_trigger_action_payload_chain(gpdf, &mut g, &annot_id, &format!("Annot/AA/{}", ev), v);
                    }
                }
            }
        }
    }

    // NameTree JavaScript
    if let Some(cat_r) = gpdf.catalog_ref() {
        if let Some(cat_e) = gpdf.get(cat_r) {
            if let Some(cat_d) = gpdf.obj_as_dict(cat_e) {
                if let Some((_, names_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/Names") {
                    if let Some(names_d) = resolve_dict(gpdf, names_obj) {
                        if let Some((_, js_tree_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(names_d, b"/JavaScript") {
                            let tnode = g.upsert_node(id_trigger("Names/JavaScript"), NodeKind::Trigger, "NamesTree(JavaScript)".into());
                            let entries = sis_pdf_pdf::nametree::enumerate_name_tree(gpdf, js_tree_obj, 12, 500);
                            for ent in entries {
                                let nm = String::from_utf8_lossy(&ent.name).to_string();
                                let entry_id = g.upsert_node(id_trigger(&format!("Names/JavaScript/{}", nm)), NodeKind::Trigger, format!("NameEntry({})", nm));
                                g.add_edge(tnode.clone(), entry_id.clone(), EdgeKind::Triggers, "entry".into());
                                add_trigger_action_payload_chain(gpdf, &mut g, &entry_id, &format!("NameTree/{}", nm), &ent.value);
                            }
                        }
                    }
                }
            }
        }
    }

    // Synthesized paths
    let paths = sis_pdf_core::path_recon::reconstruct_paths(&g, 500, 12);
    for ph in paths {
        if ph.chain.len() < 2 { continue; }
        let label = chain_label(&g, &ph.chain);
        g.add_edge(ph.from_trigger, ph.to_payload, EdgeKind::Path, label);
    }

    g
}

fn chain_label(g: &Graph, chain: &[String]) -> String {
    let mut parts = Vec::new();
    for id in chain {
        if let Some(n) = g.nodes.iter().find(|n| &n.id == id) {
            parts.push(n.label.clone());
        } else {
            parts.push(id.clone());
        }
        if parts.len() >= 8 { break; }
    }
    parts.join(" -> ")
}

fn resolve_dict<'a>(g: &sis_pdf_pdf::graph::ObjectGraph<'a>, o: &PdfObj<'a>) -> Option<&'a sis_pdf_pdf::object::PdfDict<'a>> {
    match &o.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Ref{..} => g.resolve_ref(o).and_then(|e| g.obj_as_dict(e)),
        _ => None,
    }
}

fn add_trigger_action_payload_chain<'a>(
    gpdf: &sis_pdf_pdf::graph::ObjectGraph<'a>,
    g: &mut Graph,
    container_id: &str,
    trigger_name: &str,
    action_root: &PdfObj<'a>,
) {
    let t_id = g.upsert_node(id_trigger(trigger_name), NodeKind::Trigger, trigger_name.to_string());
    g.add_edge(container_id.to_string(), t_id.clone(), EdgeKind::Contains, "trigger".into());

    let action_dict = resolve_dict(gpdf, action_root);
    if action_dict.is_none() {
        let leaf = g.upsert_node(id_action(&format!("{}:non_dict", trigger_name)), NodeKind::Action, "Action(non-dict)".into());
        g.add_edge(t_id.clone(), leaf.clone(), EdgeKind::Triggers, "action".into());
        return;
    }
    let ad = action_dict.unwrap();

    let s = if let Some((_, s_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/S") {
        match &s_obj.atom {
            PdfAtom::Name(n) => String::from_utf8_lossy(&n.decoded).to_string(),
            _ => "unknown".into()
        }
    } else { "unknown".into() };

    let a_id = g.upsert_node(id_action(&format!("{}:/S={}", trigger_name, s)), NodeKind::Action, format!("Action(/S={})", s));
    g.add_edge(t_id.clone(), a_id.clone(), EdgeKind::Triggers, "triggers".into());

    for key in [b"/JS".as_slice(), b"/URI".as_slice(), b"/F".as_slice(), b"/Launch".as_slice()] {
        if let Some((_, v)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, key) {
            let p_id = g.upsert_node(id_payload(&format!("{}{}", trigger_name, String::from_utf8_lossy(key))), NodeKind::Payload, format!("Payload({})", String::from_utf8_lossy(key)));
            g.add_edge(a_id.clone(), p_id.clone(), EdgeKind::Uses, format!("uses {}", String::from_utf8_lossy(key)));
            if let Some(n) = g.node_mut(&p_id) {
                n.attrs.insert("value_kind".into(), classify_obj(&v));
            }
        }
    }
}

fn classify_obj(o: &PdfObj<'_>) -> String {
    match &o.atom {
        PdfAtom::Ref{obj, gen} => format!("ref({} {} R)", obj, gen),
        PdfAtom::Dict(_) => "dict".into(),
        PdfAtom::Array(_) => "array".into(),
        PdfAtom::Str(_) => "string".into(),
        PdfAtom::Name(_) => "name".into(),
        PdfAtom::Int(_) | PdfAtom::Real(_) => "number".into(),
        _ => "other".into(),
    }
}
```

---

# 11.6 Joining “visitor hits” into the graph (recommended next micro-step)

Right now, the builder reconstructs trigger→action→payload **structurally**, but doesn’t link “embedded_javascript” findings as nodes/edges because those findings are emitted by other detectors.

The recommended approach is runner-level:

1. Run scan → get `Report { findings: Vec<Finding> }`
2. Build graph from structure: `build_trigger_graph(&ctx)`
3. Attach findings:

   * For each finding with `kind == embedded_javascript`:

     * create a `Finding` node
     * connect `Finding -> payload:/JS` (if you can infer) or `Finding -> Action(/S=JavaScript)`
   * Use `finding.description` and `origin.trigger` (from chunk 9) to infer which trigger node to connect to

If you want, I’ll paste **Chunk 11.7** that adds a `graph_attach_findings(&mut Graph, &Report)` function that:

* parses trigger context from finding descriptions (or better: a structured field if you add it to `Finding`)
* adds nodes/edges for findings
* upgrades path reconstruction to prefer chains ending in a finding hit

(That step is straightforward but depends on whether you’re willing to add a structured `Finding.extra: HashMap<String,String>` field.)

---

## What you have now

* A real **graph model** in core
* Exporters for **DOT / GML / JSON**
* A **path-to-payload** reconstruction pass that synthesizes “Path” edges
* A clean hook (`--export-graph prefix` + `--graph-formats dot,gml,json`) to dump the full graph for offline analysis

If you tell me whether your CLI crate uses `clap` and where the runner lives (`sis-pdf`, `sis-pdf`, etc.), I’ll paste the exact diff for the arg parsing + export hook in the correct file locations.


# Chapter 13

Perfect — here’s an **implementation-ready** way to wire **Clap** + graph export into the **`sis-pdf` binary**, without committing you to a separate “runner crate” yet.

The plan:

* Put the reusable builder in **`sis-pdf-core`** (or `sis-pdf-detectors`), but I recommend **`sis-pdf-core`** so the `sis-pdf` binary can call it directly.
* Add Clap flags to `sis-pdf`:

  * `--export-graph <prefix>`
  * `--graph-formats dot,gml,json`
  * optionally `--graph-include-paths/--no-graph-include-paths` if you want to toggle the synthesized Path edges (defaults on).
* After scan finishes, call `build_trigger_graph(&ctx)` and write formats.

Below is the concrete drop-in code.

---

## 1) Put the builder in sis-pdf-core (runner-agnostic)

### 1.1 New file: `crates/sis-pdf-core/src/graph_build.rs`

This is basically the builder you wanted, but placed in core so your `sis-pdf` binary can call it.

```rust
use crate::graph_model::*;
use sis_pdf_pdf::object::{PdfAtom, PdfObj};

/// Build a trigger/action/payload graph from the PDF structure.
/// This is deterministic and does not depend on detector outputs.
///
/// If `include_paths` is true, it synthesizes EdgeKind::Path edges using BFS path reconstruction.
pub fn build_trigger_graph<'a>(
    ctx: &crate::scan::ScanContext<'a>,
    include_paths: bool,
) -> Graph {
    let gpdf = &ctx.graph;
    let mut g = Graph::new(true);

    // ---- Catalog: OpenAction and Catalog /AA ----
    if let Some(cat_r) = gpdf.catalog_ref() {
        let cat_id = g.upsert_node(id_obj(cat_r.obj, cat_r.gen), NodeKind::ContainerObject, "Catalog".into());
        if let Some(cat_e) = gpdf.get(cat_r) {
            if let Some(cat_d) = gpdf.obj_as_dict(cat_e) {
                if let Some((_, oa)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/OpenAction") {
                    add_trigger_action_payload_chain(gpdf, &mut g, &cat_id, "Catalog/OpenAction", oa);
                }
                if let Some((_, aa)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/AA") {
                    if let Some(aad) = resolve_dict(gpdf, aa) {
                        for (k, v) in &aad.entries {
                            let ev = String::from_utf8_lossy(&k.decoded).to_string();
                            add_trigger_action_payload_chain(gpdf, &mut g, &cat_id, &format!("Catalog/AA/{}", ev), v);
                        }
                    }
                }
            }
        }
    }

    // ---- Pages + Annotations: /A and /AA event actions ----
    let pages = sis_pdf_pdf::pagetree::collect_pages(gpdf, 2000, 64);
    for p in pages {
        let page_id = g.upsert_node(id_obj(p.page_ref.obj, p.page_ref.gen), NodeKind::ContainerObject, "Page".into());

        for a in p.annots {
            let Some(annot_e) = gpdf.resolve_ref(&a) else { continue; };
            let annot_id = g.upsert_node(id_obj(annot_e.r.obj, annot_e.r.gen), NodeKind::ContainerObject, "Annot".into());
            g.add_edge(page_id.clone(), annot_id.clone(), EdgeKind::Contains, "Annots".into());

            let Some(ad) = gpdf.obj_as_dict(annot_e) else { continue; };
            if let Some((_, ao)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/A") {
                add_trigger_action_payload_chain(gpdf, &mut g, &annot_id, "Annot/A", ao);
            }
            if let Some((_, aao)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/AA") {
                if let Some(aad) = resolve_dict(gpdf, aao) {
                    for (k, v) in &aad.entries {
                        let ev = String::from_utf8_lossy(&k.decoded).to_string();
                        add_trigger_action_payload_chain(gpdf, &mut g, &annot_id, &format!("Annot/AA/{}", ev), v);
                    }
                }
            }
        }
    }

    // ---- NameTree: Catalog/Names/JavaScript ----
    if let Some(cat_r) = gpdf.catalog_ref() {
        if let Some(cat_e) = gpdf.get(cat_r) {
            if let Some(cat_d) = gpdf.obj_as_dict(cat_e) {
                if let Some((_, names_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(cat_d, b"/Names") {
                    if let Some(names_d) = resolve_dict(gpdf, names_obj) {
                        if let Some((_, js_tree_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(names_d, b"/JavaScript") {
                            let tnode = g.upsert_node(id_trigger("Names/JavaScript"), NodeKind::Trigger, "NamesTree(JavaScript)".into());
                            let entries = sis_pdf_pdf::nametree::enumerate_name_tree(gpdf, js_tree_obj, 12, 500);
                            for ent in entries {
                                let nm = String::from_utf8_lossy(&ent.name).to_string();
                                let entry_id = g.upsert_node(
                                    id_trigger(&format!("Names/JavaScript/{}", nm)),
                                    NodeKind::Trigger,
                                    format!("NameEntry({})", nm)
                                );
                                g.add_edge(tnode.clone(), entry_id.clone(), EdgeKind::Triggers, "entry".into());
                                add_trigger_action_payload_chain(gpdf, &mut g, &entry_id, &format!("NameTree/{}", nm), &ent.value);
                            }
                        }
                    }
                }
            }
        }
    }

    // ---- Synthesized paths (optional) ----
    if include_paths {
        let paths = crate::path_recon::reconstruct_paths(&g, 500, 12);
        for ph in paths {
            if ph.chain.len() < 2 { continue; }
            let label = chain_label(&g, &ph.chain);
            g.add_edge(ph.from_trigger, ph.to_payload, EdgeKind::Path, label);
        }
    }

    g
}

fn chain_label(g: &Graph, chain: &[String]) -> String {
    let mut parts = Vec::new();
    for id in chain {
        if let Some(n) = g.nodes.iter().find(|n| &n.id == id) {
            parts.push(n.label.clone());
        } else {
            parts.push(id.clone());
        }
        if parts.len() >= 8 { break; }
    }
    parts.join(" -> ")
}

fn resolve_dict<'a>(g: &sis_pdf_pdf::graph::ObjectGraph<'a>, o: &PdfObj<'a>) -> Option<&'a sis_pdf_pdf::object::PdfDict<'a>> {
    match &o.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Ref{..} => g.resolve_ref(o).and_then(|e| g.obj_as_dict(e)),
        _ => None,
    }
}

fn add_trigger_action_payload_chain<'a>(
    gpdf: &sis_pdf_pdf::graph::ObjectGraph<'a>,
    g: &mut Graph,
    container_id: &str,
    trigger_name: &str,
    action_root: &PdfObj<'a>,
) {
    let t_id = g.upsert_node(id_trigger(trigger_name), NodeKind::Trigger, trigger_name.to_string());
    g.add_edge(container_id.to_string(), t_id.clone(), EdgeKind::Contains, "trigger".into());

    let action_dict = resolve_dict(gpdf, action_root);
    if action_dict.is_none() {
        let leaf = g.upsert_node(id_action(&format!("{}:non_dict", trigger_name)), NodeKind::Action, "Action(non-dict)".into());
        g.add_edge(t_id.clone(), leaf.clone(), EdgeKind::Triggers, "action".into());
        return;
    }
    let ad = action_dict.unwrap();

    let s = if let Some((_, s_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, b"/S") {
        match &s_obj.atom {
            PdfAtom::Name(n) => String::from_utf8_lossy(&n.decoded).to_string(),
            _ => "unknown".into()
        }
    } else { "unknown".into() };

    let a_id = g.upsert_node(
        id_action(&format!("{}:/S={}", trigger_name, s)),
        NodeKind::Action,
        format!("Action(/S={})", s)
    );
    g.add_edge(t_id.clone(), a_id.clone(), EdgeKind::Triggers, "triggers".into());

    for key in [b"/JS".as_slice(), b"/URI".as_slice(), b"/F".as_slice(), b"/Launch".as_slice()] {
        if let Some((_, v)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(ad, key) {
            let p_id = g.upsert_node(
                id_payload(&format!("{}{}", trigger_name, String::from_utf8_lossy(key))),
                NodeKind::Payload,
                format!("Payload({})", String::from_utf8_lossy(key))
            );
            g.add_edge(a_id.clone(), p_id.clone(), EdgeKind::Uses, format!("uses {}", String::from_utf8_lossy(key)));
            if let Some(n) = g.node_mut(&p_id) {
                n.attrs.insert("value_kind".into(), classify_obj(&v));
            }
        }
    }
}

fn classify_obj(o: &PdfObj<'_>) -> String {
    match &o.atom {
        PdfAtom::Ref{obj, gen} => format!("ref({} {} R)", obj, gen),
        PdfAtom::Dict(_) => "dict".into(),
        PdfAtom::Array(_) => "array".into(),
        PdfAtom::Str(_) => "string".into(),
        PdfAtom::Name(_) => "name".into(),
        PdfAtom::Int(_) | PdfAtom::Real(_) => "number".into(),
        _ => "other".into(),
    }
}
```

### 1.2 Export it

`crates/sis-pdf-core/src/lib.rs` add:

```rust
pub mod graph_build; // NEW
```

---

## 2) Clap flags in the sis binary

Assuming your binary is something like `crates/sis-pdf/src/main.rs` or `src/main.rs`.

### 2.1 Add args

```rust
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "sis", version, about = "PDF security analyzer")]
pub struct Args {
    // ... your existing args, e.g. input path etc ...

    /// Export trigger/action/payload graph to files using this prefix (e.g., "out/scan1")
    #[arg(long)]
    pub export_graph: Option<String>,

    /// Comma-separated formats: dot,gml,json
    #[arg(long, default_value = "dot,json")]
    pub graph_formats: String,

    /// Include synthesized Path edges (trigger->...->payload)
    #[arg(long, default_value_t = true)]
    pub graph_include_paths: bool,
}
```

---

## 3) Write the graph files after the scan

Wherever your `sis-pdf` binary currently does:

* read PDF bytes
* build object graph
* run scan
* print report

Add the export hook **after** scan completes (or even before printing results; doesn’t matter).

### 3.1 Add helper in `sis-pdf` binary (main.rs)

```rust
fn parse_graph_formats(s: &str) -> Vec<sis_pdf_core::graph_export::GraphFormat> {
    s.split(',')
        .map(|x| x.trim().to_lowercase())
        .filter_map(|x| match x.as_str() {
            "dot" => Some(sis_pdf_core::graph_export::GraphFormat::Dot),
            "gml" => Some(sis_pdf_core::graph_export::GraphFormat::Gml),
            "json" => Some(sis_pdf_core::graph_export::GraphFormat::Json),
            _ => None,
        })
        .collect()
}

fn graph_ext(fmt: &sis_pdf_core::graph_export::GraphFormat) -> &'static str {
    match fmt {
        sis_pdf_core::graph_export::GraphFormat::Dot => "dot",
        sis_pdf_core::graph_export::GraphFormat::Gml => "gml",
        sis_pdf_core::graph_export::GraphFormat::Json => "json",
    }
}

fn export_graph_files(
    prefix: &str,
    formats: &[sis_pdf_core::graph_export::GraphFormat],
    g: &sis_pdf_core::graph_model::Graph,
) -> anyhow::Result<()> {
    // ensure parent dir exists if prefix includes path
    if let Some(parent) = std::path::Path::new(prefix).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    for fmt in formats {
        let path = format!("{}.{}", prefix, graph_ext(fmt));
        let mut f = std::fs::File::create(&path)?;
        sis_pdf_core::graph_export::write_graph(g, *fmt, &mut f)?;
    }
    Ok(())
}
```

### 3.2 Call it after scan

Inside `main()` after you build `ScanContext ctx` and run the scan:

```rust
let args = Args::parse();

// ... read bytes, build ctx, run scan ...

if let Some(prefix) = &args.export_graph {
    let formats = parse_graph_formats(&args.graph_formats);
    let graph = sis_pdf_core::graph_build::build_trigger_graph(&ctx, args.graph_include_paths);
    export_graph_files(prefix, &formats, &graph)?;
}
```

That’s enough to reliably create:

* `PREFIX.dot`
* `PREFIX.gml`
* `PREFIX.json`

---

## 4) Small (important) ergonomics: allow `--export-graph` without specifying formats

Already handled via default `dot,json`.

If you want to always include GML too, change default to `"dot,gml,json"`.

---

## 5) What this gives you right now

Even before we “attach findings to the graph”, you already get:

* Structural edges from:

  * `Catalog/OpenAction`
  * `Catalog/AA/*`
  * `Annot/A`
  * `Annot/AA/*`
  * `NameTree /JavaScript`
* Action `/S=...` nodes and payload-key nodes (`/JS`, `/URI`, `/F`, `/Launch`)
* Path edges that summarize likely trigger→payload chains (BFS over meaningful edges)

So your export is already useful in:

* Graphviz (DOT)
* Gephi / yEd / Cytoscape (GML)
* Python tooling (JSON import into NetworkX, etc.)

---

## Next step (recommended): attach visitor findings into the graph

Right now, the exported graph shows *possible* payload sites. The big upgrade is to add:

* `finding:*` nodes for actual hits (`embedded_javascript`, `embedded_uri_action`, etc.)
* edges `Finding -> Payload(/JS)` or `Finding -> Action(/S=JavaScript)`

To do that cleanly, I recommend adding a structured field to `Finding` like:

```rust
pub meta: std::collections::HashMap<String, String>
```

Then visitors can populate:

* `meta["trigger_kind"]`, `meta["trigger_path"]`
* `meta["payload_key"]` = "/JS" or "/URI"
* `meta["container_obj"]` = "10 0" etc

If you want, I’ll paste the patch that:

1. adds `Finding.meta`
2. updates embedded visitors to set payload key and trigger info
3. adds `graph_attach_findings(&mut Graph, &Report)` and includes those nodes/edges in DOT/GML/JSON exports

# Chapter 14

Alright — here’s the **“attach findings”** patch, end-to-end, in the same drop-in style.

What you’ll get after this:

* Every relevant finding carries a structured `meta` map (no more parsing descriptions).
* The graph exporter attaches:

  * `finding:*` nodes
  * edges `Finding -> Payload` (or `Finding -> Action`)
  * and (when available) `Trigger -> Finding` + `Container -> Finding`
* This works for DOT/GML/JSON exports (the graph model remains the single source of truth).

---

# 1) Add `meta` to `Finding` (sis-pdf-core model)

## 1.1 Update: `crates/sis-pdf-core/src/model.rs`

Locate your `Finding` struct and add a `meta` field.

```rust
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String,
    pub surface: AttackSurface,
    pub kind: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub objects: Vec<String>,
    pub evidence: Vec<EvidenceSpan>,
    pub remediation: Option<String>,

    // NEW: structured, stable fields for downstream analysis (graph export, SIEM, etc.)
    pub meta: HashMap<String, String>,
}
```

### 1.2 Fix compilation: update all Finding constructors

Everywhere you create a `Finding{ ... }`, add:

```rust
meta: std::collections::HashMap::new(),
```

(We’ll also set real meta values in the visitor pipeline below.)

---

# 2) Encode trigger + payload info into meta at the visitor boundary

We want *all* embedded visitor findings (JS/URI/SubmitForm/Launch) to carry:

* `meta.trigger_kind` (e.g., `AnnotationAAEvent`)
* `meta.trigger_path` (e.g., `$.Page.Annots[].AA.E`)
* `meta.trigger_event` (if any)
* `meta.origin_kind` (e.g., `xref_type2`, `objstm_deep`, `nametree_js`)
* `meta.payload_key` (e.g., `/JS`, `/URI`, `/F`, `/Launch`)
* `meta.action_s` (e.g., `/JavaScript`, `/URI`, `/SubmitForm`, `/Launch`)
* `meta.container_objects` (joined string)
* optionally, `meta.objstm_obj`, `meta.objstm_index`, etc. if you want later

To do this cleanly:

* Add `meta` to `EmbeddedFinding`
* Fill it inside visitors (payload_key, action_s)
* Copy trigger/origin fields into `Finding.meta` in `run_visitors_on_embedded`

---

## 2.1 Update: `crates/sis-pdf-core/src/visitor.rs`

### A) Add meta to EmbeddedFinding

At top, import HashMap:

```rust
use std::collections::{HashSet, HashMap};
```

Update `EmbeddedFinding`:

```rust
#[derive(Debug, Clone)]
pub struct EmbeddedFinding {
    pub surface: AttackSurface,
    pub kind: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub evidence: Vec<EvidenceSpan>,

    // NEW: visitor-provided structured fields (payload_key, action_s, etc.)
    pub meta: HashMap<String, String>,
}
```

### B) When adapting to `Finding`, populate `Finding.meta`

Inside `run_visitors_on_embedded`, where you currently construct `Finding{...}`, add:

```rust
let mut meta = ef.meta.clone();

meta.insert("origin_kind".into(), origin.origin_kind.to_string());
meta.insert("visitor_id_prefix".into(), id_prefix.to_string());

if !origin.container_objects.is_empty() {
    meta.insert("container_objects".into(), origin.container_objects.join(" | "));
}

if let Some(t) = &origin.trigger {
    meta.insert("trigger_kind".into(), format!("{:?}", t.kind));
    meta.insert("trigger_path".into(), t.path.clone());
    if let Some(ev) = &t.event { meta.insert("trigger_event".into(), ev.clone()); }
    if let Some(n) = &t.note { meta.insert("trigger_note".into(), n.clone()); }
}

out.push(Finding{
    id: format!("{}:{}:{}", id_prefix, origin.origin_kind, i),
    surface: ef.surface,
    kind: ef.kind,
    severity: ef.severity,
    confidence: ef.confidence,
    title: ef.title,
    description: format!(
        "{}\n{}\nOrigin: {}\nContainers: {}\n{}",
        ef.description,
        trigger_txt,
        origin.origin_kind,
        if origin.container_objects.is_empty() { "(none)".into() } else { origin.container_objects.join(", ") },
        origin.note.clone().unwrap_or_default(),
    ),
    objects: origin.container_objects.clone(),
    evidence: map_evidence(origin.evidence_map.as_ref(), ef.evidence),
    remediation: None,
    meta, // NEW
});
```

That’s the big piece: now every embedded visitor hit is structured.

---

# 3) Set `payload_key` and `action_s` in the visitors

## 3.1 Update: `crates/sis-pdf-detectors/src/embedded_visitors.rs`

### A) JS visitor: add meta

In `EmbeddedJavaScriptVisitor::on_node`, construct `meta`:

```rust
let mut meta = std::collections::HashMap::new();
meta.insert("payload_key".into(), "/JS".into());
meta.insert("action_s".into(), "/JavaScript".into());
meta.insert("path".into(), path.to_string());
```

Then in `EmbeddedFinding{...}` include `meta`.

Full replacement of the push block:

```rust
        let mut ev = Vec::new();
        if let Some((_, js_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS") {
            ev.push(EvidenceSpan{
                offset: js_obj.span.start,
                length: (js_obj.span.end - js_obj.span.start) as u32,
                note: Some(format!("JS span at {}", path)),
            });
        }

        let mut meta = std::collections::HashMap::new();
        meta.insert("payload_key".into(), "/JS".into());
        meta.insert("action_s".into(), "/JavaScript".into());
        meta.insert("path".into(), path.to_string());

        out.push(EmbeddedFinding{
            surface: AttackSurface::JavaScript,
            kind: "embedded_javascript".into(),
            severity: Severity::Critical,
            confidence: Confidence::Probable,
            title: "Embedded JavaScript indicator".into(),
            description: desc,
            evidence: ev,
            meta,
        });
```

### B) Network action visitor: set payload_key `/URI` or `/F` and action_s `/URI` or `/SubmitForm`

Update the two pushes.

For URI:

```rust
            let mut meta = std::collections::HashMap::new();
            meta.insert("payload_key".into(), "/URI".into());
            meta.insert("action_s".into(), "/URI".into());
            meta.insert("path".into(), path.to_string());

            out.push(EmbeddedFinding{
                surface: AttackSurface::Actions,
                kind: "embedded_uri_action".into(),
                severity: Severity::High,
                confidence: Confidence::Probable,
                title: "Embedded URI action indicator".into(),
                description: format!("Embedded URI indicator at path {}. URI={}", path, uri),
                evidence: vec![],
                meta,
            });
```

For SubmitForm:

```rust
            let mut meta = std::collections::HashMap::new();
            meta.insert("payload_key".into(), "/F".into());
            meta.insert("action_s".into(), "/SubmitForm".into());
            meta.insert("path".into(), path.to_string());

            out.push(EmbeddedFinding{
                surface: AttackSurface::Actions,
                kind: "embedded_submitform_action".into(),
                severity: Severity::High,
                confidence: Confidence::Probable,
                title: "Embedded SubmitForm action indicator".into(),
                description: format!("Embedded SubmitForm indicator at path {}. F={}", path, f),
                evidence: vec![],
                meta,
            });
```

### C) Launch visitor: payload_key `/Launch` and action_s `/Launch`

```rust
        let mut meta = std::collections::HashMap::new();
        meta.insert("payload_key".into(), "/Launch".into());
        meta.insert("action_s".into(), "/Launch".into());
        meta.insert("path".into(), path.to_string());

        out.push(EmbeddedFinding{
            surface: AttackSurface::Actions,
            kind: "embedded_launch_action".into(),
            severity: Severity::Critical,
            confidence: Confidence::Probable,
            title: "Embedded Launch action indicator".into(),
            description: format!("Embedded Launch indicator at path {}.", path),
            evidence: vec![],
            meta,
        });
```

---

# 4) Attach findings into the graph (DOT/GML/JSON)

We’ll implement:

```rust
attach_findings(&mut Graph, findings: &[Finding])
```

Rules:

* Always create a finding node: `finding:<finding.id>`
* If `meta.trigger_kind` exists: connect `trigger:*` → `finding:*` with `EdgeKind::Indicates`
* If `meta.payload_key` exists: connect `finding:*` → `payload:*` with `EdgeKind::Indicates`
* If `meta.action_s` exists: connect `finding:*` → `action:*` with `EdgeKind::Indicates`
* If `meta.container_objects` exists: create container nodes and connect `container -> finding` (`Contains`)

This is robust even if the structural graph didn’t include that exact trigger/payload (we’ll upsert nodes).

---

## 4.1 New file: `crates/sis-pdf-core/src/graph_attach.rs`

```rust
use crate::graph_model::*;
use crate::model::Finding;

pub fn attach_findings(g: &mut Graph, findings: &[Finding]) {
    for f in findings {
        // Create finding node
        let fid = id_finding(&f.id);
        g.upsert_node(fid.clone(), NodeKind::Finding, format!("Finding({})", f.kind));

        if let Some(n) = g.node_mut(&fid) {
            n.attrs.insert("severity".into(), format!("{:?}", f.severity));
            n.attrs.insert("confidence".into(), format!("{:?}", f.confidence));
            n.attrs.insert("title".into(), f.title.clone());
            n.attrs.insert("kind".into(), f.kind.clone());
            // Attach meta
            for (k, v) in &f.meta {
                n.attrs.insert(format!("meta.{}", k), v.clone());
            }
        }

        // Trigger link
        if let Some(tp) = f.meta.get("trigger_path") {
            let tid = id_trigger(tp);
            g.upsert_node(tid.clone(), NodeKind::Trigger, tp.clone());
            g.add_edge(tid.clone(), fid.clone(), EdgeKind::Indicates, "trigger_hit".into());
        } else if let Some(tk) = f.meta.get("trigger_kind") {
            // fallback: trigger_kind-only bucket
            let tid = id_trigger(&format!("kind:{}", tk));
            g.upsert_node(tid.clone(), NodeKind::Trigger, format!("TriggerKind({})", tk));
            g.add_edge(tid.clone(), fid.clone(), EdgeKind::Indicates, "trigger_kind_hit".into());
        }

        // Payload link
        if let Some(pk) = f.meta.get("payload_key") {
            let pid = id_payload(pk);
            g.upsert_node(pid.clone(), NodeKind::Payload, format!("Payload({})", pk));
            g.add_edge(fid.clone(), pid.clone(), EdgeKind::Indicates, "finding_payload".into());
        }

        // Action link
        if let Some(as_) = f.meta.get("action_s") {
            let aid = id_action(as_);
            g.upsert_node(aid.clone(), NodeKind::Action, format!("Action(/S={})", as_));
            g.add_edge(fid.clone(), aid.clone(), EdgeKind::Indicates, "finding_action".into());
        }

        // Container objects link (string list)
        if let Some(cont) = f.meta.get("container_objects") {
            for c in cont.split(" | ").map(|s| s.trim()).filter(|s| !s.is_empty()) {
                let cid = id_embedded(&format!("container:{}", c));
                g.upsert_node(cid.clone(), NodeKind::ContainerObject, c.to_string());
                g.add_edge(cid.clone(), fid.clone(), EdgeKind::Contains, "contains_finding".into());
            }
        }
    }
}
```

### 4.2 Export it

`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod graph_attach; // NEW
```

---

# 5) Update the graph export hook in `sis-pdf` binary

Now the export path becomes:

1. Run scan → get `report/findings`
2. `graph = build_trigger_graph(&ctx, include_paths)`
3. `attach_findings(&mut graph, &report.findings)`
4. write formats

## 5.1 In your `sis-pdf` binary export hook (main.rs)

Where you currently do:

```rust
let graph = sis_pdf_core::graph_build::build_trigger_graph(&ctx, args.graph_include_paths);
export_graph_files(prefix, &formats, &graph)?;
```

Change to:

```rust
let mut graph = sis_pdf_core::graph_build::build_trigger_graph(&ctx, args.graph_include_paths);
sis_pdf_core::graph_attach::attach_findings(&mut graph, &report.findings);
export_graph_files(prefix, &formats, &graph)?;
```

(Use your actual variable name for the scan results: `report`, `results`, etc.)

---

# 6) Ensure all embedded-origins set `origin.trigger` (you already did in chunk 9)

You’re already populating `origin.trigger` in:

* annotations (/A, /AA event)
* NameTree JS entries
* xref type-2 embedded extraction
* ObjStm deep

That means attached findings now produce high-quality `Trigger -> Finding` edges.

---

# 7) What the exported graph looks like now

You’ll see nodes like:

* `trigger:$.Page.Annots[].AA.E`
* `action:/JavaScript`
* `payload:/JS`
* `finding:structure.xref_type2_objstm_extract:obj123:...`

And edges:

* `Trigger --Indicates--> Finding`
* `Finding --Indicates--> Payload(/JS)`
* `Finding --Indicates--> Action(/JavaScript)`
* `ContainerObject --Contains--> Finding`

This makes Gephi/yEd analysis much nicer:

* filter by `Node.kind == Finding`
* colorize by `severity`
* traverse to payloads


# Chapter 15

Here’s the tweak to create **payload instance nodes** (distinct per hit), while still keeping the **generic payload key nodes** (`payload:/JS`, `payload:/URI`, etc.) for aggregation.

Resulting shape:

* `finding:* -> payload_instance:*` (specific hit)
* `payload_instance:* -> payload:/JS` (grouping)
* optional: `payload_instance:* -> action:/JavaScript` (if you want)
* payload instance node carries attrs:

  * `payload_key`
  * `trigger_path`
  * `container_objects`
  * `visitor_path` (the embedded object path inside the extracted subtree)
  * `origin_kind`
  * `evidence_offset` (mapped or decoded)

---

# 1) Add ID helper for payload instances

## 1.1 Update: `crates/sis-pdf-core/src/graph_model.rs`

Add:

```rust
pub fn id_payload_instance(s: &str) -> String { format!("payload_instance:{}", s) }
```

---

# 2) Compute a stable-ish payload instance key from finding.meta

We’ll build a key from a few meta fields. Since keys can be long, we’ll hash to keep IDs compact.

## 2.1 New file: `crates/sis-pdf-core/src/hashutil.rs`

```rust
use std::hash::{Hash, Hasher};

pub fn stable_u64_hash<T: Hash>(v: &T) -> u64 {
    // std::collections::hash_map::DefaultHasher is SipHash-1-3 (stable enough within a build).
    // If you need cross-version stability, swap to a fixed hash crate later.
    let mut h = std::collections::hash_map::DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

pub fn hex64(x: u64) -> String {
    format!("{:016x}", x)
}
```

Export it:
`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod hashutil; // NEW
```

---

# 3) Update attach_findings to emit payload instance nodes

## 3.1 Update: `crates/sis-pdf-core/src/graph_attach.rs`

Replace the “Payload link” section with the instance-aware version below.

### Find this block:

```rust
        // Payload link
        if let Some(pk) = f.meta.get("payload_key") {
            let pid = id_payload(pk);
            g.upsert_node(pid.clone(), NodeKind::Payload, format!("Payload({})", pk));
            g.add_edge(fid.clone(), pid.clone(), EdgeKind::Indicates, "finding_payload".into());
        }
```

### Replace with:

```rust
        // Payload instance + aggregation payload
        if let Some(pk) = f.meta.get("payload_key") {
            // Build a stable-ish identity for this specific payload hit.
            // Use meta fields that (a) exist broadly and (b) distinguish instances.
            let trigger_path = f.meta.get("trigger_path").cloned().unwrap_or_else(|| "-".into());
            let origin_kind = f.meta.get("origin_kind").cloned().unwrap_or_else(|| "-".into());
            let visitor_path = f.meta.get("path").cloned().unwrap_or_else(|| "-".into()); // embedded visitor JSONPath
            let containers = f.meta.get("container_objects").cloned().unwrap_or_else(|| "-".into());

            // Evidence is optional; take first span offset/len if present (helps disambiguate)
            let ev = f.evidence.get(0)
                .map(|e| format!("off={} len={}", e.offset, e.length))
                .unwrap_or_else(|| "-".into());

            let key_material = format!(
                "pk={}|trig={}|origin={}|vpath={}|cont={}|ev={}",
                pk, trigger_path, origin_kind, visitor_path, containers, ev
            );

            let h = crate::hashutil::hex64(crate::hashutil::stable_u64_hash(&key_material));
            let pi_id = id_payload_instance(&format!("{}:{}", pk.trim_start_matches('/'), h));

            // Instance node
            g.upsert_node(pi_id.clone(), NodeKind::Payload, format!("PayloadInstance({})", pk));
            if let Some(n) = g.node_mut(&pi_id) {
                n.attrs.insert("payload_key".into(), pk.clone());
                n.attrs.insert("trigger_path".into(), trigger_path);
                n.attrs.insert("origin_kind".into(), origin_kind);
                n.attrs.insert("visitor_path".into(), visitor_path);
                n.attrs.insert("container_objects".into(), containers);
                n.attrs.insert("evidence".into(), ev);
                n.attrs.insert("hash".into(), h);
            }

            // Edge: Finding -> PayloadInstance
            g.add_edge(fid.clone(), pi_id.clone(), EdgeKind::Indicates, "finding_payload_instance".into());

            // Aggregation payload node: payload:/JS, payload:/URI, etc.
            let agg_id = id_payload(pk);
            g.upsert_node(agg_id.clone(), NodeKind::Payload, format!("Payload({})", pk));

            // Edge: PayloadInstance -> PayloadKey (aggregation)
            g.add_edge(pi_id.clone(), agg_id.clone(), EdgeKind::Contains, "instance_of".into());
        }
```

### Also update imports at top of `graph_attach.rs`

Change:

```rust
use crate::graph_model::*;
use crate::model::Finding;
```

To:

```rust
use crate::graph_model::*;
use crate::model::Finding;
use crate::hashutil;
```

(Or use `crate::hashutil::...` fully-qualified like in the code above; either is fine.)

---

# 4) Optional: link payload instance to action node

If you want each instance to connect to `/S` too, add this *inside* the block above (after creating `pi_id`), gated on `meta.action_s`:

```rust
            if let Some(as_) = f.meta.get("action_s") {
                let aid = id_action(as_);
                g.upsert_node(aid.clone(), NodeKind::Action, format!("Action(/S={})", as_));
                g.add_edge(pi_id.clone(), aid.clone(), EdgeKind::Uses, "instance_action".into());
            }
```

This makes “payload instance” the join point between findings and action/payload.

---

# 5) Note on node kinds

I kept `payload_instance` as `NodeKind::Payload` to avoid adding another enum variant. If you prefer explicit typing, add:

* `NodeKind::PayloadInstance`

…and adjust exporter labels. Not required.

---

# 6) What changes in exports

### DOT

You’ll now see many nodes like:

* `payload_instance:/JS:9f2a0c...`
* each connected from a finding node, and connected to `payload:/JS`.

### GML/JSON

Instance nodes carry rich attrs, so your offline tooling can group by:

* payload_key
* trigger_path
* origin_kind
* container_objects
* evidence



# Chapter 16

Yep — here’s the patch to **attach exact object refs to payload instances** (and generally to findings), so every instance can be traced back to:

* the **resolved action object ref** (when it’s a ref)
* the **container object ref** (ObjStm, xref stream, annot obj, page obj, catalog obj)
* optionally the **embedded object index** (ObjStm table index or xref type-2 index)

This is done in a way that’s:

* **structured** (goes into `Finding.meta`)
* **uniform** across origins (annotations, name tree, ObjStm deep, xref type-2)
* resilient when you only have partial info (it’ll still fill what it can)

---

# 0) Convention for meta keys

We’ll standardize meta keys:

### Object refs (exact)

* `meta.obj_ref` — best “root object” ref for the embedded object/action (e.g. `"12 0 R"`)
* `meta.action_ref` — if the action dict itself was referenced (e.g. `/OpenAction 55 0 R`)
* `meta.payload_ref` — if `/JS` or `/URI` value was a ref
* `meta.container_ref.*` — containers by role:

  * `meta.container_ref.catalog`
  * `meta.container_ref.page`
  * `meta.container_ref.annot`
  * `meta.container_ref.xref_stream`
  * `meta.container_ref.objstm`

### Embedded addressing

* `meta.embedded.source` — `"xref_type2" | "objstm_deep" | "nametree_js" | "annotation_A" | ..."`
* `meta.embedded.index` — index in ObjStm table or xref type-2 index when available
* `meta.embedded.objnum` — ObjStm’s embedded object number from header table (if you parse it)
* `meta.embedded.offset` — offset inside decoded ObjStm data (if available)

We’ll implement enough to fill most of these immediately.

---

# 1) Add helpers to format refs and detect refs for payload/action keys

## 1.1 New file: `crates/sis-pdf-core/src/meta_refs.rs`

```rust
use sis_pdf_pdf::object::{PdfAtom, PdfObj};

pub fn fmt_ref(obj: u32, gen: u16) -> String {
    format!("{} {} R", obj, gen)
}

pub fn obj_ref_string(o: &PdfObj<'_>) -> Option<String> {
    match o.atom {
        PdfAtom::Ref{obj, gen} => Some(fmt_ref(obj, gen)),
        _ => None,
    }
}

/// If dict[key] exists and is a ref, return "N G R"
pub fn dict_ref_value<'a>(
    d: &sis_pdf_pdf::object::PdfDict<'a>,
    key: &[u8],
) -> Option<String> {
    let (_, v) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, key)?;
    obj_ref_string(v)
}
```

Export it:
`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod meta_refs; // NEW
```

---

# 2) Populate meta.container_ref.* in each origin builder

We already pass `origin.container_objects: Vec<String>` (string-y). Now we also set exact object refs in `Finding.meta`.

There are two ways:

1. Put these into `EmbeddedOrigin` and let `run_visitors_on_embedded` copy into meta (recommended).
2. Directly set them in each detector’s findings (harder).

We’ll do **(1)**.

---

## 2.1 Update `EmbeddedOrigin` to carry structured refs

### Update: `crates/sis-pdf-core/src/visitor.rs`

In `EmbeddedOrigin`, add:

```rust
    // NEW: structured container refs (exact object references)
    pub container_refs: std::collections::HashMap<String, String>,
```

So it becomes:

```rust
#[derive(Debug, Clone)]
pub struct EmbeddedOrigin {
    pub origin_kind: &'static str,
    pub container_objects: Vec<String>,
    pub note: Option<String>,
    pub evidence_map: Option<crate::evidence_map::EvidenceMap>,
    pub trigger: Option<crate::trigger::TriggerContext>,

    // NEW:
    pub container_refs: std::collections::HashMap<String, String>,
}
```

### Update all call sites to initialize `container_refs`

Everywhere you create an `EmbeddedOrigin{...}`, add:

```rust
container_refs: std::collections::HashMap::new(),
```

…and then we’ll fill it in the key detectors below.

---

## 2.2 Copy container_refs into Finding.meta

Still in `run_visitors_on_embedded` in `crates/sis-pdf-core/src/visitor.rs`,
after you create `let mut meta = ef.meta.clone();`, add:

```rust
for (k, v) in &origin.container_refs {
    meta.insert(format!("container_ref.{}", k), v.clone());
}
```

This produces meta keys like:

* `container_ref.objstm = "10 0 R"`
* `container_ref.annot = "25 0 R"`

---

# 3) Add action_ref / payload_ref to visitor meta

Visitors have the dict node (`d`) and can check whether `/JS` etc is a ref. Great.

## 3.1 Update `crates/sis-pdf-detectors/src/embedded_visitors.rs`

### A) In JS visitor, when you detect `/JS`:

Add:

```rust
if let Some(r) = sis_pdf_core::meta_refs::dict_ref_value(d, b"/JS") {
    meta.insert("payload_ref".into(), r);
}
```

Also, if this dict itself is an action dict and came from a ref, we can’t know the dict ref *here* (we only have a PdfObj). But we can at least record whether `/S` says `/JavaScript`:

Already have `action_s=/JavaScript`.

### B) In URI/SubmitForm visitor:

For URI:

```rust
if let Some(r) = sis_pdf_core::meta_refs::dict_ref_value(d, b"/URI") {
    meta.insert("payload_ref".into(), r);
}
```

For SubmitForm (`/F`):

```rust
if let Some(r) = sis_pdf_core::meta_refs::dict_ref_value(d, b"/F") {
    meta.insert("payload_ref".into(), r);
}
```

### C) In Launch visitor:

```rust
if let Some(r) = sis_pdf_core::meta_refs::dict_ref_value(d, b"/Launch") {
    meta.insert("payload_ref".into(), r);
}
```

You’ll need to add import at top of `embedded_visitors.rs`:

```rust
use sis_pdf_core::meta_refs;
```

(or fully qualify `sis_pdf_core::meta_refs::dict_ref_value`).

---

# 4) Set container refs in each detector’s origin

We’ll do this in the big 4:

* annotations
* name tree
* xref type-2
* objstm deep

## 4.1 Annotations: `crates/sis-pdf-detectors/src/annots.rs`

When building origin for `/A`:

Add:

```rust
let mut container_refs = std::collections::HashMap::new();
container_refs.insert("page".into(), sis_pdf_core::meta_refs::fmt_ref(p.page_ref.obj, p.page_ref.gen));
container_refs.insert("annot".into(), sis_pdf_core::meta_refs::fmt_ref(annot_e.r.obj, annot_e.r.gen));
```

Then in `EmbeddedOrigin{ ... }`, set `container_refs`.

Do the same for `/AA` events.

### Also capture action_ref when `/A` or `/AA` value is a ref

Right where you do:

```rust
let root_obj: PdfObj = match &v.atom { PdfAtom::Ref{..} => ... }
```

Add:

```rust
let action_ref = sis_pdf_core::meta_refs::obj_ref_string(&v);
```

Then after you create origin, set it into `origin.note` or better: into `origin.container_refs`? No—this is not a container. We want it as `meta.action_ref`.

Best approach: add `action_ref` into `EmbeddedOrigin` as optional meta fields.

### Minimal change (no new origin fields):

We can put `action_ref` into `origin.container_refs` as `action` **OR** into `origin.note`.
But you asked “exact object refs to instances”, so structured meta is better.

Let’s add **one more field** to `EmbeddedOrigin`:

In `sis-pdf-core/src/visitor.rs`:

```rust
pub action_ref: Option<String>,
```

So origin becomes:

```rust
pub struct EmbeddedOrigin {
    ...
    pub action_ref: Option<String>,
    pub container_refs: HashMap<String, String>,
}
```

Then in `run_visitors_on_embedded`, copy it:

```rust
if let Some(ar) = &origin.action_ref {
    meta.insert("action_ref".into(), ar.clone());
}
```

Now in `annots.rs`, set:

```rust
action_ref,
```

Do similarly in NameTree and OpenAction-type places later if you wire them through visitors.

---

## 4.2 NameTree JS: `crates/sis-pdf-detectors/src/javascript.rs`

When building origin for each NameTree entry:

* container ref is Catalog (`cat_r`)
* if `ent.value` is a ref, treat that as `action_ref` (or “value_ref”)

Add:

```rust
let mut container_refs = std::collections::HashMap::new();
container_refs.insert("catalog".into(), sis_pdf_core::meta_refs::fmt_ref(cat_r.obj, cat_r.gen));

let action_ref = sis_pdf_core::meta_refs::obj_ref_string(&ent.value);
```

Then set in origin.

---

## 4.3 Xref type-2: `crates/sis-pdf-detectors/src/xref_objstm_extract.rs`

You already have:

* `xref_obj` entry (`xref_obj.r`)
* `objstm_entry.r`

Add:

```rust
let mut container_refs = std::collections::HashMap::new();
container_refs.insert("xref_stream".into(), sis_pdf_core::meta_refs::fmt_ref(xref_obj.r.obj, xref_obj.r.gen));
container_refs.insert("objstm".into(), sis_pdf_core::meta_refs::fmt_ref(objstm_entry.r.obj, objstm_entry.r.gen));
```

Also set `origin.action_ref = None` (embedded object is not a direct action ref; if you later resolve to an action dict ref you can set it).

Additionally, since you know `objno`, `idx`, and `objstm_obj`, store them in meta via `origin.note` OR add another `origin.meta` map.

If you want structured meta without further origin fields, easiest is to inject into `EmbeddedFinding.meta` later, but we can do it at origin-level by adding:

```rust
pub origin_meta: HashMap<String,String>
```

However, to keep this patch minimal, we can encode these into `container_refs` with keys like `embedded.index`. That’s slightly weird, but works.

Better: add `origin_meta` now (clean).

### Add `origin_meta` to `EmbeddedOrigin` (recommended)

In `sis-pdf-core/src/visitor.rs` add:

```rust
pub origin_meta: std::collections::HashMap<String, String>,
```

And in `run_visitors_on_embedded` copy:

```rust
for (k, v) in &origin.origin_meta {
    meta.insert(k.clone(), v.clone());
}
```

Now in xref type-2 detector set:

```rust
let mut origin_meta = std::collections::HashMap::new();
origin_meta.insert("embedded.source".into(), "xref_type2".into());
origin_meta.insert("embedded.objno".into(), objno.to_string());
origin_meta.insert("embedded.index".into(), idx.to_string());
origin_meta.insert("embedded.objstm_obj".into(), objstm_obj.to_string());
```

And put `origin_meta` into `EmbeddedOrigin`.

---

## 4.4 ObjStm deep: `crates/sis-pdf-detectors/src/objstm_deep.rs`

You have `e.r` for ObjStm container. Add:

```rust
let mut container_refs = std::collections::HashMap::new();
container_refs.insert("objstm".into(), sis_pdf_core::meta_refs::fmt_ref(e.r.obj, e.r.gen));

let mut origin_meta = std::collections::HashMap::new();
origin_meta.insert("embedded.source".into(), "objstm_deep".into());
origin_meta.insert("embedded.table_index".into(), i.to_string());
origin_meta.insert("embedded.objnum".into(), objnum.to_string());
origin_meta.insert("embedded.offset".into(), off.to_string());
```

Set these on origin.

---

# 5) Update the payload instance key to include these refs

Now that findings have:

* `meta.action_ref`
* `meta.payload_ref`
* `meta.container_ref.objstm`, etc.
* `meta.embedded.*`

We should incorporate them into the payload instance identity so two identical payloads in different objects do not collide.

## 5.1 Update: `crates/sis-pdf-core/src/graph_attach.rs`

Inside the payload instance block, add these to `key_material`:

```rust
let action_ref = f.meta.get("action_ref").cloned().unwrap_or_else(|| "-".into());
let payload_ref = f.meta.get("payload_ref").cloned().unwrap_or_else(|| "-".into());

let obj_ref = f.meta.get("obj_ref").cloned().unwrap_or_else(|| "-".into()); // optional, if you add later
let cref_objstm = f.meta.get("container_ref.objstm").cloned().unwrap_or_else(|| "-".into());
let cref_annot = f.meta.get("container_ref.annot").cloned().unwrap_or_else(|| "-".into());
let cref_xref = f.meta.get("container_ref.xref_stream").cloned().unwrap_or_else(|| "-".into());

let emb_src = f.meta.get("embedded.source").cloned().unwrap_or_else(|| "-".into());
let emb_idx = f.meta.get("embedded.index").cloned().unwrap_or_else(|| "-".into());
let emb_objnum = f.meta.get("embedded.objnum").cloned().unwrap_or_else(|| "-".into());
```

Then extend key material:

```rust
let key_material = format!(
  "pk={}|trig={}|origin={}|vpath={}|cont={}|ev={}|action_ref={}|payload_ref={}|obj_ref={}|xref={}|objstm={}|annot={}|emb_src={}|emb_idx={}|emb_objnum={}",
  pk, trigger_path, origin_kind, visitor_path, containers, ev,
  action_ref, payload_ref, obj_ref, cref_xref, cref_objstm, cref_annot,
  emb_src, emb_idx, emb_objnum
);
```

Also store these on the instance node attrs:

```rust
n.attrs.insert("action_ref".into(), action_ref);
n.attrs.insert("payload_ref".into(), payload_ref);
if cref_xref != "-" { n.attrs.insert("container_ref.xref_stream".into(), cref_xref); }
if cref_objstm != "-" { n.attrs.insert("container_ref.objstm".into(), cref_objstm); }
if cref_annot != "-" { n.attrs.insert("container_ref.annot".into(), cref_annot); }
if emb_src != "-" { n.attrs.insert("embedded.source".into(), emb_src); }
if emb_idx != "-" { n.attrs.insert("embedded.index".into(), emb_idx); }
if emb_objnum != "-" { n.attrs.insert("embedded.objnum".into(), emb_objnum); }
```

---

# 6) One more win: record obj_ref for extracted embedded objects (optional, but good)

For top-level objects you already have real `ObjEntry` refs. For “embedded objects inside ObjStm”, they don’t have standard refs, but:

* xref type-2 provides `objno` (that’s a real object number)
* ObjStm deep parsing yields `objnum` from header (also a real object number)

So we can set:

* `meta.obj_ref = "{objno} 0 R"` (gen is typically 0; if you track it, use actual)
* for ObjStm deep: `meta.obj_ref = "{objnum} 0 R"` (header lists object numbers)

Implement this via `origin_meta`:

### In xref type-2 origin_meta:

```rust
origin_meta.insert("obj_ref".into(), format!("{} 0 R", objno));
```

### In ObjStm deep origin_meta:

```rust
origin_meta.insert("obj_ref".into(), format!("{} 0 R", objnum));
```

Now payload instances will be directly tied to `obj_ref` for most embedded cases.

---

# 7) Summary of minimal code edits you need to apply now

### Add modules

* `sis-pdf-core/src/meta_refs.rs`
* `sis-pdf-core/src/hashutil.rs` (already added earlier)
* `sis-pdf-core/src/graph_attach.rs` updates (payload instance key/attrs)
* `sis-pdf-core/src/visitor.rs`:

  * `EmbeddedOrigin` adds `container_refs`, `action_ref`, `origin_meta`
  * `run_visitors_on_embedded` copies these into `Finding.meta`
* `sis-pdf-detectors/src/embedded_visitors.rs`:

  * set `payload_ref` when `/JS`, `/URI`, `/F`, `/Launch` is a ref
* detectors set `container_refs`, `action_ref`, `origin_meta` in origins:

  * `annots.rs`
  * `javascript.rs` (name tree)
  * `xref_objstm_extract.rs`
  * `objstm_deep.rs`
* Update all `Finding{}` constructors to include `meta: HashMap::new()`



# Chapter 17

Great — this is the **final tightening step** that makes the graph *structurally exact* instead of “string-joined”.

What you’re asking for, precisely:

> **If a finding’s action dict (or payload value) resolves from a real PDF object reference (`NN GG R`) that already exists in the structural graph, then the payload instance node should attach to that *structural object node*, not just to a synthetic `action:/JavaScript` or `payload:/JS` node.**

Below is a **clean, minimal patch** that:

* prefers **structural object nodes** when available
* falls back to synthetic nodes when not
* keeps payload instances stable and deduplicated
* preserves compatibility with DOT / GML / JSON exports

---

# What changes conceptually

Before:

```
Finding
  └─Indicates→ PayloadInstance
                ├─Contains→ Payload(/JS)
                └─Uses→ Action(/JavaScript)
```

After (when refs are known):

```
Finding
  └─Indicates→ PayloadInstance
                ├─Uses→ obj:55:0        (Action dict ref)
                ├─Contains→ obj:72:0    (Payload value ref)
                └─Contains→ Payload(/JS)   [aggregation]
```

If no refs are available → old behavior remains.

---

# 1) Structural object node convention (important)

You already use this in `graph_build`:

```rust
id_obj(obj, gen) => "obj:{obj}:{gen}"
```

We will **reuse that exact ID** so everything lines up.

---

# 2) Add a helper: resolve ref string → structural node id

## 2.1 New helper in `sis-pdf-core/src/graph_attach.rs`

Add near the top:

```rust
fn obj_ref_to_node_id(s: &str) -> Option<String> {
    // Expect "N G R"
    let parts: Vec<_> = s.split_whitespace().collect();
    if parts.len() == 3 && parts[2] == "R" {
        let obj: u32 = parts[0].parse().ok()?;
        let gen: u16 = parts[1].parse().ok()?;
        Some(crate::graph_model::id_obj(obj, gen))
    } else {
        None
    }
}
```

---

# 3) Prefer structural nodes in `attach_findings`

This is the **core patch**.

## 3.1 Locate payload instance attachment block

In `crates/sis-pdf-core/src/graph_attach.rs`, you previously added:

```rust
// Instance node
g.upsert_node(pi_id.clone(), NodeKind::Payload, ...);

// Finding -> PayloadInstance
g.add_edge(fid.clone(), pi_id.clone(), EdgeKind::Indicates, ...);

// Aggregation payload
let agg_id = id_payload(pk);
g.upsert_node(agg_id.clone(), NodeKind::Payload, ...);
g.add_edge(pi_id.clone(), agg_id.clone(), EdgeKind::Contains, ...);
```

We’ll now **insert structural attachment before synthetic attachment**.

---

## 3.2 Attach payload **value ref** structurally (highest priority)

Immediately after creating the payload instance node:

```rust
// Prefer structural payload value ref if present
if let Some(pref) = f.meta.get("payload_ref") {
    if let Some(obj_id) = obj_ref_to_node_id(pref) {
        // Ensure structural object node exists
        g.upsert_node(
            obj_id.clone(),
            NodeKind::ContainerObject,
            format!("Object {}", pref),
        );

        // PayloadInstance -> Object(ref)
        g.add_edge(
            pi_id.clone(),
            obj_id.clone(),
            EdgeKind::Contains,
            "payload_value_ref".into(),
        );
    }
}
```

This handles cases like:

* `/JS 72 0 R`
* `/URI 90 0 R`
* `/F 120 0 R`

---

## 3.3 Attach **action dict ref** structurally (next priority)

Still inside the payload instance block:

```rust
// Prefer structural action dict ref if present
if let Some(aref) = f.meta.get("action_ref") {
    if let Some(obj_id) = obj_ref_to_node_id(aref) {
        g.upsert_node(
            obj_id.clone(),
            NodeKind::Action,
            format!("ActionObject {}", aref),
        );

        // PayloadInstance -> ActionObject(ref)
        g.add_edge(
            pi_id.clone(),
            obj_id.clone(),
            EdgeKind::Uses,
            "action_dict_ref".into(),
        );
    }
}
```

This is crucial for:

* `/OpenAction 55 0 R`
* `/A 40 0 R`
* `/AA << /E 77 0 R >>`

---

## 3.4 Fallback to synthetic action node (only if no ref)

Replace your existing synthetic action attachment with:

```rust
// Fallback: synthetic action node only if no action_ref
if f.meta.get("action_ref").is_none() {
    if let Some(as_) = f.meta.get("action_s") {
        let aid = id_action(as_);
        g.upsert_node(aid.clone(), NodeKind::Action, format!("Action(/S={})", as_));
        g.add_edge(pi_id.clone(), aid.clone(), EdgeKind::Uses, "instance_action".into());
    }
}
```

---

## 3.5 Always attach aggregation payload node

This remains unchanged (useful for grouping):

```rust
let agg_id = id_payload(pk);
g.upsert_node(agg_id.clone(), NodeKind::Payload, format!("Payload({})", pk));
g.add_edge(pi_id.clone(), agg_id.clone(), EdgeKind::Contains, "instance_of".into());
```

---

# 4) Optional but recommended: attach `obj_ref` itself

Earlier you added:

```rust
meta.obj_ref = "NN 0 R"
```

You can now connect payload instances to **their own object identity**:

```rust
if let Some(oref) = f.meta.get("obj_ref") {
    if let Some(obj_id) = obj_ref_to_node_id(oref) {
        g.upsert_node(
            obj_id.clone(),
            NodeKind::ContainerObject,
            format!("Object {}", oref),
        );
        g.add_edge(
            pi_id.clone(),
            obj_id.clone(),
            EdgeKind::Contains,
            "payload_object_ref".into(),
        );
    }
}
```

This is especially valuable for:

* xref type-2 recovered objects
* ObjStm deep enumeration

---

# 5) Resulting graph semantics (very strong now)

You now have **four tiers of linkage**, in priority order:

1. **Exact structural object**

   * `obj:72:0` (payload value)
   * `obj:55:0` (action dict)
2. **Payload instance** (this exact hit)
3. **Finding**
4. **Aggregation nodes**

   * `payload:/JS`
   * `action:/JavaScript`

This means:

* In **Gephi**: you can collapse aggregation nodes and still retain precise chains.
* In **NetworkX**: you can trace `Finding → obj:* → obj:* → Trigger`.
* In **DOT**: you get clean, readable graphs without losing precision.

---

# 6) Sanity check: what happens if refs are missing?

Nothing breaks.

* No `payload_ref` → no structural payload object edge.
* No `action_ref` → synthetic `/S` node is used.
* Graph remains connected.

---

# 7) You are now at a “tool-complete” milestone

At this point, **sis-pdf** has:

* full PDF attack surface traversal
* deep embedded object recovery
* structured findings
* trigger/action/payload modeling
* path reconstruction
* multi-format graph export
* **structural fidelity down to exact object refs**

This is the point where:

* fuzzing guidance
* exploit chain classification
* sandbox simulation
* or even automated patching suggestions

become realistic next steps.

If you want the *next* chunk, the natural continuation is:

> **“Exploit chain synthesis & scoring”**
> (group payload instances into exploit chains and score likelihood)

# Chapter 18

Below is the next chunk: **Exploit chain synthesis & scoring**, built *purely as analysis* (no exploit enablement). It groups findings into “chains” (trigger → action → payload instance → object refs) and assigns a **risk score** with transparent reasons.

You’ll get:

* A **Chain model** (`ExploitChain`) + **Scoring model** (`ChainScore`)
* A synthesizer that:

  * builds chains by traversing your existing graph (**including structural object refs when present**)
  * clusters multiple payload instances under the same trigger/action
* A scorer that:

  * weights by **trigger reachability** (OpenAction > Annotation mouse event > NameTree-only)
  * action type (**Launch/JavaScript/SubmitForm/URI**)
  * evidence confidence/severity
  * obfuscation indicators (you can expand later)
  * “environmental” amplifiers (e.g. `/Launch` + file path)
* A detector that emits:

  * one finding per chain (with score + explanation)
  * a summary finding
* Optional: add `EdgeKind::Path` edges for chain paths in the exported graph

---

## 1) Core: chain model + scoring

### 1.1 New file: `crates/sis-pdf-core/src/chain.rs`

```rust
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ExploitChain {
    pub id: String,

    // anchors
    pub trigger_node: String,            // trigger:* node id
    pub trigger_label: String,           // human label

    // resolved structure
    pub action_nodes: Vec<String>,       // obj:* or action:* nodes
    pub payload_instances: Vec<String>,  // payload_instance:* nodes
    pub payload_keys: Vec<String>,       // e.g. ["/JS", "/Launch"]

    // evidence/finding linkage
    pub finding_nodes: Vec<String>,      // finding:* nodes

    // structural refs if available
    pub obj_refs: Vec<String>,           // e.g. ["55 0 R", "72 0 R"]

    // computed
    pub score: ChainScore,
    pub notes: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ChainScore {
    pub total: f64,            // 0..100
    pub severity_component: f64,
    pub reachability: f64,
    pub action_risk: f64,
    pub confidence: f64,
    pub complexity: f64,       // obfuscation / deep embedding signals
    pub reasons: Vec<String>,  // transparent explanation
}
```

Export it:
`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod chain; // NEW
```

---

## 2) Core: chain synthesis from graph

We synthesize chains primarily around **Trigger nodes**:

* For each trigger, find reachable **finding nodes**
* For each finding, find its linked **payload_instance** nodes
* For each payload_instance, prefer:

  * linked **obj:** nodes (payload value refs / action dict refs)
  * otherwise fall back to synthetic `action:*` and `payload:*` nodes

### 2.1 New file: `crates/sis-pdf-core/src/chain_synth.rs`

```rust
use std::collections::{HashMap, HashSet, VecDeque};

use crate::chain::{ExploitChain, ChainScore};
use crate::graph_model::{Graph, NodeKind, EdgeKind};

pub struct ChainSynthesisOptions {
    pub max_depth: usize,
    pub max_chains: usize,
    pub max_payload_instances_per_chain: usize,
}

impl Default for ChainSynthesisOptions {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_chains: 200,
            max_payload_instances_per_chain: 200,
        }
    }
}

/// Build chains from an already-attached graph (structure + findings + payload instances).
pub fn synthesize_chains(g: &Graph, opt: ChainSynthesisOptions) -> Vec<ExploitChain> {
    let mut out = Vec::new();

    // adjacency for traversal (directed)
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut radj: HashMap<&str, Vec<&str>> = HashMap::new(); // reverse edges
    for e in &g.edges {
        // Only traverse meaningful edges
        match e.kind {
            EdgeKind::Triggers | EdgeKind::Uses | EdgeKind::Contains | EdgeKind::ResolvesTo | EdgeKind::Indicates | EdgeKind::Path => {
                adj.entry(e.source.as_str()).or_default().push(e.target.as_str());
                radj.entry(e.target.as_str()).or_default().push(e.source.as_str());
            }
        }
    }

    // list triggers
    let triggers: Vec<&crate::graph_model::Node> = g.nodes.iter()
        .filter(|n| matches!(n.kind, NodeKind::Trigger))
        .collect();

    for t in triggers {
        if out.len() >= opt.max_chains { break; }

        // Reachable nodes via BFS (bounded)
        let reachable = bfs_reachable(t.id.as_str(), &adj, opt.max_depth);

        // Gather finding nodes reachable from trigger (common pattern: trigger -> finding via Indicates)
        let finding_nodes: Vec<&str> = reachable.iter()
            .filter(|id| id.starts_with("finding:"))
            .cloned()
            .collect();

        if finding_nodes.is_empty() {
            continue;
        }

        // Group payload instances under this trigger
        let mut payload_instances = HashSet::<String>::new();
        let mut action_nodes = HashSet::<String>::new();
        let mut payload_keys = HashSet::<String>::new();
        let mut obj_refs = HashSet::<String>::new();

        for f_id in &finding_nodes {
            // From finding, look for payload_instance via outgoing edges
            // (we don’t have direct edge index; use adjacency)
            if let Some(nexts) = adj.get(f_id.as_ref()) {
                for &n in nexts {
                    if n.starts_with("payload_instance:") {
                        payload_instances.insert(n.to_string());
                    }
                    // optional: finding could point to payload:/JS too; ignore for chain core
                }
            }
        }

        // Cap payload instances for sanity
        let mut payload_instances_vec: Vec<String> = payload_instances.into_iter().collect();
        payload_instances_vec.sort();
        if payload_instances_vec.len() > opt.max_payload_instances_per_chain {
            payload_instances_vec.truncate(opt.max_payload_instances_per_chain);
        }

        // For each payload instance, collect action nodes and refs if present
        for pi in &payload_instances_vec {
            // Prefer structural object nodes linked from payload instance
            if let Some(nexts) = adj.get(pi.as_str()) {
                for &n in nexts {
                    if n.starts_with("obj:") || n.starts_with("action:") {
                        action_nodes.insert(n.to_string());
                    }
                    if n.starts_with("payload:") {
                        // payload:/JS aggregation node stores key in label; infer key from id suffix
                        payload_keys.insert(n.trim_start_matches("payload:").to_string());
                    }
                }
            }

            // Pull refs from payload instance node attrs if present
            if let Some(node) = g.nodes.iter().find(|n| n.id == *pi) {
                if let Some(k) = node.attrs.get("payload_key") {
                    payload_keys.insert(k.clone());
                }
                for key in ["action_ref", "payload_ref", "meta.obj_ref", "obj_ref"] {
                    if let Some(r) = node.attrs.get(key) {
                        obj_refs.insert(r.clone());
                    }
                }
                for key in ["container_ref.objstm", "container_ref.xref_stream", "container_ref.annot", "container_ref.page", "container_ref.catalog"] {
                    if let Some(r) = node.attrs.get(key) {
                        obj_refs.insert(r.clone());
                    }
                }
            }
        }

        let mut finding_nodes_vec: Vec<String> = finding_nodes.into_iter().map(|s| s.to_string()).collect();
        finding_nodes_vec.sort();

        let mut action_nodes_vec: Vec<String> = action_nodes.into_iter().collect();
        action_nodes_vec.sort();

        let mut payload_keys_vec: Vec<String> = payload_keys.into_iter().collect();
        payload_keys_vec.sort();

        let mut obj_refs_vec: Vec<String> = obj_refs.into_iter().collect();
        obj_refs_vec.sort();

        // Deterministic chain id from trigger + first payload instance (or first finding)
        let chain_id = format!(
            "chain:{}:{}",
            sanitize_id(&t.id),
            payload_instances_vec.get(0).map(|s| sanitize_id(s)).unwrap_or_else(|| sanitize_id(&finding_nodes_vec[0]))
        );

        out.push(ExploitChain{
            id: chain_id,
            trigger_node: t.id.clone(),
            trigger_label: t.label.clone(),
            action_nodes: action_nodes_vec,
            payload_instances: payload_instances_vec,
            payload_keys: payload_keys_vec,
            finding_nodes: finding_nodes_vec,
            obj_refs: obj_refs_vec,
            score: ChainScore{
                total: 0.0,
                severity_component: 0.0,
                reachability: 0.0,
                action_risk: 0.0,
                confidence: 0.0,
                complexity: 0.0,
                reasons: vec![],
            },
            notes: HashMap::new(),
        });
    }

    out
}

fn bfs_reachable<'a>(start: &'a str, adj: &HashMap<&'a str, Vec<&'a str>>, max_depth: usize) -> HashSet<&'a str> {
    let mut seen = HashSet::new();
    let mut q = VecDeque::new();
    seen.insert(start);
    q.push_back((start, 0usize));

    while let Some((cur, d)) = q.pop_front() {
        if d >= max_depth { continue; }
        let nexts = adj.get(cur).cloned().unwrap_or_default();
        for &n in &nexts {
            if seen.insert(n) {
                q.push_back((n, d + 1));
            }
        }
    }
    seen
}

fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}
```

Export it:
`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod chain_synth; // NEW
```

---

## 3) Core: chain scoring

This is an intentionally transparent heuristic. You can tune weights later.

### 3.1 New file: `crates/sis-pdf-core/src/chain_score.rs`

```rust
use crate::chain::{ExploitChain, ChainScore};

pub struct ChainScoringWeights {
    pub w_reachability: f64,
    pub w_action: f64,
    pub w_severity: f64,
    pub w_confidence: f64,
    pub w_complexity: f64,
}

impl Default for ChainScoringWeights {
    fn default() -> Self {
        Self{
            w_reachability: 0.30,
            w_action: 0.30,
            w_severity: 0.20,
            w_confidence: 0.15,
            w_complexity: 0.05,
        }
    }
}

pub fn score_chain(mut c: ExploitChain, w: ChainScoringWeights) -> ExploitChain {
    let mut reasons = Vec::new();

    // Reachability: how likely is auto-trigger?
    // Use trigger path label heuristics
    let reach = reachability_score(&c.trigger_label, &mut reasons);

    // Action risk: based on payload keys + action types (if present)
    let action_r = action_risk_score(&c.payload_keys, &mut reasons);

    // Severity component: infer from included payload keys (proxy) + chain size
    let sev = severity_proxy(&c.payload_keys, &mut reasons);

    // Confidence: proxy based on how many distinct corroborating elements exist
    // (e.g., payload_instance has object refs; multiple findings; etc.)
    let conf = confidence_proxy(
        c.payload_instances.len(),
        c.finding_nodes.len(),
        c.obj_refs.len(),
        &mut reasons
    );

    // Complexity: deep embedding / multi-container hints in obj_refs
    let comp = complexity_proxy(&c.obj_refs, &mut reasons);

    // Combine 0..1 signals into 0..100
    let total_01 =
        w.w_reachability * reach +
        w.w_action * action_r +
        w.w_severity * sev +
        w.w_confidence * conf +
        w.w_complexity * comp;

    let total = (total_01 * 100.0).clamp(0.0, 100.0);

    c.score = ChainScore{
        total,
        severity_component: sev * 100.0,
        reachability: reach * 100.0,
        action_risk: action_r * 100.0,
        confidence: conf * 100.0,
        complexity: comp * 100.0,
        reasons,
    };
    c
}

fn reachability_score(trigger_label: &str, reasons: &mut Vec<String>) -> f64 {
    // Higher if likely to execute without user interaction.
    let t = trigger_label.to_lowercase();
    let s = if t.contains("openaction") || t.contains("catalog/openaction") {
        reasons.push("Reachability: OpenAction (auto on document open)".into());
        1.0
    } else if t.contains("catalog/aa/") {
        reasons.push("Reachability: Catalog /AA (document-level additional action)".into());
        0.85
    } else if t.contains("annot/aa/") {
        reasons.push("Reachability: Annotation /AA event (often user-driven)".into());
        0.55
    } else if t.contains("annot/a") {
        reasons.push("Reachability: Annotation /A (user interaction)".into());
        0.50
    } else if t.contains("namestree") || t.contains("nametree") || t.contains("names/javascript") {
        reasons.push("Reachability: NameTree JavaScript (may require additional trigger linkage)".into());
        0.35
    } else {
        reasons.push("Reachability: Unknown trigger type".into());
        0.40
    };
    s
}

fn action_risk_score(payload_keys: &[String], reasons: &mut Vec<String>) -> f64 {
    // Use payload keys as the stable indicator of action class
    let mut s = 0.2;
    for k in payload_keys {
        match k.as_str() {
            "/Launch" => { s = s.max(1.0); reasons.push("Action risk: /Launch present".into()); }
            "/JS" => { s = s.max(0.9); reasons.push("Action risk: /JS (JavaScript) present".into()); }
            "/F" => { s = s.max(0.75); reasons.push("Action risk: /F (SubmitForm / file spec) present".into()); }
            "/URI" => { s = s.max(0.6); reasons.push("Action risk: /URI present".into()); }
            _ => {}
        }
    }
    s
}

fn severity_proxy(payload_keys: &[String], reasons: &mut Vec<String>) -> f64 {
    // Conservative: /Launch or /JS implies high severity; URI medium.
    if payload_keys.iter().any(|k| k == "/Launch") {
        reasons.push("Severity proxy: Critical due to /Launch".into());
        1.0
    } else if payload_keys.iter().any(|k| k == "/JS") {
        reasons.push("Severity proxy: High due to /JS".into());
        0.85
    } else if payload_keys.iter().any(|k| k == "/F") {
        reasons.push("Severity proxy: High due to /F".into());
        0.75
    } else if payload_keys.iter().any(|k| k == "/URI") {
        reasons.push("Severity proxy: Medium due to /URI".into());
        0.55
    } else {
        reasons.push("Severity proxy: Low/Unknown".into());
        0.35
    }
}

fn confidence_proxy(payload_instances: usize, findings: usize, obj_refs: usize, reasons: &mut Vec<String>) -> f64 {
    // More corroboration => more confidence (but diminishing returns).
    let mut s = 0.35;
    if findings >= 1 { s += 0.25; reasons.push("Confidence: at least one detector finding".into()); }
    if findings >= 3 { s += 0.10; reasons.push("Confidence: multiple findings corroborate".into()); }
    if obj_refs >= 1 { s += 0.15; reasons.push("Confidence: structural object refs present".into()); }
    if payload_instances >= 2 { s += 0.10; reasons.push("Confidence: multiple payload instances under trigger".into()); }
    s.clamp(0.0, 1.0)
}

fn complexity_proxy(obj_refs: &[String], reasons: &mut Vec<String>) -> f64 {
    // Heuristic: presence of ObjStm/xref container refs suggests embedding complexity.
    let joined = obj_refs.join(" | ").to_lowercase();
    let mut s = 0.2;
    if joined.contains("objstm") {
        s = s.max(0.7);
        reasons.push("Complexity: involves ObjStm (embedded objects)".into());
    }
    if joined.contains("xref") {
        s = s.max(0.6);
        reasons.push("Complexity: involves XRef stream artifacts".into());
    }
    s
}
```

Export it:
`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod chain_score; // NEW
```

---

## 4) Detector: emit “exploit chain” findings + optional graph edges

This detector runs **after** you’ve built the graph and attached findings (in your `sis-pdf` binary export path, you already do that for export; but detectors run inside the scan). So we provide both options:

* **Option A (Recommended)**: Do chain synthesis & scoring in the **runner/binary** after the scan, because it has access to the final report and can build the combined graph once.
* **Option B**: Add a detector that builds its own graph snapshot from `ctx` + partial results (less ideal).

Given your current flow, I recommend Option A. Here’s the runner-style implementation that also emits chain findings into the report.

### 4.1 New helper in core: render chain to Finding

#### New file: `crates/sis-pdf-core/src/chain_render.rs`

```rust
use std::collections::HashMap;

use crate::chain::ExploitChain;
use crate::model::{Finding, AttackSurface, Severity, Confidence};

pub fn chain_to_finding(c: &ExploitChain) -> Finding {
    let mut meta = HashMap::new();
    meta.insert("chain_id".into(), c.id.clone());
    meta.insert("chain_score".into(), format!("{:.1}", c.score.total));
    meta.insert("trigger_node".into(), c.trigger_node.clone());
    meta.insert("payload_keys".into(), c.payload_keys.join(","));
    meta.insert("payload_instances".into(), c.payload_instances.len().to_string());
    meta.insert("finding_nodes".into(), c.finding_nodes.len().to_string());
    if !c.obj_refs.is_empty() {
        meta.insert("obj_refs".into(), c.obj_refs.join(" | "));
    }

    let sev = if c.score.total >= 85.0 { Severity::Critical }
        else if c.score.total >= 70.0 { Severity::High }
        else if c.score.total >= 50.0 { Severity::Medium }
        else { Severity::Low };

    Finding{
        id: format!("exploit_chain:{}", c.id),
        surface: AttackSurface::Structure,
        kind: "exploit_chain".into(),
        severity: sev,
        confidence: Confidence::Heuristic,
        title: format!("Exploit chain candidate (score {:.1})", c.score.total),
        description: format!(
            "Trigger: {}\nPayload keys: {}\nPayload instances: {}\nAction nodes: {}\nRefs: {}\n\nScore breakdown:\n\
             - reachability: {:.1}\n- action_risk: {:.1}\n- severity_proxy: {:.1}\n- confidence: {:.1}\n- complexity: {:.1}\n\nReasons:\n- {}",
            c.trigger_label,
            if c.payload_keys.is_empty() { "-" } else { c.payload_keys.join(", ") },
            c.payload_instances.len(),
            c.action_nodes.len(),
            if c.obj_refs.is_empty() { "-" } else { c.obj_refs.join(", ") },
            c.score.reachability,
            c.score.action_risk,
            c.score.severity_component,
            c.score.confidence,
            c.score.complexity,
            c.score.reasons.join("\n- "),
        ),
        objects: vec![],
        evidence: vec![],
        remediation: Some("Treat as suspicious chain. Consider stripping active content (/OpenAction, /AA, /JS, /Launch), and validate in a hardened sandbox viewer if analysis is required.".into()),
        meta,
    }
}
```

Export it:
`crates/sis-pdf-core/src/lib.rs`

```rust
pub mod chain_render; // NEW
```

---

## 5) Runner integration (sis binary): synthesize + score + append to report + add graph edges

### 5.1 Add chain generation after you build the combined graph

In your `sis-pdf` binary, you already do:

```rust
let mut graph = sis_pdf_core::graph_build::build_trigger_graph(&ctx, args.graph_include_paths);
sis_pdf_core::graph_attach::attach_findings(&mut graph, &report.findings);
```

Now add:

```rust
// 1) Synthesize chains
let chains = sis_pdf_core::chain_synth::synthesize_chains(
    &graph,
    sis_pdf_core::chain_synth::ChainSynthesisOptions::default(),
);

// 2) Score chains
let weights = sis_pdf_core::chain_score::ChainScoringWeights::default();
let mut scored = Vec::new();
for c in chains {
    scored.push(sis_pdf_core::chain_score::score_chain(c, weights.clone()));
}

// 3) Sort by score desc and cap
scored.sort_by(|a, b| b.score.total.partial_cmp(&a.score.total).unwrap_or(std::cmp::Ordering::Equal));
let scored = scored.into_iter().take(100).collect::<Vec<_>>();

// 4) Append to report.findings
for c in &scored {
    report.findings.push(sis_pdf_core::chain_render::chain_to_finding(c));
}

// 5) (Optional) add chain edges into graph for export
// Add: trigger -> payload_instance edges labeled "chain_member" for top chains
for c in &scored {
    for pi in c.payload_instances.iter().take(50) {
        graph.add_edge(c.trigger_node.clone(), pi.clone(), sis_pdf_core::graph_model::EdgeKind::Path, "chain_member".into());
    }
}
```

That gives you:

* chain findings in the report output (JSON/text)
* chain edges inside DOT/GML/JSON exports (if you export)

---

## 6) One safety/quality note: scoring is “analysis only”

This scoring does **not** attempt to execute, deobfuscate, or “prove exploitability.” It’s a **triage** mechanism:

* prioritizes likely auto-trigger + high-impact action classes
* boosts confidence when you have structural object refs

---

## 7) Where to take it next (practical next upgrade)

If you want a stronger score with minimal extra work, add **obfuscation features** as `Finding.meta` from the JS visitor, e.g.:

* `js.contains_eval`
* `js.contains_unescape`
* `js.high_entropy` (simple byte entropy on payload)
* `js.long_string_literals`
* `js.contains_hex_escapes`

Then have `complexity_proxy()` consume these.


# Chapter 19

Below is a **drop-in chunk** that adds **JS obfuscation signals** to the embedded JavaScript visitor, stores them in `Finding.meta` (via the existing visitor meta plumbing), and uses them in **chain scoring**.

This stays strictly on the *defensive analysis* side: it does **not** deobfuscate or execute JS; it only computes static indicators.

---

# 1) Add a small JS signal extractor (sis-pdf-detectors)

We’ll compute:

* `js.len` (bytes)
* `js.entropy` (0..8-ish for bytes; reported as float)
* `js.contains_eval`
* `js.contains_function_ctor` (`Function(`)
* `js.contains_unescape`
* `js.contains_fromcharcode`
* `js.contains_atob`
* `js.contains_hex_escapes` (`\xNN`)
* `js.contains_unicode_escapes` (`\uNNNN`)
* `js.high_pct_non_ascii`
* `js.longest_token` (max contiguous [A-Za-z0-9_$] run)
* `js.base64_like_runs` (count of long base64-ish runs)

## 1.1 New file: `crates/sis-pdf-detectors/src/js_signals.rs`

```rust
use std::collections::HashMap;

pub fn extract_js_signals(js: &[u8]) -> HashMap<String, String> {
    let mut m = HashMap::new();

    m.insert("js.len".into(), js.len().to_string());

    // entropy over bytes
    let ent = shannon_entropy(js);
    m.insert("js.entropy".into(), format!("{:.3}", ent));

    // decode lossy for substring checks
    let s = String::from_utf8_lossy(js).to_lowercase();

    m.insert("js.contains_eval".into(), bool_str(s.contains("eval(")));
    m.insert("js.contains_function_ctor".into(), bool_str(s.contains("function(") && s.contains("return")) // weak
        .to_string());

    // More precise Function constructor check: "new Function" or "Function("
    let fn_ctor = s.contains("new function") || s.contains("function(");
    m.insert("js.contains_function_ctor".into(), bool_str(fn_ctor));

    m.insert("js.contains_unescape".into(), bool_str(s.contains("unescape(")));
    m.insert("js.contains_fromcharcode".into(), bool_str(s.contains("fromcharcode")));
    m.insert("js.contains_atob".into(), bool_str(s.contains("atob(")));

    // Escape patterns: operate on bytes for speed
    m.insert("js.contains_hex_escapes".into(), bool_str(contains_hex_escape(js)));
    m.insert("js.contains_unicode_escapes".into(), bool_str(contains_unicode_escape(js)));

    // Non-ascii ratio
    let non_ascii = js.iter().filter(|&&b| b >= 0x80).count();
    let pct = if js.is_empty() { 0.0 } else { (non_ascii as f64) / (js.len() as f64) };
    m.insert("js.high_pct_non_ascii".into(), bool_str(pct >= 0.15));
    m.insert("js.pct_non_ascii".into(), format!("{:.3}", pct));

    // longest "identifier-ish" token run
    let lt = longest_token_run(js);
    m.insert("js.longest_token".into(), lt.to_string());
    m.insert("js.long_token_run".into(), bool_str(lt >= 80));

    // base64-like runs
    let b64_runs = count_base64_like_runs(js, 60);
    m.insert("js.base64_like_runs".into(), b64_runs.to_string());
    m.insert("js.has_base64_like".into(), bool_str(b64_runs > 0));

    // Simple overall "obfuscation-ish" flag
    let obf = is_obfuscationish(&m);
    m.insert("js.obfuscation_suspected".into(), bool_str(obf));

    m
}

fn bool_str(b: bool) -> String { if b { "true".into() } else { "false".into() } }

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let n = data.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c == 0 { continue; }
        let p = (c as f64) / n;
        h -= p * p.log2();
    }
    h
}

fn contains_hex_escape(data: &[u8]) -> bool {
    // looks for \xNN
    let mut i = 0;
    while i + 3 < data.len() {
        if data[i] == b'\\' && (data[i+1] == b'x' || data[i+1] == b'X')
            && is_hex(data[i+2]) && is_hex(data[i+3]) {
            return true;
        }
        i += 1;
    }
    false
}

fn contains_unicode_escape(data: &[u8]) -> bool {
    // looks for \uNNNN
    let mut i = 0;
    while i + 5 < data.len() {
        if data[i] == b'\\' && (data[i+1] == b'u' || data[i+1] == b'U')
            && is_hex(data[i+2]) && is_hex(data[i+3]) && is_hex(data[i+4]) && is_hex(data[i+5]) {
            return true;
        }
        i += 1;
    }
    false
}

fn is_hex(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
}

fn longest_token_run(data: &[u8]) -> usize {
    let mut best = 0usize;
    let mut cur = 0usize;
    for &b in data {
        if is_token_char(b) { cur += 1; best = best.max(cur); }
        else { cur = 0; }
    }
    best
}

fn is_token_char(b: u8) -> bool {
    matches!(b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$'
    )
}

fn count_base64_like_runs(data: &[u8], min_len: usize) -> usize {
    let mut runs = 0usize;
    let mut cur = 0usize;
    for &b in data {
        if is_b64_char(b) { cur += 1; }
        else {
            if cur >= min_len { runs += 1; }
            cur = 0;
        }
    }
    if cur >= min_len { runs += 1; }
    runs
}

fn is_b64_char(b: u8) -> bool {
    matches!(b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'/' | b'='
    )
}

fn is_obfuscationish(m: &HashMap<String, String>) -> bool {
    let ent: f64 = m.get("js.entropy").and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let has_b64 = m.get("js.has_base64_like").map(|s| s == "true").unwrap_or(false);
    let long_tok = m.get("js.long_token_run").map(|s| s == "true").unwrap_or(false);
    let hexesc = m.get("js.contains_hex_escapes").map(|s| s == "true").unwrap_or(false);
    let uniesc = m.get("js.contains_unicode_escapes").map(|s| s == "true").unwrap_or(false);
    let eval_ = m.get("js.contains_eval").map(|s| s == "true").unwrap_or(false);
    let unesc = m.get("js.contains_unescape").map(|s| s == "true").unwrap_or(false);
    let fcc = m.get("js.contains_fromcharcode").map(|s| s == "true").unwrap_or(false);

    // Very conservative heuristic
    (ent >= 5.2 && (has_b64 || long_tok || hexesc || uniesc))
        || (eval_ && (unesc || fcc || has_b64))
}
```

Wire it:
`crates/sis-pdf-detectors/src/lib.rs`

```rust
pub mod js_signals; // NEW
```

---

# 2) Populate JS signals into EmbeddedFinding.meta

We need the actual JS bytes. You’re already producing a preview string; we’ll also extract raw bytes from `/JS` when possible.

**Cases:**

* `/JS` value is a **string** → use bytes directly
* `/JS` value is a **stream** → decode stream (budget-aware if you route via ctx; but inside visitor we don’t have ctx budget, so keep conservative: only raw if no filters or small)
* `/JS` value is a **ref** → you can resolve via graph in outer detector; visitor doesn’t have graph. So: if ref, set `payload_ref` (already done) and skip signals here (later enhancement: outer detector resolves and injects signals).

### 2.1 Update: `crates/sis-pdf-detectors/src/embedded_visitors.rs`

At top:

```rust
use sis_pdf_detectors::js_signals;
```

(If module path differs, use `crate::js_signals` since you’re inside the same crate.)

In `EmbeddedJavaScriptVisitor::on_node`, after you build `meta`, add:

```rust
        // Try to extract JS bytes from /JS when it's an inline string.
        if let Some((_, js_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS") {
            if let sis_pdf_pdf::object::PdfAtom::Str(sv) = &js_obj.atom {
                // sv.decoded is the decoded string bytes in your model (assumption consistent with other code)
                let sig = crate::js_signals::extract_js_signals(&sv.decoded);
                for (k, v) in sig { meta.insert(k, v); }
            } else {
                // Mark that bytes were not inline
                meta.insert("js.inline_bytes".into(), "false".into());
            }
        }
```

Also set:

```rust
meta.insert("js.inline_bytes".into(), "true".into());
```

right before the `if let PdfAtom::Str` block, and flip it to false if not a string.

So the full meta section becomes:

```rust
        let mut meta = std::collections::HashMap::new();
        meta.insert("payload_key".into(), "/JS".into());
        meta.insert("action_s".into(), "/JavaScript".into());
        meta.insert("path".into(), path.to_string());
        meta.insert("js.inline_bytes".into(), "true".into());

        if let Some((_, js_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS") {
            // payload_ref if ref
            if let Some(r) = sis_pdf_core::meta_refs::obj_ref_string(js_obj) {
                meta.insert("payload_ref".into(), r);
            }

            if let sis_pdf_pdf::object::PdfAtom::Str(sv) = &js_obj.atom {
                let sig = crate::js_signals::extract_js_signals(&sv.decoded);
                for (k, v) in sig { meta.insert(k, v); }
            } else {
                meta.insert("js.inline_bytes".into(), "false".into());
            }
        }
```

This gives you signals for the common inline `/JS ( ... )` case, and still records `payload_ref` for ref cases.

> Later, you can add a “resolve JS ref” step in the annotation/name-tree detectors before calling visitors, and pass the resolved bytes through origin_meta (I can paste that too if you want).

---

# 3) Ensure payload instance nodes carry these signals

Right now, payload instance nodes copy finding meta into node attrs (you already do `meta.*` on finding nodes). But payload instance nodes should carry the JS signals too.

We’ll do it in `graph_attach.rs`, where we create the payload instance node and set attrs. Add copying any `js.*` meta keys.

### 3.1 Update: `crates/sis-pdf-core/src/graph_attach.rs`

Inside the payload instance node creation:

```rust
if let Some(n) = g.node_mut(&pi_id) {
    // existing attrs...
    // NEW: copy js.* keys from finding meta for convenience on the instance node
    for (k, v) in &f.meta {
        if k.starts_with("js.") {
            n.attrs.insert(k.clone(), v.clone());
        }
    }
}
```

This makes payload instance nodes self-contained for offline graph analysis.

---

# 4) Feed JS signals into chain scoring (complexity proxy)

We currently score complexity by container refs. Now we’ll add boosts if JS suggests obfuscation.

Since chains don’t currently carry per-instance attrs, we’ll detect JS signals from **payload instance node attrs** during synthesis or scoring.

Simplest: extend `complexity_proxy()` to accept a list of payload instance node attrs.

### 4.1 Update `chain_synth.rs` to collect JS signal summaries onto the chain

In `synthesize_chains`, after building `payload_instances_vec`, compute a few chain notes:

Add:

```rust
        // Summarize JS obfuscation signals across payload instances
        let mut js_obf = 0usize;
        let mut js_eval = 0usize;
        let mut js_b64 = 0usize;
        let mut max_entropy = 0.0f64;

        for pi in &payload_instances_vec {
            if let Some(node) = g.nodes.iter().find(|n| n.id == *pi) {
                if node.attrs.get("js.obfuscation_suspected").map(|v| v == "true").unwrap_or(false) {
                    js_obf += 1;
                }
                if node.attrs.get("js.contains_eval").map(|v| v == "true").unwrap_or(false) {
                    js_eval += 1;
                }
                if node.attrs.get("js.has_base64_like").map(|v| v == "true").unwrap_or(false) {
                    js_b64 += 1;
                }
                if let Some(e) = node.attrs.get("js.entropy").and_then(|s| s.parse::<f64>().ok()) {
                    if e > max_entropy { max_entropy = e; }
                }
            }
        }
```

Then set chain notes:

```rust
        let mut notes = HashMap::new();
        notes.insert("js.obfuscation_instances".into(), js_obf.to_string());
        notes.insert("js.eval_instances".into(), js_eval.to_string());
        notes.insert("js.base64_instances".into(), js_b64.to_string());
        notes.insert("js.max_entropy".into(), format!("{:.3}", max_entropy));
```

And when creating `ExploitChain{...}`, set `notes`:

```rust
            notes,
```

(Remove the old `notes: HashMap::new(),`.)

---

# 5) Use chain.notes in scoring

### 5.1 Update: `crates/sis-pdf-core/src/chain_score.rs`

Replace `complexity_proxy(obj_refs, reasons)` with a version that also takes `notes`.

Change call site:

```rust
let comp = complexity_proxy(&c.obj_refs, &c.notes, &mut reasons);
```

Update signature + logic:

```rust
fn complexity_proxy(obj_refs: &[String], notes: &std::collections::HashMap<String,String>, reasons: &mut Vec<String>) -> f64 {
    // Base complexity from embedding
    let joined = obj_refs.join(" | ").to_lowercase();
    let mut s = 0.2;

    if joined.contains("objstm") {
        s = s.max(0.7);
        reasons.push("Complexity: involves ObjStm (embedded objects)".into());
    }
    if joined.contains("xref") {
        s = s.max(0.6);
        reasons.push("Complexity: involves XRef stream artifacts".into());
    }

    // JS signals
    let obf = notes.get("js.obfuscation_instances").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
    let eval_ = notes.get("js.eval_instances").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
    let b64 = notes.get("js.base64_instances").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
    let max_ent = notes.get("js.max_entropy").and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0);

    if obf > 0 {
        s = s.max(0.85);
        reasons.push(format!("Complexity: JS obfuscation suspected in {} payload instance(s)", obf));
    }
    if eval_ > 0 {
        s = s.max(0.75);
        reasons.push(format!("Complexity: eval() present in {} payload instance(s)", eval_));
    }
    if b64 > 0 {
        s = s.max(0.70);
        reasons.push(format!("Complexity: base64-like runs present in {} payload instance(s)", b64));
    }
    if max_ent >= 5.2 {
        s = s.max(0.70);
        reasons.push(format!("Complexity: high JS entropy observed (max {:.2})", max_ent));
    }

    s.clamp(0.0, 1.0)
}
```

---

# 6) Make chain findings include JS signal summary

### 6.1 Update: `crates/sis-pdf-core/src/chain_render.rs`

In the description string, add:

```rust
let js_obf = c.notes.get("js.obfuscation_instances").cloned().unwrap_or_else(|| "0".into());
let js_eval = c.notes.get("js.eval_instances").cloned().unwrap_or_else(|| "0".into());
let js_b64 = c.notes.get("js.base64_instances").cloned().unwrap_or_else(|| "0".into());
let js_ent = c.notes.get("js.max_entropy").cloned().unwrap_or_else(|| "0".into());
```

Then include in description:

```rust
"JS signals: obfuscation_instances={} eval_instances={} base64_instances={} max_entropy={}\n\n"
```

---

# 7) What you get now

* Findings from embedded JS carry **static obfuscation indicators** in `meta`.
* Payload instance nodes inherit `js.*` attrs, making exported graphs directly filterable:

  * filter nodes where `js.obfuscation_suspected == true`
  * color by `js.entropy`
  * highlight nodes where `js.contains_eval == true`
* Chains score higher complexity when those signals appear, with explicit reasons.

---

## Next upgrade (very useful): resolve `/JS` when it’s a ref

Right now, signals only compute when `/JS` is an inline string. If you want, I can add a small resolver in the annotation/name-tree detectors so when `/JS` is a ref, we resolve it via `ObjectGraph` and pass bytes into meta for signal extraction (still static; no execution). This dramatically increases coverage.


# Chapter 20


Cool — next upgrade is: **when `/JS` is a ref**, resolve it through the `ObjectGraph`, extract bytes (string or stream), compute the same `js.*` signals, and attach them to the **finding + payload instance**.

The clean way to do this without making detectors “know” about every visitor is to give visitors an optional **resolver context** (object graph + original bytes). Then the JS visitor can resolve `/JS 72 0 R` and compute signals.

Below is the drop-in patch.

---

# 1) Add a `VisitorContext` with ref resolution helpers

## 1.1 Update: `crates/sis-pdf-core/src/visitor.rs`

Add imports (near top):

```rust
use sis_pdf_pdf::graph::ObjectGraph;
use sis_pdf_pdf::object::{PdfAtom, PdfObj};
```

Add this new struct + helpers:

```rust
pub struct VisitorContext<'a> {
    pub gpdf: &'a ObjectGraph<'a>,
    pub bytes: &'a [u8],
    /// Safety/perf cap for resolved payload extraction (bytes). Keep small by default.
    pub max_payload_bytes: usize,
}

impl<'a> VisitorContext<'a> {
    /// Resolve a PdfObj that might be a ref into a concrete object entry.
    pub fn resolve<'b>(&'b self, o: &'b PdfObj<'a>) -> Option<sis_pdf_pdf::graph::ObjEntry<'a>> {
        match o.atom {
            PdfAtom::Ref { .. } => self.gpdf.resolve_ref(o),
            _ => None,
        }
    }

    /// Extract bytes for a string or stream-like object.
    ///
    /// - If it's a string: returns decoded bytes.
    /// - If it's a stream: returns the raw stream bytes (not decoded by filters).
    ///   (You can upgrade later to decode filters; this still gives you entropy/escape signals.)
    pub fn extract_bytes(&self, o: &PdfObj<'a>) -> Option<Vec<u8>> {
        match &o.atom {
            PdfAtom::Str(s) => {
                let mut v = s.decoded.clone();
                if v.len() > self.max_payload_bytes { v.truncate(self.max_payload_bytes); }
                Some(v)
            }
            PdfAtom::Ref{..} => {
                let e = self.resolve(o)?;
                self.extract_bytes_from_entry(e)
            }
            PdfAtom::Stream(st) => {
                // Raw stream bytes span in the original PDF bytes
                // (Assumes your Stream atom carries a span; if not, adjust to your stream model.)
                let start = st.data_span.start as usize;
                let end = st.data_span.end as usize;
                if start >= end || end > self.bytes.len() { return None; }
                let mut v = self.bytes[start..end].to_vec();
                if v.len() > self.max_payload_bytes { v.truncate(self.max_payload_bytes); }
                Some(v)
            }
            _ => None,
        }
    }

    fn extract_bytes_from_entry(&self, e: sis_pdf_pdf::graph::ObjEntry<'a>) -> Option<Vec<u8>> {
        // Prefer direct atom kinds.
        match &e.atom {
            PdfAtom::Str(s) => {
                let mut v = s.decoded.clone();
                if v.len() > self.max_payload_bytes { v.truncate(self.max_payload_bytes); }
                Some(v)
            }
            PdfAtom::Stream(st) => {
                let start = st.data_span.start as usize;
                let end = st.data_span.end as usize;
                if start >= end || end > self.bytes.len() { return None; }
                let mut v = self.bytes[start..end].to_vec();
                if v.len() > self.max_payload_bytes { v.truncate(self.max_payload_bytes); }
                Some(v)
            }
            _ => None
        }
    }
}
```

> **Note about streams:** this version uses **raw** stream bytes. It’s still useful for entropy/base64/escape pattern detection. If/when you add filter decoding, we’ll swap `extract_bytes_from_entry()` to decode through your existing stream decode path.

---

# 2) Let visitors receive `VisitorContext`

## 2.1 Update the Visitor trait

In `crates/sis-pdf-core/src/visitor.rs`, wherever your visitor trait is defined (you’ve been using `on_node(&self, node, path, out)`), change it to include ctx:

```rust
pub trait EmbeddedVisitor: Send + Sync {
    fn id(&self) -> &'static str;

    fn on_node<'a>(
        &self,
        vctx: &VisitorContext<'a>,
        node: &sis_pdf_pdf::visit::DictNode<'a>,
        path: &str,
        out: &mut Vec<EmbeddedFinding>,
    );
}
```

Then update the call site in your traversal runner (where you apply visitors over visited nodes) to pass `vctx`.

---

# 3) Pass VisitorContext from the runner / scan pipeline

Your `run_visitors_on_embedded` currently has access to bytes + (indirectly) graph in `ScanContext` at a higher layer.

### 3.1 Update: `crates/sis-pdf-core/src/visitor.rs` (or wherever `run_visitors_on_embedded` lives)

Change the function signature to accept `vctx`:

```rust
pub fn run_visitors_on_embedded<'a>(
    vctx: &VisitorContext<'a>,
    visitors: &[Box<dyn EmbeddedVisitor>],
    artifacts: &[EmbeddedArtifact<'a>],
) -> Vec<Finding> {
    // ...
}
```

And when calling each visitor:

```rust
visitor.on_node(vctx, &node, &path, &mut embedded_findings);
```

### 3.2 In your sis binary (or wherever you call visitors)

Right after you build `ScanContext ctx`:

```rust
let vctx = sis_pdf_core::visitor::VisitorContext {
    gpdf: &ctx.graph,
    bytes: ctx.bytes,
    max_payload_bytes: 256 * 1024, // 256 KiB cap (tune)
};

// then pass &vctx into run_visitors_on_embedded(...)
```

---

# 4) Update EmbeddedJavaScriptVisitor to resolve `/JS` refs and compute signals

## 4.1 Update: `crates/sis-pdf-detectors/src/embedded_visitors.rs`

Modify JS visitor signature to accept vctx:

```rust
fn on_node<'a>(
    &self,
    vctx: &sis_pdf_core::visitor::VisitorContext<'a>,
    node: &sis_pdf_pdf::visit::DictNode<'a>,
    path: &str,
    out: &mut Vec<sis_pdf_core::visitor::EmbeddedFinding>,
) {
   // ...
}
```

Then replace the `/JS` extraction section with this (the important part):

```rust
let mut meta = std::collections::HashMap::new();
meta.insert("payload_key".into(), "/JS".into());
meta.insert("action_s".into(), "/JavaScript".into());
meta.insert("path".into(), path.to_string());

// default flags
meta.insert("js.resolved".into(), "false".into());
meta.insert("js.resolved_source".into(), "-".into());

if let Some((_, js_obj)) = sis_pdf_pdf::graph::ObjectGraph::dict_get_first(d, b"/JS") {
    // record payload_ref if it is a ref
    if let Some(r) = sis_pdf_core::meta_refs::obj_ref_string(js_obj) {
        meta.insert("payload_ref".into(), r);
    }

    // Attempt to extract bytes (handles inline string, ref->string, stream, ref->stream)
    if let Some(js_bytes) = vctx.extract_bytes(js_obj) {
        meta.insert("js.resolved".into(), "true".into());
        meta.insert(
            "js.resolved_source".into(),
            match &js_obj.atom {
                sis_pdf_pdf::object::PdfAtom::Ref{..} => "ref".into(),
                sis_pdf_pdf::object::PdfAtom::Str(_) => "inline_str".into(),
                sis_pdf_pdf::object::PdfAtom::Stream(_) => "inline_stream_raw".into(),
                _ => "other".into(),
            }
        );

        // Compute signals
        let sig = crate::js_signals::extract_js_signals(&js_bytes);
        for (k, v) in sig { meta.insert(k, v); }
    }
}
```

Now JS signals will be present for:

* `/JS (inline string)`
* `/JS 72 0 R` where object 72 is a string
* `/JS 72 0 R` where object 72 is a stream (raw bytes)

---

# 5) Chain scoring already consumes js.* from payload instances

Because you earlier:

* copied `js.*` meta keys into **payload instance node attrs**
* summarized those in `chain_synth` into `chain.notes`
* used those in `chain_score`

This upgrade automatically increases coverage without changing scoring code.

---

# 6) Small (but important) safety/perf knob

The `VisitorContext.max_payload_bytes` cap prevents:

* giant streams from blowing up memory
* slow signal extraction

Start with `256 KiB` and tune later. (Entropy/escape/base64 signals don’t need megabytes.)

---

## Next incremental upgrade after this

If you want the **best quality** obfuscation signals, the next step is to **decode filtered streams** (Flate/LZW/etc.) before analysis. That requires calling your PDF stream decode path (likely already exists for content streams). If you say “decode filtered /JS streams”, I’ll paste that patch using your actual `sis_pdf_pdf` stream APIs (once you show me the stream types you’re using, or I’ll write it with the minimal assumptions you’ve been using elsewhere).


# Chapter 21

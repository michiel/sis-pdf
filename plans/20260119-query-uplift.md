Based on the deep audit of the `sis-pdf` query interface (see reviews/20260119-query-interface.md), the following recommendations are proposed to elevate the tool from a structural viewer to a forensic standard.


These recommendations prioritize **composability** (the ability to chain commands), **predictability** (reducing surprise in output formats), and **forensic safety** (handling malicious inputs securely).

### 1. Implement Boolean Logic and Property Predicates

**Priority:** Critical
**Theme:** Flexibility & Construction

Currently, the interface implies singular selector modes (`obj` OR `type`). To handle real-world forensic queries—such as finding "large JavaScript streams" or "encrypted files"—the syntax must support intersection (`AND`) and property-based filtering.

* **Technical Implementation (CLI Syntax):**
```bash
# Current (Implied):
sis query type js

# Recommended (Boolean & Predicates):
sis query type js --where "length > 1024 AND filter == 'FlateDecode'"
sis query obj 52 0 OR obj 53 0

```


* **Benefits:**
* **Flexibility:** Eliminates the need for users to write external scripts (e.g., `grep` or `jq`) for basic filtering.
* **Ergonomics:** Allows the analyst to "drill down" iteratively without dumping the entire file.



### 2. Standardize "Inverse XRef" Querying

**Priority:** High
**Theme:** Consistency & Navigability

While `obj 52 0` selects an object, forensic analysts frequently need to know *what references this object*. This is essential for determining if a malicious object is actually triggered by the Document Catalog or OpenAction.

* **Technical Implementation:**
Introduce a `ref` (references) selector that mirrors the `obj` syntax.
```bash
# Who points to Object 52?
sis query ref 52 0 --format table

# Output:
# | Source Object | Relationship |
# |---------------|--------------|
# | obj 1 0 | /OpenAction |
# | obj 14 0 | /Annot |

```


* **Benefits:**
* **Interoperability:** Aligns with industry standards like `pdf-parser.py` (which uses `-r` for references).


* **Consistency:** Maintains the `verb-noun-selector` grammar (`sis query ref...`) rather than adding a flag like `--find-parents`.



### 3. "Smart" Stream Export with Explicit Decode Control

**Priority:** Critical
**Theme:** Predictability & Usefulness

PDF streams are rarely stored as raw bytes; they are often compressed (zlib) or encoded (Hex, ASCII85). The export function must be predictable. A common failure mode in forensic tools is dumping the *compressed* bytes when the user expects the *payload*, or vice versa.

* **Technical Implementation:**
Implement a tri-state export flag: `--raw`, `--decode` (default), and `--hexdump`.
```bash
# Default: Apply filters (e.g., unzip) and output canonical bytes
sis query obj 52 0 --export > payload.js

# Raw: Dump exact file bytes (useful for hashing/integrity checks)
sis query obj 52 0 --export --raw > payload.zlib

# Hexdump: Visual inspection of binary data
sis query obj 52 0 --export --hexdump | head

```


* **Benefits:**
* **Predictability:** The user explicitly controls the transformation pipeline.
* **Usefulness:** `--raw` exports allow for external steganalysis, while `--decode` speeds up malware extraction.



### 4. NDJSON (Newline Delimitated JSON) for Streaming Pipelines

**Priority:** High
**Theme:** Interoperability

Standard JSON (`[...]`) requires the entire dataset to be held in memory to close the array, which is brittle for massive files or continuous streams. NDJSON (one JSON object per line) allows for O(1) memory usage and infinite piping.

* **Technical Implementation:**
```bash
# Output Format:
{"id": "52 0", "type": "Stream", "length": 450}
{"id": "53 0", "type": "Dictionary", "subtype": "Image"}

# Integration Example (Piping to standard tools):
sis query type img --format ndjson | jq -c 'select(.length > 10000)'

```


* **Benefits:**
* **Extensibility:** Easy integration with log aggregators (ELK stack) or stream processors.
* **Robustness:** If the parser crashes on Object 99, the valid JSON for Objects 1-98 is already flushed to stdout and preserved.



### 5. Defensive Asset Extraction (Sanitization)

**Priority:** Medium
**Theme:** Safety & Ergonomics

When extracting assets via `type asset` (EmbeddedFiles), the tool must not blindly trust the filename specified inside the PDF, which could lead to directory traversal attacks (e.g., `../../windows/system32/evil.exe`).

* **Technical Implementation:**
```bash
# Unsafe (Naive Implementation):
# Writes to /etc/passwd if the PDF specifies it.

# Recommended (Safe Sandbox):
sis query type asset --export-dir./evidence/
# Result:./evidence/file_001_malware.exe

```


*Logic:* The tool should hash the content to generate a unique filename or sanitize the provided filename, logging the mapping in a separate `manifest.json`.
* **Benefits:**
* **Safety:** Protects the analyst's machine during the extraction phase.
* **Consistency:** Ensures that extracting 50 assets doesn't result in file collisions (overwriting evidence).



### 6. Structured Error Reporting

**Priority:** Medium
**Theme:** Predictability

Forensic tools often fail silently or print stack traces when encountering malformed PDFs. `sis query` should treat errors as data.

* **Technical Implementation:**
If a query targets a missing or corrupt object, the output should still adhere to the requested schema.
```json
// sis query obj 9999 0 --format json
{
  "id": "9999 0",
  "status": "error",
  "error_code": "OBJ_NOT_FOUND",
  "message": "Object 9999 0 does not exist in the xref table."
}

```


* **Benefits:**
* **Predictability:** Automated scripts won't crash when encountering a "broken" PDF; they can simply filter for `"status": "error"`.

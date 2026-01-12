# Query Interface for sis-pdf (2026-01-12)

## Goals

Provide a unified query interface (`sis query`) that replaces common usage of external PDF tools (pdfinfo, mutool, pdftk, qpdf) with native sis-pdf queries. Support three modes:
1. **CLI one-liners**: `sis query "pages" file.pdf --json`
2. **REPL mode**: `sis query file.pdf` (interactive session)
3. **Non-interactive scripting**: JSON output for automation

## Background: PDF Tool Capabilities We Need to Replace

### pdfinfo capabilities (used in investigation)
```bash
pdfinfo file.pdf                    # Metadata: title, creator, pages, size
pdfinfo -js file.pdf                # Extract all JavaScript
pdfinfo -url file.pdf               # Extract all URLs
pdfinfo -meta file.pdf              # XML metadata stream
pdfinfo -box file.pdf               # Page bounding boxes
pdfinfo -struct file.pdf            # Document structure (tagged PDFs)
pdfinfo -dests file.pdf             # Named destinations
```

### mutool capabilities (attempted but not available)
```bash
mutool show file.pdf pages          # Show page tree
mutool show file.pdf trailer        # Show trailer
mutool show file.pdf 12 0 R         # Show specific object
mutool info file.pdf                # Document info
```

### pdftk capabilities (attempted but not available)
```bash
pdftk file.pdf dump_data_utf8       # Extract metadata and info
pdftk file.pdf cat 1-5 output       # Page manipulation (out of scope)
```

### qpdf capabilities (attempted but not available)
```bash
qpdf --show-object=12 file.pdf      # Inspect specific object
qpdf --json file.pdf                # JSON representation
qpdf --check file.pdf               # Validation
```

## Design: `sis query` Interface

### Command Structure

```bash
# One-liner queries
sis query QUERY FILE [--json] [--deep]

# Interactive REPL
sis query FILE [--deep] [--strict]

# Batch queries (stdin)
echo "pages\njs\nurls" | sis query FILE --batch
```

### Query Language (Simple and Composable)

**Metadata Queries:**
- `pages` - Page count
- `objects` - Object count
- `creator` - Creator metadata
- `producer` - Producer metadata
- `title` - Document title
- `created` - Creation date
- `modified` - Modification date
- `encrypted` - Encryption status
- `version` - PDF version
- `filesize` - File size in bytes
- `polyglot` - Polyglot risk assessment

**Structure Queries:**
- `trailer` - Show trailer dictionary
- `catalog` - Show document catalog
- `pages.tree` - Show page tree structure
- `pages.count` - Page count (alias for `pages`)
- `xref` - Cross-reference table info
- `incremental` - Incremental update info

**Object Queries:**
- `object N` or `obj N` - Show object N (generation 0)
- `object N G` or `obj N G` - Show object N generation G
- `objects.count` - Total object count
- `objects.list` - List all object IDs
- `objects.with TYPE` - Filter objects by type (e.g., `objects.with /Page`)

**Content Queries:**
- `js` or `javascript` - Extract all JavaScript
- `js.count` - Count JavaScript actions
- `urls` or `uris` - Extract all URLs
- `urls.count` - Count URLs
- `fonts` - List embedded fonts
- `images` - List image XObjects
- `images.count` - Image count
- `embedded` - List embedded files
- `embedded.count` - Embedded file count

**Finding Queries:**
- `findings` - List all findings
- `findings.count` - Total finding count
- `findings.high` - High severity findings
- `findings.kind KIND` - Filter by finding kind
- `findings.surface SURFACE` - Filter by attack surface

**Advanced Queries:**
- `chains` - List action chains
- `chains.js` - JavaScript chains
- `chains.supply` - Supply chain vectors
- `graph.suspicious` - Suspicious graph paths
- `cycles` - Reference cycles
- `cycles.page` - Page tree cycles

### Output Formats

**Human-readable (default):**
```
Pages: 37
Creator: LaTeX with Beamer class
Producer: XeTeX 0.99996
PDF version: 1.5
Encrypted: no
```

**JSON (--json flag):**
```json
{
  "query": "pages",
  "file": "file.pdf",
  "result": {
    "pages": 37,
    "creator": "LaTeX with Beamer class",
    "producer": "XeTeX 0.99996",
    "version": "1.5",
    "encrypted": false
  }
}
```

**Compact (--compact or -c):**
```
37
```

### REPL Mode

```bash
$ sis query suspicious.pdf
sis> pages
37

sis> js
Found 3 JavaScript actions:
  obj 45:0 - app.alert('test')
  obj 67:0 - submitForm(...)
  obj 89:0 - app.doc.info.title

sis> findings.high
66 High severity findings:
  object_reference_cycle: 66 findings

sis> object 45
45 0 obj
<<
  /Type /Action
  /S /JavaScript
  /JS (app.alert('test'))
>>
endobj

sis> help
Available queries:
  Metadata: pages, objects, creator, producer, title, version
  Content: js, urls, fonts, images, embedded
  Structure: trailer, catalog, xref, incremental
  Objects: object N [G], objects.list, objects.with TYPE
  Findings: findings, findings.high, findings.kind KIND
  Advanced: chains, cycles, graph.suspicious

  Commands: help, exit, quit, :json (toggle JSON mode)

sis> :json
JSON mode enabled

sis> pages
{"query":"pages","result":37}

sis> exit
```

### Integration with Existing Commands

Map queries to existing sis-pdf capabilities:

| Query | Current Command | Notes |
|-------|----------------|-------|
| `js` | `sis extract js FILE` | Extract JavaScript |
| `embedded` | `sis extract embedded FILE` | Extract embedded files |
| `findings` | `sis scan FILE` | Scan findings |
| `findings.kind X` | `sis scan FILE --json \| jq` | Filter in query layer |
| `object N` | New capability | Parse and show object |
| `chains` | `sis export-graph FILE` | Export chains |
| `urls` | `sis scan FILE --json` | Extract from findings |

## Implementation Plan

### Phase 1: Core Query Engine (MVP)
**File:** `crates/sis-pdf-cli/src/commands/query.rs`

1. Parse query string into query AST
2. Execute metadata queries (pages, creator, etc.)
3. Execute structure queries (trailer, catalog)
4. JSON output support
5. Basic error handling

**Queries to implement:**
- `pages`, `objects`, `version`, `creator`, `producer`, `title`
- `trailer`, `catalog`
- `--json` flag

### Phase 2: Content Queries
**File:** `crates/sis-pdf-cli/src/commands/query.rs` + helpers

1. JavaScript extraction (`js`, `js.count`)
2. URL extraction (`urls`, `urls.count`)
3. Font listing (`fonts`)
4. Image listing (`images`, `images.count`)
5. Embedded file listing (`embedded`, `embedded.count`)

### Phase 3: Object Inspection
**File:** `crates/sis-pdf-cli/src/commands/query.rs`

1. Object lookup (`object N [G]`)
2. Object listing (`objects.list`)
3. Type filtering (`objects.with TYPE`)
4. Pretty-printing of objects

### Phase 4: Finding Queries
**File:** Integrate with `scan.rs`

1. Finding listing (`findings`)
2. Severity filtering (`findings.high`, `findings.medium`)
3. Kind filtering (`findings.kind KIND`)
4. Surface filtering (`findings.surface SURFACE`)

### Phase 5: REPL Mode
**File:** `crates/sis-pdf-cli/src/commands/query_repl.rs`

1. Rustyline integration for readline support
2. Command history
3. Tab completion
4. Multi-line input
5. REPL-specific commands (`:json`, `:compact`, `help`, `exit`)

### Phase 6: Advanced Queries
**File:** Integration with graph exports

1. Chain queries (`chains`, `chains.js`)
2. Cycle queries (`cycles`, `cycles.page`)
3. Graph queries (`graph.suspicious`)

## API Design

### Query Executor Trait

```rust
pub trait QueryExecutor {
    fn execute(&self, query: &Query, ctx: &ScanContext) -> Result<QueryResult>;
}

pub enum Query {
    Metadata(MetadataQuery),
    Structure(StructureQuery),
    Content(ContentQuery),
    Object(ObjectQuery),
    Finding(FindingQuery),
    Advanced(AdvancedQuery),
}

pub enum MetadataQuery {
    Pages,
    Objects,
    Creator,
    Producer,
    Title,
    Version,
    Encrypted,
    Created,
    Modified,
    Filesize,
    Polyglot,
}

pub enum QueryResult {
    Scalar(ScalarValue),
    List(Vec<QueryResult>),
    Object(PdfObj),
    Structure(StructuredValue),
}

pub enum ScalarValue {
    String(String),
    Number(i64),
    Boolean(bool),
    Date(String),
}
```

### Query Parser

```rust
pub fn parse_query(input: &str) -> Result<Query> {
    // Simple string-based parser
    // "pages" -> Query::Metadata(MetadataQuery::Pages)
    // "object 45" -> Query::Object(ObjectQuery::Show(45, 0))
    // "findings.high" -> Query::Finding(FindingQuery::Severity(Severity::High))
}
```

## Usage Examples

### Replace pdfinfo
```bash
# Before: pdfinfo file.pdf
sis query "pages,creator,producer,version" file.pdf

# Before: pdfinfo -js file.pdf
sis query js file.pdf

# Before: pdfinfo -url file.pdf
sis query urls file.pdf
```

### Replace mutool info
```bash
# Before: mutool info file.pdf
sis query "pages,objects,version,encrypted" file.pdf --json

# Before: mutool show file.pdf trailer
sis query trailer file.pdf

# Before: mutool show file.pdf 12 0 R
sis query "object 12" file.pdf
```

### Replace qpdf --show-object
```bash
# Before: qpdf --show-object=12 file.pdf
sis query "object 12" file.pdf

# Before: qpdf --json file.pdf | jq '.pages'
sis query pages file.pdf --json
```

### Scripting and Automation
```bash
# Get page count for batch processing
for f in *.pdf; do
  pages=$(sis query pages "$f" --compact)
  echo "$f: $pages pages"
done

# Find PDFs with JavaScript
sis query "js.count" *.pdf --json | jq 'select(.result > 0)'

# Check for high severity findings
if [ $(sis query "findings.high" file.pdf --compact) -gt 0 ]; then
  echo "High severity findings detected!"
fi
```

## Benefits

1. **Single tool**: Replace pdfinfo, mutool, pdftk, qpdf with one tool
2. **Consistent output**: JSON support across all queries
3. **Security-focused**: Built-in finding queries and risk assessment
4. **Fast**: No need to launch external processes
5. **Scriptable**: Designed for automation and pipelines
6. **Interactive**: REPL mode for exploration
7. **Composable**: Queries can be chained and filtered

## Alternatives Considered

### Alternative 1: Extend existing commands
- Problem: Each command has different output format
- Problem: No unified query language
- Problem: Hard to compose queries

### Alternative 2: SQL-like query language
- Problem: Too complex for simple queries
- Problem: Steep learning curve
- Problem: Overkill for metadata access

### Alternative 3: JQ-like path expressions
- Problem: Not intuitive for PDF-specific queries
- Problem: Requires learning JQ syntax
- Problem: Hard to extend with security-specific queries

## Success Metrics

1. **Adoption**: Users stop using pdfinfo/mutool for basic queries
2. **Coverage**: 90% of common PDF inspection tasks covered
3. **Performance**: <100ms for metadata queries, <1s for content queries
4. **Usability**: REPL session can replace 5-10 external tool invocations

## Future Extensions

1. **Query language extensions**: Support filters, sorting, grouping
2. **Custom output formats**: CSV, XML, custom templates
3. **Query scripts**: Save and run query scripts (`.sisq` files)
4. **Remote queries**: Query PDFs over HTTP/S3
5. **Comparative queries**: Compare two PDFs
6. **Temporal queries**: Query across incremental updates
7. **Aggregation**: Statistics across multiple PDFs

## Command Deprecation and Removal

Once the query interface is fully implemented, several existing clap CLI commands can be deprecated and removed to simplify the CLI surface and reduce maintenance burden.

### Commands to REMOVE (Replaced by Query Interface)

These commands duplicate functionality that will be provided by `sis query`:

1. **`sis explain FINDING_ID FILE`** → **`sis query explain FINDING_ID FILE`**
   - Current: Explain a specific finding with evidence details
   - Replacement: Query interface with explain query
   - Timeline: Remove in Phase 4 (Finding Queries)

2. **`sis extract js FILE`** → **`sis query js FILE [--out FILE]`**
   - Current: Extract JavaScript from PDF
   - Replacement: `sis query js FILE` or `sis query js FILE > output.js`
   - Timeline: Remove in Phase 2 (Content Queries)

3. **`sis extract embedded FILE`** → **`sis query embedded FILE [--out DIR]`**
   - Current: Extract embedded files from PDF
   - Replacement: `sis query embedded FILE` or `sis query embedded FILE --extract-to DIR`
   - Timeline: Remove in Phase 2 (Content Queries)

4. **`sis export-graph FILE`** → **`sis query chains FILE [--format dot|json]`**
   - Current: Export action chains as DOT or JSON
   - Replacement: Query interface with chains query
   - Timeline: Remove in Phase 6 (Advanced Queries)

5. **`sis export-org FILE`** → **`sis query graph FILE [--format dot|json]`**
   - Current: Export object reference graph with suspicious paths
   - Replacement: Query interface with graph query
   - Timeline: Remove in Phase 6 (Advanced Queries)

6. **`sis export-ir FILE`** → **`sis query ir FILE [--format text|json]`**
   - Current: Export enhanced IR with findings and risk scores
   - Replacement: Query interface with IR query
   - Timeline: Remove in Phase 6 (Advanced Queries)

7. **`sis export-features FILE`** → **`sis query features FILE [--extended]`**
   - Current: Export extended 333-feature vectors for ML pipelines
   - Replacement: Query interface with features query
   - Timeline: Remove in Phase 6 (Advanced Queries)

### Commands to DEPRECATE (Redundant with Scan + Query)

These commands have overlapping functionality with `sis scan` and `sis query`:

1. **`sis detect --findings KIND FILE`** → **`sis query "findings.kind KIND" FILE`**
   - Current: Detect files that contain specific findings
   - Replacement: Use scan with JSON output + jq, or query interface
   - Rationale: Specialized command that can be replaced by filtering
   - Timeline: Deprecate in Phase 4, remove in future major version

2. **`sis report FILE`** → **`sis scan FILE [--json] | sis query ... | formatter`**
   - Current: Generate a full Markdown report for a PDF scan
   - Replacement: Combine scan output with query interface and formatting
   - Rationale: Report generation can be external to core tool
   - Timeline: Deprecate in Phase 4, remove in future major version
   - Note: Consider keeping if users heavily rely on Markdown reports

### Commands to KEEP (Core Functionality)

These commands provide specialized functionality not duplicated by query interface:

1. **`sis config`** - Configuration management (init, verify)
2. **`sis ml`** - ML runtime management (health, detect, configure, download)
3. **`sis update`** - Self-update functionality
4. **`sis scan`** - Primary scanning command (core functionality)
5. **`sis sandbox`** - Dynamic sandbox evaluation (specialized analysis)
6. **`sis stream-analyze`** - Stream chunking and early termination (specialized)
7. **`sis campaign-correlate`** - Cross-document correlation (specialized)
8. **`sis response-generate`** - YARA rule generation (specialized)
9. **`sis compute-baseline`** - Baseline computation (ML workflow)
10. **`sis mutate`** - Mutation testing (red-team workflow)
11. **`sis red-team`** - Evasion testing (red-team workflow)

### Migration Path

**Phase 1: Add Query Interface (v0.x)**
- Implement `sis query` command with all functionality
- Keep existing commands for backwards compatibility
- Add deprecation warnings to commands that will be removed

**Phase 2: Deprecation Period (v1.x)**
- Mark commands for removal with `#[deprecated]` or runtime warnings
- Update documentation to recommend query interface
- Provide migration examples in changelog
- Keep deprecated commands for at least one minor version

**Phase 3: Removal (v2.0)**
- Remove deprecated commands in next major version
- Update all documentation and examples
- Provide migration guide for users

### Example Deprecation Warnings

```rust
#[command(about = "Extract JavaScript or embedded files from a PDF")]
#[deprecated(since = "1.5.0", note = "Use `sis query js` or `sis query embedded` instead")]
Extract { ... }
```

Runtime warning:
```
Warning: `sis extract` is deprecated and will be removed in v2.0.
Use `sis query js FILE` or `sis query embedded FILE` instead.
Run `sis query --help` for more information.
```

### CLI Structure After Cleanup

```
sis
├── config      - Configuration management
├── ml          - ML runtime management
├── update      - Self-update
├── scan        - Scan PDFs for findings
├── query       - Query PDF structure and content (NEW - replaces 7 commands)
├── sandbox     - Dynamic sandbox evaluation
├── stream-analyze      - Stream analysis
├── campaign-correlate  - Cross-document correlation
├── response-generate   - YARA generation
├── compute-baseline    - Baseline computation
├── mutate      - Mutation testing
└── red-team    - Evasion testing
```

**Before: 21 commands**
**After: 12 commands** (43% reduction in CLI surface)

### Benefits of Consolidation

1. **Simpler CLI**: Users learn one query interface instead of many commands
2. **Consistent UX**: All queries use same syntax and output format
3. **Reduced maintenance**: Fewer commands to maintain and test
4. **Better composability**: Query interface designed for piping and filtering
5. **Easier documentation**: One comprehensive query guide instead of many command docs

### Risks and Mitigation

**Risk**: Breaking changes for existing users and scripts
**Mitigation**: Long deprecation period (6-12 months), clear migration guide, runtime warnings

**Risk**: Loss of specialized functionality
**Mitigation**: Ensure query interface has feature parity before removal

**Risk**: Performance regression from unified interface
**Mitigation**: Benchmark query interface against existing commands, optimize hot paths

## Related Plans

- `20260110-graph-query.md` - Graph query console (more advanced, graph-focused)
- This plan focuses on simple, scriptable queries for common PDF inspection tasks
- Graph query console is for interactive exploration of object graphs and chains
- This plan is for replacing pdfinfo/mutool/qpdf in scripts and workflows

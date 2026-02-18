# IR and ORG Graph Documentation

## Current graph query surface

Use the query interface for graph exports:

```bash
sis query sample.pdf org --format dot
sis query sample.pdf graph.structure --format json
sis query sample.pdf "graph.structure.depth 3" --format json
sis query sample.pdf graph.event --format json
```

- `org` remains the legacy object-reference graph export.
- `graph.structure` keeps ORG semantics and adds typed edge statistics plus action-path helpers.
- `graph.event` is the connected event/outcome graph used by the GUI event mode.
- `graph.action` remains a compatibility alias of `graph.event` in `v1.x`; new integrations should use `graph.event`.

## Overview

sis-pdf provides two complementary representations of PDF structure:

- **IR (Intermediate Representation)**: A line-by-line breakdown of PDF objects showing their internal structure, dictionary keys, values, and deviations from spec
- **ORG (Object Reference Graph)**: A graph representation showing relationships between PDF objects via references

Both formats support **enhanced modes** that enrich the base representation with security-relevant metadata, risk scores, and natural language explanations.

---

## IR (Intermediate Representation)

### Purpose

IR provides a human-readable, line-oriented view of PDF objects. Each object is decomposed into its constituent parts (dictionary entries, stream metadata, array elements) for detailed inspection.

### Basic IR Structure

```rust
pub struct PdfIrObject {
    pub obj_ref: (u32, u16),           // Object ID and generation
    pub lines: Vec<PdfIrLine>,         // Decomposed object structure
    pub deviations: Vec<String>,       // Spec violations
}

pub struct PdfIrLine {
    pub obj_ref: (u32, u16),
    pub path: String,                   // Path in object tree (e.g., "$.Type", "$.Kids[0]")
    pub value_type: String,             // Type: name, string, array, dict, stream, etc.
    pub value: String,                  // String representation of value
}
```

### Basic IR Example

```
# 1 0
$, dict, -
$.Type, name, /Page
$.Parent, ref, 2 0 R
$.Kids, array, [3 items]
$.Kids[0], ref, 3 0 R
$.Kids[1], ref, 4 0 R
$.Kids[2], ref, 5 0 R
```

### Export Formats

**JSON**:
```bash
sis export-ir document.pdf --format json -o ir.json
```

**Text** (human-readable):
```bash
sis export-ir document.pdf --format text -o ir.txt
```

---

## Enhanced IR with Semantic Annotations

### Purpose

Enhanced IR augments basic IR with security findings, risk scores, and explanations at both the object and document level.

### Structure

```rust
pub struct EnhancedPdfIrObject {
    // Basic IR fields
    pub obj_ref: (u32, u16),
    pub lines: Vec<IrLineRef>,
    pub deviations: Vec<String>,

    // NEW: Security annotations
    pub findings: Vec<IrFindingSummary>,      // Findings for this object
    pub attack_surfaces: Vec<String>,         // Attack surfaces present
    pub max_severity: Option<String>,         // Highest severity level
    pub risk_score: f32,                      // Computed risk (0.0-1.0)
    pub explanation: Option<String>,          // Natural language summary
}

pub struct IrFindingSummary {
    pub kind: String,                         // e.g., "js_eval", "xref_conflict"
    pub severity: String,                     // Critical, High, Medium, Low, Info
    pub confidence: String,                   // Strong, Probable, Heuristic
    pub surface: String,                      // Attack surface category
    pub signals: HashMap<String, Value>,      // Metadata signals
}

pub struct EnhancedIrExport {
    pub objects: Vec<EnhancedPdfIrObject>,
    pub document_summary: DocumentSummary,    // Aggregated statistics
}

pub struct DocumentSummary {
    pub total_objects: usize,
    pub objects_with_findings: usize,
    pub max_object_risk: f32,
    pub attack_surface_diversity: usize,
    pub explanation: String,                  // Document-level explanation
    pub severity_counts: HashMap<String, usize>,
    pub surface_counts: HashMap<String, usize>,
}
```

### Risk Scoring

**Object Risk Score** (0.0 - 1.0):
```rust
risk = (severity_weight * confidence_mult) / finding_count

severity_weight = sum of:
  - Critical: 1.0
  - High:     0.8
  - Medium:   0.5
  - Low:      0.2
  - Info:     0.0

confidence_mult = average of:
  - Strong:     1.0
  - Probable:   0.7
  - Heuristic:  0.4
```

### Natural Language Explanations

**Object-level**:
```
Object contains 1 critical issue, 2 high severity issues.
Attack surfaces: JavaScript, Actions
```

**Document-level**:
```
Document contains 50 objects, 12 with findings (high risk).
3 critical, 8 high, 15 medium with findings.
Primary attack surfaces: JavaScript (15), Actions (8), FileStructure (5)
```

### Enhanced IR Export

**JSON with full metadata**:
```bash
sis export-ir malicious.pdf --enhanced --format json -o enhanced_ir.json
```

**Text format** (human-readable summary):
```bash
sis export-ir malicious.pdf --enhanced --format text -o enhanced_ir.txt
```

### Example Enhanced IR Output

```json
{
  "objects": [
    {
      "obj_ref": [7, 0],
      "lines": [
        {
          "path": "$.Type",
          "value_type": "name",
          "value": "/Action"
        },
        {
          "path": "$.S",
          "value_type": "name",
          "value": "/JavaScript"
        }
      ],
      "deviations": [],
      "findings": [
        {
          "kind": "js_eval",
          "severity": "High",
          "confidence": "Strong",
          "surface": "JavaScript",
          "signals": {
            "js.obfuscation_score": 0.85,
            "js.eval_count": 3
          }
        }
      ],
      "attack_surfaces": ["JavaScript"],
      "max_severity": "High",
      "risk_score": 0.8,
      "explanation": "Object contains 1 high severity issue. Attack surfaces: JavaScript"
    }
  ],
  "document_summary": {
    "total_objects": 45,
    "objects_with_findings": 3,
    "max_object_risk": 0.8,
    "attack_surface_diversity": 2,
    "explanation": "Document contains 45 objects, 3 with findings (moderate risk). 1 high with findings. Primary attack surfaces: JavaScript (1), Actions (2)",
    "severity_counts": {
      "High": 1,
      "Medium": 2
    },
    "surface_counts": {
      "JavaScript": 1,
      "Actions": 2
    }
  }
}
```

### Use Cases

1. **Triage**: Quickly identify high-risk objects
2. **Investigation**: Understand what makes an object suspicious
3. **Reporting**: Generate human-readable summaries
4. **ML Training**: Extract labeled examples for model training
5. **SIEM Integration**: Export structured findings to security tools

---

## ORG (Object Reference Graph)

### Purpose

ORG represents the PDF as a directed graph where:
- **Nodes** = PDF objects
- **Edges** = References between objects (dictionary references, array elements, etc.)

This reveals structural patterns, action chains, and reference relationships.

### Structure graph JSON additions

`graph.structure --format json` returns:

- `type: "structure_graph"`
- `org`: the ORG export payload
- `typed_edges`: aggregate typed-edge statistics
- `action_paths`: action-chain summary counters
- `path_helpers`:
  - `max_depth`
  - `reachable_from_trigger`
  - `paths_to_outcome`
  - `next_action_branches` (`/Next` branch index and source kind metadata)

### Event graph schema summary

`graph.event --format json` returns schema version `1.0` and a connected graph with:

- `nodes`: object, event, outcome, and collapse nodes
- `edges`: structural, trigger, execute, outcome, and collapsed structural links
- `node_index`, `forward_index`, `reverse_index`: stable lookup indices
- `truncation` (optional): cap metadata when node/edge limits are reached

### Basic ORG Structure

```rust
pub struct OrgGraph {
    pub nodes: Vec<ObjRef>,                        // All objects in graph
    pub adjacency: HashMap<ObjRef, Vec<ObjRef>>,   // Reference relationships

    // Enhanced data (optional)
    pub enhanced_nodes: Option<Vec<OrgNode>>,
    pub enhanced_edges: Option<Vec<OrgEdge>>,
}

pub struct ObjRef {
    pub obj: u32,
    pub gen: u16,
}
```

### Enhanced ORG Structure

```rust
pub struct OrgNode {
    pub obj_ref: ObjRef,
    pub obj_type: Option<String>,    // Catalog, Page, Action, Stream, etc.
    pub roles: Vec<String>,          // Semantic roles (trigger, payload, etc.)
}

pub struct OrgEdge {
    pub from: ObjRef,
    pub to: ObjRef,
    pub edge_type: Option<String>,   // OpenAction, JavaScript, Reference, etc.
    pub suspicious: bool,            // Flagged as suspicious
}
```

### Export Formats

**JSON**:
```bash
sis export-org document.pdf --format json -o org.json
```

**DOT** (Graphviz):
```bash
sis export-org document.pdf --format dot -o org.dot
dot -Tpng org.dot -o org.png
```

**Enhanced with classifications**:
```bash
sis export-org document.pdf --enhanced --format json -o org_enhanced.json
```

### Example ORG JSON

```json
{
  "nodes": ["1 0", "2 0", "3 0", "4 0"],
  "edges": [
    {
      "from": "1 0",
      "to": "2 0",
      "type": "OpenAction",
      "suspicious": true
    },
    {
      "from": "2 0",
      "to": "3 0",
      "type": "JavaScriptPayload",
      "suspicious": true
    }
  ],
  "enhanced": true
}
```

---

## ORG with Suspicious Paths

### Purpose

Combines ORG graph structure with analysis of suspicious execution paths (action chains).

### Structure

```rust
pub struct OrgExportWithPaths {
    pub org: OrgGraph,                              // Graph structure
    pub paths: Option<GraphPathExplanation>,        // Path analysis
}

pub struct GraphPathExplanation {
    pub suspicious_paths: Vec<SuspiciousPath>,      // Top 10 suspicious paths
    pub max_path_risk: f32,                         // Highest risk score
    pub avg_path_risk: f32,                         // Average risk score
}

pub struct SuspiciousPath {
    pub path: Vec<PathNode>,                        // Sequence of objects
    pub risk_score: f32,                            // Computed risk (0.0-1.0)
    pub explanation: String,                        // Natural language
    pub attack_pattern: Option<String>,             // Classified pattern
}

pub struct PathNode {
    pub obj_ref: (u32, u16),
    pub node_type: String,                          // Catalog, JavaScript, URI, etc.
    pub edge_to_next: Option<EdgeInfo>,
    pub findings: Vec<String>,                      // Finding kinds at this node
}

pub struct EdgeInfo {
    pub edge_type: String,                          // OpenAction, JavaScriptPayload, etc.
    pub key: String,                                // Dictionary key or event
    pub suspicious: bool,
}
```

### Path Risk Scoring

**Path Risk Score** (0.0 - 1.0):
```rust
risk = base_risk + finding_risk + edge_risk + length_bonus

base_risk:
  - Automatic trigger:  +0.3
  - Involves JS:        +0.4
  - External action:    +0.3

finding_risk (per node):
  - Critical finding:   +0.2
  - High finding:       +0.15
  - Medium finding:     +0.08
  - Low finding:        +0.03

edge_risk:
  - Per suspicious edge: +0.1

length_bonus:
  - Per node beyond 2:  +0.05
```

### Attack Patterns

**Classified Patterns**:
1. `automatic_js_with_external_action` - Auto-execute JS + external connection
2. `automatic_js_trigger` - Auto-execute JS via OpenAction
3. `js_to_external_resource` - JS triggers external resource
4. `automatic_external_action` - Auto-execute external action
5. `automatic_js_chain` - Multi-stage automatic JS chain
6. `automatic_action_chain` - Multi-stage automatic action
7. `js_external_chain` - Combined JS + external actions

### Export with Paths

```bash
# Export ORG with path analysis
sis export-org malicious.pdf --with-paths --format json -o org_with_paths.json
```

### Example ORG with Paths

```json
{
  "org": {
    "nodes": ["1 0", "2 0", "3 0"],
    "edges": [
      {"from": "1 0", "to": "2 0", "type": "OpenAction", "suspicious": true},
      {"from": "2 0", "to": "3 0", "type": "JavaScriptPayload", "suspicious": true}
    ]
  },
  "suspicious_paths": {
    "suspicious_paths": [
      {
        "path": [
          {
            "obj_ref": [1, 0],
            "node_type": "Catalog",
            "edge_to_next": {
              "edge_type": "OpenAction",
              "key": "/OpenAction",
              "suspicious": true
            },
            "findings": []
          },
          {
            "obj_ref": [2, 0],
            "node_type": "Action",
            "edge_to_next": {
              "edge_type": "JavaScriptPayload",
              "key": "/JS",
              "suspicious": true
            },
            "findings": ["aa_openaction"]
          },
          {
            "obj_ref": [3, 0],
            "node_type": "JavaScript",
            "edge_to_next": null,
            "findings": ["js_eval", "js_obfuscated"]
          }
        ],
        "risk_score": 0.95,
        "explanation": "Path from object 1 0 through 3 objects: Automatic JavaScript execution via OpenAction (3 findings)",
        "attack_pattern": "automatic_js_trigger"
      }
    ],
    "max_path_risk": 0.95,
    "avg_path_risk": 0.95
  }
}
```

---

## Integration and Use Cases

### IR + ORG Combined Analysis

```rust
// Generate both representations
let ir_objects = ir_for_graph(&entries, &opts);
let org_graph = OrgGraph::from_object_graph(&graph);

// Enhance with findings
let enhanced_ir = generate_enhanced_ir_export(&ir_objects, &findings);
let org_with_paths = OrgExportWithPaths::enhanced(org_graph, path_explanation);

// Export
let ir_json = export_enhanced_ir_json(&enhanced_ir);
let org_json = export_org_with_paths_json(&org_with_paths);
```

### Use Case: Malware Analysis Workflow

1. **Run scanner**: `sis scan malicious.pdf`
2. **Export enhanced IR**: See which objects are suspicious
3. **Export ORG with paths**: Understand attack chains
4. **Correlate**: Match high-risk IR objects with path nodes
5. **Report**: Generate analyst-friendly explanation

### Use Case: ML Dataset Generation

```python
# Extract enhanced IR for training data
enhanced_ir = json.load(open('enhanced_ir.json'))

features = []
labels = []

for obj in enhanced_ir['objects']:
    # Extract features from IR lines
    feature_vector = extract_ir_features(obj['lines'])

    # Label from risk score and findings
    label = 1 if obj['risk_score'] > 0.5 else 0

    features.append(feature_vector)
    labels.append(label)

# Train model
model.fit(features, labels)
```

### Use Case: Threat Intelligence

```python
# Analyze path patterns across corpus
patterns = Counter()

for sample in malicious_corpus:
    org_paths = json.load(open(f'{sample}_org_paths.json'))

    for path in org_paths['suspicious_paths']['suspicious_paths']:
        if path['attack_pattern']:
            patterns[path['attack_pattern']] += 1

# Most common attack patterns
print(patterns.most_common(10))
# [('automatic_js_trigger', 1247),
#  ('js_to_external_resource', 892),
#  ('automatic_js_with_external_action', 456), ...]
```

---

## Implementation Details

### Module Structure

```
crates/sis-pdf-core/src/
├── ir_enhanced.rs          # Enhanced IR structures and logic
├── ir_export.rs            # IR export functions
├── org.rs                  # ORG graph construction
├── org_export.rs           # ORG export functions
└── explainability.rs       # Path analysis and explanations
```

### Key Functions

**IR Generation**:
- `ir_for_object()` - Generate IR for single object
- `ir_for_graph()` - Generate IR for all objects
- `convert_to_enhanced_ir()` - Add findings to IR object
- `generate_enhanced_ir_export()` - Create full enhanced export

**ORG Generation**:
- `OrgGraph::from_object_graph()` - Build basic ORG
- `OrgGraph::from_object_graph_enhanced()` - Build with classifications
- `PathFinder::find_all_action_chains()` - Extract action chains
- `extract_suspicious_paths()` - Analyze and score paths

**Export**:
- `export_ir_json()` / `export_ir_text()` - Basic IR
- `export_enhanced_ir_json()` / `export_enhanced_ir_text()` - Enhanced IR
- `export_org_json()` / `export_org_dot()` - Basic ORG
- `export_org_with_paths_json()` - ORG with paths

### Performance Characteristics

**IR Generation**:
- Time: O(n × m) where n = objects, m = avg object complexity
- Space: O(n × k) where k = avg lines per object
- Typical: ~50ms for 1000 objects

**ORG Generation**:
- Time: O(n + e) where e = edges
- Space: O(n + e)
- Typical: ~20ms for 1000 objects, 5000 edges

**Path Analysis**:
- Time: O(c × d) where c = chains, d = max chain depth
- Space: O(c × d)
- Typical: ~10ms for 50 action chains

---

## Future Enhancements

### Planned Features

1. **Interactive visualization**: Web-based ORG graph explorer
2. **Diff mode**: Compare IR/ORG between document versions
3. **Query language**: SQL-like queries over ORG graph
4. **STIX export**: Threat intelligence format
5. **Jupyter integration**: Interactive analysis notebooks

### Experimental Features

- **GNN scoring**: Graph neural network risk scores for nodes
- **Temporal analysis**: Track pattern evolution over time
- **Cross-document linking**: Cluster similar attack patterns
- **Automated reporting**: Generate analyst reports from IR+ORG

---

## References

- PDF Specification: ISO 32000-2:2020
- Action chains: See `crates/sis-pdf-pdf/src/path_finder.rs`
- TypedGraph: See `crates/sis-pdf-pdf/src/typed_graph.rs`
- Finding model: See `crates/sis-pdf-core/src/model.rs`

---

## See Also

- [ML Signals Plan](../NEXT_STEPS.md)
- [Risk Profiling and Calibration](risk-profiling.md)
- [Finding Specifications](findings.md)
- [Analysis Documentation](analysis.md)

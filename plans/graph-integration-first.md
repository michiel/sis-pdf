# Graph-First Integration Plan

## Strategic Vision

**Core Principle**: Build a strong foundation of integrated IR/ORG capabilities and object graph analysis BEFORE extending ML signals. This creates a better platform that naturally produces richer signals for ML and improves all detectors.

## Problem Statement

### Current Architecture Issues

1. **IR/ORG are Isolated**:
   - Primarily used for export (`export-ir`, `export-org`)
   - Not leveraged by detectors during scanning
   - Graph analysis happens ad-hoc in individual detectors

2. **Duplicated Graph Walking**:
   - `external_context`: Walks action chains manually
   - `uri_classification`: Resolves references manually
   - `supply_chain`: Traces object relationships manually
   - `js_detectors`: Resolve payload references manually
   - Each implements similar reference-following logic

3. **Limited Reference Tracking**:
   - `ObjectGraph.get_object()` only does direct lookup
   - No pre-computed reference chains
   - No reverse reference index (what points to this object?)
   - No typed edges (OpenAction, JS, URI, etc.)

4. **Missing Object Classification**:
   - Objects not categorized by type (catalog, page, action, stream)
   - No pre-computed attack surface mapping
   - Detectors must determine object role repeatedly

5. **No Path/Chain Analysis**:
   - Can't easily find "all paths from Catalog to JavaScript"
   - No propagation of suspiciousness through graph
   - Hard to detect multi-stage attack chains

### Impact on ML

Current ML uses basic IR/ORG that lacks:
- Object type information
- Reference chain context
- Attack surface propagation
- Relationship semantics

Improving these creates richer ML signals automatically.

## Proposed Architecture

### Phase 1: Enhanced Object Graph Core (Foundation)

**Goal**: Make `ObjectGraph` a rich, queryable structure used throughout the codebase.

#### 1.1: Object Classification

Add type information to every object:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfObjectType {
    Catalog,
    Pages,
    Page,
    Action,
    Annotation,
    Font,
    Image,
    Stream,
    ObjStm,
    Dict,
    Array,
    Other,
}

pub struct ClassifiedObject<'a> {
    pub entry: &'a ObjEntry<'a>,
    pub obj_type: PdfObjectType,
    pub roles: Vec<ObjectRole>,  // e.g., ["js_container", "action_target"]
}

pub enum ObjectRole {
    JsContainer,
    ActionTarget,
    EmbeddedFile,
    UriTarget,
    FormField,
    PageContent,
}

impl<'a> ObjectGraph<'a> {
    pub fn classify_objects(&self) -> HashMap<(u32, u16), ClassifiedObject<'a>> {
        // Classify each object by examining its dictionary
    }

    pub fn get_classified(&self, obj: u32, gen: u16) -> Option<&ClassifiedObject<'a>> {
        // Get object with type information
    }
}
```

**Benefits**:
- Detectors know object type immediately
- Can filter objects by type/role
- Attack surface mapping is automatic

#### 1.2: Typed Reference Graph

Track not just edges, but edge types and semantics:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeType {
    // Structural references
    DictReference { key: String },      // Generic /Key -> obj reference
    ArrayElement { index: usize },      // Array element reference

    // Semantic references
    OpenAction,                         // Catalog /OpenAction
    PageAction { event: String },       // Page /AA with event type
    AnnotationAction,                   // Annot /A
    JavaScriptPayload,                  // /JS or /JavaScript
    UriTarget,                          // /URI
    LaunchTarget,                       // /F in Launch action
    SubmitFormTarget,                   // /F in SubmitForm
    EmbeddedFileRef,                    // /EmbeddedFile reference
    FontReference,                      // /Font reference
    PageReference,                      // /Pages tree
    ObjStmReference,                    // Object from ObjStm
}

#[derive(Debug, Clone)]
pub struct TypedEdge {
    pub src: (u32, u16),
    pub dst: (u32, u16),
    pub edge_type: EdgeType,
    pub suspicious: bool,               // Heuristic: is this edge suspicious?
}

pub struct TypedGraph<'a> {
    pub objects: &'a ObjectGraph<'a>,
    pub edges: Vec<TypedEdge>,
    pub forward_index: HashMap<(u32, u16), Vec<usize>>,   // obj -> outgoing edges
    pub reverse_index: HashMap<(u32, u16), Vec<usize>>,   // obj -> incoming edges
}

impl<'a> TypedGraph<'a> {
    pub fn build(graph: &'a ObjectGraph<'a>) -> Self {
        // Walk all objects, extract typed references
    }

    pub fn outgoing_edges(&self, obj: u32, gen: u16) -> &[TypedEdge] {
        // All edges from this object
    }

    pub fn incoming_edges(&self, obj: u32, gen: u16) -> &[TypedEdge] {
        // All edges TO this object (reverse references)
    }

    pub fn edges_of_type(&self, edge_type: EdgeType) -> Vec<&TypedEdge> {
        // All edges of a specific type (e.g., all JavaScriptPayload edges)
    }

    pub fn suspicious_edges(&self) -> Vec<&TypedEdge> {
        // All edges marked as suspicious
    }
}
```

**Benefits**:
- Know WHY objects are connected, not just that they are
- Can query "all JavaScript payload references"
- Reverse index enables "what points to this object?"
- Suspiciousness scoring on edges

#### 1.3: Path and Chain Analysis

Add graph traversal utilities:

```rust
pub struct PathFinder<'a> {
    graph: &'a TypedGraph<'a>,
}

impl<'a> PathFinder<'a> {
    pub fn find_paths(
        &self,
        from: (u32, u16),
        to: (u32, u16),
        max_depth: usize,
    ) -> Vec<Vec<&'a TypedEdge>> {
        // Find all paths from 'from' to 'to'
    }

    pub fn find_action_chains(&self, from: (u32, u16)) -> Vec<ActionChain<'a>> {
        // Find action execution chains (OpenAction -> JS -> URI, etc.)
    }

    pub fn find_reachable_with_type(
        &self,
        from: (u32, u16),
        edge_types: &[EdgeType],
    ) -> HashSet<(u32, u16)> {
        // Find all objects reachable via specific edge types
    }

    pub fn find_javascript_sources(&self) -> Vec<(u32, u16)> {
        // All objects that can trigger JavaScript
    }

    pub fn propagate_suspiciousness(&self) -> HashMap<(u32, u16), f32> {
        // Propagate suspiciousness scores through graph
    }
}

pub struct ActionChain<'a> {
    pub trigger: TriggerType,
    pub edges: Vec<&'a TypedEdge>,
    pub payload: Option<(u32, u16)>,
    pub automatic: bool,
}

pub enum TriggerType {
    OpenAction,
    PageOpen,
    Annotation,
    FormField,
}
```

**Benefits**:
- Detect multi-stage attacks automatically
- Trace execution paths (OpenAction → AA → JS → URI)
- Propagate risk scores through reference chains
- Identify all JS entry points in one query

### Phase 2: Integrated IR/ORG Generation

**Goal**: Generate IR/ORG during normal scan, not just on export.

#### 2.1: IR as First-Class Scan Artifact

Move IR from export-only to core scanning:

```rust
pub struct ScanContext<'a> {
    pub bytes: &'a [u8],
    pub graph: Arc<ObjectGraph<'a>>,
    pub decoded: Arc<DecodedCache>,
    pub options: &'a ScanOptions,

    // New: Pre-computed IR
    pub ir: Arc<Vec<PdfIrObject>>,

    // New: Pre-computed typed graph
    pub typed_graph: Arc<TypedGraph<'a>>,

    // New: Pre-computed classifications
    pub classifications: Arc<HashMap<(u32, u16), ClassifiedObject<'a>>>,
}

impl<'a> ScanContext<'a> {
    pub fn new(bytes: &'a [u8], options: &'a ScanOptions) -> Result<Self> {
        // Parse PDF
        let graph = parse_pdf(bytes, options.parse_options)?;

        // Classify objects
        let classifications = graph.classify_objects();

        // Build typed graph
        let typed_graph = TypedGraph::build(&graph);

        // Generate IR (if enabled)
        let ir = if options.enable_ir {
            ir_for_graph(&graph.objects, &IrOptions::default())
        } else {
            Vec::new()
        };

        Ok(Self {
            bytes,
            graph: Arc::new(graph),
            decoded: Arc::new(DecodedCache::new()),
            options,
            ir: Arc::new(ir),
            typed_graph: Arc::new(typed_graph),
            classifications: Arc::new(classifications),
        })
    }
}
```

**Benefits**:
- All detectors can use IR without regenerating it
- IR is cached for ML inference
- Consistent IR generation across all code paths

#### 2.2: Enhanced IR with Graph Context

Augment IR lines with graph context:

```rust
#[derive(Debug, Clone)]
pub struct EnhancedPdfIrLine {
    pub obj_ref: (u32, u16),
    pub path: String,
    pub value_type: String,
    pub value: String,

    // New: Graph context
    pub object_type: PdfObjectType,
    pub roles: Vec<ObjectRole>,
    pub incoming_edge_types: Vec<EdgeType>,
    pub outgoing_edge_types: Vec<EdgeType>,
    pub is_reachable_from_catalog: bool,
}

pub fn enhanced_ir_for_object(
    entry: &ObjEntry<'_>,
    typed_graph: &TypedGraph<'_>,
    classifications: &HashMap<(u32, u16), ClassifiedObject<'_>>,
    opts: &IrOptions,
) -> PdfIrObject {
    // Generate basic IR
    let mut basic_ir = ir_for_object(entry, opts);

    // Enhance each line with graph context
    let obj_ref = (entry.obj, entry.gen);
    let classification = classifications.get(&obj_ref);
    let incoming = typed_graph.incoming_edges(entry.obj, entry.gen);
    let outgoing = typed_graph.outgoing_edges(entry.obj, entry.gen);

    for line in &mut basic_ir.lines {
        line.object_type = classification.map(|c| c.obj_type);
        line.roles = classification.map(|c| c.roles.clone()).unwrap_or_default();
        line.incoming_edge_types = incoming.iter().map(|e| e.edge_type.clone()).collect();
        line.outgoing_edge_types = outgoing.iter().map(|e| e.edge_type.clone()).collect();
        line.is_reachable_from_catalog = /* check reachability */;
    }

    basic_ir
}
```

**Benefits**:
- IR includes semantic information
- Object context is explicit
- ML models get richer input automatically

### Phase 3: Detector Refactoring (Use Graph Infrastructure)

**Goal**: Refactor detectors to use shared graph infrastructure instead of ad-hoc analysis.

#### 3.1: External Context Detector

**Before**:
```rust
// Manually walks action chains
fn analyze_action(ctx: &ScanContext, obj: &PdfObj) -> ActionDetails {
    // Custom graph walking logic
}
```

**After**:
```rust
fn analyze_action(ctx: &ScanContext, obj_ref: (u32, u16)) -> ActionDetails {
    // Use pre-computed action chains
    let chains = ctx.typed_graph.path_finder().find_action_chains(obj_ref);

    for chain in chains {
        // Chain analysis using typed edges
        if chain.automatic && has_javascript_in_chain(&chain) {
            // High risk
        }
    }
}
```

**Benefits**: No custom graph walking, uses shared infrastructure

#### 3.2: URI Classification Detector

**Before**:
```rust
// Manually resolves URI references
fn resolve_payload(ctx: &ScanContext, obj: &PdfObj) -> PayloadResult {
    // Custom reference resolution with cycle detection
}
```

**After**:
```rust
fn resolve_payload(ctx: &ScanContext, obj_ref: (u32, u16)) -> PayloadResult {
    // Use typed graph to find URI target
    let uri_edges = ctx.typed_graph.outgoing_edges_of_type(obj_ref, EdgeType::UriTarget);

    for edge in uri_edges {
        let payload_obj = ctx.graph.get_object(edge.dst.0, edge.dst.1)?;
        // Process payload
    }
}
```

**Benefits**: Simpler code, no cycle detection needed (handled by graph)

#### 3.3: Supply Chain Detector

**Before**:
```rust
// Manually traces object relationships
fn find_staged_payloads(ctx: &ScanContext) -> Vec<Finding> {
    // Custom multi-stage detection logic
}
```

**After**:
```rust
fn find_staged_payloads(ctx: &ScanContext) -> Vec<Finding> {
    // Use path finder to detect multi-stage chains
    let js_sources = ctx.typed_graph.path_finder().find_javascript_sources();

    for src in js_sources {
        let paths = ctx.typed_graph.path_finder().find_paths(
            (1, 0),  // Catalog
            src,
            10,      // max depth
        );

        // Analyze paths for staging patterns
        for path in paths {
            if is_staged_pattern(&path) {
                // Create finding
            }
        }
    }
}
```

**Benefits**: Leverages shared path finding, more consistent detection

#### 3.4: Multi-Stage Detector

**Before**:
```rust
// Ad-hoc multi-stage detection
```

**After**:
```rust
fn detect_multi_stage(ctx: &ScanContext) -> Vec<Finding> {
    // Use action chain analysis
    let all_chains = ctx.typed_graph.path_finder().find_all_action_chains();

    for chain in all_chains {
        if chain.edges.len() > 2 {  // Multi-stage
            if involves_javascript(&chain) && involves_external_action(&chain) {
                // High-confidence multi-stage attack
            }
        }
    }
}
```

### Phase 4: Enhanced ORG Export

**Goal**: Export the rich typed graph in a format suitable for ML.

#### 4.1: Enhanced ORG Schema

```json
{
  "schema_version": 2,
  "nodes": [
    {
      "id": 0,
      "obj": 1,
      "gen": 0,
      "type": "catalog",
      "roles": [],
      "reachable_from_root": true,
      "depth_from_root": 0
    },
    {
      "id": 1,
      "obj": 5,
      "gen": 0,
      "type": "action",
      "roles": ["js_container"],
      "reachable_from_root": true,
      "depth_from_root": 1
    }
  ],
  "edges": [
    {
      "src": 0,
      "dst": 1,
      "type": "OpenAction",
      "key": "/OpenAction",
      "suspicious": true,
      "weight": 1.0
    },
    {
      "src": 1,
      "dst": 2,
      "type": "JavaScriptPayload",
      "key": "/JS",
      "suspicious": true,
      "weight": 1.0
    }
  ],
  "attack_chains": [
    {
      "trigger": "OpenAction",
      "path": [0, 1, 2],
      "automatic": true,
      "involves_js": true,
      "involves_uri": false
    }
  ]
}
```

**Export Command**:
```bash
sis export-org malicious.pdf --enhanced --format json -o enhanced.json
```

### Phase 5: ML Signal Enhancement (Builds on Foundation)

**Goal**: Now that graph infrastructure is solid, extend ML signals.

#### 5.1: Graph-Enhanced Features

New features become trivial with graph infrastructure:

```rust
pub struct GraphEnhancedFeatures {
    // Attack chain features (easy with TypedGraph)
    pub action_chain_count: usize,
    pub max_action_chain_length: usize,
    pub automatic_action_chains: usize,
    pub js_action_chains: usize,
    pub multi_stage_chains: usize,

    // Reachability features (easy with PathFinder)
    pub js_reachable_from_catalog: bool,
    pub uri_reachable_from_openaction: bool,
    pub avg_depth_from_catalog: f32,

    // Edge type distribution (easy with TypedGraph)
    pub open_action_edges: usize,
    pub js_payload_edges: usize,
    pub uri_target_edges: usize,
    pub suspicious_edge_ratio: f32,

    // Object role features (easy with classifications)
    pub js_container_count: usize,
    pub action_target_count: usize,
    pub embedded_file_count: usize,

    // Propagated risk (easy with propagate_suspiciousness)
    pub max_propagated_risk: f32,
    pub avg_propagated_risk: f32,
}

pub fn extract_graph_features(ctx: &ScanContext) -> GraphEnhancedFeatures {
    let chains = ctx.typed_graph.path_finder().find_all_action_chains();
    let suspicious_scores = ctx.typed_graph.path_finder().propagate_suspiciousness();

    GraphEnhancedFeatures {
        action_chain_count: chains.len(),
        max_action_chain_length: chains.iter().map(|c| c.edges.len()).max().unwrap_or(0),
        automatic_action_chains: chains.iter().filter(|c| c.automatic).count(),
        // ... trivial to compute with infrastructure
    }
}
```

**Key Point**: These features were hard before, now they're trivial!

#### 5.2: Enhanced IR Automatically Includes Graph Info

Because IR generation is now integrated and includes graph context:

```json
{
  "obj_ref": [5, 0],
  "lines": [
    {
      "path": "$.S",
      "type": "name",
      "value": "/JavaScript",
      "object_type": "action",
      "roles": ["js_container"],
      "incoming_edge_types": ["OpenAction"],
      "is_reachable_from_catalog": true
    }
  ]
}
```

ML models automatically get richer context without code changes!

## Implementation Order

### Sprint 1: Object Classification (1 week)
- Implement `PdfObjectType` enum
- Implement `classify_objects()` function
- Add object roles
- Unit tests

### Sprint 2: Typed Reference Graph (2 weeks)
- Implement `EdgeType` enum
- Implement `TypedEdge` struct
- Build typed graph from ObjectGraph
- Implement forward/reverse indices
- Unit tests

### Sprint 3: Path Finding (1 week)
- Implement `PathFinder` struct
- Implement BFS/DFS traversals
- Implement action chain detection
- Implement reachability queries
- Unit tests

### Sprint 4: ScanContext Integration (1 week)
- Add typed_graph to ScanContext
- Add classifications to ScanContext
- Update all detector signatures
- Integration tests

### Sprint 5: Detector Refactoring (2 weeks)
- Refactor external_context detector
- Refactor uri_classification detector
- Refactor supply_chain detector
- Refactor multi_stage detector
- Remove duplicated graph walking code
- Integration tests

### Sprint 6: Enhanced ORG Export (1 week)
- Implement enhanced ORG schema
- Export typed edges
- Export attack chains
- Export classifications
- Tests with ML pipeline

### Sprint 7: ML Feature Enhancement (1 week)
- Implement graph-enhanced features
- Update IR generation with graph context
- Integration with ML pipeline
- Performance benchmarks

**Total**: ~9 weeks

## Benefits Summary

### For Detectors
- ✅ Less code duplication
- ✅ More consistent analysis
- ✅ Easier to implement new detectors
- ✅ Better performance (shared graph analysis)
- ✅ Automatic access to graph infrastructure

### For ML
- ✅ Richer IR/ORG automatically
- ✅ Trivial to add graph-based features
- ✅ Better context for embeddings
- ✅ More accurate GNN inputs

### For Codebase
- ✅ Cleaner architecture
- ✅ Centralized graph logic
- ✅ Easier to maintain
- ✅ Better test coverage

## Success Metrics

### Code Quality
- **Reduction in duplicated code**: Target 30-40% reduction
- **Lines of code in detectors**: Target 20-30% reduction
- **Test coverage**: Target 80%+ on graph code

### Performance
- **Graph building overhead**: < 5% of total scan time
- **Detector execution time**: 10-20% faster (shared analysis)

### Detection Quality
- **Consistency**: Same graph analysis across all detectors
- **Coverage**: All detectors use typed edges
- **Accuracy**: Better multi-stage detection

### ML Impact
- **Feature richness**: 50+ new graph-based features trivial to add
- **IR quality**: Automatic semantic annotations
- **Training data**: Richer ORG exports

## Implementation Status

### ✅ Sprint 1: Object Classification (Completed)
- **File**: `crates/sis-pdf-pdf/src/classification.rs` (450 lines)
- **Implemented**: 12 object types, 14 security roles
- **Tests**: 5 integration tests (all passing)
- **Status**: Complete

### ✅ Sprint 2: Typed Reference Graph (Completed)
- **File**: `crates/sis-pdf-pdf/src/typed_graph.rs` (680 lines)
- **Implemented**: 32 semantic edge types, forward/reverse indices
- **Tests**: 8 unit tests (all passing)
- **Status**: Complete

### ✅ Sprint 3: Path Finding (Completed)
- **File**: `crates/sis-pdf-pdf/src/path_finder.rs` (520 lines)
- **Implemented**: BFS/DFS, action chains, reachability, suspiciousness propagation
- **Tests**: 2 unit tests (all passing)
- **Status**: Complete

### ✅ Sprint 4: ScanContext Integration (Completed)
- **Modified Files**:
  - `crates/sis-pdf-core/src/scan.rs` - Added lazy-initialized classifications (OnceLock), build_typed_graph() method
  - `crates/sis-pdf-core/src/runner.rs` - Updated to use ScanContext::new()
  - `crates/sis-pdf-core/src/features.rs` - Updated to use ScanContext::new()
  - `crates/sis-pdf-core/src/content_index.rs` - Fixed lifetime parameters
- **Implementation Approach**:
  - `classifications`: Lazy-initialized with OnceLock (cached on first access)
  - `build_typed_graph()`: Builder pattern (not cached due to lifetime constraints)
  - Both use the `'a` lifetime from ScanContext<'a>
- **Documentation**: Comprehensive doc comments with usage examples
- **Tests**: All existing tests pass, manual scan verified
- **Status**: Complete

**Key Design Decision**: TypedGraph is built on-demand rather than cached due to Rust lifetime constraints. This is acceptable since graph building is fast and detectors typically only need it once per scan. Classifications are cached since they have simpler lifetimes and are accessed frequently.

### 🔄 Sprint 5: Detector Refactoring (Pending)
- **Target**: external_context, uri_classification, supply_chain, multi_stage detectors
- **Goal**: Remove duplicated graph walking, use TypedGraph and PathFinder

### 🔄 Sprint 6: Enhanced ORG Export (Pending)
- **Goal**: Include semantic edge types and classifications in ORG export

### 🔄 Sprint 7: ML Feature Enhancement (Pending)
- **Goal**: Add graph-based features to ML feature extraction

## Conclusion

By prioritizing graph infrastructure integration FIRST, we create a solid foundation that:
1. Improves all detectors immediately
2. Reduces code duplication and maintenance burden
3. Makes ML signal enhancement trivial
4. Provides better, more consistent analysis

This is the RIGHT order: **infrastructure → detectors → ML signals**

The alternative (ML signals first) would be building on a shaky foundation and missing opportunities for systematic improvement.

# Extended Graph Plan: Structure + Event + Outcomes

Date: 2026-02-18
Status: Planned
Scope: `crates/sis-pdf-pdf`, `crates/sis-pdf-core`, `crates/sis-pdf`, `crates/sis-pdf-gui`, docs/tests

## 1. Context and current state

The current graph capabilities are split:

1. **Structure graph (ORG / object graph)** exists and is object-reference driven.
   - Core export: `crates/sis-pdf-core/src/org_export.rs`
   - GUI rendering: `crates/sis-pdf-gui/src/graph_data.rs`, `crates/sis-pdf-gui/src/panels/graph.rs`
2. **Action graph** exists as a filtered view of the typed graph, separate from the structure graph.
   - `export_action_graph_json()`, `export_action_graph_dot()` in `crates/sis-pdf-core/src/org_export.rs`
   - Private `TriggerClass` enum (Automatic, Hidden, User) and `classify_action_edge()` for edge colouring.
   - Limitation: only exports edges, no outcome nodes, no collapse/connectivity logic.
3. **Event/trigger extraction** exists, but as a disconnected list output, not as a unified connected graph.
   - Query implementation: `extract_event_triggers` in `crates/sis-pdf/src/commands/query.rs`
   - Covers document (`/OpenAction`, catalog `/AA`), page (`/AA`), and field/widget (`/A`, `/AA`) events.
   - Missing: Link annotation actions, `/Next` chain traversal, delayed/independent events.
4. **Typed semantic edges** already exist and are rich enough to seed an event graph.
   - `EdgeType` includes 35+ semantic edge types in `crates/sis-pdf-pdf/src/typed_graph.rs`.
   - Structural (17): DictReference, ArrayElement, PagesKids, PageParent, PageContents, PageResources, PageAnnots, ObjStmReference, FormFieldKids, etc.
   - Semantic action (5): OpenAction, PageAction{event}, AnnotationAction, AdditionalAction{event}, FormFieldAction{event}.
   - `/Next` is currently represented as `DictReference { key: "/Next" }` and treated executable by `is_executable()`.
   - JavaScript (2): JavaScriptPayload, JavaScriptNames.
   - External action (4): UriTarget, LaunchTarget, SubmitFormTarget, GoToRTarget.
   - Content/Resource (4): EmbeddedFileRef, FontReference, XObjectReference, ExtGStateReference.
   - Crypto/Media (6): EncryptRef, SignatureRef, RichMediaRef, ThreeDRef, SoundRef, MovieRef.
   - Key methods: `is_suspicious()`, `is_executable()`, forward/reverse indices.
   - Current extraction gaps from implementation review:
     - `PageAction`, `FormFieldAction`, and `UriTarget` are defined but not emitted consistently by `EdgeExtractor`.
     - `/Next` branch arrays are traversed by detectors but not represented as first-class typed edges.
     - action detail semantics (`/N`, trigger initiation, target kind/value) are spread across detectors/query metadata and not unified in graph edges.
5. **Chain synthesis** currently emits singleton chains (one finding per chain), which is noisy.
   - `synthesise_chains` in `crates/sis-pdf-core/src/chain_synth.rs`
   - Creates a chain for every finding individually; no minimum cardinality filter.
6. **GUI graph panel** renders a single-mode object graph.
   - `GraphNode` is tightly coupled to PDF objects (`obj: u32, gen: u16, obj_type: String`).
   - `GraphEdge` carries only a `suspicious` flag, no typed edge information.
   - Interactions: pan, zoom, hover, click select, double-click navigate to object inspector.
   - Chain filter exists but only dims non-chain nodes; no event->outcome path highlighting.
   - `MAX_GRAPH_NODES = 2000` performance cap.

### 1.1 Disposition of existing action graph

The existing action graph exports (`export_action_graph_json`, `export_action_graph_dot`) in `org_export.rs` will be **superseded** by the new event graph. The event graph is a strict superset: it includes action edges plus event nodes, outcome nodes, and collapse semantics.

Migration path:
1. During development, both action graph and event graph exports coexist.
2. After Stage D (CLI integration), `graph.action` becomes an alias for `graph.event` with a filter preset (event and action edges only, no collapse).
3. The private `TriggerClass` enum moves to the new `event_graph` module as a public type and is re-exported for `org_export.rs` backward compatibility.
4. `export_action_graph_*` functions are deprecated in docs after Stage F.

## 2. Goals

1. Keep current ORG behaviour as the **Structure Graph**.
2. Introduce an **Event Graph** that is connected and includes:
   - structure objects,
   - event nodes (document/page/form/annotation/link/independent/delayed/rendering),
   - outcome nodes (network exfiltration, filesystem write, launch, submission, etc).
3. Remove chains with only one item from default outputs and GUI overlays.
4. Support chain overlay on the Event Graph.
5. Include all Structure Graph elements in Event Graph semantics, but collapse structure-only nodes not participating in event flow.
6. Provide equivalent capability in CLI and GUI.

## 3. Non-goals (first delivery)

1. No probabilistic causal inference engine; use deterministic graph construction.
2. No full timeline simulator of every PDF reader.
3. No breaking change to existing `org` queries; new graph modes are additive.

## 4. Proposed architecture

### 4.1 New graph model in core

Add a new core module: `crates/sis-pdf-core/src/event_graph.rs`.

#### 4.1.0 Schema types

```rust
/// Classification of the PDF event trigger.
/// Moved from org_export.rs private enum to public type.
pub enum TriggerClass {
    /// Fires without user interaction (e.g., /OpenAction, page /AA /O, /AA /V)
    Automatic,
    /// Fires from a non-obvious user action (e.g., hidden annotation click)
    Hidden,
    /// Fires from explicit user action (e.g., button click, field keystroke)
    User,
}

/// What kind of document event triggers action execution.
pub enum EventType {
    // Document-level
    DocumentOpen,       // /OpenAction
    DocumentWillClose,  // catalog /AA /WC
    DocumentWillSave,   // catalog /AA /WS
    DocumentDidSave,    // catalog /AA /DS
    DocumentWillPrint,  // catalog /AA /WP
    DocumentDidPrint,   // catalog /AA /DP

    // Page-level
    PageOpen,           // page /AA /O
    PageClose,          // page /AA /C
    PageVisible,        // page /AA /PV
    PageInvisible,      // page /AA /PI

    // Field/widget-level
    FieldKeystroke,     // field /AA /K
    FieldFormat,        // field /AA /F
    FieldValidate,      // field /AA /V
    FieldCalculate,     // field /AA /C
    FieldMouseDown,     // field /AA /D
    FieldMouseUp,       // field /AA /U
    FieldMouseEnter,    // field /AA /E
    FieldMouseExit,     // field /AA /X
    FieldOnFocus,       // field /AA /Fo
    FieldOnBlur,        // field /AA /Bl
    FieldActivation,    // field /A (direct action)

    // Annotation-level
    AnnotationActivation,   // annotation /A (Link, Widget, etc.)

    // Independent/delayed
    NextAction,         // /Next chain step
    JsTimerDelayed,     // setTimeout/setInterval detected in JS findings

    // Rendering
    ContentStreamExec,  // PageContents / XObject render-linked action
}

/// What observable effect an action chain produces.
pub enum OutcomeType {
    // Network
    NetworkEgress,      // UriTarget, SubmitFormTarget, JS network intent
    // Filesystem / system
    FilesystemWrite,    // JS file write/probe
    ExternalLaunch,     // LaunchTarget, GoToRTarget
    // Code execution
    CodeExecution,      // JS eval, shell exec, payload execution
    // Form submission
    FormSubmission,     // SubmitFormTarget, JS doc submit
    // Embedded payload
    EmbeddedPayload,    // EmbeddedFileRef access/extraction
}

/// Static MITRE ATT&CK technique mapping for event/outcome types.
/// Populated on nodes during graph construction (zero-cost static lookup).
pub fn mitre_techniques(event: &EventType) -> &'static [&'static str] { .. }
pub fn mitre_techniques_outcome(outcome: &OutcomeType) -> &'static [&'static str] { .. }
```

MITRE ATT&CK mapping table (static, embedded in binary):

| Type | ATT&CK Technique |
|---|---|
| `DocumentOpen` | T1204.002 (User Execution: Malicious File) |
| `FieldActivation`, `AnnotationActivation` | T1204.001 (User Execution: Malicious Link) |
| `JsTimerDelayed` | T1497.003 (Virtualization/Sandbox Evasion: Time Based) |
| `NetworkEgress` | T1071 (Application Layer Protocol) |
| `ExternalLaunch` | T1204.002 (User Execution: Malicious File) |
| `CodeExecution` via JS | T1059.007 (Command and Scripting Interpreter: JavaScript) |
| `FormSubmission` | T1056.003 (Input Capture: Web Portal Capture) |
| `EmbeddedPayload` | T1027.006 (Obfuscated Files: HTML Smuggling / Embedded Payloads) |

Nodes carry `mitre_techniques: Vec<&'static str>` populated at construction time.

```text (closing the schema section)
```

Primary node/edge model:

```rust
pub enum EventNodeKind {
    Object { obj: u32, gen: u16, obj_type: Option<String> },
    Event {
        event_type: EventType,
        trigger: TriggerClass,
        label: String,
        source_obj: Option<(u32, u16)>,
    },
    Outcome {
        outcome_type: OutcomeType,
        label: String,
        target: Option<String>,
        source_obj: Option<(u32, u16)>,
        evidence: Vec<String>,        // finding IDs or edge-type labels
        confidence_source: Option<String>,
    },
    Collapse { label: String, member_count: usize, collapsed_members: Vec<EventNodeId> },
}

pub enum EventEdgeKind {
    Structural,
    Triggers,
    Executes,       // action -> next action (including /Next chains)
    References,
    ProducesOutcome,
    ChainMembership,
    CollapsedStructural,
}

pub struct EventEdge {
    pub from: EventNodeId,
    pub to: EventNodeId,
    pub kind: EventEdgeKind,
    pub provenance: EdgeProvenance,
    pub metadata: Option<EdgeMetadata>,
}

pub struct EdgeMetadata {
    /// AA dictionary key that triggered this edge (e.g., "/O", "/WC", "/K")
    pub event_key: Option<String>,
    /// Index within a /Next array branch (None for single-ref /Next)
    pub branch_index: Option<usize>,
    /// Trigger initiation hint when derivable from context
    pub initiation: Option<String>,
}

pub enum EdgeProvenance {
    TypedEdge(EdgeType),   // derived from typed graph edge
    Finding(String),       // derived from detector finding (finding ID)
    Heuristic,             // derived from builder heuristic (e.g., collapse connector)
}
```

#### 4.1.1 Node ID scheme

Node IDs use a structured short-readable format. IDs are guaranteed stable within a release, but not across releases.

- Object nodes: `"obj:{obj}:{gen}"` (e.g., `"obj:5:0"`)
- Event nodes: `"ev:{obj}:{gen}:{event_type}:{k}"` (e.g., `"ev:5:0:DocumentOpen:0"`)
- Outcome nodes: `"out:{obj}:{gen}:{outcome_type}:{k}"` (e.g., `"out:12:0:NetworkEgress:1"`)
- Synthetic outcome nodes (no backing object): `"out:synthetic:{monotonic_index}:{outcome_type}"`
- Collapse nodes: `"collapse:{monotonic_index}"`

Where `k` is a deterministic small ordinal among sibling nodes sharing `(obj, gen, type)` and sorted by stable key (action key + target hash prefix). This prevents ID collisions for repeated same-type events/outcomes on one object.

Type alias:

```rust
pub type EventNodeId = String;
```

#### 4.1.2 Graph container

```rust
pub struct EventGraph {
    pub schema_version: &'static str,  // "1.0"
    pub nodes: Vec<EventNode>,
    pub edges: Vec<EventEdge>,
    pub node_index: HashMap<EventNodeId, usize>,
    pub forward_index: HashMap<EventNodeId, Vec<usize>>,  // node -> outgoing edge indices
    pub reverse_index: HashMap<EventNodeId, Vec<usize>>,  // node -> incoming edge indices
}
```

**Ownership constraint:** `EventGraph` must be fully owned (`'static`-compatible) since it crosses the core-to-GUI boundary and must be serialisable. The builder extracts and clones all needed data from the borrowed `TypedGraph` and `ScanContext` during construction. This clone cost is acceptable since it happens once per scan and the event graph is a subset of the full object graph.

### 4.2 Event graph builder inputs

Builder should consume:

1. `ObjectGraph` + `ClassificationMap`
2. `TypedGraph`
3. detector findings and correlations (for outcomes and confidence lift)
4. optional chain list

Proposed builder API:

```rust
pub fn build_event_graph(ctx: &ScanContext<'_>, options: EventGraphOptions) -> EventGraph;
```

The builder internally uses the existing typed-graph construction path (`TypedGraph::build(&ctx.graph, classifications)`), extracts needed data into owned structures, and constructs the fully-owned `EventGraph`.
Findings input is explicit:
- primary: `EventGraphOptions::findings: Option<&[Finding]>`
- fallback: query layer resolves findings using existing findings execution/caching, then passes them in.

### 4.2.1 Typed graph uplift (hard prerequisite for Stage C)

Before event/outcome derivation, improve typed action connectivity in `crates/sis-pdf-pdf/src/typed_graph.rs`:

1. Add explicit `EdgeType::NextAction` and emit it for:
   - `/Next` as single ref
   - `/Next` as array of refs (one edge per branch)
2. Emit `PageAction { event }` for page `/AA` entries.
3. Emit `FormFieldAction { event }` for field/widget `/AA` entries.
4. Emit `UriTarget` edges for `/S /URI` actions:
   - when `/URI` is direct string/name, carry target metadata for event graph outcome creation;
   - when `/URI` resolves to ref, emit typed edge directly.
5. Keep legacy `DictReference { key: "/Next" }` for non-action contexts only.
6. Add edge metadata support for `event_key`, `branch_index`, and initiation hint where derivable.

#### 4.2.2 `/Next` call site migration

When `EdgeType::NextAction` is introduced, update all call sites currently matching on `DictReference { key: "/Next" }`:

| File | Location | Current usage | Migration |
|---|---|---|---|
| `crates/sis-pdf-pdf/src/typed_graph.rs` | `is_executable()` ~line 162 | `matches!(self, EdgeType::DictReference { key } if key == "/Next")` | Add `EdgeType::NextAction` arm; keep `DictReference` arm for non-action `/Next` |
| `crates/sis-pdf-detectors/src/supply_chain.rs` | `is_action_trigger_edge()` ~line 430 | `matches!(&edge.edge_type, EdgeType::DictReference { key } if key == "/Next")` | Match on `EdgeType::NextAction` instead |
| `crates/sis-pdf-detectors/src/actions_triggers.rs` | `action_chain_summary()` ~line 640 | Direct dict lookup `dict.get_first(b"/Next")` (not EdgeType) | No change needed (operates on raw dict, not typed edges) |

### 4.3 Event node derivation

Derive event nodes from typed edges and dictionaries:

1. **Document events**: `/OpenAction`, catalog `/AA` (`/WC`, `/WS`, `/WP`, `/DS`, `/DP`, etc)
2. **Page events**: page `/AA` (`/O`, `/C`, etc)
3. **Form/field events**: widget/field `/A`, `/AA` (`/K`, `/V`, `/Fo`, `/Bl`, `/F`, `/C`, `/D`, `/U`, `/E`, `/X`, etc)
4. **Annotation activation events**:
   - Widget annotation `/A` and related triggers (existing coverage)
   - **Link annotation** (`/Subtype /Link`) with `/A` actions: common malware vector for phishing URIs and JS execution on click
   - Other annotation subtypes with `/A` or `/AA` dictionaries
5. **Independent/delayed events**:
   - `/Next` action chains: traverse typed `NextAction` edges (including branch arrays) to connect multi-step action sequences into ordered event subgraphs, producing `Executes` edges between sequential action nodes
   - JavaScript timing primitives detected by sandbox/static findings (`setTimeout`, `setInterval`, delayed dispatch)
6. **Rendering events**:
   - page/content stream execution points (at least `PageContents` + XObject/annotation render-linked actions in stage 1)

#### 4.3.1 EventType derivation mapping

| Source | AA key | EventType | TriggerClass |
|---|---|---|---|
| Catalog `/OpenAction` | -- | `DocumentOpen` | Automatic |
| Catalog `/AA` | `/WC` | `DocumentWillClose` | Automatic |
| Catalog `/AA` | `/WS` | `DocumentWillSave` | Automatic |
| Catalog `/AA` | `/DS` | `DocumentDidSave` | Automatic |
| Catalog `/AA` | `/WP` | `DocumentWillPrint` | Automatic |
| Catalog `/AA` | `/DP` | `DocumentDidPrint` | Automatic |
| Page `/AA` | `/O` | `PageOpen` | Automatic |
| Page `/AA` | `/C` | `PageClose` | Automatic |
| Page `/AA` | `/PV` | `PageVisible` | Automatic |
| Page `/AA` | `/PI` | `PageInvisible` | Automatic |
| Field `/AA` | `/K` | `FieldKeystroke` | User |
| Field `/AA` | `/F` | `FieldFormat` | User |
| Field `/AA` | `/V` | `FieldValidate` | Automatic |
| Field `/AA` | `/C` | `FieldCalculate` | User |
| Field `/AA` | `/D` | `FieldMouseDown` | User |
| Field `/AA` | `/U` | `FieldMouseUp` | User |
| Field `/AA` | `/E` | `FieldMouseEnter` | User |
| Field `/AA` | `/X` | `FieldMouseExit` | User |
| Field `/AA` | `/Fo` | `FieldOnFocus` | User |
| Field `/AA` | `/Bl` | `FieldOnBlur` | User |
| Field `/A` | -- | `FieldActivation` | User |
| Annotation `/A` | -- | `AnnotationActivation` | User (Hidden if annotation is invisible) |
| `/Next` edge | -- | `NextAction` | (inherits from parent) |
| JS timing finding | -- | `JsTimerDelayed` | Automatic |
| PageContents | -- | `ContentStreamExec` | Automatic |

#### 4.3.2 `/Next` chain edge semantics

When the typed graph contains `NextAction` edges forming a chain (A -> B -> C), the event graph produces:
- Event nodes for each action in the chain
- `Executes` edges preserving chain order: event(A) --Executes--> event(B) --Executes--> event(C)
- Each `Executes` edge carries `provenance: TypedEdge(NextAction)` and `metadata.branch_index` when from an array branch
- `/Next` array branches preserve `branch_index` metadata so parallel branches remain visible in graph exports.
- The chain is traversed with a depth bound of 20 to prevent infinite loops from circular `/Next` references

### 4.4 Outcome node derivation

Outcome nodes should be explicit and connected:

1. **Network exfiltration/egress**:
   - URI actions (`UriTarget`) -- edge provenance: `TypedEdge(UriTarget)`
   - submit form targets (`SubmitFormTarget`) -- edge provenance: `TypedEdge(SubmitFormTarget)`
   - JS runtime network intent findings (see 4.4.1)
2. **Filesystem/system outcomes**:
   - launch targets (`LaunchTarget`, `GoToRTarget`) -- edge provenance: `TypedEdge(LaunchTarget)` / `TypedEdge(GoToRTarget)`
   - JS runtime file write/probe findings (see 4.4.1)
3. **Embedded payload staging outcomes**:
   - embedded file access/extract-like behaviour (`EmbeddedFileRef`)
4. **Code execution outcomes**:
   - JS runtime exec payload findings (see 4.4.1)

Outcome nodes include metadata: `target` (URL, path, or command), `evidence` (list of finding IDs and edge types), `confidence_source` (detector name or edge derivation), `mitre_techniques` (static ATT&CK mapping from OutcomeType).

#### 4.4.1 JavaScript finding to outcome mapping

JS analysis findings from the `js-analysis` crate carry rich metadata that maps to specific outcome types:

| JS Finding Kind | OutcomeType | Evidence Field |
|---|---|---|
| `js_runtime_network_intent`, `js_runtime_downloader_pattern` | `NetworkEgress` | finding ID + `payload.summary` |
| `js_runtime_file_probe` | `FilesystemWrite` | finding ID + target path if available |
| `js_sandbox_exec`, `js_runtime_risky_calls` | `CodeExecution` | finding ID + `payload.summary` |
| `xfa_submit`, `content_phishing` (with submit target) | `FormSubmission` | finding ID + target URL if available |

The query/scan layer passes JS findings into `EventGraphOptions::findings`. Each matching JS finding produces an outcome node with `provenance: Finding(finding_id)` on the connecting `ProducesOutcome` edge. When a JS finding references a specific object (via `obj`/`gen` metadata), the outcome node is connected to that object's event node; otherwise it connects to the nearest JS container event node.

#### 4.4.2 OutcomeType derivation from typed edges

| EdgeType | OutcomeType |
|---|---|
| `UriTarget` | `NetworkEgress` |
| `SubmitFormTarget` | `FormSubmission` |
| `LaunchTarget` | `ExternalLaunch` |
| `GoToRTarget` | `ExternalLaunch` |
| `EmbeddedFileRef` | `EmbeddedPayload` |
| `JavaScriptPayload` (when finding indicates exec) | `CodeExecution` |

### 4.5 Connectivity and collapse rules

To satisfy "all connected":

1. Build full directed graph first.
2. Compute event-participating object set:
   - objects incident to any `Triggers/Executes/ProducesOutcome` edge,
   - plus shortest-path connectors between event and outcome anchors (**bounded to 3 hops**).
3. Collapse remaining structure-only connected components into `Collapse` supernodes.
4. Preserve reversibility metadata (`collapsed_members`) for CLI JSON output.

#### 4.5.1 Collapse specifics

- **Disconnected structural components** (no path to any event or outcome within 3 hops): collapsed unconditionally into a single `Collapse` supernode per connected component.
- **Isolated event nodes** (event with no reachable outcome): **kept visible**, not collapsed. These represent dead triggers and are forensically interesting (e.g., an OpenAction pointing to a deleted/broken action object).
- **Collapse supernode edges**: a `CollapsedStructural` edge connects each collapse supernode to the nearest event-participating object that originally referenced any member of the collapsed component.
- **Determinism**: collapse ordering is deterministic based on lowest `(obj, gen)` in each component.

### 4.5.2 Intent confidence boost from graph connectivity

The existing intent system (`intent.rs`) checks whether finding *types* co-occur (e.g., JS + URI = DataExfiltration signal). The event graph can prove these are *connected*: an `DocumentOpen` event that triggers JS that produces a `NetworkEgress` outcome is stronger evidence than finding JS and a URI in unrelated objects.

After event graph construction, `apply_intent()` receives an optional `&EventGraph` parameter. For each intent signal pair (e.g., JS finding + URI finding), if both findings map to nodes on a connected event→outcome path, boost the signal weight by +1. This requires no new detection work -- it reuses existing intent signals and graph structure.

### 4.6 Chain policy change (singleton removal in default views)

In CLI/GUI chain presentation paths:

1. Keep synthesis internals unchanged initially to minimise regression risk.
2. Default views filter out singleton chains (`len(findings) == 1` and no multi-node path evidence).
3. Add compatibility flag/query option for legacy display (`include_singleton_chains=true`).
4. Ensure grouped chain metadata and counts remain deterministic with filtering.

### 4.7 Structure graph enhancements (parallel track)

Enhance `graph.structure` so it remains useful alongside the event graph:

1. Add optional typed-edge overlay in structure mode:
   - render edge categories (structural/action/resource/external) with distinct styles.
2. Surface action-link metadata in structure exports:
   - edge labels include event key (`/AA /O`, `/AA /V`, etc), action `/S`, and initiation class when known.
3. Add branch-aware `/Next` visualisation:
   - show fan-out/fan-in explicitly (not flattened).
4. Add optional structural collapse parity:
   - collapse low-value isolated components in structure view without changing default ORG output.
5. Add path helpers:
   - "reachable from trigger" and "path to outcome" summaries for selected nodes/chains.

### 4.8 Extended graph enhancements (post-MVP)

After baseline event graph stabilises, add richer semantics already available in detectors/query code:

1. Add action dictionary metadata:
   - `/N` named action target,
   - `/F` target type (embedded/external),
   - launch target hash/path metadata,
   - URI context/visibility/placement indicators.
2. Expand action-type coverage:
   - `/GoToE`, `/ImportData`, `/ResetForm`, `/Hide`, `/SetOCGState`, `/Rendition`.
3. Add trigger-context enrichment:
   - hidden annotation/field markers,
   - automatic vs user initiation.
4. Add confidence-calibrated edge weighting:
   - combine typed-edge certainty with detector confidence for ranking/overlay.
5. Comparative event graph topology for campaign detection:
   - compute graph fingerprint (sorted edge-kind sequence hash) from event graph topology,
   - compare fingerprints across batch scans to detect documents with identical trigger→outcome patterns (same campaign, different payloads),
   - power `sis batch --detect-campaigns` without full document comparison.
6. Event graph diff for revision analysis:
   - build event graph per revision, diff to show which trigger→outcome paths were added/removed in incremental updates,
   - answers "what malicious capability was introduced in this revision?" without manual inspection.
7. Supply chain risk metric via graph reachability:
   - compute minimum hop count from `DocumentOpen` (or any Automatic event) to any outcome node,
   - documents where auto-trigger reaches external outcome in 2 hops = higher risk than 5 hops through user-initiated events,
   - emit as numeric `supply_chain_reachability_score` on event graph summary.

## 5. CLI integration plan

### 5.1 Query surface

Extend `crates/sis-pdf/src/commands/query.rs` with:

1. `graph.structure` (alias existing ORG output)
2. `graph.event`
3. `graph.event.json`
4. `graph.event.dot`
5. `graph.event.count` (nodes/edges summary)
6. `graph.event.outcomes`
7. `graph.event.iocs` -- extract and deduplicate `target` values from all outcome nodes; defang URLs by default (`hxxps://`); output as structured list with IOC type, value, source outcome node ID, and MITRE technique IDs. Supersedes `--export-intents` as a superset (includes launch targets, embedded file refs, JS-derived indicators in addition to network intents).
8. `graph.event.narrative` -- walk each root event node (no incoming `Triggers` edges) forward through `Executes`/`ProducesOutcome` edges and render one sentence per path describing the trigger→action→outcome flow in natural language. Deterministic (graph-structure-based, not ML-generated).

Add predicates for event graph fields (`node_kind`, `event_type`, `outcome_type`, `trigger`, `target`, `mitre`).

### 5.2 Output contracts

1. **JSON**: machine-stable schema with explicit `schema_version` field (initial value `"1.0"`), node/edge kinds, provenance, MITRE technique IDs, and collapse metadata.
2. **DOT**: separate styling for object/event/outcome/collapse nodes.
3. **Readable/text**: compact summary table (events by class, outcomes by target/type, collapse counts).
4. **SARIF**: embed event graph in SARIF 2.1 `graphs` property (nodes as SARIF graph nodes, edges as `graphTraversal` objects). Extends existing `--sarif` output so CI/CD pipelines see event→outcome relationships alongside findings.

### 5.3 Backward compatibility

1. Keep `org`, `org.dot`, `org.json` unchanged.
2. Keep `events` list query unchanged.
3. Add `events.graph_ref` field to each event in the existing `events` list output, containing the corresponding `EventNodeId` in the event graph. Always present (null when mapping fails). No external consumer concerns; schema is still in development.

### 5.4 Action graph deprecation

1. `graph.action` is parsed as `Query::GraphEvent` with a pre-applied filter in `EventGraphOptions` (filter to `node_kind in {Event, Outcome}`, action-related edges only). No new query variant needed.
2. `export_action_graph_json()` and `export_action_graph_dot()` emit a deprecation log (`warn!`) recommending `graph.event`.
3. Full removal deferred to a future major version.

## 6. GUI visualisation plan

### 6.1 Graph data model refactor

The current `GraphNode` is tightly coupled to PDF objects and cannot represent event, outcome, or collapse nodes. This requires an internal API change in `crates/sis-pdf-gui/src/graph_data.rs`:

```rust
pub enum GraphNodeKind {
    Object { obj: u32, gen: u16, obj_type: String, roles: Vec<String> },
    Event { event_type: String, trigger: String, label: String, source_obj: Option<(u32, u16)> },
    Outcome { outcome_type: String, label: String, target: Option<String> },
    Collapse { label: String, member_count: usize },
}

pub struct GraphNode {
    pub id: String,
    pub kind: GraphNodeKind,
    pub x: f64,
    pub y: f64,
}
```

The existing `from_object_data*` builders continue to produce `GraphNodeKind::Object` nodes for structure mode. A new `from_event_graph()` builder converts the core `EventGraph` into the GUI `GraphData` format.

### 6.2 Dual graph mode

In `crates/sis-pdf-gui/src/panels/graph.rs`:

1. Add mode switch: `Structure` vs `Event`.
2. Preserve current structure graph behaviour in `Structure` mode.
3. In `Event` mode, render typed node shapes:
   - Object: circle (same as structure mode)
   - Event: diamond/hex-like marker
   - Outcome: square/pill marker
   - Collapse: grouped cluster node (dashed border)

### 6.3 Overlay and focus behaviour

1. Chain overlay toggle applies in both modes.
2. In event mode, selecting a chain highlights full event->outcome path.
3. "Show in graph" centres selected object/event node and keeps in/out edge highlighting.
4. Add legend and filters:
   - event class filter,
   - outcome type filter,
   - collapse on/off,
   - hide isolated structural nodes,
   - reader profile filter (Acrobat/Pdfium/Preview): grey out event nodes for events the selected reader does not support (static lookup derived from existing `reader_context.rs` annotations).
5. Finding detail panel context link: when a finding is selected in the detail panel, show "Event graph paths" section listing event→outcome paths that include this finding (via `events.graph_ref` and reverse traversal). Turns the event graph from an expert-mode panel into contextual navigation across all panels.

### 6.4 Performance guardrails

1. Cap expanded nodes (reuse `MAX_GRAPH_NODES` strategy, add event-specific caps).
2. Lazy expand collapse nodes on click.
3. Deterministic layout seed to reduce jitter between toggles.

### 6.5 WASM compatibility

The branch is `feature/egui-wasm` and the GUI is being ported to WASM. Event graph construction and layout must respect WASM constraints:

1. **No threads**: event graph builder and force-directed layout run single-threaded. The builder should complete within a bounded time budget (target: <50ms for documents with <500 objects).
2. **Memory budget**: event graph node/edge allocation should be bounded. Apply `MAX_GRAPH_NODES` cap before layout, not after. For documents exceeding the cap, auto-enable collapse before refusing to render.
3. **Web worker compatibility**: if event graph construction is expensive (>50ms), consider running the builder in a web worker using the same payload transport pattern as the existing WASM worker infrastructure.
4. **No thread-spawn assumptions**: no `std::thread` usage; cache/synchronisation primitives must remain wasm-compatible and single-thread safe.

## 7. Implementation stages

### Stage A: Chain changes (independent, quick win)

**Rationale**: singleton removal is independent of the event graph, lower risk, and delivers immediate noise reduction. Running first lets the event graph build on cleaner chain data.

1. Implement singleton filtering in default CLI/GUI chain views (leave synthesis internals unchanged initially).
2. Add `include_singleton_chains` option (default false) to CLI/GUI view options.
3. Update chain rendering/query tests and fixtures.
4. Verify no downstream breakage in CLI/GUI chain rendering and counters.

### Stage B: Core model + typed graph uplift

**Part 1: Schema types and module scaffold** (in `crates/sis-pdf-core`):

1. Add `event_graph` module to `crates/sis-pdf-core/src/`.
2. Define schema types: `EventNodeKind`, `EventEdgeKind`, `EventType`, `OutcomeType`, `TriggerClass`, `EdgeProvenance`, `EdgeMetadata`, `EventGraph`, plus static `mitre_techniques()` / `mitre_techniques_outcome()` lookup functions.
3. Move `TriggerClass` from `org_export.rs` to `event_graph` module as public enum; re-export from `org_export.rs` for backward compatibility.
4. Add JSON export function with `schema_version: "1.0"`.
5. Add unit tests for node ID generation and schema serialisation.

**Part 2: Typed graph action connectivity uplift** (in `crates/sis-pdf-pdf`, prerequisite for Stage C):

6. Implement `EdgeType::NextAction` and extractor support for `/Next` ref + array branches.
7. Implement extraction for `PageAction { event }` and `FormFieldAction { event }`.
8. Implement `UriTarget` extraction from `/S /URI` actions (with best-effort target metadata capture).
9. Update `/Next` call sites (see section 4.2.2):
   - `typed_graph.rs` `is_executable()`: add `NextAction` arm, keep `DictReference` arm for non-action contexts.
   - `supply_chain.rs` `is_action_trigger_edge()`: match on `NextAction` instead of `DictReference { key: "/Next" }`.
   - `actions_triggers.rs` `action_chain_summary()`: no change (raw dict lookup, not EdgeType).
10. Add targeted tests in `crates/sis-pdf-pdf/tests/` for each new extraction path.

**Part 3: Builder scaffold** (depends on Part 1):

11. Implement builder scaffold: `build_event_graph()` that ingests ObjectGraph + TypedGraph + ClassificationMap and produces object nodes + structural edges.
12. Add explicit wiring tasks in query layer for findings retrieval/caching and pass-through into `EventGraphOptions::findings`.

Parts 1 and 2 can proceed in parallel (different crates). Part 3 depends on Part 1 completing.

### Stage C: Event/outcome derivation + connectivity

Depends on Stage B (all parts).

1. Map typed edges to event nodes (document, page, field, annotation, link annotation, `/Next` chains) using EventType derivation table (section 4.3.1).
2. Derive outcome nodes from typed edges using OutcomeType derivation table (section 4.4.2).
3. Add JS finding integration: map JS analysis findings to outcome nodes using finding kind mapping table (section 4.4.1).
4. Implement collapse algorithm with 3-hop depth bound and deterministic ordering.
5. Add `EdgeProvenance` and `EdgeMetadata` to all edges.
6. Populate `mitre_techniques` on event and outcome nodes from static lookup.
7. Add graph-connectivity boost to `apply_intent()`: when findings on the same event→outcome path co-occur, boost intent signal weight.
8. Unit tests for each event source and outcome type, including MITRE technique presence and intent boost behaviour.

### Stage D: CLI query integration + structure graph uplift

**Part 1: Event graph queries**:

1. Parse new `graph.event*` queries in `query.rs`.
2. Wire output format handling (`json`, `dot`, `readable`).
3. Add predicate support for event graph fields.
4. Add `events.graph_ref` field to existing `events` list output.
5. Set up `graph.action` as `Query::GraphEvent` with pre-applied filter in `EventGraphOptions`.
6. Add deprecation `warn!` to `export_action_graph_*` functions.
7. Add `graph.event.iocs` query: extract/deduplicate targets from outcome nodes, defang URLs, include IOC type + source node ID + MITRE technique IDs.
8. Add `graph.event.narrative` query: walk root event nodes forward to outcomes, render one sentence per path.
9. Integration tests on fixtures with known triggers/outcomes, IOC extraction, and narrative output.

**Part 2: Structure graph uplift** (section 4.7, all items):

8. Add `graph.structure` typed-edge overlay and readable summary options.
9. Add optional branch-aware `/Next` rendering in DOT/JSON (without changing default legacy ORG output).
10. Add trigger-reachability/path summaries for interactive query output.
11. Add optional structural collapse parity (collapse isolated components without changing default ORG).
12. Add path helpers ("reachable from trigger", "path to outcome" summaries).

### Stage E: GUI integration

1. Refactor `GraphNode` to use `GraphNodeKind` enum in `graph_data.rs`.
2. Add `from_event_graph()` builder for converting core `EventGraph` to GUI `GraphData`.
3. Update all `GraphNode` consumers (rendering, tooltips, click handlers, double-click navigation).
4. Add mode switch (Structure/Event) in toolbar.
5. Add node shape rendering (diamond, square, dashed cluster) for event mode.
6. Add legend, event/outcome filters, reader profile filter, and chain path highlighting.
7. Add finding detail panel "Event graph paths" context section (reverse traversal from finding to connected paths).
8. Test WASM compatibility: verify event graph builds and renders within budget in wasm32 target.
9. Add event graph rendering tests (unit-level for mapping + snapshot-friendly logic where practical).

### Stage F: Docs and rollout

1. Update `docs/query-interface.md` and `docs/ir-org-graph.md`.
2. Add event graph schema docs and examples.
3. Add migration note for chain singleton removal.
4. Document `graph.action` deprecation path and timeline.
5. Document `events.graph_ref` bridge field.
6. Document `graph.event.iocs` query and IOC export format.
7. Document `graph.event.narrative` query.
8. Add SARIF graph embedding: populate SARIF 2.1 `graphs` property with event graph nodes/edges when `--sarif` is used.
9. Document MITRE ATT&CK technique mapping and add examples.

## 8. Testing strategy

### 8.1 Fixture audit (pre-Stage B)

Before beginning implementation, audit existing fixtures for coverage:

| Required coverage | Fixture needed | Status |
|---|---|---|
| Document `/OpenAction` + catalog `/AA` | `launch_cve_2010_1240.pdf` | Exists |
| Multi-stage `/Next` action chain | TBD | **Needs creation or identification** |
| `/Next` array branch fan-out (1->many action branches) | TBD | **Needs creation or identification** |
| URI submit-form action (`SubmitFormTarget`) | TBD | **Needs creation or identification** |
| JS-triggered network egress (outcome via finding) | TBD | **Needs creation or identification** |
| Link annotation with `/A` action | TBD | **Needs creation or identification** |
| Document with collapsed structural regions | Any large document | Likely exists, confirm |

Fixtures must be committed to `crates/sis-pdf-core/tests/fixtures/` and registered in manifest per project guidelines.

### 8.2 Core unit tests

- Event node derivation from each source: DocumentOpen, PageOpen, FieldKeystroke, AnnotationActivation, NextAction, JsTimerDelayed, ContentStreamExec.
- EventType derivation mapping: verify each AA key maps to correct EventType and TriggerClass per table in 4.3.1.
- Typed graph extraction coverage: `NextAction`, `PageAction`, `FormFieldAction`, `UriTarget`.
- `/Next` branch preservation: branch index in `EdgeMetadata` and edge count correctness for array branches.
- Outcome derivation for each OutcomeType: NetworkEgress, ExternalLaunch, CodeExecution, FormSubmission, EmbeddedPayload.
- OutcomeType derivation from typed edges per table in 4.4.2.
- JS finding -> outcome mapping for each finding kind in the table (section 4.4.1).
- Collapse determinism: same input produces same collapse grouping and supernode IDs.
- Collapse reversibility: `collapsed_members` accurately lists all member node IDs.
- Node ID stability: same document produces same node IDs across runs.
- `/Next` chain depth bound: circular `/Next` references terminate at depth 20.
- EdgeMetadata populated correctly: `event_key`, `branch_index`, `initiation` present where derivable.
- MITRE technique IDs present on event and outcome nodes per static mapping table.
- Intent boost: `apply_intent()` with event graph produces higher confidence for connected finding pairs than without.

### 8.3 Integration tests

(`crates/sis-pdf/tests` / `crates/sis-pdf-core/tests`):

- `graph.event.json` on fixtures with known triggers/outcomes: verify node/edge counts, specific node IDs, and edge connections.
- `graph.event.outcomes` returns expected outcome nodes with correct OutcomeType.
- `events.graph_ref` field contains valid event graph node IDs.
- `graph.action` alias produces same result as filtered `graph.event`.
- `graph.structure` typed-edge overlay includes action edge categories while default `org` output stays unchanged.
- No singleton chains by default; singleton chains present when `include_singleton_chains=true`.
- Chain overlay references valid graph node IDs.
- Schema version field present and correct.
- `graph.event.iocs` returns deduplicated, defanged IOCs with source node IDs and MITRE technique IDs.
- `graph.event.narrative` produces deterministic sentences matching known trigger→outcome paths in fixtures.
- SARIF output with `--sarif` includes `graphs` property when event graph is available.

### 8.4 Regression fixtures

- Include at least one document with document/page/form triggers and external outcomes.
- Include at least one document with a multi-stage `/Next` chain leading to an outcome.
- Include at least one document with `/Next` array branches.
- Include at least one document with a Link annotation action.

### 8.5 GUI tests

- Mapping tests for `GraphNodeKind` variants -> node shape/colour.
- `from_event_graph()` builder produces correct node/edge counts.
- Focus/centering and selection-edge highlight behaviour in event mode.
- Mode switch preserves pan/zoom state.
- WASM build: event graph construction completes within 50ms budget for test fixture.

### 8.6 Performance tests

- Event graph builder on `launch_cve_2010_1240.pdf`: completes within scan pipeline SLO (<50ms).
- Event graph builder on a large document (>200 objects): verify collapse reduces node count and builder stays within budget.

## 9. Risks and mitigations

1. **Graph bloat/noise**: collapse non-participating structure nodes by default; cap at `MAX_GRAPH_NODES`.
2. **False causal links**: encode `EdgeProvenance` on every edge (TypedEdge/Finding/Heuristic) so consumers can filter by confidence. Outcome nodes carry `evidence` and `confidence_source` metadata.
3. **Runtime cost**: reuse typed graph and bounded path search (3 hops); avoid all-pairs traversals. `/Next` chain traversal bounded at depth 20.
4. **UX complexity**: keep structure mode default and event mode explicit with legend/tooltips.
5. **WASM constraints**: bound builder time/memory; use web worker for expensive builds; no thread assumptions.
6. **Action graph migration**: coexistence period with deprecation warnings; no immediate removal.
7. **Fixture gaps**: audit and create missing fixtures before Stage B to avoid blocking integration tests.
8. **Edge extraction drift**: new typed edges may shift detector/path behaviour.
   - Mitigation: compatibility tests for existing findings/chains and strict extraction regression tests.

## 10. Acceptance criteria

1. `graph.structure` preserves current ORG semantics.
2. `graph.event` outputs connected event/outcome-aware graph with collapsed structure-only regions.
3. `graph.event.json` includes `schema_version: "1.0"` and `EdgeProvenance` on every edge.
4. Chain output defaults exclude one-item chains.
5. GUI graph panel supports mode switch and chain overlay in event mode.
6. CLI + GUI expose outcomes (network/filesystem/launch/submission/code execution) as connected nodes.
7. `events.graph_ref` bridges existing event list output to event graph node IDs.
8. Link annotations with `/A` actions produce event nodes.
9. `/Next` action chains (including array branches) produce connected `Executes` edge sequences with `EdgeMetadata.branch_index`.
10. JS analysis findings produce outcome nodes with finding ID evidence.
11. `graph.action` alias works as filtered event graph view (no separate query variant).
12. New behaviour is covered by automated tests and documented in user-facing docs.
13. Event graph builds and renders correctly under WASM target within performance budget.
14. Typed graph emits `NextAction`, `PageAction`, `FormFieldAction`, and `UriTarget` where applicable.
15. `graph.structure` gains typed-edge/action-path visibility without breaking legacy `org` compatibility.
16. All `/Next` call sites updated to match on `NextAction` where appropriate.
17. `graph.event.iocs` extracts and defangs outcome targets as structured IOC list with MITRE technique IDs.
18. `graph.event.narrative` produces deterministic natural-language attack path descriptions.
19. Event and outcome nodes carry MITRE ATT&CK technique IDs from static mapping.
20. `apply_intent()` boosts confidence for findings connected via event graph paths.
21. SARIF output embeds event graph in `graphs` property.
22. GUI finding detail panel shows event graph path context for selected findings.
23. GUI event graph supports reader profile filter (Acrobat/Pdfium/Preview).

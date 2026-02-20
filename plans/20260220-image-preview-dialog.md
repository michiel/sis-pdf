# On-Demand Image Preview Dialog Plan

Date: 2026-02-20
Status: Completed (implementation) / Pending GUI manual verification
Owner: GUI (`sis-pdf-gui`), PDF decode integration (`sis-pdf-pdf`), image reconstruction (`image-analysis`)

## Goals

1. Provide comprehensive, on-demand image preview support for Object Inspector image objects.
2. Replace inline image rendering with a dedicated preview dialog opened via a `Preview` button.
3. Prioritise safety and speed over full-fidelity rendering or colour accuracy.
4. Surface clear preview metadata, decoding path, and failure status to support analyst decisions.

## Implementation progress (2026-02-20)

Completed:
- Phase 1 engine and status model (`crates/sis-pdf-gui/src/image_preview.rs`) with staged outcomes and budget guards.
- Phase 2 dialog workflow and Object Inspector `Preview` action; inline preview removed in favour of dialog rendering.
- Phase 3 metadata/status enrichment in dialog (source, byte counts, timing, outcome badges).
- Phase 4 hardening slices:
  - source-byte budget fast-fail gates,
  - bounded preview cache with entry/byte eviction and utilisation display,
  - on-demand preview generation at dialog open (no eager preview during full object extraction),
  - fixture-driven integration coverage in `crates/sis-pdf-gui/tests/image_preview_pipeline.rs`,
  - on-demand analysis integration coverage in `crates/sis-pdf-gui/tests/analysis.rs`.

Remaining:
- Add fixture manifest/provenance entries if corpus-derived image fixtures are introduced beyond synthetic builders.
- Run final GUI manual verification pass in an environment where `winit` GUI tests can execute.

## Regression commands

- `cargo test -p sis-pdf-gui --no-default-features --test image_preview_pipeline -- --nocapture`
- `cargo test -p sis-pdf-gui --no-default-features --test analysis on_demand_image_preview_generation_from_analysis_result -- --nocapture`
- `cargo test -p sis-pdf-gui --no-default-features preview_cache -- --nocapture`
- `cargo test -p sis-pdf-gui --no-default-features image_preview -- --nocapture`

## Analyst problem statement

Current behaviour mixes preview attempts directly into the Object Inspector panel and can fail silently or with generic status text. For large PDFs with many images, inline preview also wastes panel space and does not give enough decode provenance.

Operational impact:
- Analysts cannot quickly tell if failure is due to unsupported filter chains, decode budgets, malformed bytes, or reconstruction limits.
- Inline previews reduce readability of object context and dictionary details.
- There is no dedicated workspace for preview-specific controls and metadata.

## Scope

In scope:
- New image preview dialog (egui `Window` widget, non-blocking, consistent with existing `findings::show_window` and `chains::show_window` patterns) with metadata and decode status.
- Object Inspector action button to open preview on demand.
- Removal of inline preview widget from Object Inspector details, including the interim `image_preview_status: Option<String>` field.
- Preview decode pipeline refactor with explicit staged outcomes and status codes.
- Fast-path and fallback-path support for mixed filter chains (including non-deferred prefix decoding).
- Caching and bounded resource controls for safe repeated use.
- Fixture and regression coverage for complex and hostile image scenarios.

Out of scope:
- Colour-managed rendering (ICC-accurate output).
- Lossless/full-resolution rendering targets.
- Export/edit workflows (future phase).
- Separate OS-level window for the preview dialog (egui `Window` only).

## Design principles

1. Fail closed, explain clearly: every preview attempt yields a deterministic status code and human-readable summary.
2. Budget-first execution: hard caps on decode bytes, pixel count, CPU-heavy steps, and cache memory.
3. On-demand compute: no automatic decode work during object list navigation.
4. Single pipeline: one preview engine for all UI entry points to avoid divergence.
5. Additive schema/state changes only: avoid breaking existing GUI worker payloads.

## Risk assessment

The non-deferred prefix decode path (pipeline step 4, acceptance criterion 3) is the highest-risk item in this plan. It requires partial execution of the filter chain in `sis-pdf-pdf`, must not panic on hostile or truncated streams, and is the path most likely to expose new crash surfaces. It should be prototyped as a spike during Phase 1 alongside the engine — not deferred to Phase 2 — so that feasibility is confirmed before the dialog UX is built on top of it.

## Technical design

## 1) Data model and state

### 1.1 Preview status model

Add canonical preview status types in `crates/sis-pdf-gui/src/image_preview.rs` (new file, see Section 2):

```rust
pub enum ImagePreviewStage {
    RawProbe,
    FullStreamDecode,
    PrefixDecode,
    ContainerDecode,
    PixelReconstruct,
    Thumbnail,
}

pub enum ImagePreviewOutcome {
    Ready,
    SkippedBudget,
    Unsupported,
    DecodeFailed,
    ReconstructFailed,
    InvalidMetadata,
}

pub struct ImagePreviewStatus {
    pub stage: ImagePreviewStage,
    pub outcome: ImagePreviewOutcome,
    pub detail: String,
    pub input_bytes: Option<usize>,
    pub output_bytes: Option<usize>,
    pub elapsed_ms: Option<u64>,
}
```

Retain `image_preview_status: Option<String>` for compatibility and UI one-line summary, and add:
- `preview_statuses: Vec<ImagePreviewStatus>` — full stage log from the pipeline.
- `preview_summary: Option<String>` — human-readable one-liner for the Object Inspector status row.

Both fields are additive with `#[serde(default)]`.

### 1.2 Dialog state

Add GUI dialog state in `crates/sis-pdf-gui/src/app.rs`, following the existing pattern used by findings and chains windows:

```rust
pub struct ImagePreviewDialogState {
    pub open: bool,
    pub object_ref: Option<(u32, u16)>,
    pub loading: bool,
    pub image: Option<PreviewImage>,
    pub metadata: PreviewMetadata,
    pub statuses: Vec<ImagePreviewStatus>,
    pub error: Option<String>,
}
```

Add cache alongside the dialog state:

```rust
pub struct PreviewCache {
    // Ordered by insertion; evict least-recently-used entries when either
    // max_entries or max_total_bytes is exceeded.
    entries: Vec<(PreviewCacheKey, CachedPreviewResult)>,
    total_bytes: usize,
    max_entries: usize,
    max_total_bytes: usize,
}
```

Implementation note: the cache is implemented in `crates/sis-pdf-gui/src/preview_cache.rs` as an in-tree bounded cache (`HashMap` + recency queue), so no external `lru` dependency was introduced.

Eviction policy:
- On each insert, evict least-recent entries until both entry and byte budgets are satisfied.
- The cache exposes `len`, `total_bytes`, `max_entries`, and `max_total_bytes` and these are surfaced in the preview dialog.

## 2) Preview pipeline

Create shared engine `crates/sis-pdf-gui/src/image_preview.rs`. This file replaces the interim `generate_image_preview` / `decode_image_preview` functions currently scattered in `object_data.rs`.

```rust
pub fn build_preview_for_object(
    bytes: &[u8],
    obj: u32,
    gen: u16,
    limits: PreviewLimits,
) -> Option<PreviewBuildResult>
```

Pipeline order:
1. Validate object type and stream span. Record `InvalidMetadata` and return early if stream is absent or span is zero-length.
2. Raw probe: detect container signatures (`JPEG`, `PNG`, `GIF`, `BMP`, `TIFF`, `WEBP`) from raw stream bytes. Record `RawProbe` stage outcome.
3. Full stream decode (existing `decode_stream`) with image budget (`max_stream_decode_bytes`). Record `FullStreamDecode` stage outcome.
4. On deferred-filter failure, attempt non-deferred prefix decode (spike required — see risk note). Record `PrefixDecode` stage outcome.
5. Attempt container decode (`image` crate) on best candidate bytes. Record `ContainerDecode` stage outcome.
6. Fallback to raw pixel reconstruction (`image-analysis::pixel_buffer`). Record `PixelReconstruct` stage outcome.
7. Produce bounded thumbnail. Record `Thumbnail` stage outcome.

Each step:
- Appends a `ImagePreviewStatus` entry with stage, outcome, detail, byte counts, and elapsed time measured via `std::time::Instant` at the start and end of that step.
- Exits early on any budget breach, recording `SkippedBudget`.
- Never panics on malformed input.

The `decode_image_preview` function from the interim diff maps to stage 5 (`ContainerDecode`). It should be moved into this file and labelled accordingly.

## 3) UI changes

### 3.1 Object Inspector actions

File: `crates/sis-pdf-gui/src/panels/objects.rs`

- Add `Preview` button for `obj_type == "image"`.
- Keep `View raw`, `Download raw`, `Download decoded` actions.
- Remove inline `Image preview` collapsible rendering section (including interim WIP).
- Keep an inline one-line status summary only (latest `preview_summary` from `ObjectSummary`), linking to the dialog via the `Preview` button.

### 3.2 Preview dialog

File: new `crates/sis-pdf-gui/src/panels/image_preview_dialog.rs`

Use `egui::Window::new("Image Preview").show(ctx, ...)` consistent with `findings::show_window` and `chains::show_window`. The window is non-blocking; the rest of the UI remains interactive while it is open.

Dialog sections:
- Header: object ref, dimensions (previewed), close/retry buttons.
- Canvas: scaled preview image (nearest/linear toggle optional).
- Metadata:
  - object id/gen
  - declared width/height/bits/colour space
  - stream filters and decode parms summary
  - source used (`raw`, `decoded`, `prefix-decoded`, `reconstructed`)
  - input bytes, decoded bytes, preview bytes
- Decode status timeline:
  - per-stage outcome and short detail
  - elapsed ms per stage
  - final outcome badge (`Ready`, `Unsupported`, etc.)

Default behaviour:
- Opening the dialog triggers decode only once per object unless `Retry` clicked.
- If cached, load instantly and show `from cache` marker.

## 4) Limits and safety controls

Add `PreviewLimits` in `image_preview.rs`:

```rust
pub struct PreviewLimits {
    pub max_stream_decode_bytes: usize,   // default 8 MiB
    pub max_source_bytes: usize,          // default 16 MiB
    pub max_pixels: u64,                  // default 16M
    pub max_rgba_bytes: u64,              // default 64 MiB
}
```

Note: a wall-time limit is deferred to the follow-up list. Checking elapsed time at every stage boundary is feasible via `std::time::Instant`, but enforcing it as a hard stop requires either cooperative cancellation or threading, neither of which is in scope. Timing is still recorded per stage (in `ImagePreviewStatus::elapsed_ms`) for observability.

Rules:
- Hard-stop path if any budget is exceeded; record `SkippedBudget` status.
- Never allocate output buffers before checked arithmetic.
- Never panic on malformed dictionaries/filters.
- Budget-triggered skips are always recorded as explicit statuses with byte counts.

## 5) Performance and quality gates

The following tests are targets to be created in Phase 4 (they do not yet exist):

- `cargo test -p sis-pdf-gui preview_pipeline_budget_mixed_filters -- --nocapture`
- `cargo test -p sis-pdf-gui preview_pipeline_budget_large_raw_pixels -- --nocapture`
- `cargo test -p sis-pdf-gui preview_cache_hit_avoids_redecode -- --nocapture`

Target thresholds:
- Cached preview open: p95 < 30 ms.
- First decode common JPEG/Flate+JPEG: p95 < 150 ms.
- Memory growth per preview: <= 80 MiB peak transient, <= cache budget steady-state.

These thresholds become gating criteria once the tests exist at end of Phase 4.

## 6) Fixture plan

Add fixtures under `crates/sis-pdf-core/tests/fixtures/images/`. This is a new directory; the following provenance steps are mandatory before any fixture is committed:

1. Add a `README.md` to `crates/sis-pdf-core/tests/fixtures/images/` documenting the directory purpose and fixture provenance requirements.
2. Register every fixture in `crates/sis-pdf-core/tests/fixtures/corpus_captured/manifest.json` (or a sibling `images/manifest.json` if a separate manifest is preferred) with:
   - `path`
   - `sha256`
   - `source_path`
   - `regression_targets`
3. Update `crates/sis-pdf-core/tests/fixtures/README.md` to reference the new directory.

Required fixture families:
- Mixed-filter containers: `FlateDecode,DCTDecode`, `ASCII85Decode,FlateDecode,DCTDecode`.
- Raw pixel reconstruction: indexed palette, CMYK, sub-byte bpc.
- Hostile/malformed: truncated streams, bad decode parms, invalid colour-space refs.
- Distributed/fragmented image resources across object streams and incremental revisions.
- Large-but-bounded images to validate budget cut-offs.

For GUI-focused determinism, add synthetic JSON object-data fixtures in `crates/sis-pdf-gui/tests/fixtures/`.

## 7) Implementation phases

### Phase 1: Engine, status model, and prefix-decode spike

- Remove interim `image_preview_status: Option<String>` field and the `generate_image_preview`/`decode_image_preview` functions from `object_data.rs`.
- Add `ImagePreviewStage`, `ImagePreviewOutcome`, `ImagePreviewStatus`, and `PreviewLimits` in new `image_preview.rs`.
- Implement `build_preview_for_object` with all pipeline stages, including a working prototype of non-deferred prefix decode (the highest-risk step — see risk note).
- Return structured `Vec<ImagePreviewStatus>` from every path; add `preview_statuses` and `preview_summary` to `ObjectSummary`.
- Unit tests must cover:
  - Each `ImagePreviewOutcome` variant is reachable via a specific input.
  - `SkippedBudget` is returned (not a panic) when `max_stream_decode_bytes` is exceeded.
  - `SkippedBudget` is returned when `max_pixels` is exceeded.
  - `InvalidMetadata` is returned for a stream with a zero-length span.
  - `PrefixDecode` stage succeeds for a `FlateDecode,DCTDecode` chain where full decode fails.
  - Hostile/truncated stream input does not panic on any code path.

### Phase 2: Dialog UX and action wiring

- Add `ImagePreviewDialogState` and `PreviewCache` to `app.rs`.
- Implement `image_preview_dialog.rs` using `egui::Window`.
- Wire `Preview` button in `objects.rs`; remove inline collapsible image rendering.
- Add retry/close and `from cache` indicators.
- Compile and basic smoke-test against a real PDF with image objects.

### Phase 3: Metadata/decode detail enrichment

- Add decode metadata table and per-stage timing/byte metrics to dialog.
- Add source attribution and filter-chain summary.
- Improve status wording consistency and outcome badges.

### Phase 4: Fixtures, budgets, hardening

- Add required fixtures, `README.md`, and manifest updates per Section 6.
- Implement performance tests listed in Section 5.
- Run targeted regression suite and document baseline timing deltas in this plan.
- Review cache eviction behaviour under repeated opens with large images.

## 8) Acceptance criteria

1. Object Inspector no longer renders inline images; preview is dialog-only.
2. Every image object has a visible preview action and deterministic status path.
3. Mixed deferred filter chains (for example `FlateDecode,DCTDecode`) render previews when non-deferred prefix decoding is sufficient.
4. Preview dialog always shows metadata + decoding information + final status.
5. Decode and memory budgets are enforced and covered by tests.
6. No panics/unwraps introduced; hostile inputs fail safely.
7. Interim `image_preview_status: Option<String>` field is fully removed before Phase 2 begins.

## Opportunities for follow-up improvement

1. Progressive preview levels (`tiny`, `small`, `full`) selectable in dialog for very large images.
2. Optional worker-thread preview generation to keep UI frame-time stable under heavy decode.
3. Wall-time limit enforcement via cooperative cancellation across pipeline stages.
4. Preview diff mode for comparing two image objects across revisions.
5. Export sanitised preview artefacts and decode trace JSON for analyst reports.
6. Add CLI parity command (`sis query ... image.preview <obj> <gen>`) returning status/metadata without GUI.

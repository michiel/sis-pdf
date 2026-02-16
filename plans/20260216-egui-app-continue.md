# egui GUI Continuation: Fix Layout, Add Missing Features, Polish

Date: 2026-02-16
Status: Complete
Branch: `feature/egui-wasm`

## Context

The egui GUI was built across 3 milestones (M1-M3) per `plans/20260215-egui-app.md` and `plans/20260215-egui-wasm.md`. A review against the spec identified 20 issues ranging from missing structural elements (no top bar, no progress indicator) to incorrect behaviour (sort by Debug string) and incomplete panels (missing filters, missing detail sections). This plan addresses all 20 issues in 5 incremental stages.

## Files Changed

| File | Changes |
|------|---------|
| `crates/sis-pdf-gui/src/app.rs` | Added `show_findings`, `dark_mode`, `findings_search`, `surface_filter`, `min_confidence`, `has_cve_filter`, `auto_triggered_filter`, `chain_sort_column`, `chain_sort_ascending`, `command_history_pos`, `app_state`, `window_max` fields. Added `AppState` and `ChainSortColumn` enums. Restructured `update()` layout: top bar + workspace bar + 120px nav + empty CentralPanel + floating windows. Extracted `process_analysis()` from `handle_file_drop()` for deferred analysis. Theme visuals applied per frame. |
| `crates/sis-pdf-gui/src/lib.rs` | Added `pub mod util` and `pub mod window_state` |
| `crates/sis-pdf-gui/src/workspace.rs` | Added `show_findings`, `findings_search`, `surface_filter`, `min_confidence`, `has_cve_filter`, `auto_triggered_filter`, `chain_sort_column`, `chain_sort_ascending`, `command_history_pos` to `WorkspaceContext` |
| `crates/sis-pdf-gui/src/shortcuts.rs` | `F` key toggles `show_findings` (was: clear `show_chains`). `C` key toggles `show_chains`. Escape chain includes `show_findings` and `show_chains`. Arrow keys gated on `show_findings` instead of `!show_chains`. |
| `crates/sis-pdf-gui/src/analysis.rs` | Added `pdf_version: Option<String>` and `page_count: usize` to `AnalysisResult`. Added `extract_pdf_version()` and `count_pages()` helpers. |
| `crates/sis-pdf-gui/src/util.rs` | **New file.** Canonical `parse_obj_ref()` with unit tests. |
| `crates/sis-pdf-gui/src/window_state.rs` | **New file.** `WindowMaxState` struct and `maximise_button()` helper. |
| `crates/sis-pdf-gui/src/panels/summary.rs` | Added `show_top_bar()` with File menu (`MenuBar::new`), tab labels, theme toggle button. `show()` now displays PDF version, page count, scan duration, formatted file size. Removed standalone `show_tab_bar` (now private `show_tab_bar_inner`). Added `format_file_size()`. |
| `crates/sis-pdf-gui/src/panels/nav.rs` | Findings and Chains buttons now toggle independent booleans instead of mutual exclusion. |
| `crates/sis-pdf-gui/src/panels/findings.rs` | Added `show_window()` wrapper with maximise support. Added text search, surface dropdown, confidence slider, CVE/auto-triggered toggle filters. Fixed Confidence sorting to use `confidence_rank()` (Certain < Heuristic). Fixed Surface sorting to use `surface_label()` (human-readable). Added `severity_colour()` for colour-coded severity cells. Added `confidence_label()`, `surface_label()`, `confidence_threshold_label()`. Added empty state with "Reset filters" button. |
| `crates/sis-pdf-gui/src/panels/detail.rs` | Added `show_window()` wrapper with maximise support. All sections now collapsible via `CollapsingState` (Description, Evidence, Objects, Chain Membership default open; Reader Impacts, Metadata default collapsed). Added Chain Membership section (clickable links to chains). Added CVE References section (extracted from `meta` keys). Added YARA Matches section (`rule_name`, `tags`, `strings`). Reader impacts rendered as structured grid table. |
| `crates/sis-pdf-gui/src/panels/chains.rs` | Added `show_window()` wrapper with maximise support. Added sort controls (Score, Path, Findings) with toggle direction. Chain list rendered in sorted order. |
| `crates/sis-pdf-gui/src/panels/metadata.rs` | Added `show_encryption()` (resolves /Encrypt dict from catalog). Added `show_temporal_signals()` (revisions, new surfaces, deltas). Added `show_revision_timeline()` (temporal snapshots grid). Structure section now shows page count and PDF version. |
| `crates/sis-pdf-gui/src/panels/objects.rs` | Added maximise support to Object Inspector window. Added "Copy as JSON" button (serialises obj/gen/type/dict to clipboard). Replaced local `parse_obj_ref` with `crate::util::parse_obj_ref`. |
| `crates/sis-pdf-gui/src/panels/command_bar.rs` | Full command history cycling via `command_history_pos`: up arrow decrements, down arrow increments, typing resets position. History pos reset on command execution. |
| `crates/sis-pdf-gui/src/panels/drop_zone.rs` | Shows spinner with "Analysing {file_name}..." during `AppState::Analysing`. |

## Stage 1: Top Bar, Theme Toggle, and Layout Restructure

**Goal**: Add application top bar (File menu, tab labels, theme toggle). Convert Findings, Chains, and Detail from fixed panels to floating windows. Widen left nav column.

**Issues addressed**: #1 (no top bar), #3 (findings/chains fill CentralPanel), #5 (nav too narrow), #7 (detail always visible), #9 (no theme toggle)

**Changes**:
- `app.rs`: Added `show_findings: bool` and `dark_mode: bool` fields. Restructured `update()` layout from `TopBottomPanel(summary) + SidePanel(nav,80px) + SidePanel(detail) + CentralPanel(findings|chains)` to `TopBottomPanel(top_bar) + TopBottomPanel(workspace_bar) + SidePanel(nav,120px) + CentralPanel(empty) + floating Windows`. Theme visuals set per frame via `ctx.set_visuals()`. Initial theme set in `SisApp::new()`.
- `workspace.rs`: Added `show_findings` to `WorkspaceContext`.
- `summary.rs`: New `show_top_bar()` with `egui::MenuBar::new()` File menu, tab labels (always shown even for single file), right-aligned theme toggle. Replaced deprecated `egui::menu::bar` and `ui.close_menu()`.
- `findings.rs`: Added `show_window()` wrapping `show()` in `egui::Window`.
- `chains.rs`: Added `show_window()` wrapping `show()` in `egui::Window`.
- `detail.rs`: Added `show_window()` wrapping `show()` in `egui::Window` (only shown when `selected_finding.is_some()`).
- `nav.rs`: Findings/Chains buttons now toggle independent booleans.
- `shortcuts.rs`: `F` toggles `show_findings`, `C` toggles `show_chains`, escape chain extended.

**Status**: Complete

## Stage 2: Findings Filters, Sorting Fixes, Severity Colours

**Goal**: Add all missing filter controls, fix incorrect sorting, add severity colour coding, handle empty states.

**Issues addressed**: #4 (missing filters), #6 (severity not coloured), #10 (sort by Debug string), #17 (no empty state)

**Changes**:
- `app.rs`: Added `findings_search: String`, `surface_filter: Option<String>`, `min_confidence: u8`, `has_cve_filter: bool`, `auto_triggered_filter: bool` fields. All persisted in `WorkspaceContext` and reset on file drop.
- `findings.rs`: Completely rewritten filter/sort/display logic:
  - Extended filter bar: text search (matches kind/title/description), surface dropdown (populated from findings), confidence slider (0=All to 5=Heuristic+), CVE toggle, auto-triggered toggle.
  - All 6 filters combine with AND logic.
  - Confidence sorting uses `confidence_rank()` (Certain=0 < Heuristic=5) instead of `format!("{:?}")`.
  - Surface sorting uses `surface_label()` (human-readable) instead of `format!("{:?}")`.
  - Severity cells colour-coded: Critical=red(220,50,50), High=orange(255,140,0), Medium=yellow(220,200,50), Low=blue(100,160,230), Info=grey(150,150,150).
  - Empty state: "No findings match the current filters (N total)" with "Reset filters" button when all filtered out; "No findings detected" when none exist.
  - Added `confidence_label()` and `surface_label()` for human-readable column text.

**Status**: Complete

## Stage 3: Workspace Top Bar, File Size, Detail Sections, Metadata

**Goal**: Complete workspace-top-bar with missing fields, format file size, make detail sections collapsible, add CVE/YARA/Chain Membership sections, extend Metadata panel.

**Issues addressed**: #8 (missing top bar fields), #12 (sections not collapsible), #13 (missing detail sections), #18 (raw file size), #20 (missing metadata sections)

**Changes**:
- `analysis.rs`: Added `pdf_version: Option<String>` and `page_count: usize` to `AnalysisResult`. `extract_pdf_version()` parses `%PDF-X.Y` header. `count_pages()` counts objects with `obj_type == "page"`.
- `summary.rs`: Workspace bar now shows: file name, formatted file size (KB/MB/GB via `format_file_size()`), PDF version, page count, object count, scan duration (ms), severity counts, chain count.
- `detail.rs`: All sections converted to collapsible `CollapsingState`. Default open: Description, Evidence, Objects, Chain Membership. Default collapsed: Reader Impacts, Metadata.
  - New **Chain Membership** section: finds chains containing this finding's ID, renders as clickable links that open Chains panel and select the chain.
  - New **CVE References** section: extracts from `f.meta` keys containing "cve".
  - New **YARA Matches** section: shows `rule_name`, `tags`, `strings` when `f.yara` present.
  - **Reader Impacts** section: structured grid table (Reader, Severity, Impact, Notes) instead of pre-formatted strings.
- `metadata.rs`: Added `show_encryption()` (resolves /Encrypt dict reference from catalog, shows all encrypt dict entries). Added `show_temporal_signals()` (revisions, new_high_severity, new_attack_surfaces, new_findings, removed_findings, structural_deltas from `report.temporal_signals`). Added `show_revision_timeline()` (renders `report.temporal_snapshots` as grid: version_label, score, high_severity_count, finding_count). Structure section now includes page count and PDF version.

**Status**: Complete

## Stage 4: Code Cleanup, Chain Sorting, Progress Indicator, Polish

**Goal**: Deduplicate `parse_obj_ref`, add chain sorting, fix command history, add "Copy as JSON" to Object Inspector, add analysis progress indicator.

**Issues addressed**: #2 (no progress indicator), #14 (chains not sortable), #15 (parse_obj_ref duplicated), #16 (command history), #19 (no Copy as JSON)

**Changes**:
- `util.rs`: **New file.** Canonical `parse_obj_ref(s: &str) -> Option<(u32, u16)>` with unit tests.
- `detail.rs`, `metadata.rs`, `objects.rs`: Local `parse_obj_ref` replaced with thin wrappers calling `crate::util::parse_obj_ref`.
- `app.rs`: Added `ChainSortColumn` enum (Score, Path, Findings). Added `chain_sort_column`, `chain_sort_ascending`, `command_history_pos` fields. Added `AppState` enum (Idle, Analysing). `handle_file_drop()` now sets `AppState::Analysing` instead of calling `analyze()` directly. New `process_analysis()` runs analysis on the next frame. `update()` checks for `AppState::Analysing` before panel rendering.
- `chains.rs`: Added sort controls (Score/Path/Findings buttons with direction toggle). Chain list rendered via sorted index vector.
- `command_bar.rs`: Full history cycling: up arrow walks backwards through history, down arrow walks forward, reaching the end clears input. Typing resets position. Position reset on execute.
- `objects.rs`: Added "Copy as JSON" button that serialises `{obj, gen, type, dict}` to clipboard via `ui.ctx().copy_text()`.
- `drop_zone.rs`: Shows spinner with file name during `AppState::Analysing`.

**Status**: Complete

## Stage 5: Window Maximise, Confidence Labels, Final Polish

**Goal**: Add maximise/restore to floating windows, clean up confidence display, polish reader impact table.

**Issues addressed**: #11 (no maximise/unmaximise)

**Changes**:
- `window_state.rs`: **New file.** `WindowMaxState { is_maximised: bool }` and `maximise_button()` helper.
- `app.rs`: Added `window_max: HashMap<String, WindowMaxState>` field.
- All 5 floating windows (Findings, Chains, Finding Detail, Metadata, Object Inspector) updated:
  - Each has a "Max"/"Restore" toggle button in the first row.
  - When maximised, window uses `fixed_pos(available_rect.left_top())` and `fixed_size(available_rect.size())` to fill the workspace area.
  - When not maximised, uses `default_size()` with original dimensions.
- Confidence and Surface columns already cleaned up in Stage 2 (`confidence_label()` and `surface_label()` produce human-readable text).

**Status**: Complete

## Issue-to-Stage Map

| # | Issue | Stage | Resolution |
|---|-------|-------|------------|
| 1 | No top bar (File menu, theme, tabs) | 1 | `show_top_bar()` in summary.rs |
| 2 | No progress indicator during analysis | 4 | `AppState::Analysing` + spinner in drop_zone.rs |
| 3 | Findings/Chains fill CentralPanel | 1 | Converted to floating `egui::Window` |
| 4 | Missing findings filters | 2 | 6 filter controls in findings.rs |
| 5 | Left nav column too narrow | 1 | Changed from 80px to 120px |
| 6 | Severity not colour-coded in table | 2 | `severity_colour()` applied to severity cells |
| 7 | Detail panel always consuming space | 1 | Converted to floating window, only shown when finding selected |
| 8 | Missing workspace-top-bar fields | 3 | PDF version, page count, scan duration added |
| 9 | No theme toggle | 1 | Light/Dark button in top bar |
| 10 | Sorting by Debug string | 2 | `confidence_rank()` and `surface_label()` for sorting |
| 11 | Dialogs lack maximise/unmaximise | 5 | `WindowMaxState` + maximise button on all 5 windows |
| 12 | Detail sections not collapsible | 3 | `CollapsingState` with configurable default open/closed |
| 13 | Missing detail sections (CVE, YARA, Chain) | 3 | Chain Membership, CVE References, YARA Matches sections |
| 14 | Chain panel not sortable | 4 | Sort by Score/Path/Findings with direction toggle |
| 15 | parse_obj_ref duplicated 3x | 4 | Canonical impl in util.rs, 3 call sites updated |
| 16 | Command history only recalls last entry | 4 | Full up/down cycling via `command_history_pos` |
| 17 | No empty state for filtered findings | 2 | "No findings match" + "Reset filters" button |
| 18 | File size shown as raw bytes | 3 | `format_file_size()` returns KB/MB/GB |
| 19 | No Copy as JSON on Object Inspector | 4 | "Copy as JSON" button serialises to clipboard |
| 20 | Missing Metadata panel sections | 3 | Encryption, Temporal Signals, Revision Timeline sections |

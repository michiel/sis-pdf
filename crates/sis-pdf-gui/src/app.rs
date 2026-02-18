use crate::analysis::{AnalysisError, AnalysisResult, WorkerAnalysisResult};
use crate::telemetry::TelemetryLog;
use crate::window_state::WindowMaxState;
use crate::workspace::{self, WorkspaceContext};
#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
#[cfg(target_arch = "wasm32")]
use std::rc::Rc;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

/// Application state for the PDF security analyser.
pub struct SisApp {
    // --- Active workspace state (panels read/write these directly) ---
    /// Current analysis result, if a file has been analysed.
    pub result: Option<AnalysisResult>,
    /// Index of the currently selected finding in the table.
    pub selected_finding: Option<usize>,
    /// Whether to show the findings floating window.
    pub show_findings: bool,
    /// Whether to show the chains floating window.
    pub show_chains: bool,
    /// Whether to show the metadata floating window.
    pub show_metadata: bool,
    /// Whether to show the Object Inspector floating window.
    pub show_objects: bool,
    /// Currently selected object in the Object Inspector.
    pub selected_object: Option<(u32, u16)>,
    /// Type filter for the Object Inspector list.
    pub object_type_filter: Option<String>,
    /// Object Inspector back/forward navigation stack.
    pub object_nav_stack: Vec<(u32, u16)>,
    /// Current position within the navigation stack.
    pub object_nav_pos: usize,
    /// Object Inspector search text.
    pub object_search: String,
    /// Whether to show stream content as hex instead of text.
    pub show_stream_hex: bool,
    /// Whether to show the hex viewer panel.
    pub show_hex: bool,
    /// Hex viewer state.
    pub hex_view: HexViewState,
    /// Whether to show the command bar.
    pub show_command_bar: bool,
    /// Current command bar input text.
    pub command_input: String,
    /// Command history for up-arrow recall.
    pub command_history: Vec<String>,
    /// Command bar output results.
    pub command_results: Vec<crate::query::QueryOutput>,
    /// Active severity filters (true = shown).
    pub severity_filters: SeverityFilters,
    /// Current sort column and direction.
    pub sort: SortState,
    /// Text search filter for findings.
    pub findings_search: String,
    /// Attack surface filter (None = all, Some(name) = specific surface).
    pub surface_filter: Option<String>,
    /// Minimum confidence filter (0 = show all, higher = stricter).
    pub min_confidence: u8,
    /// Filter to show only findings with CVE references.
    pub has_cve_filter: bool,
    /// Filter to show only auto-triggered findings.
    pub auto_triggered_filter: bool,
    /// Chain sort column.
    pub chain_sort_column: ChainSortColumn,
    /// Chain sort direction.
    pub chain_sort_ascending: bool,
    /// Command history position for up/down arrow cycling.
    pub command_history_pos: Option<usize>,
    /// Whether to show the graph viewer.
    pub show_graph: bool,
    /// Graph viewer state.
    pub graph_state: crate::panels::graph::GraphViewerState,
    /// Currently selected chain index (for graph highlighting).
    pub selected_chain: Option<usize>,
    /// Whether chain views should include single-item chains.
    pub include_singleton_chains: bool,

    // --- Multi-tab state ---
    /// Inactive workspaces (all tabs except the active one).
    pub inactive_workspaces: Vec<WorkspaceContext>,
    /// Index of the currently active tab (0-based across all workspaces).
    pub active_tab: usize,
    /// Total number of open tabs (1 + inactive_workspaces.len() when result is Some).
    pub tab_count: usize,
    /// Name of the active tab.
    pub active_tab_name: String,

    // --- Global state ---
    /// Application state for progress indication.
    pub app_state: AppState,
    /// Per-window maximise state, keyed by window name.
    pub window_max: HashMap<String, WindowMaxState>,
    /// Dark mode toggle (global, not per-tab).
    pub dark_mode: bool,
    /// Current error, if analysis failed.
    pub error: Option<AnalysisError>,
    /// Telemetry log (global, not per-tab).
    pub telemetry: TelemetryLog,
    /// Whether to show the telemetry debug panel.
    pub show_telemetry: bool,
    /// Elapsed time since app start, in seconds.
    pub elapsed_time: f64,
    #[cfg(target_arch = "wasm32")]
    pending_upload: Rc<RefCell<Option<(String, Vec<u8>)>>>,
    #[cfg(target_arch = "wasm32")]
    pending_worker_result: Rc<RefCell<Option<WorkerAnalysisOutcome>>>,
    #[cfg(target_arch = "wasm32")]
    analysis_worker: Option<web_sys::Worker>,
    #[cfg(target_arch = "wasm32")]
    analysis_worker_onmessage:
        Option<wasm_bindgen::closure::Closure<dyn FnMut(web_sys::MessageEvent)>>,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
enum WorkerAnalysisOutcome {
    Ok { result: WorkerAnalysisResult, result_bytes: usize, decode_ms: f64, received_ms: f64 },
    Err(String),
}

pub struct SeverityFilters {
    pub critical: bool,
    pub high: bool,
    pub medium: bool,
    pub low: bool,
    pub info: bool,
}

impl Default for SeverityFilters {
    fn default() -> Self {
        Self { critical: true, high: true, medium: true, low: true, info: true }
    }
}

pub struct SortState {
    pub column: SortColumn,
    pub ascending: bool,
}

impl Default for SortState {
    fn default() -> Self {
        Self { column: SortColumn::Severity, ascending: true }
    }
}

#[derive(Default, PartialEq)]
pub enum SortColumn {
    #[default]
    Severity,
    Confidence,
    Kind,
    Surface,
}

/// Application state for progress indication during analysis.
#[derive(Default)]
pub enum AppState {
    /// No analysis in progress.
    #[default]
    Idle,
    /// File is being loaded from disk before analysis.
    LoadingPath { file_name: String, path: PathBuf, shown_once: bool },
    /// Analysis is queued (renders spinner on next frame).
    Analysing { file_name: String, bytes: Vec<u8>, shown_once: bool },
    #[cfg(target_arch = "wasm32")]
    /// Analysis has been dispatched to the browser worker and is still running.
    AnalysingWorker { file_name: String, bytes: Vec<u8>, request_bytes: usize, started_ms: f64 },
}

#[derive(Default, PartialEq)]
pub enum ChainSortColumn {
    #[default]
    Score,
    Path,
    Findings,
}

/// State for the hex viewer panel.
#[derive(Default)]
pub struct HexViewState {
    pub source: HexSource,
    pub highlights: Vec<HexHighlight>,
}

/// Data source for the hex viewer.
#[derive(Default, PartialEq)]
pub enum HexSource {
    #[default]
    File,
    Stream {
        obj: u32,
        gen: u16,
    },
}

/// A highlighted region in the hex viewer.
pub struct HexHighlight {
    pub start: usize,
    pub length: usize,
    pub color: egui::Color32,
    pub label: String,
}

#[cfg(target_arch = "wasm32")]
fn now_ms() -> f64 {
    if let Some(window) = web_sys::window() {
        if let Some(performance) = window.performance() {
            return performance.now();
        }
    }
    js_sys::Date::now()
}

impl SisApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        Self {
            result: None,
            dark_mode: false,
            error: None,
            selected_finding: None,
            show_findings: true,
            show_chains: false,
            show_metadata: false,
            show_objects: false,
            selected_object: None,
            object_type_filter: None,
            object_nav_stack: Vec::new(),
            object_nav_pos: 0,
            object_search: String::new(),
            show_stream_hex: false,
            show_hex: false,
            hex_view: HexViewState::default(),
            show_command_bar: false,
            command_input: String::new(),
            command_history: Vec::new(),
            command_results: Vec::new(),
            severity_filters: SeverityFilters::default(),
            sort: SortState::default(),
            findings_search: String::new(),
            surface_filter: None,
            min_confidence: 0,
            has_cve_filter: false,
            auto_triggered_filter: false,
            chain_sort_column: ChainSortColumn::default(),
            chain_sort_ascending: false,
            command_history_pos: None,
            show_graph: false,
            graph_state: crate::panels::graph::GraphViewerState::default(),
            selected_chain: None,
            include_singleton_chains: false,
            inactive_workspaces: Vec::new(),
            active_tab: 0,
            tab_count: 0,
            active_tab_name: String::new(),
            app_state: AppState::default(),
            window_max: HashMap::new(),
            telemetry: TelemetryLog::new(),
            show_telemetry: false,
            elapsed_time: 0.0,
            #[cfg(target_arch = "wasm32")]
            pending_upload: Rc::new(RefCell::new(None)),
            #[cfg(target_arch = "wasm32")]
            pending_worker_result: Rc::new(RefCell::new(None)),
            #[cfg(target_arch = "wasm32")]
            analysis_worker: None,
            #[cfg(target_arch = "wasm32")]
            analysis_worker_onmessage: None,
        }
    }

    /// Queue a file for analysis. The actual analysis runs on the next frame
    /// so the progress spinner has a chance to render.
    pub fn handle_file_drop(&mut self, name: String, bytes: &[u8]) {
        self.error = None;
        self.app_state =
            AppState::Analysing { file_name: name, bytes: bytes.to_vec(), shown_once: false };
    }

    /// Queue a file path for loading before analysis.
    pub fn handle_file_path_drop(&mut self, file_name: String, path: PathBuf) {
        self.error = None;
        self.app_state = AppState::LoadingPath { file_name, path, shown_once: false };
    }

    /// Run analysis and open the result as a new tab.
    #[cfg(not(target_arch = "wasm32"))]
    fn process_analysis(&mut self, name: String, bytes: &[u8]) {
        let file_size = bytes.len();

        match crate::analysis::analyze(bytes, &name) {
            Ok(result) => {
                self.open_analysis_result(name, file_size, result);
            }
            Err(err) => {
                self.error = Some(err);
            }
        }
    }

    fn open_analysis_result(&mut self, name: String, file_size: usize, result: AnalysisResult) {
        self.telemetry.record(
            self.elapsed_time,
            crate::telemetry::TelemetryEventKind::FileOpened { file_name: name, file_size },
        );
        // Save the current active workspace (if any) before switching
        self.save_active_workspace();

        // Enforce tab limit: evict oldest inactive tab if needed
        while self.inactive_workspaces.len() >= workspace::MAX_TABS {
            self.inactive_workspaces.remove(0);
        }

        // Set up the new workspace as active
        self.active_tab_name = result.file_name.clone();
        self.result = Some(result);
        self.selected_finding = None;
        self.selected_object = None;
        self.object_type_filter = None;
        self.object_nav_stack.clear();
        self.object_nav_pos = 0;
        self.object_search.clear();
        self.show_stream_hex = false;
        self.show_hex = false;
        self.hex_view = HexViewState::default();
        self.show_command_bar = false;
        self.command_input.clear();
        self.command_history.clear();
        self.command_results.clear();
        self.show_findings = true;
        self.show_chains = false;
        self.show_metadata = false;
        self.show_objects = false;
        self.show_graph = false;
        self.graph_state = crate::panels::graph::GraphViewerState::default();
        self.selected_chain = None;
        self.include_singleton_chains = false;
        self.severity_filters = SeverityFilters::default();
        self.sort = SortState::default();
        self.findings_search.clear();
        self.surface_filter = None;
        self.min_confidence = 0;
        self.has_cve_filter = false;
        self.auto_triggered_filter = false;
        self.chain_sort_column = ChainSortColumn::default();
        self.chain_sort_ascending = false;
        self.command_history_pos = None;

        // Active tab is the last one
        self.active_tab = self.inactive_workspaces.len();
        self.tab_count = self.inactive_workspaces.len() + 1;
    }

    #[cfg(target_arch = "wasm32")]
    fn ensure_analysis_worker(&mut self) -> Result<(), AnalysisError> {
        if self.analysis_worker.is_some() {
            return Ok(());
        }
        let worker = web_sys::Worker::new("./analysis_worker.js").map_err(|_| {
            AnalysisError::ParseFailed("Failed to initialise analysis worker".to_string())
        })?;
        let pending_result = Rc::clone(&self.pending_worker_result);
        let onmessage = wasm_bindgen::closure::Closure::<dyn FnMut(web_sys::MessageEvent)>::new(
            move |event: web_sys::MessageEvent| {
                let payload = event.data();
                let ok = js_sys::Reflect::get(&payload, &JsValue::from_str("ok"))
                    .ok()
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false);
                if !ok {
                    let error = js_sys::Reflect::get(&payload, &JsValue::from_str("error"))
                        .ok()
                        .and_then(|value| value.as_string())
                        .unwrap_or_else(|| "Worker reported unsuccessful analysis".to_string());
                    *pending_result.borrow_mut() = Some(WorkerAnalysisOutcome::Err(error));
                    return;
                }

                let result_value =
                    match js_sys::Reflect::get(&payload, &JsValue::from_str("result")) {
                        Ok(value) => value,
                        Err(_) => {
                            *pending_result.borrow_mut() = Some(WorkerAnalysisOutcome::Err(
                                "Worker response missing result payload".to_string(),
                            ));
                            return;
                        }
                    };
                let decode_started_ms = now_ms();
                let result_bytes = js_sys::JSON::stringify(&result_value)
                    .ok()
                    .and_then(|json| json.as_string())
                    .map(|json| json.len())
                    .unwrap_or(0);
                match js_sys::JSON::stringify(&result_value)
                    .ok()
                    .and_then(|json| json.as_string())
                    .and_then(|json| serde_json::from_str::<WorkerAnalysisResult>(&json).ok())
                {
                    Some(parsed) => {
                        *pending_result.borrow_mut() = Some(WorkerAnalysisOutcome::Ok {
                            result: parsed,
                            result_bytes,
                            decode_ms: (now_ms() - decode_started_ms).max(0.0),
                            received_ms: now_ms(),
                        });
                    }
                    None => {
                        *pending_result.borrow_mut() = Some(WorkerAnalysisOutcome::Err(
                            "Failed to decode worker result".to_string(),
                        ));
                    }
                };
            },
        );
        worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        self.analysis_worker_onmessage = Some(onmessage);
        self.analysis_worker = Some(worker);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    fn dispatch_worker_analysis(
        &mut self,
        file_name: String,
        bytes: &[u8],
    ) -> Result<usize, AnalysisError> {
        self.ensure_analysis_worker()?;
        let worker = self.analysis_worker.as_ref().ok_or_else(|| {
            AnalysisError::ParseFailed("Analysis worker is unavailable".to_string())
        })?;

        let buffer_len = u32::try_from(bytes.len()).map_err(|_| {
            AnalysisError::ParseFailed("PDF exceeds browser transfer capacity".to_string())
        })?;
        let byte_view = js_sys::Uint8Array::new_with_length(buffer_len);
        byte_view.copy_from(bytes);

        let request = js_sys::Object::new();
        js_sys::Reflect::set(
            &request,
            &JsValue::from_str("file_name"),
            &JsValue::from_str(&file_name),
        )
        .map_err(|_| AnalysisError::ParseFailed("Failed to encode worker request".to_string()))?;
        js_sys::Reflect::set(&request, &JsValue::from_str("bytes"), &byte_view.buffer()).map_err(
            |_| AnalysisError::ParseFailed("Failed to encode worker request".to_string()),
        )?;

        let transferables = js_sys::Array::new();
        transferables.push(&byte_view.buffer());
        worker.post_message_with_transfer(&request, &transferables).map_err(|_| {
            AnalysisError::ParseFailed("Failed to send work to analysis worker".to_string())
        })?;
        Ok(bytes.len())
    }

    /// Save the current active workspace into the inactive list.
    fn save_active_workspace(&mut self) {
        if let Some(result) = self.result.take() {
            let ws = WorkspaceContext {
                result,
                selected_finding: self.selected_finding.take(),
                show_findings: self.show_findings,
                show_chains: self.show_chains,
                show_metadata: self.show_metadata,
                show_objects: self.show_objects,
                show_hex: self.show_hex,
                selected_object: self.selected_object.take(),
                object_type_filter: self.object_type_filter.take(),
                object_nav_stack: std::mem::take(&mut self.object_nav_stack),
                object_nav_pos: self.object_nav_pos,
                object_search: std::mem::take(&mut self.object_search),
                show_stream_hex: self.show_stream_hex,
                hex_view: std::mem::take(&mut self.hex_view),
                severity_filters: std::mem::take(&mut self.severity_filters),
                sort: std::mem::take(&mut self.sort),
                findings_search: std::mem::take(&mut self.findings_search),
                surface_filter: self.surface_filter.take(),
                min_confidence: self.min_confidence,
                has_cve_filter: self.has_cve_filter,
                auto_triggered_filter: self.auto_triggered_filter,
                chain_sort_column: std::mem::take(&mut self.chain_sort_column),
                chain_sort_ascending: self.chain_sort_ascending,
                command_history_pos: self.command_history_pos.take(),
                show_command_bar: self.show_command_bar,
                command_input: std::mem::take(&mut self.command_input),
                command_history: std::mem::take(&mut self.command_history),
                command_results: std::mem::take(&mut self.command_results),
                tab_name: std::mem::take(&mut self.active_tab_name),
                show_graph: self.show_graph,
                graph_state: std::mem::take(&mut self.graph_state),
                selected_chain: self.selected_chain.take(),
                include_singleton_chains: self.include_singleton_chains,
            };
            self.inactive_workspaces.push(ws);
        }
    }

    /// Restore a workspace from the inactive list to active.
    fn restore_workspace(&mut self, index: usize) {
        if index >= self.inactive_workspaces.len() {
            return;
        }
        let ws = self.inactive_workspaces.remove(index);
        self.result = Some(ws.result);
        self.selected_finding = ws.selected_finding;
        self.show_findings = ws.show_findings;
        self.show_chains = ws.show_chains;
        self.show_metadata = ws.show_metadata;
        self.show_objects = ws.show_objects;
        self.show_hex = ws.show_hex;
        self.selected_object = ws.selected_object;
        self.object_type_filter = ws.object_type_filter;
        self.object_nav_stack = ws.object_nav_stack;
        self.object_nav_pos = ws.object_nav_pos;
        self.object_search = ws.object_search;
        self.show_stream_hex = ws.show_stream_hex;
        self.hex_view = ws.hex_view;
        self.severity_filters = ws.severity_filters;
        self.sort = ws.sort;
        self.findings_search = ws.findings_search;
        self.surface_filter = ws.surface_filter;
        self.min_confidence = ws.min_confidence;
        self.has_cve_filter = ws.has_cve_filter;
        self.auto_triggered_filter = ws.auto_triggered_filter;
        self.chain_sort_column = ws.chain_sort_column;
        self.chain_sort_ascending = ws.chain_sort_ascending;
        self.command_history_pos = ws.command_history_pos;
        self.show_command_bar = ws.show_command_bar;
        self.command_input = ws.command_input;
        self.command_history = ws.command_history;
        self.command_results = ws.command_results;
        self.active_tab_name = ws.tab_name;
        self.show_graph = ws.show_graph;
        self.graph_state = ws.graph_state;
        self.selected_chain = ws.selected_chain;
        self.include_singleton_chains = ws.include_singleton_chains;
    }

    /// Switch to a different tab by index.
    pub fn switch_tab(&mut self, tab_index: usize) {
        if tab_index == self.active_tab {
            return;
        }
        self.telemetry.record(
            self.elapsed_time,
            crate::telemetry::TelemetryEventKind::TabSwitched {
                from: self.active_tab,
                to: tab_index,
            },
        );
        // Save current active as inactive
        self.save_active_workspace();

        // The workspaces list now has all tabs. Restore the requested one.
        if tab_index < self.inactive_workspaces.len() {
            self.restore_workspace(tab_index);
            // After removing from inactive, recalculate active_tab
            self.active_tab = tab_index;
            self.tab_count = self.inactive_workspaces.len() + 1;
        }
    }

    /// Close a tab by index. Returns true if a tab was closed.
    pub fn close_tab(&mut self, tab_index: usize) -> bool {
        if self.tab_count <= 1 {
            // Closing the last tab: reset to drop zone
            self.result = None;
            self.tab_count = 0;
            self.active_tab = 0;
            self.inactive_workspaces.clear();
            return true;
        }

        if tab_index == self.active_tab {
            // Closing the active tab: switch to another first
            let new_active = if tab_index > 0 { tab_index - 1 } else { 0 };
            self.save_active_workspace();
            // Remove the closed tab
            if tab_index < self.inactive_workspaces.len() {
                self.inactive_workspaces.remove(tab_index);
            }
            // Restore the new active
            let restore_idx = new_active.min(self.inactive_workspaces.len().saturating_sub(1));
            if !self.inactive_workspaces.is_empty() {
                self.restore_workspace(restore_idx);
                self.active_tab = restore_idx;
                self.tab_count = self.inactive_workspaces.len() + 1;
            } else {
                self.tab_count = 0;
                self.active_tab = 0;
            }
        } else {
            // Closing an inactive tab
            // Convert tab_index to inactive index: tabs before active are at same index,
            // tabs after active are at index - 1 (since active is not in inactive list)
            let inactive_idx = if tab_index < self.active_tab { tab_index } else { tab_index - 1 };
            if inactive_idx < self.inactive_workspaces.len() {
                self.inactive_workspaces.remove(inactive_idx);
            }
            self.tab_count = self.inactive_workspaces.len() + 1;
            // Adjust active_tab if needed
            if self.active_tab > tab_index {
                self.active_tab -= 1;
            }
        }
        true
    }

    /// Get the list of all tab names in order, for display in the tab bar.
    pub fn tab_names(&self) -> Vec<String> {
        let mut names = Vec::with_capacity(self.tab_count);
        for (i, ws) in self.inactive_workspaces.iter().enumerate() {
            if i == self.active_tab {
                // Insert the active tab at its position
                names.push(self.active_tab_name.clone());
            }
            names.push(ws.tab_name.clone());
        }
        // If active_tab is at the end (or the only tab)
        if self.active_tab >= self.inactive_workspaces.len() && self.result.is_some() {
            names.push(self.active_tab_name.clone());
        }
        names
    }

    /// Navigate to an object in the Object Inspector, pushing to the nav stack.
    pub fn navigate_to_object(&mut self, obj: u32, gen: u16) {
        let target = (obj, gen);
        if self.selected_object == Some(target) {
            return;
        }
        // Truncate forward history if we navigated back
        if !self.object_nav_stack.is_empty() && self.object_nav_pos < self.object_nav_stack.len() {
            self.object_nav_stack.truncate(self.object_nav_pos);
        }
        self.object_nav_stack.push(target);
        self.object_nav_pos = self.object_nav_stack.len();
        self.selected_object = Some(target);
    }

    /// Navigate back in the Object Inspector history.
    pub fn object_nav_back(&mut self) {
        if self.object_nav_pos > 1 {
            self.object_nav_pos -= 1;
            self.selected_object = Some(self.object_nav_stack[self.object_nav_pos - 1]);
        }
    }

    /// Navigate forward in the Object Inspector history.
    pub fn object_nav_forward(&mut self) {
        if self.object_nav_pos < self.object_nav_stack.len() {
            self.object_nav_pos += 1;
            self.selected_object = Some(self.object_nav_stack[self.object_nav_pos - 1]);
        }
    }

    /// Open the hex viewer showing file bytes with an evidence highlight.
    pub fn open_hex_at_evidence(&mut self, offset: u64, length: u32, label: String) {
        self.hex_view = HexViewState {
            source: HexSource::File,
            highlights: vec![HexHighlight {
                start: offset as usize,
                length: length as usize,
                color: egui::Color32::from_rgba_premultiplied(255, 200, 0, 80),
                label,
            }],
        };
        self.show_hex = true;
    }

    /// Open the hex viewer showing a stream's raw bytes.
    pub fn open_hex_for_stream(&mut self, obj: u32, gen: u16) {
        self.hex_view =
            HexViewState { source: HexSource::Stream { obj, gen }, highlights: Vec::new() };
        self.show_hex = true;
    }

    pub fn request_file_upload(&mut self) {
        #[cfg(target_arch = "wasm32")]
        self.request_file_upload_wasm();
        #[cfg(not(target_arch = "wasm32"))]
        self.request_file_upload_native();
    }

    pub fn download_bytes(&mut self, suggested_name: &str, bytes: &[u8]) {
        #[cfg(target_arch = "wasm32")]
        self.download_bytes_wasm(suggested_name, bytes);
        #[cfg(not(target_arch = "wasm32"))]
        self.download_bytes_native(suggested_name, bytes);
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn download_bytes_native(&mut self, suggested_name: &str, bytes: &[u8]) {
        if let Some(path) = rfd::FileDialog::new().set_file_name(suggested_name).save_file() {
            if let Err(err) = std::fs::write(path, bytes) {
                self.error =
                    Some(AnalysisError::ParseFailed(format!("Failed to save file: {}", err)));
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn download_bytes_wasm(&mut self, suggested_name: &str, bytes: &[u8]) {
        use wasm_bindgen::JsCast;

        let Some(window) = web_sys::window() else {
            self.error =
                Some(AnalysisError::ParseFailed("No browser window available".to_string()));
            return;
        };
        let Some(document) = window.document() else {
            self.error =
                Some(AnalysisError::ParseFailed("No browser document available".to_string()));
            return;
        };

        let uint8 = js_sys::Uint8Array::from(bytes);
        let parts = js_sys::Array::new();
        parts.push(&uint8.buffer());
        let Ok(blob) = web_sys::Blob::new_with_u8_array_sequence(&parts) else {
            self.error =
                Some(AnalysisError::ParseFailed("Failed to create download blob".to_string()));
            return;
        };
        let Ok(url) = web_sys::Url::create_object_url_with_blob(&blob) else {
            self.error =
                Some(AnalysisError::ParseFailed("Failed to create download URL".to_string()));
            return;
        };

        let Ok(element) = document.create_element("a") else {
            let _ = web_sys::Url::revoke_object_url(&url);
            self.error =
                Some(AnalysisError::ParseFailed("Failed to create download link".to_string()));
            return;
        };
        if element.set_attribute("href", &url).is_err()
            || element.set_attribute("download", suggested_name).is_err()
        {
            let _ = web_sys::Url::revoke_object_url(&url);
            self.error =
                Some(AnalysisError::ParseFailed("Failed to configure download link".to_string()));
            return;
        }

        let Ok(anchor) = element.dyn_into::<web_sys::HtmlElement>() else {
            let _ = web_sys::Url::revoke_object_url(&url);
            self.error =
                Some(AnalysisError::ParseFailed("Failed to initialise download link".to_string()));
            return;
        };

        if let Some(body) = document.body() {
            let _ = body.append_child(&anchor);
            anchor.click();
            let _ = body.remove_child(&anchor);
        } else {
            anchor.click();
        }

        let _ = web_sys::Url::revoke_object_url(&url);
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn request_file_upload_native(&mut self) {
        if let Some(path) = rfd::FileDialog::new().add_filter("PDF document", &["pdf"]).pick_file()
        {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "uploaded.pdf".to_string());
            self.handle_file_path_drop(name, path);
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn request_file_upload_wasm(&mut self) {
        use wasm_bindgen::closure::Closure;
        use wasm_bindgen::JsCast;

        let Some(window) = web_sys::window() else {
            self.error =
                Some(AnalysisError::ParseFailed("No browser window available".to_string()));
            return;
        };
        let Some(document) = window.document() else {
            self.error =
                Some(AnalysisError::ParseFailed("No browser document available".to_string()));
            return;
        };
        let Ok(element) = document.create_element("input") else {
            self.error =
                Some(AnalysisError::ParseFailed("Failed to create file input".to_string()));
            return;
        };
        let Ok(input) = element.dyn_into::<web_sys::HtmlInputElement>() else {
            self.error =
                Some(AnalysisError::ParseFailed("Failed to initialise file input".to_string()));
            return;
        };
        input.set_type("file");
        input.set_accept(".pdf,application/pdf");
        input.set_hidden(true);

        if let Some(body) = document.body() {
            let _ = body.append_child(&input);
        }

        let pending_upload = Rc::clone(&self.pending_upload);
        let onchange = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            let Some(target) = event.target() else {
                return;
            };
            let Ok(input) = target.dyn_into::<web_sys::HtmlInputElement>() else {
                return;
            };
            let Some(files) = input.files() else {
                return;
            };
            let Some(file) = files.get(0) else {
                return;
            };
            let file_name = file.name();
            let Ok(reader) = web_sys::FileReader::new() else {
                return;
            };
            let pending_upload_inner = Rc::clone(&pending_upload);
            let onload = Closure::<dyn FnMut(web_sys::ProgressEvent)>::new(
                move |event: web_sys::ProgressEvent| {
                    let Some(target) = event.target() else {
                        return;
                    };
                    let Ok(reader) = target.dyn_into::<web_sys::FileReader>() else {
                        return;
                    };
                    let Ok(result) = reader.result() else {
                        return;
                    };
                    let bytes = js_sys::Uint8Array::new(&result).to_vec();
                    *pending_upload_inner.borrow_mut() = Some((file_name.clone(), bytes));
                },
            );
            reader.set_onload(Some(onload.as_ref().unchecked_ref()));
            let _ = reader.read_as_array_buffer(&file);
            onload.forget();
        });

        input.set_onchange(Some(onchange.as_ref().unchecked_ref()));
        onchange.forget();
        input.click();
    }
}

impl eframe::App for SisApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Record frame time for telemetry
        let dt = ctx.input(|i| i.stable_dt as f64);
        self.elapsed_time += dt;
        self.telemetry.record_frame_time(dt);

        #[cfg(target_arch = "wasm32")]
        {
            let maybe_upload = self.pending_upload.borrow_mut().take();
            if let Some((name, bytes)) = maybe_upload {
                self.handle_file_drop(name, &bytes);
            }
            let maybe_worker_result = self.pending_worker_result.borrow_mut().take();
            if let Some(outcome) = maybe_worker_result {
                match outcome {
                    WorkerAnalysisOutcome::Ok { result, result_bytes, decode_ms, received_ms } => {
                        let state = std::mem::replace(&mut self.app_state, AppState::Idle);
                        let (bytes, request_bytes, started_ms) = match state {
                            AppState::AnalysingWorker {
                                bytes, request_bytes, started_ms, ..
                            } => (bytes, request_bytes, started_ms),
                            other => {
                                self.app_state = other;
                                self.error = Some(AnalysisError::ParseFailed(
                                    "Worker result arrived without active worker state".to_string(),
                                ));
                                (Vec::new(), 0, 0.0)
                            }
                        };
                        if !bytes.is_empty() {
                            self.telemetry.record(
                                self.elapsed_time,
                                crate::telemetry::TelemetryEventKind::WorkerAnalysisCompleted {
                                    request_bytes,
                                    result_bytes,
                                    worker_roundtrip_ms: (received_ms - started_ms).max(0.0),
                                    decode_ms,
                                },
                            );
                            let file_size = bytes.len();
                            let file_name = result.file_name.clone();
                            let analysis =
                                crate::analysis::worker_result_into_analysis(result, bytes);
                            self.open_analysis_result(file_name, file_size, analysis);
                        }
                    }
                    WorkerAnalysisOutcome::Err(err) => {
                        self.app_state = AppState::Idle;
                        self.error = Some(AnalysisError::ParseFailed(err));
                    }
                }
            }
        }

        // Handle file drops
        let dropped_files: Vec<_> = ctx.input(|i| i.raw.dropped_files.clone());
        for file in dropped_files {
            let name = file.name.clone();
            if let Some(bytes) = file.bytes {
                self.handle_file_drop(name, &bytes);
            } else if let Some(path) = &file.path {
                let path_name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| name.clone());
                self.handle_file_path_drop(path_name, path.clone());
            }
        }

        let progress_state = match &self.app_state {
            AppState::Idle => None,
            AppState::LoadingPath { file_name, .. } => {
                Some(("Loading PDF".to_string(), file_name.clone()))
            }
            AppState::Analysing { file_name, .. } => {
                Some(("Processing PDF".to_string(), file_name.clone()))
            }
            #[cfg(target_arch = "wasm32")]
            AppState::AnalysingWorker { file_name, .. } => {
                Some(("Processing PDF".to_string(), file_name.clone()))
            }
        };

        // Handle keyboard shortcuts (after file drops, before panel rendering)
        if matches!(self.app_state, AppState::Idle) {
            crate::shortcuts::handle_shortcuts(ctx, self);
        }

        // Apply theme
        ctx.set_visuals(if self.dark_mode {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        });

        if self.result.is_some() {
            // Menu bar: File menu + cog + theme toggle
            egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
                crate::panels::summary::show_menu_bar(ui, self);
            });

            // Tab strip (only when multiple tabs are open)
            if self.tab_count > 1 {
                egui::TopBottomPanel::top("tab_strip").show(ctx, |ui| {
                    crate::panels::summary::show_tab_strip(ui, self);
                });
            }

            // Workspace bar: file summary
            egui::TopBottomPanel::top("workspace_bar").show(ctx, |ui| {
                crate::panels::summary::show(ui, self);
            });

            // Left: navigation column
            egui::SidePanel::left("nav_panel").exact_width(120.0).resizable(false).show(
                ctx,
                |ui| {
                    crate::panels::nav::show(ui, self);
                },
            );

            // Command bar (bottom panels, rendered before central to claim space)
            if self.show_command_bar {
                crate::panels::command_bar::show(ctx, self);
            }

            // Central: empty workspace background
            egui::CentralPanel::default().show(ctx, |_ui| {});

            // Floating windows
            if self.show_findings {
                crate::panels::findings::show_window(ctx, self);
            }

            if self.show_chains {
                crate::panels::chains::show_window(ctx, self);
            }

            if self.selected_finding.is_some() {
                crate::panels::detail::show_window(ctx, self);
            }

            if self.show_metadata {
                let mut open = true;
                let mut ws = self.window_max.remove("Metadata").unwrap_or_default();
                let win =
                    crate::window_state::dialog_window(ctx, "Metadata", [400.0, 500.0], &mut ws);
                win.show(ctx, |ui| {
                    crate::window_state::dialog_title_bar(ui, "Metadata", &mut open, &mut ws);
                    crate::panels::metadata::show(ui, self);
                });
                self.window_max.insert("Metadata".to_string(), ws);
                self.show_metadata = open;
            }

            if self.show_objects {
                crate::panels::objects::show(ctx, self);
            }

            if self.show_hex {
                crate::panels::hex_viewer::show(ctx, self);
            }

            if self.show_graph {
                crate::panels::graph::show(ctx, self);
            }

            if self.show_telemetry {
                crate::panels::telemetry_debug::show(ctx, self);
            }
        } else {
            // Show drop zone
            egui::CentralPanel::default().show(ctx, |ui| {
                crate::panels::drop_zone::show(ui, self);
            });
        }

        if let Some((phase, file_name)) = progress_state {
            show_analysis_progress_overlay(ctx, &phase, &file_name);
            ctx.request_repaint();

            let process_now = match &mut self.app_state {
                AppState::LoadingPath { shown_once, .. } => {
                    if *shown_once {
                        true
                    } else {
                        *shown_once = true;
                        false
                    }
                }
                AppState::Analysing { shown_once, .. } => {
                    if *shown_once {
                        true
                    } else {
                        *shown_once = true;
                        false
                    }
                }
                #[cfg(target_arch = "wasm32")]
                AppState::AnalysingWorker { .. } => false,
                AppState::Idle => false,
            };

            if !process_now {
                return;
            }

            let state = std::mem::replace(&mut self.app_state, AppState::Idle);
            match state {
                AppState::LoadingPath { file_name, path, .. } => {
                    #[cfg(not(target_arch = "wasm32"))]
                    match std::fs::read(&path) {
                        Ok(bytes) => {
                            self.app_state =
                                AppState::Analysing { file_name, bytes, shown_once: false };
                        }
                        Err(err) => {
                            self.error = Some(AnalysisError::ParseFailed(format!(
                                "Failed to read selected file: {}",
                                err
                            )));
                        }
                    }
                    #[cfg(target_arch = "wasm32")]
                    {
                        let _ = path;
                        self.error = Some(AnalysisError::ParseFailed(format!(
                            "Loading from path is not supported in browser mode for {}",
                            file_name
                        )));
                    }
                }
                AppState::Analysing { file_name, bytes, .. } => {
                    #[cfg(not(target_arch = "wasm32"))]
                    self.process_analysis(file_name, &bytes);
                    #[cfg(target_arch = "wasm32")]
                    match self.dispatch_worker_analysis(file_name.clone(), &bytes) {
                        Ok(request_bytes) => {
                            self.app_state = AppState::AnalysingWorker {
                                file_name,
                                bytes,
                                request_bytes,
                                started_ms: now_ms(),
                            };
                        }
                        Err(err) => {
                            self.error = Some(err);
                        }
                    }
                }
                #[cfg(target_arch = "wasm32")]
                AppState::AnalysingWorker { file_name, bytes, request_bytes, started_ms } => {
                    self.app_state =
                        AppState::AnalysingWorker { file_name, bytes, request_bytes, started_ms };
                }
                AppState::Idle => {}
            }
        }
    }
}

fn show_analysis_progress_overlay(ctx: &egui::Context, phase: &str, file_name: &str) {
    let screen_rect = ctx.content_rect();
    let dimmer = egui::Color32::from_rgba_premultiplied(
        0,
        0,
        0,
        if phase == "Loading PDF" { 170 } else { 190 },
    );
    ctx.layer_painter(egui::LayerId::new(
        egui::Order::Foreground,
        egui::Id::new("analysis_dimmer"),
    ))
    .rect_filled(screen_rect, 0.0, dimmer);

    egui::Area::new("analysis_progress_modal_blocker".into())
        .order(egui::Order::Foreground)
        .fixed_pos(screen_rect.min)
        .show(ctx, |ui| {
            ui.allocate_rect(
                egui::Rect::from_min_size(egui::Pos2::ZERO, screen_rect.size()),
                egui::Sense::click_and_drag(),
            );
        });

    let overlay_size = egui::vec2(380.0, 140.0);
    let position = screen_rect.center() - overlay_size * 0.5;

    egui::Area::new("analysis_progress_overlay".into())
        .order(egui::Order::Tooltip)
        .fixed_pos(position)
        .show(ctx, |ui| {
            egui::Frame::window(ui.style()).show(ui, |ui| {
                ui.set_min_size(overlay_size);
                ui.vertical_centered(|ui| {
                    ui.add_space(10.0);
                    ui.heading(phase);
                    ui.label(file_name);
                    ui.add_space(8.0);
                    ui.add(egui::ProgressBar::new(0.0).animate(true).show_percentage());
                    ui.add_space(6.0);
                    ui.spinner();
                });
            });
        });
}

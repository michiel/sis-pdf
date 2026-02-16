use crate::analysis::{AnalysisError, AnalysisResult};
use crate::workspace::{self, WorkspaceContext};
#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;
#[cfg(target_arch = "wasm32")]
use std::rc::Rc;

/// Application state for the PDF security analyser.
pub struct SisApp {
    // --- Active workspace state (panels read/write these directly) ---
    /// Current analysis result, if a file has been analysed.
    pub result: Option<AnalysisResult>,
    /// Index of the currently selected finding in the table.
    pub selected_finding: Option<usize>,
    /// Whether to show the chain panel instead of findings in the central area.
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
    /// Current error, if analysis failed.
    pub error: Option<AnalysisError>,
    #[cfg(target_arch = "wasm32")]
    pending_upload: Rc<RefCell<Option<(String, Vec<u8>)>>>,
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

#[derive(Default)]
pub struct SortState {
    pub column: SortColumn,
    pub ascending: bool,
}

#[derive(Default, PartialEq)]
pub enum SortColumn {
    #[default]
    Severity,
    Confidence,
    Kind,
    Surface,
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

impl SisApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            result: None,
            error: None,
            selected_finding: None,
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
            inactive_workspaces: Vec::new(),
            active_tab: 0,
            tab_count: 0,
            active_tab_name: String::new(),
            #[cfg(target_arch = "wasm32")]
            pending_upload: Rc::new(RefCell::new(None)),
        }
    }

    /// Process a dropped file: run analysis and open as a new tab.
    pub fn handle_file_drop(&mut self, name: String, bytes: &[u8]) {
        self.error = None;

        match crate::analysis::analyze(bytes, &name) {
            Ok(result) => {
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
                self.show_chains = false;
                self.show_metadata = false;
                self.show_objects = false;
                self.severity_filters = SeverityFilters::default();
                self.sort = SortState::default();

                // Active tab is the last one
                self.active_tab = self.inactive_workspaces.len();
                self.tab_count = self.inactive_workspaces.len() + 1;
            }
            Err(err) => {
                self.error = Some(err);
            }
        }
    }

    /// Save the current active workspace into the inactive list.
    fn save_active_workspace(&mut self) {
        if let Some(result) = self.result.take() {
            let ws = WorkspaceContext {
                result,
                selected_finding: self.selected_finding.take(),
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
                show_command_bar: self.show_command_bar,
                command_input: std::mem::take(&mut self.command_input),
                command_history: std::mem::take(&mut self.command_history),
                command_results: std::mem::take(&mut self.command_results),
                tab_name: std::mem::take(&mut self.active_tab_name),
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
        self.show_command_bar = ws.show_command_bar;
        self.command_input = ws.command_input;
        self.command_history = ws.command_history;
        self.command_results = ws.command_results;
        self.active_tab_name = ws.tab_name;
    }

    /// Switch to a different tab by index.
    pub fn switch_tab(&mut self, tab_index: usize) {
        if tab_index == self.active_tab {
            return;
        }
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

    #[cfg(not(target_arch = "wasm32"))]
    fn request_file_upload_native(&mut self) {
        if let Some(path) = rfd::FileDialog::new().add_filter("PDF document", &["pdf"]).pick_file()
        {
            match std::fs::read(&path) {
                Ok(bytes) => {
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "uploaded.pdf".to_string());
                    self.handle_file_drop(name, &bytes);
                }
                Err(err) => {
                    self.error = Some(AnalysisError::ParseFailed(format!(
                        "Failed to read selected file: {}",
                        err
                    )));
                }
            }
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
        #[cfg(target_arch = "wasm32")]
        {
            let maybe_upload = self.pending_upload.borrow_mut().take();
            if let Some((name, bytes)) = maybe_upload {
                self.handle_file_drop(name, &bytes);
            }
        }

        // Handle file drops
        let dropped_files: Vec<_> = ctx.input(|i| i.raw.dropped_files.clone());
        for file in dropped_files {
            let name = file.name.clone();
            if let Some(bytes) = file.bytes {
                self.handle_file_drop(name, &bytes);
            } else if let Some(path) = &file.path {
                // Native: read from filesystem
                if let Ok(bytes) = std::fs::read(path) {
                    let path_name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| name.clone());
                    self.handle_file_drop(path_name, &bytes);
                }
            }
        }

        if self.result.is_some() {
            // Top: tab bar + summary
            egui::TopBottomPanel::top("summary_panel").show(ctx, |ui| {
                // Tab bar (only when multiple tabs are open)
                if self.tab_count > 1 {
                    crate::panels::summary::show_tab_bar(ui, self);
                    ui.separator();
                }
                crate::panels::summary::show(ui, self);
            });

            // Left: navigation column
            egui::SidePanel::left("nav_panel").exact_width(80.0).resizable(false).show(ctx, |ui| {
                crate::panels::nav::show(ui, self);
            });

            // Right: finding detail (when a finding is selected)
            egui::SidePanel::right("detail_panel").min_width(300.0).show(ctx, |ui| {
                crate::panels::detail::show(ui, self);
            });

            // Floating windows for metadata and object inspector
            if self.show_metadata {
                let mut open = true;
                egui::Window::new("Metadata")
                    .open(&mut open)
                    .default_size([400.0, 500.0])
                    .resizable(true)
                    .show(ctx, |ui| {
                        crate::panels::metadata::show(ui, self);
                    });
                self.show_metadata = open;
            }

            if self.show_objects {
                crate::panels::objects::show(ctx, self);
            }

            if self.show_hex {
                crate::panels::hex_viewer::show(ctx, self);
            }

            // Command bar (bottom panels, rendered before central to claim space)
            if self.show_command_bar {
                crate::panels::command_bar::show(ctx, self);
            }

            // Central: findings table or chains
            egui::CentralPanel::default().show(ctx, |ui| {
                if self.show_chains {
                    crate::panels::chains::show(ui, self);
                } else {
                    crate::panels::findings::show(ui, self);
                }
            });
        } else {
            // Show drop zone
            egui::CentralPanel::default().show(ctx, |ui| {
                crate::panels::drop_zone::show(ui, self);
            });
        }
    }
}

use crate::analysis::{AnalysisError, AnalysisResult};
#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;
#[cfg(target_arch = "wasm32")]
use std::rc::Rc;

/// Application state for the PDF security analyser.
pub struct SisApp {
    /// Current analysis result, if a file has been analysed.
    pub result: Option<AnalysisResult>,
    /// Current error, if analysis failed.
    pub error: Option<AnalysisError>,
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
    /// Active severity filters (true = shown).
    pub severity_filters: SeverityFilters,
    /// Current sort column and direction.
    pub sort: SortState,
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
            severity_filters: SeverityFilters::default(),
            sort: SortState::default(),
            #[cfg(target_arch = "wasm32")]
            pending_upload: Rc::new(RefCell::new(None)),
        }
    }

    /// Process a dropped file: read bytes and run analysis.
    pub fn handle_file_drop(&mut self, name: String, bytes: &[u8]) {
        self.error = None;
        self.selected_finding = None;
        self.selected_object = None;
        self.object_type_filter = None;
        self.show_chains = false;
        self.show_metadata = false;
        self.show_objects = false;
        match crate::analysis::analyze(bytes, &name) {
            Ok(result) => {
                self.result = Some(result);
            }
            Err(err) => {
                self.result = None;
                self.error = Some(err);
            }
        }
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
            // Top: summary bar
            egui::TopBottomPanel::top("summary_panel").show(ctx, |ui| {
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

use crate::analysis::{AnalysisError, AnalysisResult};

/// Application state for the PDF security analyser.
pub struct SisApp {
    /// Current analysis result, if a file has been analysed.
    pub result: Option<AnalysisResult>,
    /// Current error, if analysis failed.
    pub error: Option<AnalysisError>,
    /// Index of the currently selected finding in the table.
    pub selected_finding: Option<usize>,
    /// Whether to show the chain panel.
    pub show_chains: bool,
    /// Active severity filters (true = shown).
    pub severity_filters: SeverityFilters,
    /// Current sort column and direction.
    pub sort: SortState,
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
        Self {
            critical: true,
            high: true,
            medium: true,
            low: true,
            info: true,
        }
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
            severity_filters: SeverityFilters::default(),
            sort: SortState::default(),
        }
    }

    /// Process a dropped file: read bytes and run analysis.
    pub fn handle_file_drop(&mut self, name: String, bytes: &[u8]) {
        self.error = None;
        self.selected_finding = None;
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
}

impl eframe::App for SisApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle file drops
        let dropped_files: Vec<_> = ctx.input(|i| i.raw.dropped_files.clone());
        for file in dropped_files {
            let name = file
                .name
                .clone();
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
            // Show analysis panels
            egui::TopBottomPanel::top("summary_panel").show(ctx, |ui| {
                crate::panels::summary::show(ui, self);
            });
            egui::SidePanel::right("detail_panel")
                .min_width(300.0)
                .show(ctx, |ui| {
                    crate::panels::detail::show(ui, self);
                });
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

use crate::app::{SisApp, SortColumn};
use egui_extras::{Column, TableBuilder};
use sis_pdf_core::model::{Confidence, Severity};

pub fn show_window(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_findings;
    let mut ws = app.window_max.remove("Findings").unwrap_or_default();
    let win = crate::window_state::dialog_window(ctx, "Findings", [600.0, 400.0], &mut ws);
    win.show(ctx, |ui| {
        crate::window_state::dialog_title_bar(ui, "Findings", &mut open, &mut ws);
        show(ui, app);
    });
    app.window_max.insert("Findings".to_string(), ws);
    app.show_findings = open;
}

pub fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    let Some(ref result) = app.result else {
        return;
    };

    // Severity filter toggles
    ui.horizontal(|ui| {
        ui.label("Severity:");
        ui.toggle_value(&mut app.severity_filters.critical, "Critical");
        ui.toggle_value(&mut app.severity_filters.high, "High");
        ui.toggle_value(&mut app.severity_filters.medium, "Medium");
        ui.toggle_value(&mut app.severity_filters.low, "Low");
        ui.toggle_value(&mut app.severity_filters.info, "Info");
    });

    // Extended filter row
    let surface_names = collect_surface_names(result);
    ui.horizontal(|ui| {
        ui.label("Search:");
        ui.add(
            egui::TextEdit::singleline(&mut app.findings_search)
                .desired_width(120.0)
                .hint_text("kind, title..."),
        );

        ui.separator();
        ui.label("Surface:");
        egui::ComboBox::from_id_salt("surface_filter")
            .selected_text(app.surface_filter.as_deref().unwrap_or("All"))
            .width(100.0)
            .show_ui(ui, |ui| {
                if ui.selectable_label(app.surface_filter.is_none(), "All").clicked() {
                    app.surface_filter = None;
                }
                for name in &surface_names {
                    let selected = app.surface_filter.as_deref() == Some(name.as_str());
                    if ui.selectable_label(selected, name).clicked() {
                        app.surface_filter = Some(name.clone());
                    }
                }
            });

        ui.separator();
        ui.label("Min conf:");
        ui.add(egui::Slider::new(&mut app.min_confidence, 0..=5).show_value(false));
        ui.label(confidence_threshold_label(app.min_confidence));

        ui.separator();
        ui.toggle_value(&mut app.has_cve_filter, "Has CVE");
        ui.toggle_value(&mut app.auto_triggered_filter, "Auto-triggered");
    });
    ui.separator();

    let findings = &result.report.findings;
    let total_count = findings.len();
    let search_lower = app.findings_search.to_lowercase();

    // Filter findings
    let filtered: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            // Severity filter
            let sev_ok = match f.severity {
                Severity::Critical => app.severity_filters.critical,
                Severity::High => app.severity_filters.high,
                Severity::Medium => app.severity_filters.medium,
                Severity::Low => app.severity_filters.low,
                Severity::Info => app.severity_filters.info,
            };
            if !sev_ok {
                return false;
            }

            // Text search
            if !search_lower.is_empty()
                && !f.kind.to_lowercase().contains(&search_lower)
                && !f.title.to_lowercase().contains(&search_lower)
                && !f.description.to_lowercase().contains(&search_lower)
            {
                return false;
            }

            // Surface filter
            if let Some(ref surface) = app.surface_filter {
                if surface_label(&f.surface) != surface.as_str() {
                    return false;
                }
            }

            // Confidence filter
            if !passes_min_confidence_filter(&f.confidence, app.min_confidence) {
                return false;
            }

            // CVE filter
            if app.has_cve_filter && !f.meta.keys().any(|k| k.contains("cve")) {
                return false;
            }

            // Auto-triggered filter
            if app.auto_triggered_filter && f.action_initiation.as_deref() != Some("automatic") {
                return false;
            }

            true
        })
        .map(|(i, _)| i)
        .collect();

    // Sort filtered indices
    let mut sorted = filtered;
    sorted.sort_by(|&a, &b| {
        let fa = &findings[a];
        let fb = &findings[b];
        let ord = match app.sort.column {
            SortColumn::Severity => severity_rank(&fa.severity).cmp(&severity_rank(&fb.severity)),
            SortColumn::Confidence => {
                confidence_rank(&fa.confidence).cmp(&confidence_rank(&fb.confidence))
            }
            SortColumn::Kind => fa.kind.cmp(&fb.kind),
            SortColumn::Surface => surface_label(&fa.surface).cmp(surface_label(&fb.surface)),
        };
        if app.sort.ascending {
            ord
        } else {
            ord.reverse()
        }
    });

    // Empty state
    if sorted.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            if total_count == 0 {
                ui.label("No findings detected");
            } else {
                ui.label(format!("No findings match the current filters ({} total)", total_count));
                if ui.button("Reset filters").clicked() {
                    app.severity_filters = crate::app::SeverityFilters::default();
                    app.findings_search.clear();
                    app.surface_filter = None;
                    app.min_confidence = 0;
                    app.has_cve_filter = false;
                    app.auto_triggered_filter = false;
                }
            }
        });
        return;
    }

    ui.label(format!("{} of {} findings shown", sorted.len(), total_count));

    let available = ui.available_size();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(70.0).at_least(50.0)) // Severity
        .column(Column::initial(80.0).at_least(50.0)) // Confidence
        .column(Column::initial(200.0).at_least(80.0)) // Kind
        .column(Column::initial(100.0).at_least(60.0)) // Surface
        .column(Column::remainder()) // Description
        .min_scrolled_height(0.0)
        .max_scroll_height(available.y - 40.0)
        .header(20.0, |mut header| {
            header.col(|ui| {
                if ui
                    .selectable_label(app.sort.column == SortColumn::Severity, "Severity")
                    .clicked()
                {
                    toggle_sort(&mut app.sort, SortColumn::Severity);
                }
            });
            header.col(|ui| {
                if ui
                    .selectable_label(app.sort.column == SortColumn::Confidence, "Confidence")
                    .clicked()
                {
                    toggle_sort(&mut app.sort, SortColumn::Confidence);
                }
            });
            header.col(|ui| {
                if ui.selectable_label(app.sort.column == SortColumn::Kind, "Kind").clicked() {
                    toggle_sort(&mut app.sort, SortColumn::Kind);
                }
            });
            header.col(|ui| {
                if ui.selectable_label(app.sort.column == SortColumn::Surface, "Surface").clicked()
                {
                    toggle_sort(&mut app.sort, SortColumn::Surface);
                }
            });
            header.col(|ui| {
                ui.label("Description");
            });
        })
        .body(|body| {
            body.rows(20.0, sorted.len(), |mut row| {
                let idx = sorted[row.index()];
                let f = &findings[idx];
                let selected = app.selected_finding == Some(idx);
                row.col(|ui| {
                    let label = egui::RichText::new(severity_label(&f.severity))
                        .color(severity_colour(&f.severity));
                    if ui.selectable_label(selected, label).clicked() {
                        app.selected_finding = Some(idx);
                        app.finding_origin_event = None;
                    }
                });
                row.col(|ui| {
                    ui.label(confidence_label(&f.confidence));
                });
                row.col(|ui| {
                    ui.label(&f.kind);
                });
                row.col(|ui| {
                    ui.label(surface_label(&f.surface));
                });
                row.col(|ui| {
                    ui.label(&f.title);
                });
            });
        });
}

fn toggle_sort(sort: &mut crate::app::SortState, column: SortColumn) {
    if sort.column == column {
        sort.ascending = !sort.ascending;
    } else {
        sort.column = column;
        sort.ascending = true;
    }
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn severity_colour(s: &Severity) -> egui::Color32 {
    match s {
        Severity::Critical => egui::Color32::from_rgb(220, 50, 50),
        Severity::High => egui::Color32::from_rgb(255, 140, 0),
        Severity::Medium => egui::Color32::from_rgb(220, 200, 50),
        Severity::Low => egui::Color32::from_rgb(100, 160, 230),
        Severity::Info => egui::Color32::from_rgb(150, 150, 150),
    }
}

fn confidence_rank(c: &Confidence) -> u8 {
    match c {
        Confidence::Certain => 0,
        Confidence::Strong => 1,
        Confidence::Probable => 2,
        Confidence::Tentative => 3,
        Confidence::Weak => 4,
        Confidence::Heuristic => 5,
    }
}

fn confidence_label(c: &Confidence) -> &'static str {
    match c {
        Confidence::Certain => "Certain",
        Confidence::Strong => "Strong",
        Confidence::Probable => "Probable",
        Confidence::Tentative => "Tentative",
        Confidence::Weak => "Weak",
        Confidence::Heuristic => "Heuristic",
    }
}

fn passes_min_confidence_filter(confidence: &Confidence, min_level: u8) -> bool {
    min_level == 0 || confidence_rank(confidence) <= min_level
}

/// Label shown next to the confidence slider to indicate the threshold.
fn confidence_threshold_label(level: u8) -> &'static str {
    match level {
        0 => "All",
        1 => "Strong+",
        2 => "Probable+",
        3 => "Tentative+",
        4 => "Weak+",
        _ => "Heuristic+",
    }
}

fn surface_label(s: &sis_pdf_core::model::AttackSurface) -> &'static str {
    use sis_pdf_core::model::AttackSurface;
    match s {
        AttackSurface::FileStructure => "File Structure",
        AttackSurface::XRefTrailer => "XRef/Trailer",
        AttackSurface::ObjectStreams => "Object Streams",
        AttackSurface::StreamsAndFilters => "Streams & Filters",
        AttackSurface::Actions => "Actions",
        AttackSurface::JavaScript => "JavaScript",
        AttackSurface::Forms => "Forms",
        AttackSurface::EmbeddedFiles => "Embedded Files",
        AttackSurface::RichMedia3D => "Rich Media/3D",
        AttackSurface::Images => "Images",
        AttackSurface::CryptoSignatures => "Crypto/Signatures",
        AttackSurface::Metadata => "Metadata",
        AttackSurface::ContentPhishing => "Content Phishing",
    }
}

/// Collect unique surface names present in the findings for the filter dropdown.
fn collect_surface_names(result: &crate::analysis::AnalysisResult) -> Vec<String> {
    let mut names: Vec<String> =
        result.report.findings.iter().map(|f| surface_label(&f.surface).to_string()).collect();
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_confidence_all_includes_all_confidences() {
        let all = [
            Confidence::Certain,
            Confidence::Strong,
            Confidence::Probable,
            Confidence::Tentative,
            Confidence::Weak,
            Confidence::Heuristic,
        ];

        for confidence in all {
            assert!(passes_min_confidence_filter(&confidence, 0));
        }
    }

    #[test]
    fn min_confidence_strong_only_allows_strong_or_higher() {
        assert!(passes_min_confidence_filter(&Confidence::Certain, 1));
        assert!(passes_min_confidence_filter(&Confidence::Strong, 1));
        assert!(!passes_min_confidence_filter(&Confidence::Probable, 1));
        assert!(!passes_min_confidence_filter(&Confidence::Tentative, 1));
        assert!(!passes_min_confidence_filter(&Confidence::Weak, 1));
        assert!(!passes_min_confidence_filter(&Confidence::Heuristic, 1));
    }
}

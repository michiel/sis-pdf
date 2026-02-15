use crate::app::{SisApp, SortColumn};
use egui_extras::{Column, TableBuilder};
use sis_pdf_core::model::Severity;

pub fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    let Some(ref result) = app.result else {
        return;
    };

    // Severity filter toggles
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.toggle_value(&mut app.severity_filters.critical, "Critical");
        ui.toggle_value(&mut app.severity_filters.high, "High");
        ui.toggle_value(&mut app.severity_filters.medium, "Medium");
        ui.toggle_value(&mut app.severity_filters.low, "Low");
        ui.toggle_value(&mut app.severity_filters.info, "Info");
    });
    ui.separator();

    let findings = &result.report.findings;

    // Filter findings by severity
    let filtered: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| match f.severity {
            Severity::Critical => app.severity_filters.critical,
            Severity::High => app.severity_filters.high,
            Severity::Medium => app.severity_filters.medium,
            Severity::Low => app.severity_filters.low,
            Severity::Info => app.severity_filters.info,
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
            SortColumn::Confidence => format!("{:?}", fa.confidence).cmp(&format!("{:?}", fb.confidence)),
            SortColumn::Kind => fa.kind.cmp(&fb.kind),
            SortColumn::Surface => format!("{:?}", fa.surface).cmp(&format!("{:?}", fb.surface)),
        };
        if app.sort.ascending {
            ord
        } else {
            ord.reverse()
        }
    });

    ui.label(format!("{} findings shown", sorted.len()));

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
                if ui.selectable_label(app.sort.column == SortColumn::Severity, "Severity").clicked() {
                    toggle_sort(&mut app.sort, SortColumn::Severity);
                }
            });
            header.col(|ui| {
                if ui.selectable_label(app.sort.column == SortColumn::Confidence, "Confidence").clicked() {
                    toggle_sort(&mut app.sort, SortColumn::Confidence);
                }
            });
            header.col(|ui| {
                if ui.selectable_label(app.sort.column == SortColumn::Kind, "Kind").clicked() {
                    toggle_sort(&mut app.sort, SortColumn::Kind);
                }
            });
            header.col(|ui| {
                if ui.selectable_label(app.sort.column == SortColumn::Surface, "Surface").clicked() {
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
                    let label = severity_label(&f.severity);
                    if ui.selectable_label(selected, label).clicked() {
                        app.selected_finding = Some(idx);
                    }
                });
                row.col(|ui| {
                    ui.label(format!("{:?}", f.confidence));
                });
                row.col(|ui| {
                    ui.label(&f.kind);
                });
                row.col(|ui| {
                    ui.label(format!("{:?}", f.surface));
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

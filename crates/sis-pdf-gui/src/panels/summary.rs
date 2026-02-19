use crate::app::SisApp;
use sis_pdf_core::model::Severity;

/// Display the menu bar: File menu, then cog and theme toggle on the far right.
pub fn show_menu_bar(ui: &mut egui::Ui, app: &mut SisApp) {
    egui::MenuBar::new().ui(ui, |ui| {
        ui.menu_button("File", |ui| {
            if ui.button("Open file...").clicked() {
                app.request_file_upload();
                ui.close();
            }
            ui.separator();
            if ui.add_enabled(app.tab_count > 0, egui::Button::new("Close tab")).clicked() {
                app.close_tab(app.active_tab);
                ui.close();
            }
        });

        // Push remaining items to the right edge.
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let theme_icon = if app.dark_mode { "\u{2600}" } else { "\u{263E}" };
            let theme_text =
                if app.dark_mode { "Switch to light theme" } else { "Switch to dark theme" };
            if ui.button(theme_icon).on_hover_text(theme_text).clicked() {
                app.dark_mode = !app.dark_mode;
            }
            if ui.button("\u{2699}").on_hover_text("Options").clicked() {
                app.show_telemetry = !app.show_telemetry;
            }
        });
    });
}

/// Display the tab strip for multi-tab switching (shown only when >1 tab).
pub fn show_tab_strip(ui: &mut egui::Ui, app: &mut SisApp) {
    let tab_names = app.tab_names();
    let active = app.active_tab;
    let btn_height = ui.spacing().interact_size.y;
    let mut switch_to = None;
    let mut close_tab = None;

    ui.horizontal(|ui| {
        for (i, name) in tab_names.iter().enumerate() {
            let is_active = i == active;
            let truncated =
                if name.len() > 20 { format!("{}...", &name[..17]) } else { name.clone() };

            let mut button = egui::Button::new(&truncated);
            if is_active {
                button = button.fill(ui.visuals().selection.bg_fill);
            }
            if ui.add_sized([120.0, btn_height], button).clicked() && !is_active {
                switch_to = Some(i);
            }
            if ui.add_sized([btn_height, btn_height], egui::Button::new("x")).clicked() {
                close_tab = Some(i);
            }

            ui.add_space(2.0);
        }

        // "+" button to open a new file
        if tab_names.len() < crate::workspace::MAX_TABS {
            if ui.add_sized([btn_height, btn_height], egui::Button::new("+")).clicked() {
                app.request_file_upload();
            }
        }
    });

    if let Some(idx) = close_tab {
        app.close_tab(idx);
    } else if let Some(idx) = switch_to {
        app.switch_tab(idx);
    }
}

pub fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    let Some(ref result) = app.result else {
        return;
    };

    // Extract display data before entering the closure that needs &mut app
    let file_name = result.file_name.clone();
    let file_size = result.file_size;
    let pdf_version = result.pdf_version.clone();
    let page_count = result.page_count;
    let duration_ms = result.report.detection_duration_ms;
    let object_count = result.report.structural_summary.as_ref().map(|s| s.object_count);
    let critical =
        result.report.findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = result.report.summary.high;
    let medium = result.report.summary.medium;
    let low = result.report.summary.low;
    let info = result.report.summary.info;
    let chain_count = result.report.chains.iter().filter(|chain| chain.findings.len() > 1).count();

    ui.horizontal(|ui| {
        ui.heading(&file_name);
        ui.separator();
        ui.label(format_file_size(file_size));

        if let Some(ref ver) = pdf_version {
            ui.separator();
            ui.label(format!("v{}", ver));
        }

        if page_count > 0 {
            ui.separator();
            ui.label(format!("{} pages", page_count));
        }

        if let Some(count) = object_count {
            ui.separator();
            ui.label(format!("{} objects", count));
        }

        if let Some(ms) = duration_ms {
            ui.separator();
            ui.label(format!("{}ms", ms));
        }

        ui.separator();

        // Severity counts -- clickable to filter
        if critical > 0 {
            let label = egui::RichText::new(format!("C:{}", critical)).color(egui::Color32::RED);
            if ui.link(label).clicked() {
                set_severity_filter_only(app, Severity::Critical);
            }
        }
        if high > 0 {
            let label = egui::RichText::new(format!("H:{}", high))
                .color(egui::Color32::from_rgb(255, 140, 0));
            if ui.link(label).clicked() {
                set_severity_filter_only(app, Severity::High);
            }
        }
        if medium > 0 {
            let label = egui::RichText::new(format!("M:{}", medium)).color(egui::Color32::YELLOW);
            if ui.link(label).clicked() {
                set_severity_filter_only(app, Severity::Medium);
            }
        }
        if low > 0 {
            let label = egui::RichText::new(format!("L:{}", low)).color(egui::Color32::LIGHT_BLUE);
            if ui.link(label).clicked() {
                set_severity_filter_only(app, Severity::Low);
            }
        }
        if info > 0 {
            let label = egui::RichText::new(format!("I:{}", info)).color(egui::Color32::GRAY);
            if ui.link(label).clicked() {
                set_severity_filter_only(app, Severity::Info);
            }
        }

        ui.separator();
        ui.label(format!("{} chains", chain_count));
    });
}

/// Set severity filter to show only the given severity level and switch to findings view.
fn set_severity_filter_only(app: &mut SisApp, severity: Severity) {
    app.severity_filters.critical = severity == Severity::Critical;
    app.severity_filters.high = severity == Severity::High;
    app.severity_filters.medium = severity == Severity::Medium;
    app.severity_filters.low = severity == Severity::Low;
    app.severity_filters.info = severity == Severity::Info;
    app.show_findings = true;
}

/// Format a byte count as a human-readable size string.
fn format_file_size(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let size = bytes as f64;
    if size >= GB {
        format!("{:.1} GB", size / GB)
    } else if size >= MB {
        format!("{:.1} MB", size / MB)
    } else if size >= KB {
        format!("{:.1} KB", size / KB)
    } else {
        format!("{} B", bytes)
    }
}

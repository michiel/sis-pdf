use crate::app::SisApp;
use sis_pdf_core::model::Severity;

/// Display the tab bar for multi-tab switching.
pub fn show_tab_bar(ui: &mut egui::Ui, app: &mut SisApp) {
    let tab_names = app.tab_names();
    let active = app.active_tab;
    let mut switch_to = None;
    let mut close_tab = None;

    ui.horizontal(|ui| {
        for (i, name) in tab_names.iter().enumerate() {
            let is_active = i == active;
            let truncated =
                if name.len() > 20 { format!("{}...", &name[..17]) } else { name.clone() };

            ui.horizontal(|ui| {
                if ui.selectable_label(is_active, &truncated).clicked() && !is_active {
                    switch_to = Some(i);
                }
                if ui.small_button("x").clicked() {
                    close_tab = Some(i);
                }
            });
        }

        // "+" button to open a new file
        if tab_names.len() < crate::workspace::MAX_TABS {
            if ui.small_button("+").clicked() {
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
    let object_count = result.report.structural_summary.as_ref().map(|s| s.object_count);
    let critical =
        result.report.findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = result.report.summary.high;
    let medium = result.report.summary.medium;
    let low = result.report.summary.low;
    let info = result.report.summary.info;
    let chain_count = result.report.chains.len();

    ui.horizontal(|ui| {
        ui.heading(&file_name);
        ui.separator();
        ui.label(format!("{} bytes", file_size));

        if let Some(count) = object_count {
            ui.separator();
            ui.label(format!("{} objects", count));
        }

        ui.separator();

        // Severity counts — clickable to filter
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

        // Toggle chains view
        if ui.selectable_label(app.show_chains, "Chains").clicked() {
            app.show_chains = !app.show_chains;
        }
    });
}

/// Set severity filter to show only the given severity level and switch to findings view.
fn set_severity_filter_only(app: &mut SisApp, severity: Severity) {
    app.severity_filters.critical = severity == Severity::Critical;
    app.severity_filters.high = severity == Severity::High;
    app.severity_filters.medium = severity == Severity::Medium;
    app.severity_filters.low = severity == Severity::Low;
    app.severity_filters.info = severity == Severity::Info;
    app.show_chains = false;
}

use crate::app::SisApp;
use sis_pdf_core::model::Severity;

pub fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    let Some(ref result) = app.result else {
        return;
    };

    ui.horizontal(|ui| {
        ui.heading(&result.file_name);
        ui.separator();
        ui.label(format!("{} bytes", result.file_size));

        if let Some(ref structural) = result.report.structural_summary {
            ui.separator();
            ui.label(format!("{} objects", structural.object_count));
        }

        ui.separator();

        // Severity counts from report summary
        let summary = &result.report.summary;
        let findings = &result.report.findings;
        let critical = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();

        if critical > 0 {
            ui.colored_label(egui::Color32::RED, format!("C:{}", critical));
        }
        if summary.high > 0 {
            ui.colored_label(
                egui::Color32::from_rgb(255, 140, 0),
                format!("H:{}", summary.high),
            );
        }
        if summary.medium > 0 {
            ui.colored_label(egui::Color32::YELLOW, format!("M:{}", summary.medium));
        }
        if summary.low > 0 {
            ui.colored_label(egui::Color32::LIGHT_BLUE, format!("L:{}", summary.low));
        }
        if summary.info > 0 {
            ui.colored_label(egui::Color32::GRAY, format!("I:{}", summary.info));
        }

        ui.separator();
        ui.label(format!("{} chains", result.report.chains.len()));

        // Toggle chains view
        if ui.selectable_label(app.show_chains, "Chains").clicked() {
            app.show_chains = !app.show_chains;
        }
    });
}

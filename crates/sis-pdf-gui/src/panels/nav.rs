use crate::app::SisApp;

pub fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    ui.vertical_centered(|ui| {
        ui.add_space(4.0);

        let findings_label = if !app.show_chains { "> Findings" } else { "Findings" };
        if ui.selectable_label(!app.show_chains, findings_label).clicked() {
            app.show_chains = false;
        }

        let chains_label = if app.show_chains { "> Chains" } else { "Chains" };
        if ui.selectable_label(app.show_chains, chains_label).clicked() {
            app.show_chains = true;
        }

        ui.separator();

        if ui.selectable_label(app.show_metadata, "Metadata").clicked() {
            app.show_metadata = !app.show_metadata;
        }

        if ui.selectable_label(app.show_objects, "Objects").clicked() {
            app.show_objects = !app.show_objects;
        }
    });
}

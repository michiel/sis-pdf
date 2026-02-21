use crate::app::SisApp;

pub fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    ui.vertical_centered(|ui| {
        ui.add_space(4.0);

        if ui.selectable_label(app.show_findings, "Findings").clicked() {
            app.show_findings = !app.show_findings;
        }

        if ui.selectable_label(app.show_chains, "Chains").clicked() {
            app.show_chains = !app.show_chains;
        }

        ui.separator();

        if ui.selectable_label(app.show_metadata, "Metadata").clicked() {
            app.show_metadata = !app.show_metadata;
        }
        if ui.selectable_label(app.show_revision, "Revisions").clicked() {
            app.show_revision = !app.show_revision;
        }

        if ui.selectable_label(app.show_objects, "Objects").clicked() {
            app.show_objects = !app.show_objects;
        }

        if ui.selectable_label(app.show_events, "Events").clicked() {
            app.show_events = !app.show_events;
        }

        if ui.selectable_label(app.show_image_preview, "Preview").clicked() {
            app.show_image_preview = !app.show_image_preview;
        }

        if ui.selectable_label(app.show_hex, "Hex").clicked() {
            app.show_hex = !app.show_hex;
        }

        if ui.selectable_label(app.show_graph, "Graph").clicked() {
            app.show_graph = !app.show_graph;
        }

        ui.separator();

        if ui.selectable_label(app.show_command_bar, "Command").clicked() {
            app.show_command_bar = !app.show_command_bar;
        }

        ui.separator();

        if ui.selectable_label(app.show_telemetry, "Debug").clicked() {
            app.show_telemetry = !app.show_telemetry;
        }
    });
}

use crate::app::SisApp;

pub fn show(ui: &mut egui::Ui, app: &mut SisApp) {
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() / 3.0);

        ui.heading("sis - PDF Security Analyser");
        ui.add_space(20.0);

        let drop_area = ui.group(|ui| {
            ui.set_min_size(egui::vec2(400.0, 200.0));
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.label(
                    egui::RichText::new("Drop a PDF file here to analyse")
                        .size(18.0)
                        .color(egui::Color32::GRAY),
                );
                ui.add_space(10.0);
                if ui.button("Select PDF file").clicked() {
                    app.request_file_upload();
                }
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new("Maximum file size: 50 MB")
                        .size(12.0)
                        .color(egui::Color32::DARK_GRAY),
                );
            });
        });

        // Highlight drop area when hovering with file
        if ui.input(|i| !i.raw.hovered_files.is_empty()) {
            ui.painter().rect_stroke(
                drop_area.response.rect,
                4.0,
                egui::Stroke::new(2.0, egui::Color32::LIGHT_BLUE),
                egui::StrokeKind::Outside,
            );
        }

        if let Some(ref err) = app.error {
            ui.add_space(20.0);
            ui.colored_label(egui::Color32::RED, format!("Error: {}", err));
        }
    });
}

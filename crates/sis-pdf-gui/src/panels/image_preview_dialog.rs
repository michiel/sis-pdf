use crate::app::SisApp;

pub fn show(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_image_preview;
    let mut ws = app.window_max.remove("Image Preview").unwrap_or_default();
    let win = crate::window_state::dialog_window(ctx, "Image Preview", [820.0, 640.0], &mut ws);
    win.show(ctx, |ui| {
        crate::window_state::dialog_title_bar(ui, "Image Preview", &mut open, &mut ws);
        render_dialog(ui, app);
    });
    app.window_max.insert("Image Preview".to_string(), ws);
    app.show_image_preview = open;
}

fn render_dialog(ui: &mut egui::Ui, app: &mut SisApp) {
    if app.image_preview_state.data.is_none() {
        ui.label("No image object selected for preview.");
        return;
    }

    let mut retry = false;
    ui.horizontal_wrapped(|ui| {
        let data = app.image_preview_state.data.as_ref().expect("checked above");
        ui.label(format!("Object {} {}", data.obj, data.gen));
        ui.separator();
        if app.image_preview_state.from_cache {
            ui.small("Loaded from cache");
        } else {
            ui.small("Fresh load");
        }
        if ui.small_button("Retry").clicked() {
            retry = true;
        }
    });
    if retry {
        app.retry_image_preview();
    }
    let data = app.image_preview_state.data.as_ref().expect("checked above");
    ui.separator();

    if let Some((w, h, pixels)) = data.image_preview.as_ref() {
        let tex_id = format!("img_preview_dialog_{}_{}", data.obj, data.gen);
        let texture = ui.ctx().load_texture(
            tex_id,
            egui::ColorImage::from_rgba_unmultiplied([*w as usize, *h as usize], pixels),
            egui::TextureOptions::LINEAR,
        );
        ui.image(&texture);
        ui.small(format!("Preview dimensions: {} x {}", w, h));
    } else {
        ui.label("Preview unavailable");
    }

    ui.separator();
    ui.collapsing("Metadata", |ui| {
        egui::Grid::new("image_preview_meta_grid").num_columns(2).spacing([8.0, 2.0]).show(
            ui,
            |ui| {
                if let Some(width) = data.image_width {
                    ui.label("Declared width:");
                    ui.label(width.to_string());
                    ui.end_row();
                }
                if let Some(height) = data.image_height {
                    ui.label("Declared height:");
                    ui.label(height.to_string());
                    ui.end_row();
                }
                if let Some(bits) = data.image_bits {
                    ui.label("Bits/component:");
                    ui.label(bits.to_string());
                    ui.end_row();
                }
                if let Some(colour_space) = data.image_color_space.as_deref() {
                    ui.label("Colour space:");
                    ui.label(colour_space);
                    ui.end_row();
                }
                if !data.stream_filters.is_empty() {
                    ui.label("Filters:");
                    ui.label(data.stream_filters.join(" > "));
                    ui.end_row();
                }
                if let Some(content_type) = data.stream_content_type.as_deref() {
                    ui.label("Content type:");
                    ui.label(content_type);
                    ui.end_row();
                }
                if let Some(stream_length) = data.stream_length {
                    ui.label("Raw stream bytes:");
                    ui.label(stream_length.to_string());
                    ui.end_row();
                }
            },
        );
    });

    ui.separator();
    ui.collapsing("Decode status", |ui| {
        if let Some(summary) = data.image_preview_summary.as_deref() {
            ui.label(format!("Summary: {summary}"));
        } else if let Some(status) = data.image_preview_status.as_deref() {
            ui.label(format!("Summary: {status}"));
        } else {
            ui.label("Summary unavailable");
        }
        for status in &data.preview_statuses {
            ui.horizontal_wrapped(|ui| {
                ui.monospace(format!("{:?}", status.stage));
                ui.label("->");
                ui.monospace(format!("{:?}", status.outcome));
                ui.label(&status.detail);
            });
        }
    });
}

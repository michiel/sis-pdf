use crate::app::{HexSource, SisApp};
use crate::hex_format;
use sis_pdf_core::model::EvidenceSource;

pub fn show(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_hex;
    egui::Window::new("Hex Viewer")
        .open(&mut open)
        .default_size([750.0, 450.0])
        .max_size(ctx.available_rect().size())
        .resizable(true)
        .show(ctx, |ui| {
            show_inner(ui, app);
        });
    app.show_hex = open;
}

fn show_inner(ui: &mut egui::Ui, app: &mut SisApp) {
    let Some(ref result) = app.result else {
        return;
    };

    // Resolve the data source to a byte slice (owned copy for display)
    let (data, source_label) = match &app.hex_view.source {
        HexSource::File => (Some(result.bytes.clone()), format!("File: {}", result.file_name)),
        HexSource::Stream { obj, gen } => {
            let label = format!("Stream {} {} R", obj, gen);
            let bytes = result
                .object_data
                .index
                .get(&(*obj, *gen))
                .and_then(|&idx| result.object_data.objects[idx].stream_data_span)
                .and_then(|(start, end)| {
                    if start < end && end <= result.bytes.len() {
                        Some(result.bytes[start..end].to_vec())
                    } else {
                        None
                    }
                });
            (bytes, label)
        }
    };

    let Some(data) = data else {
        ui.label("No data available for this source");
        return;
    };

    // Header: source, size, source switcher
    ui.horizontal(|ui| {
        ui.strong(&source_label);
        ui.separator();
        ui.label(format!("{} bytes", data.len()));

        // Source switch buttons
        ui.separator();
        let is_file = app.hex_view.source == HexSource::File;
        if ui.selectable_label(is_file, "File").clicked() && !is_file {
            app.hex_view.source = HexSource::File;
            app.hex_view.highlights.clear();
        }
    });

    // Show highlight labels if any
    if !app.hex_view.highlights.is_empty() {
        ui.horizontal(|ui| {
            for hl in &app.hex_view.highlights {
                ui.colored_label(
                    egui::Color32::from_rgb(255, 200, 0),
                    format!("{}: offset 0x{:X}, {} bytes", hl.label, hl.start, hl.length),
                );
            }
        });
    }
    if let Some(jump) = app.hex_view.jump_to.as_ref() {
        let source_label = match jump.source {
            EvidenceSource::File => "File",
            EvidenceSource::Decoded => "Decoded",
        };
        ui.label(format!(
            "Jump target: 0x{:X} ({} bytes, source: {})",
            jump.offset, jump.length, source_label
        ));
    }

    ui.separator();

    // Render hex view with virtual scrolling
    let total_lines = hex_format::line_count(data.len());
    let line_height = 16.0;
    let jump_row = app.hex_view.jump_to.as_ref().map(|jump| (jump.offset as usize) / 16);
    let mut consumed_jump = false;

    egui::ScrollArea::vertical().id_salt("hex_viewer_scroll").show_rows(
        ui,
        line_height,
        total_lines,
        |ui, row_range| {
            ui.style_mut().override_font_id = Some(egui::FontId::monospace(12.0));

            for row in row_range {
                let byte_offset = row * 16;
                let end = (byte_offset + 16).min(data.len());
                if byte_offset >= data.len() {
                    break;
                }
                let chunk = &data[byte_offset..end];

                // Check if any highlight overlaps this line
                let has_highlight = app.hex_view.highlights.iter().any(|hl| {
                    let hl_end = hl.start + hl.length;
                    byte_offset < hl_end && end > hl.start
                });

                let line = hex_format::format_hex_line(byte_offset, chunk);
                if has_highlight {
                    let text = egui::RichText::new(&line)
                        .background_color(egui::Color32::from_rgba_premultiplied(255, 200, 0, 40));
                    let response = ui.label(text);
                    if !consumed_jump && jump_row == Some(row) {
                        ui.scroll_to_rect(response.rect, Some(egui::Align::Center));
                        consumed_jump = true;
                    }
                } else {
                    let response = ui.label(&line);
                    if !consumed_jump && jump_row == Some(row) {
                        ui.scroll_to_rect(response.rect, Some(egui::Align::Center));
                        consumed_jump = true;
                    }
                }
            }
        },
    );
    if consumed_jump {
        app.hex_view.jump_to = None;
    }
}

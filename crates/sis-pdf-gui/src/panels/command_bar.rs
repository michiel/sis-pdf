use crate::app::SisApp;
use crate::query::{self, QueryOutput};
use egui_extras::{Column, TableBuilder};

/// Show the command bar at the bottom and results panel above it.
pub fn show(ctx: &egui::Context, app: &mut SisApp) {
    // Results panel (above the command bar input)
    if !app.command_results.is_empty() {
        egui::TopBottomPanel::bottom("command_results_panel")
            .resizable(true)
            .min_height(60.0)
            .max_height(400.0)
            .default_height(200.0)
            .show(ctx, |ui| {
                show_results(ui, app);
            });
    }

    // Command input bar
    egui::TopBottomPanel::bottom("command_bar_panel").show(ctx, |ui| {
        show_input(ui, app);
    });
}

fn show_input(ui: &mut egui::Ui, app: &mut SisApp) {
    ui.horizontal(|ui| {
        ui.label(">");

        let response = ui.add(
            egui::TextEdit::singleline(&mut app.command_input)
                .desired_width(ui.available_width() - 80.0)
                .hint_text("Type a query (try 'help')..."),
        );

        // Handle Enter to execute
        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            execute_command(app);
            response.request_focus();
        }

        // Handle up/down for history
        if response.has_focus() {
            if ui.input(|i| i.key_pressed(egui::Key::ArrowUp)) {
                if let Some(prev) = app.command_history.last() {
                    app.command_input = prev.clone();
                }
            }
        }

        // Tab completion
        if response.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Tab)) {
            let input_lower = app.command_input.to_lowercase();
            if let Some(match_name) = query::query_names()
                .iter()
                .find(|name| name.starts_with(&input_lower) && **name != input_lower)
            {
                app.command_input = match_name.to_string();
            }
        }

        if ui.button("Run").clicked() {
            execute_command(app);
        }
    });
}

fn execute_command(app: &mut SisApp) {
    let input = app.command_input.trim().to_string();
    if input.is_empty() {
        return;
    }

    app.command_history.push(input.clone());
    app.command_input.clear();

    let Some(ref result) = app.result else {
        app.command_results.push(QueryOutput::Error("No file loaded".to_string()));
        return;
    };

    match query::parse_query(&input) {
        Ok(query) => {
            let output = query::execute_query(&query, result);
            // Handle navigation outputs
            match &output {
                QueryOutput::Navigation { obj, gen } => {
                    app.navigate_to_object(*obj, *gen);
                    app.show_objects = true;
                    app.command_results
                        .push(QueryOutput::Text(format!("Navigated to object {} {}", obj, gen)));
                }
                _ => {
                    app.command_results.push(output);
                }
            }
        }
        Err(err) => {
            app.command_results.push(QueryOutput::Error(err));
        }
    }
}

fn show_results(ui: &mut egui::Ui, app: &mut SisApp) {
    ui.horizontal(|ui| {
        ui.strong("Results");
        ui.separator();
        ui.label(format!("{} entries", app.command_results.len()));
        if ui.small_button("Clear").clicked() {
            app.command_results.clear();
        }
    });
    ui.separator();

    egui::ScrollArea::vertical().id_salt("command_results_scroll").stick_to_bottom(true).show(
        ui,
        |ui| {
            for (i, output) in app.command_results.iter().enumerate() {
                match output {
                    QueryOutput::Text(text) => {
                        ui.monospace(text);
                    }
                    QueryOutput::Table { headers, rows } => {
                        show_result_table(ui, i, headers, rows);
                    }
                    QueryOutput::Navigation { obj, gen } => {
                        ui.label(format!("Navigate to object {} {}", obj, gen));
                    }
                    QueryOutput::Error(msg) => {
                        ui.colored_label(egui::Color32::RED, format!("Error: {}", msg));
                    }
                }
                ui.separator();
            }
        },
    );
}

fn show_result_table(
    ui: &mut egui::Ui,
    table_idx: usize,
    headers: &[String],
    rows: &[Vec<String>],
) {
    if rows.is_empty() {
        ui.label("(no results)");
        return;
    }

    ui.label(format!("{} rows", rows.len()));

    let mut builder = TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .id_salt(format!("cmd_table_{}", table_idx));

    for (i, _) in headers.iter().enumerate() {
        if i == headers.len() - 1 {
            builder = builder.column(Column::remainder());
        } else {
            builder = builder.column(Column::auto().at_least(40.0));
        }
    }

    builder
        .header(18.0, |mut header| {
            for h in headers {
                header.col(|ui| {
                    ui.strong(h);
                });
            }
        })
        .body(|body| {
            body.rows(18.0, rows.len(), |mut row| {
                let row_data = &rows[row.index()];
                for cell in row_data {
                    row.col(|ui| {
                        ui.label(cell);
                    });
                }
            });
        });
}

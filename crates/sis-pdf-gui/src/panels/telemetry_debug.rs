use crate::app::SisApp;
use crate::telemetry::{TelemetryEventKind, FrameTimePercentiles};

/// Show the telemetry debug panel as a floating window.
pub fn show(ctx: &egui::Context, app: &mut SisApp) {
    let mut open = app.show_telemetry;
    egui::Window::new("Debug / Telemetry")
        .open(&mut open)
        .default_size([450.0, 400.0])
        .resizable(true)
        .show(ctx, |ui| {
            show_inner(ui, app);
        });
    app.show_telemetry = open;
}

fn show_inner(ui: &mut egui::Ui, app: &mut SisApp) {
    // Frame time section
    ui.heading("Frame Times");
    let percentiles = app.telemetry.frame_time_percentiles();
    show_frame_times(ui, &percentiles, app.telemetry.frame_sample_count());
    ui.separator();

    // Session info
    ui.heading("Session");
    let duration = app.telemetry.session_duration();
    ui.label(format!("Duration: {:.1}s", duration));
    ui.label(format!("Events recorded: {}", app.telemetry.event_count()));
    ui.label(format!("Active tabs: {}", app.tab_count));
    ui.separator();

    // Recent events
    ui.heading("Recent Events");
    let recent = app.telemetry.recent_events(50);
    egui::ScrollArea::vertical().id_salt("telemetry_events_scroll").show(ui, |ui| {
        for event in &recent {
            let desc = format_event_kind(&event.kind);
            ui.horizontal(|ui| {
                ui.monospace(format!("{:8.2}s", event.timestamp));
                ui.label(desc);
            });
        }
        if recent.is_empty() {
            ui.label("No events recorded yet");
        }
    });
}

fn show_frame_times(ui: &mut egui::Ui, p: &FrameTimePercentiles, sample_count: usize) {
    egui::Grid::new("frame_times_grid")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.label("Samples:");
            ui.label(format!("{}", sample_count));
            ui.end_row();

            ui.label("p50:");
            ui.label(format_frame_time(p.p50_ms));
            ui.end_row();

            ui.label("p95:");
            ui.label(format_frame_time(p.p95_ms));
            ui.end_row();

            ui.label("p99:");
            ui.label(format_frame_time(p.p99_ms));
            ui.end_row();
        });
}

fn format_frame_time(ms: f64) -> String {
    if ms == 0.0 {
        "-".to_string()
    } else {
        format!("{:.1} ms", ms)
    }
}

fn format_event_kind(kind: &TelemetryEventKind) -> String {
    match kind {
        TelemetryEventKind::FileOpened { file_name, file_size } => {
            format!("File opened: {} ({} bytes)", file_name, file_size)
        }
        TelemetryEventKind::PanelOpened { panel } => {
            format!("Panel opened: {}", panel)
        }
        TelemetryEventKind::PanelClosed { panel } => {
            format!("Panel closed: {}", panel)
        }
        TelemetryEventKind::TabSwitched { from, to } => {
            format!("Tab switched: {} -> {}", from, to)
        }
        TelemetryEventKind::QueryExecuted { query, duration_ms } => {
            format!("Query: {} ({:.1}ms)", query, duration_ms)
        }
        TelemetryEventKind::GraphLayoutCompleted { node_count, duration_ms } => {
            format!("Graph layout: {} nodes ({:.0}ms)", node_count, duration_ms)
        }
        TelemetryEventKind::Navigation { from_panel, to_panel, target } => {
            format!("Navigate: {} -> {} ({})", from_panel, to_panel, target)
        }
        TelemetryEventKind::FindingSelected { index } => {
            format!("Finding selected: #{}", index)
        }
        TelemetryEventKind::FilterApplied { filter_type, value } => {
            format!("Filter: {} = {}", filter_type, value)
        }
    }
}

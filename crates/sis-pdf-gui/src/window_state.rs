/// Per-window maximise/restore state.
#[derive(Default)]
pub struct WindowMaxState {
    pub is_maximised: bool,
}

/// Clamp a floating window so it cannot exceed the current workspace viewport.
pub fn clamp_to_viewport<'a>(window: egui::Window<'a>, ctx: &egui::Context) -> egui::Window<'a> {
    window.max_size(ctx.available_rect().size())
}

/// Render a maximise/restore toggle button. Returns true when maximised.
pub fn maximise_button(ui: &mut egui::Ui, state: &mut WindowMaxState) {
    let label = if state.is_maximised { "Restore" } else { "Max" };
    if ui.small_button(label).clicked() {
        state.is_maximised = !state.is_maximised;
    }
}

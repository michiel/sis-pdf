/// Per-window maximise/restore state.
#[derive(Default)]
pub struct WindowMaxState {
    pub is_maximised: bool,
}

/// Render a maximise/restore toggle button. Returns true when maximised.
pub fn maximise_button(ui: &mut egui::Ui, state: &mut WindowMaxState) {
    let label = if state.is_maximised { "Restore" } else { "Max" };
    if ui.small_button(label).clicked() {
        state.is_maximised = !state.is_maximised;
    }
}

/// Per-window maximise/restore state.
#[derive(Default)]
pub struct WindowMaxState {
    pub is_maximised: bool,
    /// Saved position and size before maximising, so we can restore them.
    prev_rect: Option<egui::Rect>,
}

/// Build a dialog window with a custom title bar containing maximise/restore
/// and close buttons alongside the title.
///
/// Uses `title_bar(false)` so we control the title bar layout. The underlying
/// `Area` still handles drag-to-move on non-interactive regions of the window.
///
/// Call `.show(ctx, |ui| { ... })` on the returned window to render it.
/// Inside the closure, call [`dialog_title_bar`] as the first element.
pub fn dialog_window<'a>(
    ctx: &egui::Context,
    title: &'a str,
    default_size: [f32; 2],
    state: &mut WindowMaxState,
) -> egui::Window<'a> {
    // We do NOT call .open() here because the custom title bar rendered by
    // dialog_title_bar handles closing via its own close button. This avoids
    // double mutable borrow of the open flag.
    let mut win = egui::Window::new(title)
        .resizable(!state.is_maximised)
        .title_bar(false)
        .max_size(ctx.available_rect().size());

    if state.is_maximised {
        // Save the current (pre-maximise) rect so we can restore it later.
        let window_id = egui::Id::new(title);
        if state.prev_rect.is_none() {
            state.prev_rect = ctx.memory(|mem| mem.area_rect(window_id));
        }
        let area = ctx.available_rect();
        win = win.fixed_pos(area.left_top()).fixed_size(area.size());
    } else if let Some(rect) = state.prev_rect.take() {
        // Restore to the saved position and size after unmaximising.
        win = win.current_pos(rect.left_top()).default_size(rect.size());
    } else {
        win = win.default_size(default_size);
    }

    win
}

/// Render a custom title bar with title, maximise/restore, and close buttons
/// all on a single row.
///
/// Place this as the first element inside a [`dialog_window`] content closure.
pub fn dialog_title_bar(
    ui: &mut egui::Ui,
    title: &str,
    open: &mut bool,
    state: &mut WindowMaxState,
) {
    ui.horizontal(|ui| {
        ui.strong(title);

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("\u{2715}").on_hover_text("Close").clicked() {
                *open = false;
            }

            let icon = if state.is_maximised { "\u{2750}" } else { "\u{25A2}" };
            let tooltip = if state.is_maximised {
                "Restore window"
            } else {
                "Maximise window"
            };
            if ui.small_button(icon).on_hover_text(tooltip).clicked() {
                state.is_maximised = !state.is_maximised;
            }
        });
    });
    ui.separator();
}

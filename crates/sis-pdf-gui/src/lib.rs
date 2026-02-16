#![forbid(unsafe_code)]

pub mod analysis;
#[cfg(feature = "gui")]
pub mod app;
pub mod graph_data;
pub mod graph_layout;
pub mod hex_format;
pub mod object_data;
#[cfg(feature = "gui")]
pub mod panels;
pub mod query;
#[cfg(feature = "gui")]
pub mod shortcuts;
pub mod telemetry;
#[cfg(feature = "gui")]
pub mod workspace;

/// WASM entry point: start eframe in the browser.
#[cfg(all(target_arch = "wasm32", feature = "gui"))]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start_wasm() {
    use wasm_bindgen::JsCast;

    console_error_panic_hook::set_once();
    let web_options = eframe::WebOptions::default();
    wasm_bindgen_futures::spawn_local(async {
        let document = web_sys::window().expect("no window").document().expect("no document");
        let canvas = document
            .get_element_by_id("sis_canvas")
            .expect("no canvas element with id 'sis_canvas'")
            .dyn_into::<web_sys::HtmlCanvasElement>()
            .expect("element is not a canvas");
        eframe::WebRunner::new()
            .start(canvas, web_options, Box::new(|cc| Ok(Box::new(app::SisApp::new(cc)))))
            .await
            .expect("failed to start eframe");
    });
}

/// Native entry point: run eframe in a desktop window.
#[cfg(all(not(target_arch = "wasm32"), feature = "gui"))]
pub fn start_native() -> eframe::Result {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "sis - PDF security analyser",
        options,
        Box::new(|cc| Ok(Box::new(app::SisApp::new(cc)))),
    )
}

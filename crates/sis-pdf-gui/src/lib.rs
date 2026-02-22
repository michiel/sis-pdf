#![forbid(unsafe_code)]

pub mod analysis;
#[cfg(feature = "gui")]
pub mod app;
pub mod event_view;
pub mod graph_data;
pub mod graph_layout;
pub mod hex_format;
pub mod image_preview;
pub mod object_data;
#[cfg(feature = "gui")]
pub mod panels;
pub mod preview_cache;
pub mod query;
#[cfg(feature = "gui")]
pub mod shortcuts;
pub mod telemetry;
pub mod util;
#[cfg(feature = "gui")]
pub mod window_state;
#[cfg(feature = "gui")]
pub mod workspace;

/// WASM entry point: start eframe in the browser.
#[cfg(all(target_arch = "wasm32", feature = "gui"))]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start_wasm() {
    use wasm_bindgen::JsCast;

    console_error_panic_hook::set_once();
    let Some(window) = web_sys::window() else {
        // Worker context: no UI bootstrap required.
        return;
    };
    let Some(document) = window.document() else {
        // Worker context: no UI bootstrap required.
        return;
    };
    let Some(canvas_el) = document.get_element_by_id("sis_canvas") else {
        // Worker context: no UI canvas available.
        return;
    };
    let web_options = eframe::WebOptions::default();
    wasm_bindgen_futures::spawn_local(async {
        let canvas =
            canvas_el.dyn_into::<web_sys::HtmlCanvasElement>().expect("element is not a canvas");
        eframe::WebRunner::new()
            .start(canvas, web_options, Box::new(|cc| Ok(Box::new(app::SisApp::new(cc)))))
            .await
            .expect("failed to start eframe");
    });
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn wasm_analyze_json(
    bytes: Vec<u8>,
    file_name: String,
) -> Result<String, wasm_bindgen::JsValue> {
    let result = crate::analysis::analyze_for_worker(&bytes, &file_name)
        .map_err(|err| wasm_bindgen::JsValue::from_str(&err.to_string()))?;
    serde_json::to_string(&result).map_err(|err| {
        wasm_bindgen::JsValue::from_str(&format!("serialize analysis result: {err}"))
    })
}

/// Native entry point: run eframe in a desktop window.
#[cfg(all(not(target_arch = "wasm32"), feature = "gui"))]
pub fn start_native() -> eframe::Result {
    #[cfg(target_os = "macos")]
    let viewport = egui::ViewportBuilder::default()
        .with_title("sis - PDF security analyser")
        .with_inner_size([1240.0, 820.0])
        .with_min_inner_size([960.0, 620.0]);
    #[cfg(target_os = "windows")]
    let viewport = egui::ViewportBuilder::default()
        .with_title("sis - PDF security analyser")
        .with_inner_size([1280.0, 860.0])
        .with_min_inner_size([980.0, 640.0]);
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let viewport = egui::ViewportBuilder::default()
        .with_title("sis - PDF security analyser")
        .with_inner_size([1200.0, 800.0])
        .with_min_inner_size([920.0, 600.0]);

    let options = eframe::NativeOptions { viewport, ..eframe::NativeOptions::default() };
    eframe::run_native(
        "sis - PDF security analyser",
        options,
        Box::new(|cc| Ok(Box::new(app::SisApp::new(cc)))),
    )
}

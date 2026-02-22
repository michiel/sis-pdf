#[cfg(all(not(target_arch = "wasm32"), feature = "gui"))]
fn main() {
    if let Err(err) = sis_pdf_gui::start_native() {
        eprintln!("Failed to launch sis-pdf-gui: {err}");
        std::process::exit(1);
    }
}

#[cfg(any(target_arch = "wasm32", not(feature = "gui")))]
fn main() {
    eprintln!("Native GUI entry point is unavailable for this build target.");
    std::process::exit(1);
}

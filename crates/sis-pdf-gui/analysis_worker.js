let wasmModulePromise = null;

async function loadWasmModule() {
  if (!wasmModulePromise) {
    // Some Rust/WASM code paths probe `window` for timing APIs.
    // In workers, map `window` to the worker global to preserve compatibility.
    if (typeof self.window === "undefined") {
      self.window = self;
    }
    wasmModulePromise = import("./sis-pdf-gui.js").then(async (module) => {
      if (typeof module.default === "function") {
        await module.default();
      }
      return module;
    });
  }
  return wasmModulePromise;
}

self.onmessage = async (event) => {
  try {
    if (typeof event.data !== "string") {
      self.postMessage(JSON.stringify({ ok: false, error: "Worker request must be JSON text" }));
      return;
    }
    const request = JSON.parse(event.data);
    const { file_name, bytes } = request ?? {};
    if (typeof file_name !== "string" || !Array.isArray(bytes)) {
      self.postMessage(JSON.stringify({ ok: false, error: "Invalid worker request payload" }));
      return;
    }
    const module = await loadWasmModule();
    if (typeof module.wasm_analyze_json !== "function") {
      self.postMessage(JSON.stringify({ ok: false, error: "WASM analysis entrypoint unavailable" }));
      return;
    }
    const result_json = module.wasm_analyze_json(bytes, file_name);
    self.postMessage(JSON.stringify({ ok: true, result_json }));
  } catch (err) {
    const message = err && typeof err.message === "string" ? err.message : String(err);
    self.postMessage(JSON.stringify({ ok: false, error: message }));
  }
};

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
    const workerStart = performance.now();
    const request = event.data ?? {};
    const { file_name, bytes } = request ?? {};
    if (typeof file_name !== "string") {
      self.postMessage({ ok: false, error: "Invalid worker request payload" });
      return;
    }
    let byteView = null;
    if (bytes instanceof ArrayBuffer) {
      byteView = new Uint8Array(bytes);
    } else if (bytes && ArrayBuffer.isView(bytes)) {
      byteView = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    }
    if (!byteView) {
      self.postMessage({ ok: false, error: "Invalid worker request payload" });
      return;
    }
    const module = await loadWasmModule();
    if (typeof module.wasm_analyze_value === "function") {
      const result = module.wasm_analyze_value(byteView, file_name);
      const result_json_bytes = (() => {
        try {
          return JSON.stringify(result).length;
        } catch (_) {
          return 0;
        }
      })();
      self.postMessage({
        ok: true,
        result,
        meta: {
          worker_ms: Math.max(0, performance.now() - workerStart),
          result_json_bytes,
        },
      });
      return;
    }
    if (typeof module.wasm_analyze_json === "function") {
      const result_json = module.wasm_analyze_json(byteView, file_name);
      const result = JSON.parse(result_json);
      self.postMessage({
        ok: true,
        result,
        meta: {
          worker_ms: Math.max(0, performance.now() - workerStart),
          result_json_bytes: result_json.length,
        },
      });
      return;
    }
    self.postMessage({ ok: false, error: "WASM analysis entrypoint unavailable" });
  } catch (err) {
    const message = err && typeof err.message === "string" ? err.message : String(err);
    self.postMessage({ ok: false, error: message });
  }
};

# Plan: migrate ML runtime from tract to ort (ONNX Runtime)

## Goals

- Replace `tract` runtime execution with `ort` for ONNX inference while keeping model behaviour stable.
- Enable cross-platform hardware acceleration for Windows, Linux, and macOS.
- Support GPU backends for AMD Radeon (MIGraphX), NVIDIA (CUDA), Intel Arc/Intel (DirectML/OpenVINO/oneDNN), and Apple (CoreML).
- Preserve security controls (no external tensor data, model integrity checks).
- Keep the pipeline observable and debuggable with structured tracing.

## Scope

- Crates affected: `crates/sis-pdf-ml-graph`, `crates/sis-pdf-core`, `crates/sis-pdf`.
- Inference paths: embedding model, graph model, and any future ONNX-based models.
- Non-goals (initially): training pipelines, model format changes, and new feature extraction logic.

## Current state (implemented)

- ORT is the active ONNX runtime; tract runtime execution has been removed (tract is retained only for ONNX safety parsing).
- Runtime configuration is available via CLI flags and `~/.config/sis/config.toml` (platform-specific defaults).
- Dynamic ORT library loading supported via config (`ml_ort_dylib`) and environment (`SIS_ORT_DYLIB_PATH`).
- Provider selection supports `auto`, `cpu`, `cuda`, `migraphx`, `rocm`, `directml`, `coreml`, `onednn`, `openvino`.
- `sis ml-health` subcommand validates runtime setup and reports selected provider.
- Model cache avoids repeated ORT session builds.
- Optional quantised model paths and batch size overrides are available.
- Tracing spans added for model load/infer and provider selection.

## Delivered changes

### Runtime abstraction

- ORT-backed session loader and runner in `crates/sis-pdf-ml-graph`.
- Session cache keyed by model path + provider settings.
- Provider selection uses ordered fallback with config override.

### Device selection and execution providers

- Provider selection is explicit and configurable:
  - Windows: DirectML, CUDA, CPU; OpenVINO/oneDNN as optional CPU accelerators.
  - Linux: CUDA, MIGraphX, CPU; OpenVINO/oneDNN optional.
  - macOS: CoreML, CPU.
- `rocm` remains available for compatibility, but ORT 1.23+ deprecates ROCm EP; prefer MIGraphX.

### Model safety validation

- Safety checks remain in place: no external tensor data, unsupported domains rejected, integrity checks optional.

### Instrumentation

- Tracing spans and events for `ml.onnx.load`, `ml.onnx.infer`, and provider selection.
- Logs are emitted to STDERR for compatibility with stdout report output.

## Technical examples

### Config snippet (TOML)

```toml
[scan]
ml_provider = "migraphx" # auto, cpu, cuda, migraphx, rocm, directml, coreml, onednn, openvino
ml_provider_order = ["migraphx", "cuda", "cpu"]
ml_ort_dylib = "/lib64/rocm/lib/libonnxruntime.so"
ml_provider_info = true
ml_quantized = false
ml_batch_size = 32
```

### CLI examples

```bash
# Report provider selection and runtime state
sis ml-health --ml-provider migraphx --ml-provider-info

# Run with explicit ORT dylib path
SIS_ORT_DYLIB_PATH=/path/to/libonnxruntime.so sis scan --ml --ml-mode graph --ml-model-dir target/
```

## Considerations

- **Binary size**: dynamic loading avoids bundling large ORT binaries.
- **Version compatibility**: `ort` 2.0.x requires ORT >= 1.23; MIGraphX EP is the supported AMD path from ORT 1.23 onwards.
- **Driver variance**: provider availability depends on OS/driver; fallbacks must stay reliable.
- **Threading**: ORT uses internal thread pools; avoid oversubscription with Rayon.
- **Security**: model integrity checks remain required when enabling GPU backends.
- **Performance**: session build time can be high; caching is mandatory.

## Risks

- Provider availability varies by OS and driver version.
- MIGraphX on Linux can be fragile with consumer AMD GPUs.
- DirectML may differ numerically on older hardware.
- CoreML provider behaviour can differ between Intel and Apple Silicon.
- Output parity may drift depending on precision settings.

## Suggestions and improvements (implemented or in progress)

- Local model cache to avoid repeated session builds.
- CLI option to print selected execution provider (`--ml-provider-info`).
- Config and env overrides for dynamic ORT library discovery (`ml_ort_dylib`, `SIS_ORT_DYLIB_PATH`).
- `sis ml-health` subcommand for runtime validation.
- Optional quantised models for faster CPU fallback.
- Batch size override for bulk scanning and feature extraction.

## Expected benefits

- Wider hardware acceleration support across all target platforms.
- Better long-term support and compatibility with ONNX tooling.
- Easier integration with production inference workflows.
- Improved performance on GPUs and modern CPUs.
- Clearer operational telemetry for debugging and incident response.

## Open questions

- Which providers should be enabled by default per platform once stability data is collected?
- Do we need per-model provider overrides, or a global preference is enough?
- What minimum driver versions should we document for each provider?

## Acceptance criteria

- ORT inference matches expected outputs within tolerance on a reference dataset.
- Device selection is configurable and logs the active provider.
- All CLI paths that use ML work with `--ml-mode graph`.
- Fallback to CPU works when acceleration is not available.

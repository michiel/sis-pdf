# Plan: Move `ml-health` to `sis ml health` and add `sis ml ort download`

## Goals

- Move the ML health check to a namespaced subcommand: `sis ml health`.
- Add `sis ml ort download` to fetch the correct ONNX Runtime (ORT) dylib for the host platform and configured ML provider.
- Select the ORT build based on OS, architecture, and ML provider (e.g., `migraphx` on Linux).
- Keep logs on STDERR and preserve structured logging for security telemetry.
- Add explicit GPU detection via `sis ml detect`.
- Add `sis ml autoconfig` to update configuration with optimal detected settings.

## Scope

- CLI command structure in `crates/sis-pdf/src/main.rs`.
- Configuration mapping for ML runtime provider selection.
- Download/verification logic (reuse existing updater patterns where possible).
- Documentation updates in `docs/` and `README.md`/`USAGE.md` as needed.
- Basic test coverage for provider resolution, mapping selection, and checksum verification.
- GPU detection logic and config updates.

## Non-goals

- Implementing new GPU detection libraries.
- Bundling ORT binaries inside the release.
- Managing per-user ORT caches across multiple versions (out of scope for v1).
- Writing complex driver/version compatibility validation beyond basic detection.

## Design overview

### 1) CLI restructuring

- Introduce `sis ml` as a parent command with subcommands:
  - `sis ml health` (replacing `sis ml-health`)
  - `sis ml ort download` (new)
  - `sis ml detect` (new)
  - `sis ml autoconfig` (new)
- Keep the old `sis ml-health` as a deprecated alias for one release cycle, or remove if breaking changes are acceptable.

### 2) Provider and platform resolution

- Inputs:
  - Config: `ml_provider`, `ml_provider_order`, `ml_ort_dylib`.
  - CLI overrides for provider and dylib path.
  - Runtime info: OS + architecture (from `std::env::consts`).
  - GPU detection output (`sis ml detect`).
- Resolution rules:
  - If `ml_ort_dylib` is set, skip download and report the configured path.
  - Otherwise resolve provider preference (prefer explicit `ml_provider`, fall back to `ml_provider_order` or `auto`).
  - Map provider + OS + arch to a known ORT build.

### 3) ORT distribution mapping

- Maintain a table of downloadable ORT distributions per platform/provider:
  - Linux x86_64:
    - `cpu` -> `onnxruntime-linux-x64-<ver>.tgz`
    - `cuda` -> `onnxruntime-linux-x64-gpu-<ver>.tgz`
    - `openvino` -> `onnxruntime-linux-x64-openvino-<ver>.tgz` (Intel Arc)
    - `migraphx` -> ROCm build (e.g., `onnxruntime-linux-x64-rocm-<ver>.tgz`)
  - Windows x86_64:
    - `cpu` -> `onnxruntime-win-x64-<ver>.zip`
    - `cuda` -> `onnxruntime-win-x64-gpu-<ver>.zip`
    - `directml` -> `onnxruntime-win-x64-directml-<ver>.zip`
  - macOS arm64:
    - `cpu` -> `onnxruntime-osx-arm64-<ver>.tgz`
    - `coreml` -> `onnxruntime-osx-arm64-coreml-<ver>.tgz`
- Store known versions in a single constant (default) and allow override via env or config (e.g., `SIS_ORT_VERSION`).

### 4) Download + verification

- Use HTTPS download to a temp dir, extract, and place `libonnxruntime.*` into a cache directory.
- Cache location:
  - `~/.cache/sis/ort/<version>/<target>` on Linux/macOS.
  - `%LOCALAPPDATA%\sis\ort\<version>\<target>` on Windows.
- Verify with SHA256 using upstream checksum files (required, not optional).
- Refuse to install if checksum verification is not available or does not match.
- Print final library path and optionally update the config file (opt-in).

### 5) Command behaviour

- `sis ml ort download`:
  - Resolves target from config + runtime.
  - Downloads and verifies the correct archive (required).
  - Extracts and prints the resolved dylib path.
  - Optional `--write-config` to set `ml_ort_dylib`.
- `sis ml health`:
  - Uses existing health checks with the reworked command path.
- `sis ml detect`:
  - Reports OS, arch, CPU features, and best-effort GPU detection.
  - Outputs provider suggestions in priority order.
  - Supports `--format json` for automation.
- `sis ml autoconfig`:
  - Runs detection and writes `ml_provider`, `ml_provider_order`, and optional `ml_ort_dylib`.
  - Supports `--dry-run` and `--config` overrides.

## Risks

- Provider availability varies by driver and OS version.
- ROCm/MIGraphX builds are more brittle and require specific driver versions.
- Upstream ORT archive naming conventions can change.
- Downloading binaries introduces supply-chain risk if checksums are not verified.
- GPU detection via CLI tools can be incomplete on locked-down hosts.

## Improvements and suggestions

- Add checksum verification for all downloads (required).
- Allow mirror URLs for enterprises (config option).
- Add `--dry-run` to show which build would be downloaded.
- Provide a `sis ml ort list` command to show supported combinations.
- Provide `sis ml detect --format json` output for fleet automation.

## Acceptance criteria

- `sis ml health` works and `sis ml-health` either aliases or provides a clear deprecation message.
- `sis ml ort download` selects the correct ORT build based on OS/arch/provider.
- Downloaded dylib is verified and cached.
- Config and docs reflect the new command structure.
- `sis ml detect` reports detection output and recommended providers.
- `sis ml autoconfig` updates config predictably with a dry-run mode.
- Tests cover provider resolution, target mapping, and checksum mismatch handling.

## Progress

- [x] Restructured CLI to add `sis ml` subcommands and deprecated `sis ml-health`.
- [x] Implemented ORT download, checksum verification, extraction, and caching.
- [x] Added `sis ml detect` and `sis ml autoconfig` with provider recommendations.
- [x] Added basic tests for provider order resolution, ORT mapping, and checksum verification.
- [x] Updated documentation in `docs/`, `README.md`, and `USAGE.md`.

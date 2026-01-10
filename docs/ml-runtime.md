# ML runtime management

This guide documents the ML runtime commands for selecting execution providers, downloading ONNX Runtime (ORT) libraries, and updating configuration safely.

## Overview

The ML runtime controls the execution provider (CPU/GPU) used by graph inference. You can:

- Validate current runtime health with `sis ml health`.
- Detect available execution providers with `sis ml detect`.
- Download the correct ORT dynamic library with `sis ml ort download`.
- Update config automatically with `sis ml autoconfig`.

All commands emit logs to STDERR and write machine-readable output to STDOUT when `--format json` is used.

## Commands

### `sis ml health`

Validates provider availability and optionally loads the model to confirm runtime compatibility.

```
sis ml health --ml-model-dir models/
```

### `sis ml detect`

Reports host OS/architecture, CPU feature flags, GPU tool availability, and provider recommendations.

Provider availability checks require the `ml-graph` feature.

```
sis ml detect
sis ml detect --format json
```

### `sis ml ort download`

Downloads and verifies the correct ORT archive for your OS, architecture, and provider.

```
sis ml ort download
sis ml ort download --ml-provider cuda
sis ml ort download --write-config
```

The command verifies SHA256 checksums and refuses to install if verification fails or is unavailable.

### `sis ml autoconfig`

Detects the best available providers and writes `ml_provider` and `ml_provider_order` into the config.

```
sis ml autoconfig
sis ml autoconfig --dry-run
```

## Cache locations

Downloaded ORT libraries are cached per version and target:

- Linux/macOS: `~/.cache/sis/ort/<version>/<target>`
- Windows: `%LOCALAPPDATA%\sis\ort\<version>\<target>`

## Configuration and overrides

Configuration is stored in `config.toml` under the `scan` section:

```
[scan]
ml_provider = "auto"
ml_provider_order = ["cuda", "migraphx", "cpu"]
ml_ort_dylib = "/path/to/libonnxruntime.so"
```

Intel Arc on Linux typically uses the `openvino` provider.

Environment overrides:

- `SIS_ORT_VERSION`: override the default ORT version.
- `SIS_ORT_BASE_URL`: override the ORT release base URL (for mirrors).
- `SIS_ORT_CHECKSUM_URL`: override the checksum file URL.
- `SIS_ORT_DYLIB_PATH`: point to a local ORT dynamic library.

## Safety notes

- Always validate checksums before using downloaded binaries.
- Avoid running unknown ORT archives without verification.
- Prefer `sis ml detect` to confirm provider availability before configuring GPU providers.

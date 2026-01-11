# ML runtime management

This guide documents the ML runtime commands for selecting execution providers, downloading ONNX Runtime (ORT) libraries, and updating configuration safely.

## Overview

The ML runtime controls the execution provider (CPU/GPU) used by graph inference. You can:

- Validate current runtime health with `sis ml health`.
- Detect available execution providers with `sis ml detect`.
- Download the correct ORT dynamic library with `sis ml ort download`.
- Update config automatically with `sis ml autoconfig`.

All commands emit logs to STDERR and write machine-readable output to STDOUT when `--format json` is used.

### ROCm/MIGraphX Support Status

**Important:** Microsoft stopped publishing pre-built ROCm binaries after ONNX Runtime 1.17.3. The current `ort` Rust crate (v2.0.0-rc.11) requires ONNX Runtime >= 1.23.x, creating a compatibility gap.

**Recommended approaches for ROCm users:**

1. **Use CPU provider** (simplest, works immediately):
   ```bash
   sis ml ort download --ml-provider cpu --write-config
   ```
   No GPU acceleration, but requires no additional setup.

2. **Build ONNX Runtime from source** (best performance):
   Follow the detailed instructions in the "Building ONNX Runtime from source with ROCm support" section below.
   Provides full GPU acceleration with modern ONNX Runtime versions.

3. **Wait for ort crate downgrade** (future option):
   The project could downgrade to `ort` v2.0.0-rc.2 which supports ORT 1.17.3, but this requires code refactoring.

**Recommendation:** For production use with ROCm GPUs, **build ONNX Runtime 1.23+ from source with `--use_rocm`**. For testing or CPU-only inference, use the CPU provider.

**Important Note:** Building ONNX Runtime 1.23.2 with ROCm on very new GCC versions (14+) may encounter header include issues (`uint32_t` not defined). If you encounter build failures:
1. Try using the CPU provider as a fallback: `sis ml ort download --ml-provider cpu --write-config`
2. Use a containerized build environment with GCC 12 or 13
3. Wait for ONNX Runtime 1.24+ which may have better compiler compatibility
4. Use Fedora's `onnxruntime-rocm` package (version 1.20.1) with an older `ort` crate if you downgrade the project dependencies

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

The command verifies SHA256 checksums automatically:
- Uses embedded checksums for known ORT versions when available
- If no checksum is available, computes the SHA256 hash and prompts for user confirmation
- Refuses to install if verification fails

You can provide a trusted checksum override:

```
sis ml ort download --checksum-url https://mirror.example/onnxruntime-linux-x64-rocm-1.17.3.tgz.sha256
sis ml ort download --checksum-file /path/to/onnxruntime.sha256
sis ml ort download --checksum-sha256 <sha256>
```

### `sis ml autoconfig`

Detects the best available providers and writes `ml_provider` and `ml_provider_order` into the config.

```
sis ml autoconfig
sis ml autoconfig --dry-run
```

## Building ONNX Runtime from source with ROCm support

### Background

Microsoft stopped publishing pre-built ROCm binaries after ONNX Runtime 1.17.3. The current `ort` Rust crate (v2.0.0-rc.11) requires ONNX Runtime >= 1.23.x, creating an incompatibility.

**Why you need to build from source:**
- Microsoft's last ROCm build: ONNX Runtime 1.17.3
- Current ort crate requires: ONNX Runtime >= 1.23.x
- Fedora's `onnxruntime-rocm` package: version 1.20.1 (still too old)
- **Solution:** Build ONNX Runtime 1.23.2 from source with ROCm support

**Estimated time:** 20-40 minutes for the build on a modern CPU

### Prerequisites

```bash
# Install ROCm
# Fedora:
sudo dnf install \
  rocm-hip rocm-hip-devel \
  rocm-runtime rocm-runtime-devel \
  rocm-opencl rocm-opencl-devel \
  rocm-clang rocm-device-libs \
  rocminfo rocm-smi

# Ubuntu/Debian:
# Follow official guide at https://rocm.docs.amd.com/

# Install build dependencies
sudo dnf install cmake ninja-build python3-pip git gcc-c++  # Fedora
# OR
sudo apt install cmake ninja-build python3-pip git g++     # Ubuntu

# Install Python dependencies
pip install --upgrade pip setuptools wheel

# Verify ROCm installation
rocminfo
rocm-smi  # Should show your AMD GPU
```

### Understanding ROCm vs MIGraphX

ONNX Runtime provides two execution providers for AMD GPUs:

1. **ROCm EP** (`--use_rocm`): Direct ROCm execution provider. **Recommended** - simpler to build, no extra dependencies.
2. **MIGraphX EP** (`--use_migraphx`): Uses AMD's MIGraphX graph compiler. Requires MIGraphX to be installed separately.

**For most users, the ROCm EP is sufficient and easier to set up.**

### Complete build guide (ROCm EP - Recommended)

This is the complete step-by-step process for Fedora/RHEL systems. For Ubuntu/Debian, adjust the ROCm path from `/usr` to `/opt/rocm`.

#### Step 1: Clone and prepare ONNX Runtime

```bash
# Clone ONNX Runtime repository
git clone --recursive https://github.com/microsoft/onnxruntime.git
cd onnxruntime

# Checkout version 1.23.2 (required for ort crate 2.0.0-rc.11)
git checkout v1.23.2
git submodule update --init --recursive
```

#### Step 2: Build ONNX Runtime with ROCm support

**Important notes:**
- Build takes 20-40 minutes depending on your CPU
- Uses `--rocm_home /usr` for Fedora/RHEL (change to `/opt/rocm` for Ubuntu/Debian)
- Uses `-w` to disable all warnings with newer GCC versions (13+)
- Use `--use_rocm` NOT `--use_migraphx` (simpler, no MIGraphX dependency)

```bash
# Clean any previous build attempts
rm -rf build/ CMakeCache.txt

# Build with ROCm Execution Provider
# Note: -w completely disables warnings (needed for newer GCC versions)
./build.sh --config Release \
  --build_shared_lib \
  --parallel \
  --use_rocm \
  --rocm_home /usr \
  --skip_tests \
  --cmake_extra_defines CMAKE_CXX_FLAGS="-w"

# Verify build succeeded - should show library files
ls -lh build/Linux/Release/libonnxruntime.so*
```

#### Step 3: Install to sis cache

```bash
# Create cache directory
mkdir -p ~/.cache/sis/ort/1.23.2/linux-x86_64-rocm

# Copy all library files (main + versioned)
cp build/Linux/Release/libonnxruntime.so* ~/.cache/sis/ort/1.23.2/linux-x86_64-rocm/

# Verify files were copied
ls -lh ~/.cache/sis/ort/1.23.2/linux-x86_64-rocm/
```

#### Step 4: Configure sis to use the library

```bash
# Add ML runtime configuration to sis config
cat >> ~/.config/sis/config.toml <<'EOF'
[scan]
ml_provider = "rocm"
ml_ort_dylib = "$HOME/.cache/sis/ort/1.23.2/linux-x86_64-rocm/libonnxruntime.so"
EOF
```

#### Step 5: Verify the setup

```bash
# Test that sis can detect and use ROCm
sis ml detect

# Expected output should show:
# - ROCm in available providers
# - ROCm as selected provider
# - GPU detected via rocm-smi
```

#### Quick build script

For convenience, you can use this script to automate the build:

```bash
#!/bin/bash
set -e

cd ~/onnxruntime
echo "Cleaning previous build..."
rm -rf build/ CMakeCache.txt

echo "Building ONNX Runtime 1.23.2 with ROCm support..."
echo "This will take 20-40 minutes..."

./build.sh --config Release \
  --build_shared_lib \
  --parallel \
  --use_rocm \
  --rocm_home /usr \
  --skip_tests \
  --cmake_extra_defines CMAKE_CXX_FLAGS="-w"

echo "Build complete! Installing to sis cache..."
mkdir -p ~/.cache/sis/ort/1.23.2/linux-x86_64-rocm
cp build/Linux/Release/libonnxruntime.so* ~/.cache/sis/ort/1.23.2/linux-x86_64-rocm/

echo "Done! Library installed at:"
ls -lh ~/.cache/sis/ort/1.23.2/linux-x86_64-rocm/

echo ""
echo "Next step: Add to your sis config.toml:"
echo "[scan]"
echo "ml_provider = \"rocm\""
echo "ml_ort_dylib = \"\$HOME/.cache/sis/ort/1.23.2/linux-x86_64-rocm/libonnxruntime.so\""
```

### Build instructions (MIGraphX EP - Advanced)

**Only use this if you specifically need MIGraphX.** Requires installing MIGraphX first.

```bash
# Install MIGraphX (Ubuntu/Debian)
wget https://repo.radeon.com/rocm/apt/debian/rocm.gpg.key -O - | gpg --dearmor | \
  sudo tee /etc/apt/keyrings/rocm.gpg > /dev/null
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/rocm.gpg] https://repo.radeon.com/rocm/apt/debian jammy main" | \
  sudo tee /etc/apt/sources.list.d/rocm.list
sudo apt update
sudo apt install migraphx

# Or for Fedora/RHEL
sudo dnf install migraphx

# Then build ONNX Runtime with MIGraphX
cd onnxruntime
git checkout v1.23.2
git submodule update --init --recursive

./build.sh --config Release \
  --build_shared_lib \
  --parallel \
  --use_migraphx \
  --rocm_home /opt/rocm \
  --skip_tests

# Copy to sis cache
mkdir -p ~/.cache/sis/ort/1.23.2/linux-x86_64-migraphx
cp build/Linux/Release/libonnxruntime.so* ~/.cache/sis/ort/1.23.2/linux-x86_64-migraphx/

# Configure sis to use it
cat >> ~/.config/sis/config.toml <<EOF
[scan]
ml_provider = "migraphx"
ml_ort_dylib = "$HOME/.cache/sis/ort/1.23.2/linux-x86_64-migraphx/libonnxruntime.so"
EOF
```

### Build options

Common build flags:

- `--use_rocm`: Enable ROCm Execution Provider (simpler, recommended)
- `--use_migraphx`: Enable MIGraphX Execution Provider (requires MIGraphX installed)
- `--rocm_home /opt/rocm`: Specify ROCm installation path
- `--build_shared_lib`: Build shared library (required for dynamic loading)
- `--parallel`: Enable parallel build
- `--skip_tests`: Skip running tests (faster build)
- `--config Release`: Build in release mode (optimized)

### Verification

After building, verify the library loads correctly:

```bash
# Check library dependencies
ldd build/Linux/Release/libonnxruntime.so

# Test with Python
python3 -c "import onnxruntime as ort; print(ort.__version__); print(ort.get_available_providers())"
```

### Configuration

Point sis to your custom build:

```toml
[scan]
ml_provider = "rocm"  # or "migraphx" if you built with MIGraphX
ml_ort_dylib = "/path/to/onnxruntime/build/Linux/Release/libonnxruntime.so"
```

Or use the environment variable:

```bash
export SIS_ORT_DYLIB_PATH=/path/to/onnxruntime/build/Linux/Release/libonnxruntime.so
sis ml detect
```

### Troubleshooting

**Error: "Could not find a package configuration file provided by migraphx"**

This means you used `--use_migraphx` instead of `--use_rocm`. Solution:
```bash
# Clean and rebuild with correct flag
cd ~/onnxruntime
rm -rf build/ CMakeCache.txt
./build.sh --config Release --build_shared_lib --parallel --use_rocm --rocm_home /usr --skip_tests --cmake_extra_defines CMAKE_CXX_FLAGS="-Wno-error"
```

**Error: "error: loop variable 'provider' creates a copy" or other compiler warnings**

Newer GCC versions (13+) treat warnings as errors. Solution:
```bash
# Use -w to completely disable all warnings
./build.sh --config Release \
  --build_shared_lib \
  --parallel \
  --use_rocm \
  --rocm_home /usr \
  --skip_tests \
  --cmake_extra_defines CMAKE_CXX_FLAGS="-w"

# Note: -Wno-error doesn't work for all warning types, -w is more reliable
```

**Build fails with ROCm not found:**

Verify ROCm is installed and check the path:
```bash
# Check ROCm installation
rocminfo

# Fedora/RHEL: ROCm is in /usr
ls /usr/lib64/libamdhip64.so

# Ubuntu/Debian: ROCm is in /opt/rocm
ls /opt/rocm/lib/libamdhip64.so

# Use the correct path in build command
# Fedora: --rocm_home /usr
# Ubuntu: --rocm_home /opt/rocm
```

**Runtime error: "ort 2.0.0-rc.11 is not compatible with ONNX Runtime version 1.17.3"**

The pre-built ROCm binaries from Microsoft are too old. You must build ONNX Runtime >= 1.23.x from source (see instructions above).

**Runtime "provider not available" errors:**

Verify ROCm runtime is working:
```bash
# Check HIP runtime
hipconfig --version

# Check GPU is detected
rocm-smi

# Ensure ROCm libraries are in library path (Fedora usually handles this automatically)
export LD_LIBRARY_PATH=/usr/lib64:$LD_LIBRARY_PATH  # Fedora
export LD_LIBRARY_PATH=/opt/rocm/lib:$LD_LIBRARY_PATH  # Ubuntu
```

**Build fails: "ROCm not installed"**

Install ROCm packages first:
```bash
# Fedora
sudo dnf install rocm-hip rocm-hip-devel rocm-runtime rocm-runtime-devel rocm-opencl rocm-opencl-devel rocm-clang rocm-device-libs rocminfo rocm-smi

# Verify installation
rocminfo
rocm-smi
```

**Build fails: "error: 'uint32_t' does not name a type"**

This occurs with very new GCC versions (14+) due to missing header includes in ONNX Runtime 1.23.2. Solutions:

1. **Use CPU provider instead** (recommended for quick start):
   ```bash
   sis ml ort download --ml-provider cpu --write-config
   ```

2. **Use a container with older GCC**:
   ```bash
   # Pull container with GCC 13
   podman run -it -v ~/onnxruntime:/build fedora:39 bash
   # Then build inside container
   ```

3. **Wait for ONNX Runtime 1.24+** which may have better compiler compatibility

4. **Patch the source** (advanced): Add `#include <cstdint>` to affected header files

### Quick reference: Key differences for Fedora vs Ubuntu

| Aspect | Fedora/RHEL | Ubuntu/Debian |
|--------|-------------|---------------|
| ROCm location | `/usr` | `/opt/rocm` |
| Build flag | `--rocm_home /usr` | `--rocm_home /opt/rocm` |
| Library path | `/usr/lib64` | `/opt/rocm/lib` |
| ROCm install | `dnf install rocm-*` | Follow AMD guide |

### Common pitfalls to avoid

1. **Don't use** `--use_migraphx` unless you specifically need MIGraphX and have it installed
2. **Always use** `--cmake_extra_defines CMAKE_CXX_FLAGS="-w"` with GCC 13+ (disables all warnings)
3. **Fedora users:** Use `--rocm_home /usr`, not `/opt/rocm`
4. **Don't forget** to copy ALL `.so*` files, not just `libonnxruntime.so`
5. **Build takes time:** Allow 20-40 minutes, don't interrupt it

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

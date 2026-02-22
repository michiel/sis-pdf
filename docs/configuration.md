# Configuration Guide

This guide covers how to configure `sis-pdf` using configuration files and named profiles.

## Overview

`sis-pdf` supports external configuration files that allow you to:
- Define reusable scan configurations
- Create named profiles for different use cases
- Override default settings without lengthy command-line arguments
- Share configurations across your team

## Configuration Files

Configuration files can be written in **YAML** or **JSON** format.

### Basic Structure

```yaml
# Global scan defaults (optional)
scan:
  deep: true
  max_decode_bytes: 134217728

# Named profiles (optional)
profiles:
  interactive:
    scan:
      deep: true
      diff_parser: true

  fast:
    scan:
      fast: true
      parallel: true
```

### Loading Configuration

Use the `--config` flag to load a configuration file:

```bash
sis scan file.pdf --config config.yml
```

## Using Profiles

The `--profile` flag selects a named profile from your configuration file.

### Syntax

```bash
sis scan <file.pdf> --config <config-file> --profile <profile-name>
```

### Example

**config.yml:**
```yaml
profiles:
  interactive:
    scan:
      deep: true
      diff_parser: true
      max_decode_bytes: 134217728

  fast:
    scan:
      fast: true
      parallel: true
      max_decode_bytes: 33554432

  thorough:
    scan:
      deep: true
      strict: true
      diff_parser: true
      ml_threshold: 0.3
```

**Usage:**
```bash
# Use the 'interactive' profile
sis scan suspicious.pdf --config config.yml --profile interactive

# Use the 'fast' profile
sis scan batch/*.pdf --config config.yml --profile fast

# Use the 'thorough' profile with ML
sis scan unknown.pdf --config config.yml --profile thorough --ml --ml-model-dir models/
```

## Configuration Precedence

Settings are applied in the following order (later overrides earlier):

1. **Built-in defaults** - Hard-coded defaults in `sis-pdf`
2. **Global `scan` section** - Applies to all scans when using this config
3. **Selected profile** - Overrides global settings when `--profile` is specified
4. **Command-line flags** - Always take highest precedence

### Example

```yaml
# Global defaults
scan:
  deep: false
  max_objects: 500000

profiles:
  thorough:
    scan:
      deep: true  # Overrides global 'deep: false'
      strict: true
```

```bash
# Results in: deep=true, strict=true, max_objects=1000000
sis scan file.pdf --config config.yml --profile thorough --max-objects 1000000
```

## Available Configuration Options

All `scan` configuration options correspond to command-line flags.

### Core Scanning Options

| Configuration Key | Type | Description | CLI Flag |
|------------------|------|-------------|----------|
| `deep` | boolean | Enable deep scanning | `--deep` |
| `fast` | boolean | Fast mode (cheap detectors only) | `--fast` |
| `strict` | boolean | Strict PDF parsing | `--strict` |
| `parallel` | boolean | Parallel detector execution | Default: true, `--sequential` to disable |
| `batch_parallel` | boolean | Parallel batch processing | Default: false |
| `recover_xref` | boolean | Attempt xref recovery | `--recover-xref` |
| `diff_parser` | boolean | Compare with secondary parser | `--diff-parser` |
| `group_chains` | boolean | Group similar chains in output | `--ungroup-chains` to disable |

### Resource Limits

| Configuration Key | Type | Description | CLI Flag |
|------------------|------|-------------|----------|
| `max_objects` | integer | Maximum PDF objects to parse | `--max-objects` |
| `max_decode_bytes` | integer | Max bytes to decode per stream | `--max-decode-bytes` |
| `max_total_decoded_bytes` | integer | Max total decoded bytes | `--max-total-decoded-bytes` |
| `max_recursion_depth` | integer | Max recursion depth | `--max-recursion-depth` |

### Focus Options

| Configuration Key | Type | Description | CLI Flag |
|------------------|------|-------------|----------|
| `focus_trigger` | string | Focus on specific finding type | `--focus` |
| `focus_depth` | integer | Graph traversal depth for focus | `--focus-depth` |

### YARA Options

| Configuration Key | Type | Description | CLI Flag |
|------------------|------|-------------|----------|
| `yara_scope` | string | YARA scope: `all`, `medium`, `high` | `--yara-scope` |

### Machine Learning Options

| Configuration Key | Type | Description | CLI Flag |
|------------------|------|-------------|----------|
| `ml_model` | string | Path to ML model directory | `--ml-model-dir` |
| `ml_threshold` | float | ML classification threshold | `--ml-threshold` |
| `ml_mode` | string | ML mode: `traditional` or `graph` | `--ml-mode` |
| `ml_provider` | string | ONNX runtime provider | `--ml-provider` |
| `ml_provider_order` | array | Provider priority order | `--ml-provider-order` |
| `ml_ort_dylib` | string | Path to ONNX Runtime library | `--ml-ort-dylib` |
| `ml_quantized` | boolean | Use quantized models | `--ml-quantized` |
| `ml_batch_size` | integer | Batch size for inference | `--ml-batch-size` |
| `ml_provider_info` | boolean | Show provider information | `--ml-provider-info` |

### Font Analysis Options

| Configuration Key | Type | Description | CLI Flag |
|------------------|------|-------------|----------|
| `font-analysis.enabled` | boolean | Enable font analysis | N/A |
| `font-analysis.dynamic_enabled` | boolean | Enable dynamic font loading | N/A |
| `font-analysis.dynamic_timeout_ms` | integer | Timeout for dynamic loading (ms) | N/A |
| `font-analysis.max_fonts` | integer | Maximum fonts to analyze | N/A |

### Image Analysis Options

| Configuration Key | Type | Description | CLI Flag |
|------------------|------|-------------|----------|
| `image-analysis.enabled` | boolean | Enable image analysis | `--no-image-analysis` to disable |
| `image-analysis.dynamic_enabled` | boolean | Enable dynamic image decoding | `--no-image-dynamic` to disable |
| `image-analysis.max_pixels` | integer | Maximum pixels per image decode | N/A |
| `image-analysis.max_decode_bytes` | integer | Maximum decode bytes per image | N/A |
| `image-analysis.timeout_ms` | integer | Per-image decode timeout in milliseconds | N/A |
| `image-analysis.max_header_bytes` | integer | Max bytes to inspect from image headers | N/A |
| `image-analysis.max_dimension` | integer | Maximum width or height for images | N/A |
| `image-analysis.max_xfa_decode_bytes` | integer | Maximum bytes for XFA image decoding | N/A |
| `image-analysis.max_filter_chain_depth` | integer | Max filter chain depth for XFA decoding | N/A |

### Correlation Options

| Configuration Key | Type | Description | CLI Flag |
|------------------|------|-------------|----------|
| `correlation.enabled` | boolean | Enable Stage 9 cross-finding correlation (composite findings) | N/A |
| `correlation.launch_obfuscated` | boolean | Emit `launch_obfuscated_executable` for correlated launch + embedded executable | N/A |
| `correlation.action_chain_malicious` | boolean | Emit `action_chain_malicious` for automatic JS chains | N/A |
| `correlation.xfa_data_exfiltration` | boolean | Emit `xfa_data_exfiltration_risk` when sensitive fields pair with external submits | N/A |
| `correlation.encrypted_payload_delivery` | boolean | Emit `encrypted_payload_delivery` for encrypted archives + launch/SWF | N/A |
| `correlation.obfuscated_payload` | boolean | Emit `obfuscated_payload` when unusual filters coincide with high entropy streams | N/A |
| `correlation.content_stream_exec_alignment` | boolean | Emit `content_stream_exec_outcome_alignment` when stream-exec anomalies align with high-risk execute/egress findings | N/A |
| `correlation.high_entropy_threshold` | float | Entropy threshold (0-8) used when matching high entropy streams | N/A |
| `correlation.action_chain_depth` | integer | Minimum depth required to treat an action chain as complex | N/A |
| `correlation.xfa_sensitive_field_threshold` | integer | Minimum sensitive field count for XFA exfiltration correlation | N/A |

## Example Configurations

### Example 1: Security-Focused Profile

```yaml
profiles:
  security:
    scan:
      deep: true
      strict: true
      diff_parser: true
      max_decode_bytes: 268435456  # 256 MB
      max_objects: 1000000
      ml_threshold: 0.4
      font-analysis:
        enabled: true
        max_fonts: 512
      image-analysis:
        enabled: true
        dynamic_enabled: true
        max_pixels: 100000000
```

### Example 2: Performance-Optimized Profile

```yaml
profiles:
  fast:
    scan:
      fast: true
      parallel: true
      max_decode_bytes: 33554432  # 32 MB
      max_objects: 100000
      font-analysis:
        enabled: false
```

### Example 3: Multiple Profiles for Different Scenarios

```yaml
# Global defaults applied to all profiles
scan:
  recover_xref: true
  parallel: true

profiles:
  # Quick triage of potentially malicious PDFs
  triage:
    scan:
      fast: true
      max_decode_bytes: 33554432
      max_objects: 100000

  # Interactive analysis during investigation
  interactive:
    scan:
      deep: true
      diff_parser: true
      max_decode_bytes: 134217728
      yara_scope: "medium"

  # Comprehensive analysis for high-value targets
  forensic:
    scan:
      deep: true
      strict: true
      diff_parser: true
      max_decode_bytes: 536870912  # 512 MB
      max_objects: 5000000
      yara_scope: "all"
      ml_threshold: 0.3
      font-analysis:
        enabled: true
        dynamic_enabled: true
        max_fonts: 1000

  # Batch processing of document corpus
  batch:
    scan:
      fast: false
      deep: false
      batch_parallel: true
      max_decode_bytes: 67108864  # 64 MB
      max_objects: 500000
```

**Usage:**
```bash
# Quick triage
sis scan suspicious.pdf --config profiles.yml --profile triage

# Interactive investigation
sis scan evidence.pdf --config profiles.yml --profile interactive

# Forensic analysis
sis scan critical.pdf --config profiles.yml --profile forensic --ml --ml-model-dir models/

# Batch processing
sis scan corpus/*.pdf --config profiles.yml --profile batch
```

## Configuration File Locations

You can place configuration files anywhere and reference them with `--config`:

```bash
# Local configuration
sis scan file.pdf --config ./config.yml --profile security

# Team-shared configuration
sis scan file.pdf --config /etc/sis-pdf/config.yml --profile default

# Per-project configuration
sis scan file.pdf --config ~/.sis-pdf/project-x.yml --profile thorough
```

## JSON Format

Configuration files can also be written in JSON:

```json
{
  "scan": {
    "deep": true,
    "max_decode_bytes": 134217728
  },
  "profiles": {
    "interactive": {
      "scan": {
        "deep": true,
        "diff_parser": true
      }
    },
    "fast": {
      "scan": {
        "fast": true,
        "parallel": true
      }
    }
  }
}
```

## Validation

Configuration files are validated when loaded:
- Maximum config file size: 1 MB
- Numeric limits are enforced (e.g., `max_objects` ≤ 10,000,000)
- Invalid keys are ignored with warnings
- Type mismatches result in errors

## Difference from Runtime Profiling

⚠️ **Note:** The `--profile` flag is **different** from `--runtime-profile`:

- **`--profile <name>`** - Selects a configuration profile (scan settings)
- **`--runtime-profile`** - Enables performance profiling (timing measurements)

You can use both together:
```bash
sis scan file.pdf --config config.yml --profile thorough --runtime-profile
```

This will:
1. Apply the "thorough" scanning configuration
2. Measure and report detector performance timings

## See Also

- [Usage Guide](../USAGE.md) - Complete command reference
- [Runtime Profiling](profiling.md) - Performance measurement guide (if created)
- Configuration implementation: [`crates/sis-pdf-core/src/config.rs`](../crates/sis-pdf-core/src/config.rs)

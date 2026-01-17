# Font Analysis

Comprehensive font security analysis library for detecting vulnerabilities, malformed structures, and suspicious patterns in font files.

## Features

- **Static Analysis**: Fast pattern-based detection of common font anomalies
- **Dynamic Analysis**: Deep parsing and validation using ttf-parser and skrifa
- **CVE Signature Matching**: Automated detection of known vulnerabilities
- **Type 1 Font Analysis**: Specialized analysis for PostScript Type 1 fonts
- **Variable Font Detection**: Analysis of OpenType variable fonts (fvar, HVAR, MVAR, etc.)
- **Color Font Analysis**: Detection of COLR/CPAL anomalies
- **WOFF/WOFF2 Support**: Decompression bomb detection and format validation
- **TrueType VM**: Hinting bytecode analysis with security checks
- **Context-Aware Severity**: Adjustable severity based on deployment context

## Usage

### Basic Analysis

```rust
use font_analysis::{analyse_font, FontAnalysisConfig};

let font_data = std::fs::read("suspicious.ttf")?;
let config = FontAnalysisConfig::default();
let outcome = analyse_font(&font_data, &config);

for finding in outcome.findings {
    println!("{}: {}", finding.severity, finding.title);
    println!("  {}", finding.description);
}
```

### With Dynamic Analysis

```rust
let mut config = FontAnalysisConfig::default();
config.dynamic_enabled = true;
config.dynamic_timeout_ms = 5000;

let outcome = analyse_font(&font_data, &config);
```

### CVE Signature Matching

```rust
let mut config = FontAnalysisConfig::default();
config.signature_matching_enabled = true;
config.signature_directory = Some("/path/to/signatures".to_string());

let outcome = analyse_font(&font_data, &config);

// Check for specific CVEs
for finding in outcome.findings {
    if finding.kind.starts_with("cve.") {
        println!("Detected: {}", finding.kind);
    }
}
```

### Custom Signatures

```rust
use font_analysis::{SignatureRegistry, Signature};

// Load signatures from custom location
let config = FontAnalysisConfig::default();
let signatures = config.load_signatures()?;

// Or build registry manually
let mut registry = SignatureRegistry::new();
let signature = Signature {
    cve_id: "CVE-2024-12345".to_string(),
    description: "Example vulnerability".to_string(),
    severity: SignatureSeverity::High,
    // ... other fields
};
registry.add(signature);
```

## Configuration

### FontAnalysisConfig Options

```rust
FontAnalysisConfig {
    // Core settings
    enabled: true,                    // Enable font analysis
    max_fonts: 100,                   // Max fonts per PDF

    // Dynamic analysis
    dynamic_enabled: false,           // Enable deep parsing
    dynamic_timeout_ms: 5000,         // Timeout for dynamic analysis

    // Type 1 settings
    max_charstring_ops: 50_000,       // Max operators in charstring
    max_stack_depth: 256,             // Max stack depth

    // Signature matching
    signature_matching_enabled: true, // Enable CVE signatures
    signature_directory: None,        // Custom signature path (None = embedded)

    // Network
    network_access: false,            // Allow external font fetching
}
```

### Configuration Formats

Load configuration from JSON, YAML, or TOML:

```rust
// From JSON
let config = FontAnalysisConfig::from_json(json_str)?;

// From YAML
let config = FontAnalysisConfig::from_yaml(yaml_str)?;

// From TOML
let config = FontAnalysisConfig::from_toml(toml_str)?;
```

## CVE Signature System

The signature system enables automated detection of known font vulnerabilities through pattern matching.

### Features

- **12 Pattern Types**: Comprehensive coverage of font vulnerability classes
- **Flexible Matching**: AND/OR logic for multi-condition vulnerabilities
- **Extensible**: Easy to add new signatures as CVEs are discovered
- **Well-Documented**: Each signature includes rationale and references

### Pattern Types

1. **TableLengthMismatch**: Table size inconsistent with metadata
2. **GlyphCountMismatch**: Glyph count discrepancies between tables
3. **OffsetOutOfBounds**: Table offsets exceeding boundaries
4. **TableSizeExceeds**: Tables exceeding safe size limits
5. **OperatorSequence**: Suspicious operator patterns in bytecode
6. **IntegerOverflow**: Arithmetic overflow detection
7. **InvalidMagic**: Corrupted magic numbers
8. **RecursionDepthExceeds**: Excessive nesting in structures
9. **CircularReference**: Circular references in font data
10. **BufferOverflow**: Offset+size exceeding boundaries
11. **InvalidTableReference**: Missing or invalid cross-references
12. **InvalidInstructionSequence**: Dangerous TrueType instructions

### Creating Signatures

See [SIGNATURE_GUIDE.md](SIGNATURE_GUIDE.md) for detailed documentation on writing signatures.

Quick example:

```yaml
- cve_id: CVE-2025-27163
  description: hmtx table length mismatch
  severity: high
  signature_rationale: |
    The hmtx table must contain at least numberOfHMetrics * 4 bytes.
    When smaller, parsers perform out-of-bounds reads.
  match_logic: all
  patterns:
    - type: table_length_mismatch
      table1: hmtx
      table2: hhea
      condition: "table1.length < 4 * table2.num_metrics"
  references:
    - https://nvd.nist.gov/vuln/detail/CVE-2025-27163
```

### Signature Locations

- **Embedded**: `crates/font-analysis/signatures/` (compiled into binary)
- **Custom**: Specify via `config.signature_directory`
- **Pending Review**: `crates/font-analysis/signatures-pending/`

## Analysis Capabilities

### Static Analysis

Fast checks without parsing:

- Font format identification (TrueType, OpenType, Type 1, WOFF)
- File size anomalies
- Magic number validation
- Basic structure checks

### Dynamic Analysis (requires `dynamic` feature)

Deep parsing and validation:

- Full font structure parsing
- Table validation and cross-checking
- Glyph count consistency
- Variable font table analysis
- Color font validation
- TrueType hinting bytecode analysis
- Compression ratio checks (WOFF/WOFF2)

### Type 1 Analysis

PostScript Type 1 font checks:

- eexec section decryption
- Charstring operator analysis
- Blend operator detection (Multiple Master)
- Stack depth analysis
- Dangerous operator detection

### Context-Aware Analysis

Adjust severity based on deployment context:

```rust
use font_analysis::AnalysisContext;

let mut context = AnalysisContext::default();
context.is_server_side_rendering = true;  // Increase severity
context.is_trusted_source = false;        // Don't downgrade severity

let adjusted_findings = context.adjust_findings(&findings);
```

## Feature Flags

- **`dynamic`**: Enable dynamic analysis (ttf-parser, skrifa)
  - Required for signature matching
  - Adds ~2MB to binary size
  - Enables deep font parsing

## Findings

All analysis returns `FontFinding` objects:

```rust
pub struct FontFinding {
    pub kind: String,           // "font.malformed_table", "cve.2024-12345"
    pub severity: Severity,     // Info, Low, Medium, High
    pub confidence: Confidence, // Heuristic, Probable, Strong
    pub title: String,          // Human-readable title
    pub description: String,    // Detailed description
    pub meta: HashMap<String, String>, // Additional context
}
```

### Finding Types

- `font.*`: General font anomalies
- `cve.*`: CVE signature matches
- `type1.*`: Type 1 font issues
- `variable.*`: Variable font issues
- `color.*`: Color font issues
- `woff.*`: WOFF/WOFF2 issues
- `ttf_vm.*`: TrueType hinting issues

## Performance

- **Static Analysis**: <1ms per font
- **Dynamic Analysis**: 1-50ms per font (with 5s timeout)
- **Signature Matching**: <1ms per font (3 signatures)
- **Memory**: ~10KB per font analysis

## Testing

```bash
# Run all tests
cargo test --package font-analysis --features dynamic

# Run specific test module
cargo test --package font-analysis --lib signatures --features dynamic

# Run integration tests
cargo test --package font-analysis --test integration_tests --features dynamic
```

## Documentation

- **[SIGNATURE_GUIDE.md](SIGNATURE_GUIDE.md)**: Complete guide to writing CVE signatures
- **[signatures/README.md](signatures/README.md)**: Active signature index
- **[signatures-pending/README.md](signatures-pending/README.md)**: Pending signatures

## Architecture

```
font-analysis/
├── src/
│   ├── lib.rs              # Main analysis pipeline
│   ├── model.rs            # Configuration and data models
│   ├── signatures.rs       # CVE signature system
│   ├── static_scan.rs      # Fast static checks
│   ├── dynamic/            # Dynamic analysis
│   │   ├── mod.rs
│   │   ├── parser.rs       # FontContext extraction
│   │   ├── ttf_vm.rs       # TrueType VM interpreter
│   │   └── variable_fonts.rs
│   ├── type1/              # PostScript Type 1
│   │   ├── charstring.rs
│   │   ├── eexec.rs
│   │   └── findings.rs
│   ├── color_fonts.rs      # COLR/CPAL analysis
│   ├── variable_fonts.rs   # Variable font detection
│   ├── woff.rs             # WOFF/WOFF2 handling
│   └── context.rs          # Context-aware severity
├── signatures/             # Active CVE signatures
├── signatures-pending/     # Signatures under review
└── tests/                  # Integration tests
```

## Dependencies

### Core
- `serde` - Serialization
- `serde_json`, `serde_yaml`, `toml` - Configuration formats

### Dynamic Feature
- `ttf-parser` - TrueType/OpenType parsing
- `skrifa` - Additional font validation
- `owned_ttf_parser` - Owned font data structures

## Security

### Threat Model

This library is designed to analyze potentially malicious fonts safely:

- **Sandboxing**: Dynamic analysis runs in timeout-protected threads
- **Bounds Checking**: All offset/length operations validate bounds
- **Resource Limits**: Configurable timeouts and size limits
- **No Execution**: Font hinting bytecode is analyzed, not executed (except in controlled VM)
- **Fail-Safe**: Parse errors don't crash, they generate findings

### Known Limitations

- Signature matching requires `dynamic` feature
- Complex font exploits may evade detection
- False positives possible on unusual but valid fonts
- Performance impact of deep analysis on large fonts

## Contributing

### Adding Signatures

1. Research the CVE thoroughly
2. Create signature in `signatures-pending/`
3. Write comprehensive tests
4. Document in `signature_rationale`
5. Submit for review

See [SIGNATURE_GUIDE.md](SIGNATURE_GUIDE.md) for details.

### Reporting Issues

- Security vulnerabilities: Report privately to maintainers
- Bugs: Open GitHub issue with minimal reproducer
- Feature requests: Discuss in issue tracker first

## License

See project root for license information.

## References

- [OpenType Specification](https://learn.microsoft.com/en-us/typography/opentype/spec/)
- [TrueType Reference Manual](https://developer.apple.com/fonts/TrueType-Reference-Manual/)
- [PostScript Type 1 Font Format](https://adobe-type-tools.github.io/font-tech-notes/)
- [WOFF File Format](https://www.w3.org/TR/WOFF/)
- [NVD CVE Database](https://nvd.nist.gov/)

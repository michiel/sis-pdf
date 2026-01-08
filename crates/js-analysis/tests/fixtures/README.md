# Hostile JavaScript Payload Test Fixtures

This directory contains real-world malicious JavaScript payloads extracted from VirusShare PDF samples. These fixtures are used for integration testing of the JavaScript sandbox to ensure it can safely analyze actual malware without crashing or hanging.

## ⚠️ WARNING

**These files contain actual malware samples.** They are safe to store as text files, but **DO NOT** execute them outside of the controlled sandbox environment. The sandbox has been specifically designed with safety limits to prevent:

- Infinite loops (100,000 iteration limit)
- Stack overflow (128 recursion levels, 512KB stack)
- Timeouts (5 second execution limit)
- Memory exhaustion (64KB payload size limit)

## Fixture Descriptions

### 1. `event_target_eval_obfuscated.js`
- **Pattern**: event.target.eval with string concatenation obfuscation
- **Techniques**: String splitting, replace operations, unescape function
- **APIs Used**: `event.target.eval`, `replace`, `unescape`, `getAnnots`, `syncAnnotScan`
- **Size**: ~373 bytes
- **Obfuscation Level**: Medium

### 2. `getannots_unescape_eval.js`
- **Pattern**: app.doc.getAnnots with unescape and eval
- **Techniques**: PDF annotation injection, URL decoding
- **APIs Used**: `app.doc.syncAnnotScan`, `app.doc.getAnnots`, `unescape`, `eval`
- **Size**: ~109 bytes
- **Obfuscation Level**: Low
- **Purpose**: Extracts malicious code from PDF annotation subjects

### 3. `charcode_array_decrypt.js`
- **Pattern**: Comma-separated character codes with custom decrypt function
- **Techniques**: Array splitting, character code conversion
- **APIs Used**: `String.fromCharCode`, `split`, `eval`
- **Size**: ~1,418 bytes
- **Obfuscation Level**: Medium
- **Features**: Includes decrypt function with jump parameter

### 4. `arguments_callee_obfuscation.js`
- **Pattern**: Function introspection using arguments.callee
- **Techniques**: Function source extraction, regex replacement, string building
- **APIs Used**: `arguments.callee.toString()`, `replace`, array manipulation
- **Size**: ~430 bytes
- **Obfuscation Level**: High
- **Purpose**: Builds executable code from function source dynamically

### 5. `simple_charcode_decrypt.js`
- **Pattern**: Simple character code decryption with time-based key
- **Techniques**: String.fromCharCode, Date-based obfuscation key
- **APIs Used**: `String.fromCharCode`, `Date().getSeconds()`, `eval`
- **Size**: ~252 bytes
- **Obfuscation Level**: Low
- **Features**: Uses current seconds as decryption key modulo

### 6. `complex_obfuscation_custom_accessors.js`
- **Pattern**: Complex obfuscation with custom property accessor functions
- **Techniques**: Wrapper functions for property access, this context manipulation
- **APIs Used**: Custom accessor functions, `event.target`, `syncAnnotScan`, hex decoding
- **Size**: ~1,011 bytes
- **Obfuscation Level**: Very High
- **Features**: VAR_* accessor functions, dskp hex decoder, multi-level indirection

### 7. `base64_custom_decoder.js`
- **Pattern**: Custom Base64 decoder implementation
- **Techniques**: Full Base64 alphabet, manual decode algorithm, eval of decoded payload
- **APIs Used**: `indexOf`, `charAt`, `String.fromCharCode`, bitwise operations, `eval`
- **Size**: ~6,534 bytes
- **Obfuscation Level**: High
- **Features**: Complete Base64 decoder with custom implementation

### 8. `heap_spray_exploit.js`
- **Pattern**: Heap spray exploit with embedded shellcode
- **Techniques**: String padding, heap spray loops, shellcode in character codes
- **APIs Used**: `String.fromCharCode`, `while` loops, `substring`, array allocation
- **Size**: ~10,482 bytes
- **Obfuscation Level**: Medium
- **Purpose**: Memory corruption exploit (heap spray + shellcode)
- **Note**: May timeout due to intensive heap spray loops

### 9. `whitespace_obfuscation.js`
- **Pattern**: Extreme whitespace padding obfuscation
- **Techniques**: Code spread across hundreds of lines with whitespace padding
- **APIs Used**: Array manipulation, string concatenation, `unescape`
- **Size**: ~433 lines (mostly whitespace)
- **Obfuscation Level**: High
- **Purpose**: Evade pattern matching and visual inspection

## Coverage Analysis

These fixtures collectively test:

✅ **Obfuscation Techniques**:
- String concatenation and splitting
- Character code encoding
- Base64 encoding
- Whitespace padding
- Function introspection
- Hex encoding
- Custom decoder implementations

✅ **Malware Behaviors**:
- PDF annotation injection
- Event object manipulation
- Eval chain execution
- Heap spray attacks
- Shellcode embedding
- Time-based obfuscation

✅ **Sandbox Features**:
- Event object simulation (`event.target`)
- PDF globals (`app`, `doc`, `info`)
- String encoding functions (`escape`, `unescape`)
- Global metadata (`creator`, `producer`, etc.)
- Function call tracking
- Property access monitoring
- Error recovery
- Variable promotion
- Loop/recursion limits
- Timeout protection

## Testing

Run all hostile payload tests:
```bash
cargo test --features js-sandbox --test hostile_payloads
```

Run a specific test:
```bash
cargo test --features js-sandbox --test hostile_payloads test_heap_spray_exploit
```

Test a fixture directly:
```bash
cargo run --release --features js-sandbox --example test_hostile -- \
    crates/js-analysis/tests/fixtures/event_target_eval_obfuscated.js
```

## Expected Results

| Fixture | Expected Outcome | Notes |
|---------|-----------------|-------|
| event_target_eval_obfuscated | ✅ Executed | Should complete without timeout |
| getannots_unescape_eval | ✅ Executed | May have errors for missing getAnnots |
| charcode_array_decrypt | ✅ Executed | Decrypt function should work |
| arguments_callee_obfuscation | ✅ Executed | Handles function introspection |
| simple_charcode_decrypt | ✅ Executed | Small, should execute quickly |
| complex_obfuscation_custom_accessors | ✅ Executed | Complex but within limits |
| base64_custom_decoder | ✅ Executed | Decoder should work |
| heap_spray_exploit | ⏱️ May Timeout | Intensive loops may hit 5s limit |
| whitespace_obfuscation | ✅ Executed / ⏭️ May Skip | Large file may hit size limit |

**Success Rate Target**: ≥70% executed successfully (not timed out or skipped)

## Adding New Fixtures

When adding new hostile payload fixtures:

1. **Source**: Extract from VirusShare or other reputable malware repositories
2. **Naming**: Use descriptive names indicating the primary technique
3. **Documentation**: Add entry to this README with pattern description
4. **Test**: Create corresponding test in `hostile_payloads.rs`
5. **Verify**: Ensure it tests a unique pattern not covered by existing fixtures

## Malware Analysis Safety

These samples are **SAFE** because:
- Stored as plaintext JavaScript (not executable binaries)
- Executed only in controlled Boa engine sandbox
- PDF environment is simulated (no real system access)
- Sandbox has strict limits on loops, recursion, and execution time
- No network access or file system access in sandbox
- All sandbox operations are monitored and logged

## Source

All fixtures extracted from VirusShare PDF corpus using:
```bash
cargo run --features js-sandbox -- extract --js <pdf_file>
```

Original VirusShare hashes are preserved in filenames where applicable.

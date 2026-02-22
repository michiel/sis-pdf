# Fuzz Targets

This directory contains `cargo-fuzz` harnesses for parser, decoding, graph, and
execution-surface paths.

## Quick start

```bash
cd fuzz
cargo +nightly install cargo-fuzz --locked
cargo +nightly fuzz list
```

## Smoke runs

Use short smoke runs in CI and local pre-merge checks:

```bash
cd fuzz
cargo +nightly fuzz run parser -- -max_total_time=20
cargo +nightly fuzz run image_metadata -- -max_total_time=20
cargo +nightly fuzz run do_chain_recursion -- -max_total_time=10
cargo +nightly fuzz run inline_image_parse -- -max_total_time=10
cargo +nightly fuzz run type3_charproc -- -max_total_time=10
```

## New execution-surface targets

- `do_chain_recursion`: nested form-XObject recursion tracing paths.
- `inline_image_parse`: inline image (`BI ... ID ... EI`) parsing paths.
- `type3_charproc`: Type3 charproc stream inspection paths.

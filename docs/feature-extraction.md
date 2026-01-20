# Feature Extraction

This document summarises the feature sets used by `sis` for risk profiling and
ML workflows. Feature extraction operates on scan findings and selected parser
metadata.

## Feature Categories

- Structural features: object counts, xref/trailer anomalies, ObjStm density.
- Action features: presence of `/OpenAction`, `/AA`, `/Launch`, `/URI`.
- Embedded content features: counts of embedded files, scripts, encrypted
  containers, and rich media.
- Stream features: filter depth, decompression ratios, entropy summary.
- XFA features: presence, script count, submit actions, sensitive fields.
- Crypto features: encryption presence, key length, signature anomalies.

## Notes

- Feature definitions live in `crates/sis-pdf-core/src/features.rs` and
  `crates/sis-pdf-core/src/features_extended.rs`.
- When new findings are added, corresponding feature counters should be updated
  in both the standard and extended feature vectors where applicable.

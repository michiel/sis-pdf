# Datasets

Store local datasets under a top-level `datasets/` directory (not committed).

Example layout:

```
datasets/
  evasive-pdfmal2022/
    benign/
    malicious/
```

## Feature export

JSONL export:

```
# From repo root
cargo run -p sis-pdf --bin sis -- export-features --path datasets/evasive-pdfmal2022 --glob "*.pdf" --format jsonl -o features.jsonl
```

CSV export:

```
cargo run -p sis-pdf --bin sis -- export-features --path datasets/evasive-pdfmal2022 --glob "*.pdf" --format csv -o features.csv
```

## Evaluation

If you store predictions in JSONL with `label`, `score`, and optional `threshold`, you can compute metrics:

```
./scripts/eval_features.py predictions.jsonl
```

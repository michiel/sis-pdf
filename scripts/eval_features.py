#!/usr/bin/env python3
"""Evaluate JSONL predictions with labels.

Expected JSONL fields:
- label: 0/1 or "malicious"/"benign"
- score: float
- threshold: float (optional)
"""
import json
import sys
from pathlib import Path


def parse_label(val):
    if isinstance(val, bool):
        return 1 if val else 0
    if isinstance(val, (int, float)):
        return 1 if val > 0 else 0
    if isinstance(val, str):
        return 1 if val.lower() in {"1", "true", "malicious", "malware"} else 0
    return 0


def main(path):
    tp = fp = tn = fn = 0
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            label = parse_label(row.get("label"))
            score = float(row.get("score", 0.0))
            threshold = float(row.get("threshold", 0.5))
            pred = 1 if score >= threshold else 0
            if pred == 1 and label == 1:
                tp += 1
            elif pred == 1 and label == 0:
                fp += 1
            elif pred == 0 and label == 0:
                tn += 1
            else:
                fn += 1
    total = tp + fp + tn + fn
    if total == 0:
        print("no rows")
        return 1
    acc = (tp + tn) / total
    prec = tp / (tp + fp) if tp + fp > 0 else 0.0
    rec = tp / (tp + fn) if tp + fn > 0 else 0.0
    print(f"rows={total} acc={acc:.4f} prec={prec:.4f} rec={rec:.4f}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: eval_features.py predictions.jsonl", file=sys.stderr)
        sys.exit(1)
    sys.exit(main(sys.argv[1]))

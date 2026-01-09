#!/usr/bin/env python3
"""
Apply Calibration to Predictions

Applies a trained calibration model to raw predictions.

Usage:
    python scripts/apply_calibration.py \
        --calibration calibration_model.json \
        --predictions raw_predictions.jsonl \
        --output calibrated_predictions.jsonl

Input predictions format (JSONL):
    {"file": "doc1.pdf", "score": 0.73, "label": 1}
    {"file": "doc2.pdf", "score": 0.21, "label": 0}
    ...

Output format (JSONL):
    {"file": "doc1.pdf", "raw_score": 0.73, "calibrated_score": 0.68, "label": 1}
    {"file": "doc2.pdf", "raw_score": 0.21, "calibrated_score": 0.15, "label": 0}
    ...
"""

import argparse
import json
import sys
from typing import List, Dict, Any

import numpy as np


def apply_platt_scaling(scores: np.ndarray, params: Dict[str, Any]) -> np.ndarray:
    """
    Apply Platt scaling calibration.

    Transforms: P(y=1|s) = 1 / (1 + exp(coef*s + intercept))
    """
    coef = np.array(params['coef'])
    intercept = np.array(params['intercept'])

    # Logistic function
    logits = coef[0] * scores + intercept[0]
    calibrated = 1.0 / (1.0 + np.exp(-logits))

    return calibrated


def apply_isotonic_regression(scores: np.ndarray, params: Dict[str, Any]) -> np.ndarray:
    """
    Apply isotonic regression calibration.

    Uses piecewise constant mapping defined by X and Y thresholds.
    """
    X_thresholds = np.array(params['X_thresholds'])
    y_thresholds = np.array(params['y_thresholds'])

    # Apply piecewise mapping
    calibrated = np.zeros_like(scores)

    for i, score in enumerate(scores):
        # Find the bin for this score
        idx = np.searchsorted(X_thresholds, score, side='left')
        idx = min(idx, len(y_thresholds) - 1)
        calibrated[i] = y_thresholds[idx]

    return calibrated


def apply_calibration(scores: np.ndarray, calibration: Dict[str, Any]) -> np.ndarray:
    """Apply calibration based on method type."""
    method = calibration['method']

    if method == 'platt':
        return apply_platt_scaling(scores, calibration['params'])
    elif method == 'isotonic':
        return apply_isotonic_regression(scores, calibration['params'])
    else:
        raise ValueError(f"Unknown calibration method: {method}")


def main():
    parser = argparse.ArgumentParser(
        description='Apply calibration model to predictions'
    )
    parser.add_argument(
        '--calibration',
        required=True,
        help='Path to calibration model JSON'
    )
    parser.add_argument(
        '--predictions',
        required=True,
        help='Path to JSONL file with raw predictions'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Output JSONL file for calibrated predictions'
    )
    parser.add_argument(
        '--method',
        choices=['platt', 'isotonic'],
        help='Calibration method to use (if calibration file contains both)'
    )

    args = parser.parse_args()

    # Load calibration model
    print(f"Loading calibration from {args.calibration}...", file=sys.stderr)
    with open(args.calibration) as f:
        calibration = json.load(f)

    # Handle multi-method calibration files
    if 'method' not in calibration:
        # File contains multiple methods
        if not args.method:
            print("Error: calibration file contains multiple methods, specify --method", file=sys.stderr)
            return 1
        if args.method not in calibration:
            print(f"Error: method '{args.method}' not found in calibration file", file=sys.stderr)
            return 1
        calibration = calibration[args.method]

    print(f"Using {calibration['method']} calibration fitted on {calibration['fitted_on_samples']} samples",
          file=sys.stderr)

    # Load and process predictions
    print(f"Loading predictions from {args.predictions}...", file=sys.stderr)

    scores = []
    records = []

    with open(args.predictions) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
                scores.append(float(record['score']))
                records.append(record)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"Warning: skipping line {line_num}: {e}", file=sys.stderr)
                continue

    print(f"Loaded {len(scores)} predictions", file=sys.stderr)

    # Apply calibration
    scores_array = np.array(scores)
    calibrated_scores = apply_calibration(scores_array, calibration)

    # Write output
    print(f"Writing calibrated predictions to {args.output}...", file=sys.stderr)

    with open(args.output, 'w') as f:
        for record, raw_score, cal_score in zip(records, scores, calibrated_scores):
            output_record = {**record}
            output_record['raw_score'] = float(raw_score)
            output_record['calibrated_score'] = float(cal_score)
            # Update 'score' field to calibrated value
            output_record['score'] = float(cal_score)

            f.write(json.dumps(output_record) + '\n')

    print("Done", file=sys.stderr)

    # Print summary statistics
    print(f"\nSummary:", file=sys.stderr)
    print(f"  Raw scores:        mean={np.mean(scores_array):.3f}, std={np.std(scores_array):.3f}",
          file=sys.stderr)
    print(f"  Calibrated scores: mean={np.mean(calibrated_scores):.3f}, std={np.std(calibrated_scores):.3f}",
          file=sys.stderr)
    print(f"  Mean adjustment:   {np.mean(calibrated_scores - scores_array):+.3f}", file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())

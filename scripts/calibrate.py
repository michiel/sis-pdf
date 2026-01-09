#!/usr/bin/env python3
"""
Model Calibration Script for sis-pdf

Calibrates model predictions using:
1. Platt Scaling (logistic regression on predictions)
2. Isotonic Regression (non-parametric monotonic mapping)

Usage:
    python scripts/calibrate.py \
        --predictions validation_predictions.jsonl \
        --method platt \
        --output calibration_model.json

Input format (JSONL):
    {"score": 0.73, "label": 1}
    {"score": 0.21, "label": 0}
    ...

Output format (JSON):
    {
        "method": "platt",
        "params": {"coef": [2.3], "intercept": -1.2},
        "fitted_on_samples": 1000
    }
"""

import argparse
import json
import sys
from typing import List, Dict, Any, Tuple

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import log_loss, brier_score_loss


def load_predictions(path: str) -> Tuple[np.ndarray, np.ndarray]:
    """Load predictions from JSONL file."""
    scores = []
    labels = []

    with open(path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
                scores.append(float(record['score']))
                labels.append(int(record['label']))
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"Warning: skipping line {line_num}: {e}", file=sys.stderr)
                continue

    return np.array(scores), np.array(labels)


def platt_scaling(scores: np.ndarray, labels: np.ndarray) -> Dict[str, Any]:
    """
    Fit Platt scaling (logistic regression on predictions).

    Transforms raw scores to calibrated probabilities using:
        P(y=1|s) = 1 / (1 + exp(A*s + B))
    """
    # Reshape for sklearn
    X = scores.reshape(-1, 1)

    # Fit logistic regression
    lr = LogisticRegression(solver='lbfgs', max_iter=1000)
    lr.fit(X, labels)

    # Extract parameters
    coef = lr.coef_[0].tolist()
    intercept = lr.intercept_.tolist()

    # Compute calibrated scores
    calibrated = lr.predict_proba(X)[:, 1]

    # Evaluate calibration quality
    log_loss_score = log_loss(labels, calibrated)
    brier_score = brier_score_loss(labels, calibrated)

    return {
        'method': 'platt',
        'params': {
            'coef': coef,
            'intercept': intercept,
        },
        'metrics': {
            'log_loss': float(log_loss_score),
            'brier_score': float(brier_score),
        },
        'fitted_on_samples': len(scores),
    }


def isotonic_calibration(scores: np.ndarray, labels: np.ndarray) -> Dict[str, Any]:
    """
    Fit isotonic regression calibration.

    Non-parametric method that learns a monotonic mapping from
    raw scores to calibrated probabilities.
    """
    # Fit isotonic regression
    iso = IsotonicRegression(out_of_bounds='clip')
    iso.fit(scores, labels)

    # Extract the mapping (X, Y pairs)
    # These define a piecewise constant function
    X_thresholds = iso.X_thresholds_.tolist()
    y_thresholds = iso.y_thresholds_.tolist()

    # Compute calibrated scores
    calibrated = iso.predict(scores)

    # Evaluate calibration quality
    log_loss_score = log_loss(labels, calibrated)
    brier_score = brier_score_loss(labels, calibrated)

    return {
        'method': 'isotonic',
        'params': {
            'X_thresholds': X_thresholds,
            'y_thresholds': y_thresholds,
        },
        'metrics': {
            'log_loss': float(log_loss_score),
            'brier_score': float(brier_score),
        },
        'fitted_on_samples': len(scores),
    }


def evaluate_calibration(scores: np.ndarray, labels: np.ndarray, n_bins: int = 10) -> Dict[str, Any]:
    """
    Evaluate calibration using reliability diagrams.

    Returns expected calibration error (ECE) and binned statistics.
    """
    # Create bins
    bin_edges = np.linspace(0, 1, n_bins + 1)
    bin_indices = np.digitize(scores, bin_edges[:-1]) - 1
    bin_indices = np.clip(bin_indices, 0, n_bins - 1)

    # Compute statistics per bin
    bin_stats = []
    total_ece = 0.0
    total_samples = 0

    for i in range(n_bins):
        mask = bin_indices == i
        if not mask.any():
            continue

        bin_scores = scores[mask]
        bin_labels = labels[mask]

        mean_predicted = float(bin_scores.mean())
        mean_actual = float(bin_labels.mean())
        count = int(mask.sum())

        # Contribution to ECE (weighted by bin size)
        ece_contrib = abs(mean_predicted - mean_actual) * count
        total_ece += ece_contrib
        total_samples += count

        bin_stats.append({
            'bin_index': i,
            'bin_lower': float(bin_edges[i]),
            'bin_upper': float(bin_edges[i + 1]),
            'mean_predicted': mean_predicted,
            'mean_actual': mean_actual,
            'count': count,
        })

    ece = total_ece / total_samples if total_samples > 0 else 0.0

    return {
        'expected_calibration_error': float(ece),
        'n_bins': n_bins,
        'bins': bin_stats,
    }


def main():
    parser = argparse.ArgumentParser(
        description='Calibrate model predictions using Platt scaling or isotonic regression'
    )
    parser.add_argument(
        '--predictions',
        required=True,
        help='Path to JSONL file with predictions ({"score": 0.73, "label": 1})'
    )
    parser.add_argument(
        '--method',
        choices=['platt', 'isotonic', 'both'],
        default='platt',
        help='Calibration method (default: platt)'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Output JSON file for calibration model'
    )
    parser.add_argument(
        '--evaluate',
        action='store_true',
        help='Also compute calibration diagnostics before and after'
    )
    parser.add_argument(
        '--bins',
        type=int,
        default=10,
        help='Number of bins for calibration evaluation (default: 10)'
    )

    args = parser.parse_args()

    # Load predictions
    print(f"Loading predictions from {args.predictions}...", file=sys.stderr)
    scores, labels = load_predictions(args.predictions)
    print(f"Loaded {len(scores)} predictions", file=sys.stderr)

    if len(scores) < 10:
        print("Error: need at least 10 samples for calibration", file=sys.stderr)
        return 1

    # Evaluate pre-calibration if requested
    pre_calibration = None
    if args.evaluate:
        print("Evaluating pre-calibration...", file=sys.stderr)
        pre_calibration = evaluate_calibration(scores, labels, args.bins)
        print(f"  Pre-calibration ECE: {pre_calibration['expected_calibration_error']:.4f}", file=sys.stderr)

    # Fit calibration
    results = {}

    if args.method in ['platt', 'both']:
        print("Fitting Platt scaling...", file=sys.stderr)
        platt_result = platt_scaling(scores, labels)
        print(f"  Log loss: {platt_result['metrics']['log_loss']:.4f}", file=sys.stderr)
        print(f"  Brier score: {platt_result['metrics']['brier_score']:.4f}", file=sys.stderr)
        results['platt'] = platt_result

    if args.method in ['isotonic', 'both']:
        print("Fitting isotonic regression...", file=sys.stderr)
        iso_result = isotonic_calibration(scores, labels)
        print(f"  Log loss: {iso_result['metrics']['log_loss']:.4f}", file=sys.stderr)
        print(f"  Brier score: {iso_result['metrics']['brier_score']:.4f}", file=sys.stderr)
        results['isotonic'] = iso_result

    # Add pre-calibration diagnostics if requested
    if pre_calibration:
        results['pre_calibration'] = pre_calibration

    # Save results
    output = results if args.method == 'both' else results[args.method]

    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"Calibration model saved to {args.output}", file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())

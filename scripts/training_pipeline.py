#!/usr/bin/env python3
"""
ML Training Pipeline for sis-pdf

Complete pipeline demonstrating:
1. Feature extraction from PDFs
2. Baseline computation from benign samples
3. Model training with extended features
4. Calibration fitting and application
5. Model evaluation

Usage:
    python scripts/training_pipeline.py \
        --benign-dir /path/to/benign/pdfs \
        --malicious-dir /path/to/malicious/pdfs \
        --output-dir models/ \
        --sis-binary ./target/release/sis

Prerequisites:
    - Labeled datasets (benign and malicious PDFs)
    - Compiled sis-pdf binary
    - Python dependencies: numpy, scikit-learn

Pipeline Steps:
    1. Extract features: sis export-features
    2. Compute baseline: sis compute-baseline
    3. Train model: sklearn LogisticRegression
    4. Fit calibration: scripts/calibrate.py
    5. Evaluate: metrics and calibration analysis
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)


def run_command(cmd: List[str], desc: str) -> None:
    """Run a shell command and handle errors."""
    print(f"[{desc}] Running: {' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error in {desc}:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)


def extract_features(
    pdf_dir: str,
    output_file: str,
    sis_binary: str,
    label: int,
) -> None:
    """Extract features from PDFs in a directory."""
    print(f"\n=== Extracting features from {pdf_dir} (label={label}) ===", file=sys.stderr)

    pdf_files = list(Path(pdf_dir).glob("*.pdf"))
    if not pdf_files:
        print(f"Warning: no PDF files found in {pdf_dir}", file=sys.stderr)
        return

    print(f"Found {len(pdf_files)} PDF files", file=sys.stderr)

    # Run sis export-features with extended features (default)
    cmd = [
        sis_binary,
        "export-features",
        pdf_dir,
        "--format", "jsonl",
        "--out", output_file,
    ]

    run_command(cmd, "feature extraction")

    # Add labels to the feature vectors
    print(f"Adding labels to features...", file=sys.stderr)

    with open(output_file) as f:
        records = [json.loads(line) for line in f if line.strip()]

    with open(output_file, 'w') as f:
        for record in records:
            record['label'] = label
            f.write(json.dumps(record) + '\n')

    print(f"Extracted {len(records)} feature vectors", file=sys.stderr)


def compute_baseline(
    benign_features: str,
    baseline_output: str,
    sis_binary: str,
) -> None:
    """Compute benign baseline from feature vectors."""
    print(f"\n=== Computing baseline from {benign_features} ===", file=sys.stderr)

    cmd = [
        sis_binary,
        "compute-baseline",
        "--input", benign_features,
        "--out", baseline_output,
    ]

    run_command(cmd, "baseline computation")

    # Load and print baseline stats
    with open(baseline_output) as f:
        baseline = json.load(f)

    print(f"Baseline computed: {len(baseline['feature_means'])} features", file=sys.stderr)


def load_features(feature_files: List[str]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """Load features from JSONL files."""
    all_features = []
    all_labels = []
    all_filenames = []

    for feature_file in feature_files:
        with open(feature_file) as f:
            for line in f:
                if not line.strip():
                    continue

                record = json.loads(line)
                all_features.append(record['features'])
                all_labels.append(record['label'])
                all_filenames.append(record.get('file', 'unknown'))

    X = np.array(all_features, dtype=np.float32)
    y = np.array(all_labels, dtype=np.int32)

    return X, y, all_filenames


def train_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    output_file: str,
) -> LogisticRegression:
    """Train logistic regression model."""
    print(f"\n=== Training model ===", file=sys.stderr)
    print(f"Training samples: {len(X_train)}", file=sys.stderr)
    print(f"  Benign: {np.sum(y_train == 0)}", file=sys.stderr)
    print(f"  Malicious: {np.sum(y_train == 1)}", file=sys.stderr)

    # Train logistic regression
    model = LogisticRegression(
        max_iter=1000,
        solver='lbfgs',
        class_weight='balanced',
        random_state=42,
    )
    model.fit(X_train, y_train)

    # Save model
    model_data = {
        'bias': float(model.intercept_[0]),
        'weights': model.coef_[0].tolist(),
    }

    with open(output_file, 'w') as f:
        json.dump(model_data, f, indent=2)

    print(f"Model saved to {output_file}", file=sys.stderr)

    return model


def evaluate_model(
    model: LogisticRegression,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> Dict[str, float]:
    """Evaluate model performance."""
    print(f"\n=== Evaluating model ===", file=sys.stderr)

    # Predictions
    y_pred = model.predict(X_test)
    y_scores = model.predict_proba(X_test)[:, 1]

    # Metrics
    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred),
        'recall': recall_score(y_test, y_pred),
        'f1': f1_score(y_test, y_pred),
        'roc_auc': roc_auc_score(y_test, y_scores),
    }

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    metrics.update({
        'true_negatives': int(tn),
        'false_positives': int(fp),
        'false_negatives': int(fn),
        'true_positives': int(tp),
    })

    # Print results
    print(f"Accuracy:  {metrics['accuracy']:.4f}", file=sys.stderr)
    print(f"Precision: {metrics['precision']:.4f}", file=sys.stderr)
    print(f"Recall:    {metrics['recall']:.4f}", file=sys.stderr)
    print(f"F1 Score:  {metrics['f1']:.4f}", file=sys.stderr)
    print(f"ROC AUC:   {metrics['roc_auc']:.4f}", file=sys.stderr)
    print(f"\nConfusion Matrix:", file=sys.stderr)
    print(f"  TN: {tn:4d}  FP: {fp:4d}", file=sys.stderr)
    print(f"  FN: {fn:4d}  TP: {tp:4d}", file=sys.stderr)

    return metrics


def fit_calibration(
    validation_predictions: str,
    calibration_output: str,
    method: str = 'platt',
) -> None:
    """Fit calibration model."""
    print(f"\n=== Fitting {method} calibration ===", file=sys.stderr)

    cmd = [
        sys.executable,
        "scripts/calibrate.py",
        "--predictions", validation_predictions,
        "--method", method,
        "--output", calibration_output,
        "--evaluate",
    ]

    run_command(cmd, "calibration fitting")


def main():
    parser = argparse.ArgumentParser(
        description='Complete ML training pipeline for sis-pdf'
    )
    parser.add_argument(
        '--benign-dir',
        required=True,
        help='Directory with benign PDF files'
    )
    parser.add_argument(
        '--malicious-dir',
        required=True,
        help='Directory with malicious PDF files'
    )
    parser.add_argument(
        '--output-dir',
        required=True,
        help='Output directory for models and artifacts'
    )
    parser.add_argument(
        '--sis-binary',
        default='./target/release/sis',
        help='Path to sis binary (default: ./target/release/sis)'
    )
    parser.add_argument(
        '--calibration-method',
        choices=['platt', 'isotonic', 'both'],
        default='platt',
        help='Calibration method (default: platt)'
    )
    parser.add_argument(
        '--test-split',
        type=float,
        default=0.2,
        help='Test set fraction (default: 0.2)'
    )
    parser.add_argument(
        '--val-split',
        type=float,
        default=0.2,
        help='Validation set fraction from training data (default: 0.2)'
    )

    args = parser.parse_args()

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Extract features
    benign_features = output_dir / "benign_features.jsonl"
    malicious_features = output_dir / "malicious_features.jsonl"

    extract_features(args.benign_dir, str(benign_features), args.sis_binary, label=0)
    extract_features(args.malicious_dir, str(malicious_features), args.sis_binary, label=1)

    # Step 2: Compute baseline
    baseline_file = output_dir / "baseline.json"
    compute_baseline(str(benign_features), str(baseline_file), args.sis_binary)

    # Step 3: Load all features
    print(f"\n=== Loading features ===", file=sys.stderr)
    X, y, filenames = load_features([str(benign_features), str(malicious_features)])

    print(f"Total samples: {len(X)}", file=sys.stderr)
    print(f"Feature dimension: {X.shape[1]}", file=sys.stderr)

    # Split: train/test, then train -> train/validation
    X_train_full, X_test, y_train_full, y_test = train_test_split(
        X, y, test_size=args.test_split, random_state=42, stratify=y
    )

    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full, y_train_full, test_size=args.val_split, random_state=42, stratify=y_train_full
    )

    print(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}", file=sys.stderr)

    # Step 4: Train model
    model_file = output_dir / "model.json"
    model = train_model(X_train, y_train, str(model_file))

    # Step 5: Evaluate on test set
    metrics = evaluate_model(model, X_test, y_test)

    # Save metrics
    metrics_file = output_dir / "metrics.json"
    with open(metrics_file, 'w') as f:
        json.dump(metrics, f, indent=2)

    print(f"Metrics saved to {metrics_file}", file=sys.stderr)

    # Step 6: Prepare validation predictions for calibration
    val_scores = model.predict_proba(X_val)[:, 1]

    val_predictions_file = output_dir / "validation_predictions.jsonl"
    with open(val_predictions_file, 'w') as f:
        for score, label in zip(val_scores, y_val):
            f.write(json.dumps({'score': float(score), 'label': int(label)}) + '\n')

    # Step 7: Fit calibration
    calibration_file = output_dir / "calibration.json"
    fit_calibration(
        str(val_predictions_file),
        str(calibration_file),
        method=args.calibration_method,
    )

    print(f"\n=== Pipeline complete ===", file=sys.stderr)
    print(f"Output directory: {output_dir}", file=sys.stderr)
    print(f"  - model.json: Trained model", file=sys.stderr)
    print(f"  - baseline.json: Benign baseline", file=sys.stderr)
    print(f"  - calibration.json: Calibration model", file=sys.stderr)
    print(f"  - metrics.json: Test set metrics", file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())

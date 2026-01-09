# ML Training Pipeline Documentation

## Overview

This document describes the complete machine learning training pipeline for sis-pdf, from feature extraction through model training, calibration, and deployment.

**Pipeline Stages:**
1. Feature Extraction
2. Baseline Computation
3. Model Training
4. Calibration Fitting
5. Model Evaluation
6. Deployment

---

## Prerequisites

### Data Requirements

- **Benign corpus**: 500-10,000 legitimate PDF files
- **Malicious corpus**: 500-10,000 malicious PDF files
- **Balanced classes**: Aim for roughly equal benign/malicious samples
- **Representative samples**: Cover diverse document types and attack patterns

### Software Requirements

```bash
# Build sis-pdf
cargo build --release

# Install Python dependencies
pip install numpy scikit-learn
```

---

## Stage 1: Feature Extraction

### Extended Feature Vector (333 Features)

sis-pdf exports a 333-feature vector by default, combining:
- 35 legacy features (structural, behavioral, content)
- 298 extended features (detector findings, JS/URI signals, attack surfaces)

### Extract Features from Directory

```bash
# Extract features from benign PDFs (extended features by default)
sis export-features /path/to/benign/pdfs \
    --format jsonl \
    --out benign_features.jsonl

# Extract features from malicious PDFs
sis export-features /path/to/malicious/pdfs \
    --format jsonl \
    --out malicious_features.jsonl
```

### Output Format (JSONL)

Each line contains:
```json
{
  "file": "/path/to/document.pdf",
  "features": [0.0, 1.0, 0.25, ...],
  "label": 1
}
```

- `file`: Source PDF path
- `features`: Array of 333 float values
- `label`: 0 (benign) or 1 (malicious) - add this manually or via pipeline script

### Basic Features Only (Legacy Mode)

If you want the legacy 35-feature vector:

```bash
sis export-features /path/to/pdfs \
    --basic \
    --format jsonl \
    --out features_basic.jsonl
```

---

## Stage 2: Baseline Computation

### Purpose

Compute statistical baseline from benign samples for:
- Feature normalization
- Anomaly detection
- Explainability (deviation scoring)

### Compute Baseline

```bash
sis compute-baseline \
    --input benign_features.jsonl \
    --out baseline.json
```

### Baseline Format

```json
{
  "feature_means": {"feature1": 0.5, "feature2": 0.3, ...},
  "feature_stddevs": {"feature1": 0.2, "feature2": 0.1, ...},
  "feature_percentiles": {
    "feature1": {"p25": 0.4, "p50": 0.5, "p75": 0.6, "p90": 0.7, "p95": 0.8, "p99": 0.9},
    ...
  },
  "sample_count": 5000
}
```

**Usage:**
- **Normalization**: `(x - mean) / stddev`
- **Anomaly Detection**: Values beyond p99 are suspicious
- **Explainability**: Show how far a feature deviates from baseline

---

## Stage 3: Model Training

### Recommended Approach: Logistic Regression

**Why Logistic Regression:**
- Fast training and inference
- Interpretable coefficients
- Works well with high-dimensional features
- Easy to deploy (just weights + bias)

### Training Script

```python
import json
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

# Load features
def load_features(jsonl_path):
    X, y = [], []
    with open(jsonl_path) as f:
        for line in f:
            record = json.loads(line)
            X.append(record['features'])
            y.append(record['label'])
    return np.array(X), np.array(y)

# Load benign and malicious
X_benign, y_benign = load_features('benign_features.jsonl')
X_mal, y_mal = load_features('malicious_features.jsonl')

# Combine
X = np.vstack([X_benign, X_mal])
y = np.hstack([y_benign, y_mal])

# Split: 60% train, 20% validation, 20% test
X_train_full, X_test, y_train_full, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
X_train, X_val, y_train, y_val = train_test_split(
    X_train_full, y_train_full, test_size=0.25, random_state=42, stratify=y_train_full
)

# Train model
model = LogisticRegression(
    max_iter=1000,
    solver='lbfgs',
    class_weight='balanced',  # Handle class imbalance
    random_state=42
)
model.fit(X_train, y_train)

# Save model (JSON format for Rust integration)
model_data = {
    'bias': float(model.intercept_[0]),
    'weights': model.coef_[0].tolist()
}

with open('model.json', 'w') as f:
    json.dump(model_data, f)
```

### Alternative: Automated Pipeline

Use the provided training pipeline script:

```bash
python scripts/training_pipeline.py \
    --benign-dir /path/to/benign/pdfs \
    --malicious-dir /path/to/malicious/pdfs \
    --output-dir models/ \
    --sis-binary ./target/release/sis \
    --test-split 0.2 \
    --val-split 0.2
```

**Outputs:**
- `models/model.json`: Trained model
- `models/baseline.json`: Benign baseline
- `models/calibration.json`: Calibration model
- `models/metrics.json`: Test metrics

---

## Stage 4: Calibration Fitting

### Why Calibration?

Raw model scores are **not calibrated probabilities**. Calibration transforms raw scores into meaningful probabilities:
- `score=0.7` should mean "70% probability of malware"
- Without calibration, scores may be overconfident or underconfident

### Calibration Methods

**1. Platt Scaling** (Recommended)
- Fits logistic regression on model outputs
- Fast, works with small validation sets (100-1000 samples)
- Assumes sigmoid relationship

**2. Isotonic Regression**
- Non-parametric, learns arbitrary monotonic mapping
- More flexible but requires larger validation set (1000+ samples)
- Better for non-sigmoid score distributions

### Fit Calibration

```bash
# Generate validation predictions
python -c "
import json
import numpy as np
from sklearn.linear_model import LogisticRegression

# Load model
with open('model.json') as f:
    model_data = json.load(f)

# Load validation features
X_val = ...  # Load from JSONL
y_val = ...

# Predict
bias = model_data['bias']
weights = np.array(model_data['weights'])
scores = 1.0 / (1.0 + np.exp(-(X_val @ weights + bias)))

# Save
with open('validation_predictions.jsonl', 'w') as f:
    for score, label in zip(scores, y_val):
        f.write(json.dumps({'score': float(score), 'label': int(label)}) + '\n')
"

# Fit calibration
python scripts/calibrate.py \
    --predictions validation_predictions.jsonl \
    --method platt \
    --output calibration.json \
    --evaluate
```

### Apply Calibration

```bash
# Calibrate new predictions
python scripts/apply_calibration.py \
    --calibration calibration.json \
    --predictions raw_predictions.jsonl \
    --output calibrated_predictions.jsonl
```

**Output:**
```json
{"file": "doc.pdf", "raw_score": 0.73, "calibrated_score": 0.68, "label": 1}
```

---

## Stage 5: Model Evaluation

### Metrics

**Classification Metrics:**
- **Accuracy**: Overall correctness
- **Precision**: Of predicted malware, how many are truly malicious
- **Recall**: Of actual malware, how many are detected
- **F1 Score**: Harmonic mean of precision/recall
- **ROC AUC**: Area under ROC curve

**Calibration Metrics:**
- **Log Loss**: Cross-entropy between predictions and labels (lower is better)
- **Brier Score**: Mean squared error of probability predictions (lower is better)
- **Expected Calibration Error (ECE)**: Average calibration error across bins

### Evaluation Script

```python
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# Predictions
y_pred = (scores >= 0.5).astype(int)

metrics = {
    'accuracy': accuracy_score(y_test, y_pred),
    'precision': precision_score(y_test, y_pred),
    'recall': recall_score(y_test, y_pred),
    'f1': f1_score(y_test, y_pred),
    'roc_auc': roc_auc_score(y_test, scores)
}

print(f"Accuracy:  {metrics['accuracy']:.4f}")
print(f"Precision: {metrics['precision']:.4f}")
print(f"Recall:    {metrics['recall']:.4f}")
print(f"F1 Score:  {metrics['f1']:.4f}")
print(f"ROC AUC:   {metrics['roc_auc']:.4f}")
```

### Calibration Evaluation

```bash
python scripts/calibrate.py \
    --predictions test_predictions.jsonl \
    --method platt \
    --output test_calibration_eval.json \
    --evaluate \
    --bins 10
```

**ECE Interpretation:**
- ECE < 0.05: Well calibrated
- ECE 0.05-0.10: Acceptable
- ECE > 0.10: Poorly calibrated, refit or collect more validation data

---

## Stage 6: Deployment

### Integration with sis-pdf

The trained model, baseline, and calibration can be integrated into sis-pdf for inference:

```rust
// crates/sis-pdf/src/main.rs

// Load model
let model: LinearModel = serde_json::from_reader(File::open("model.json")?)?;

// Load baseline
let baseline: BenignBaseline = serde_json::from_reader(File::open("baseline.json")?)?;

// Load calibration
let calibration: CalibrationModel = serde_json::from_reader(File::open("calibration.json")?)?;

// Extract features
let features = extract_extended_features(&ctx, &findings);

// Predict
let raw_score = model.predict_vec(&features.as_f32_vec());

// Calibrate
let calibrated_score = calibration.apply(raw_score);

// Generate explanation
let explanation = create_ml_explanation(&features, &findings, &baseline, raw_score, None);
```

### Serving the Model

**Option 1: Embedded in CLI**
- Bundle model weights with binary
- Include in `sis scan` output as ML score

**Option 2: Separate Service**
- Run Python service with `scikit-learn`
- Call from sis-pdf via HTTP API
- Better for frequent model updates

**Option 3: ONNX Export**
- Convert scikit-learn model to ONNX
- Use `onnxruntime` in Rust for inference
- Good balance of flexibility and performance

---

## Complete Pipeline Example

### Directory Structure

```
project/
├── data/
│   ├── benign/       # Benign PDF corpus
│   └── malicious/    # Malicious PDF corpus
├── models/
│   ├── model.json
│   ├── baseline.json
│   └── calibration.json
└── results/
    ├── benign_features.jsonl
    ├── malicious_features.jsonl
    └── metrics.json
```

### Run Complete Pipeline

```bash
#!/bin/bash

# Build sis-pdf
cargo build --release

# Run training pipeline
python scripts/training_pipeline.py \
    --benign-dir data/benign \
    --malicious-dir data/malicious \
    --output-dir models \
    --sis-binary ./target/release/sis \
    --calibration-method platt \
    --test-split 0.2 \
    --val-split 0.2

echo "Training complete!"
echo "Model artifacts in models/"
echo "  - model.json: Trained logistic regression"
echo "  - baseline.json: Benign feature baseline"
echo "  - calibration.json: Platt scaling calibration"
echo "  - metrics.json: Test set evaluation"
```

### Expected Output

```
=== Extracting features from data/benign (label=0) ===
Found 5000 PDF files
Extracted 5000 feature vectors

=== Extracting features from data/malicious (label=1) ===
Found 5000 PDF files
Extracted 5000 feature vectors

=== Computing baseline from benign_features.jsonl ===
Baseline computed: 333 features

=== Loading features ===
Total samples: 10000
Feature dimension: 333
Train: 6000, Val: 2000, Test: 2000

=== Training model ===
Training samples: 6000
  Benign: 3000
  Malicious: 3000
Model saved to models/model.json

=== Evaluating model ===
Accuracy:  0.9450
Precision: 0.9523
Recall:    0.9350
F1 Score:  0.9436
ROC AUC:   0.9810

Confusion Matrix:
  TN:  965  FP:   35
  FN:   75  TP:  925

=== Fitting platt calibration ===
  Log loss: 0.1523
  Brier score: 0.0842
  Pre-calibration ECE: 0.0723

=== Pipeline complete ===
Output directory: models
  - model.json: Trained model
  - baseline.json: Benign baseline
  - calibration.json: Calibration model
  - metrics.json: Test set metrics
```

---

## Model Updates and Retraining

### When to Retrain

- **New attack patterns**: Monthly or quarterly retraining recommended
- **Performance degradation**: Monitor false positive/negative rates
- **Corpus drift**: If benign documents change (e.g., new PDF standard)

### Incremental Training

```python
# Load existing model
with open('model.json') as f:
    old_model = json.load(f)

# Use old weights as warm start
model = LogisticRegression(max_iter=1000, warm_start=True)
model.coef_ = np.array([old_model['weights']])
model.intercept_ = np.array([old_model['bias']])

# Train on new data
model.fit(X_new, y_new)
```

### A/B Testing

1. Train new model on updated corpus
2. Deploy both models in parallel
3. Compare performance on live traffic
4. Switch to new model if metrics improve

---

## Troubleshooting

### Low Accuracy (<85%)

**Possible causes:**
- Insufficient training data
- Class imbalance not handled
- Features not capturing relevant patterns

**Solutions:**
- Collect more diverse samples
- Use `class_weight='balanced'`
- Check feature distributions (many zeros may indicate metadata misalignment)

### Poor Calibration (ECE > 0.10)

**Possible causes:**
- Small validation set
- Model overfitting
- Wrong calibration method

**Solutions:**
- Increase validation set size (aim for 1000+ samples)
- Try isotonic regression instead of Platt scaling
- Regularize model (increase C parameter)

### High False Positive Rate

**Possible causes:**
- Threshold too low
- Benign corpus not representative
- Features biased toward malicious patterns

**Solutions:**
- Adjust decision threshold (default 0.5 → 0.6 or 0.7)
- Expand benign corpus with more diverse documents
- Analyze false positives to identify problematic features

---

## References

- [Extended Features Documentation](features-extended.md)
- [Explainability Documentation](explainability.md)
- [IR and ORG Export Documentation](ir-org-graph.md)
- [scikit-learn Calibration Guide](https://scikit-learn.org/stable/modules/calibration.html)
- [Platt Scaling Paper](https://www.cs.cornell.edu/~alexn/papers/calibration.icml05.crc.rev3.pdf)

---

## See Also

- Phase 1-4 implementation: `plans/20260109-ml-signals-and-explainability.md`
- Progress review: `plans/20260109-ml-signals-and-explainability-progress-review.md`
- Next steps: `NEXT_STEPS.md`

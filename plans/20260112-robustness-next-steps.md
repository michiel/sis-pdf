# Robustness next steps (2026-01-12)

Reviewing `plans/20260111-updates-from-scans.md` against current progress, the following items remain open.

## Major open tracks

### Track 1: ML model training (0% complete)

Duration: 2-3 weeks | Status: not started

1. Dataset preparation (2 days)
   - Extract ML features from 314K+ samples
   - Create train/val/test splits
   - Balance dataset (malicious/benign)
2. Feature engineering (3 days)
   - URI analysis features (count, domains, TLDs, obfuscation)
   - Form analysis features (credential fields, submit actions)
   - Temporal features (rapid updates, timestamp analysis)
   - JavaScript behavioural features
   - Combination/interaction features
3. Model training (5 days)
   - XGBoost classifier (primary)
   - Random Forest (ensemble)
   - Optional: neural network
   - Hyperparameter tuning
   - Target: AUC > 0.90 on 2024 data
4. Evaluation (3 days)
   - Performance metrics (AUC, precision, recall)
   - Error analysis (false positives/false negatives)
   - SHAP explainability
   - Temporal robustness validation
5. Deployment preparation (2 days)
   - ONNX model export
   - Rust integration (`sis` classify command)
   - Feature extraction pipeline
   - Inference API

### Track 2: Detection rule updates (30% complete)

Completed:
- Some heuristic updates (tolerance logic, context-aware severity)
- Object cycle detection
- Metadata analysis

Open (70%):

1. Phase 2.1: High-confidence YARA rules (2 days) - not done
   - 15-20 new YARA rules for 2024 patterns:
     - Phishing URI detection (suspicious TLDs: .tk, .ml, .ga)
     - Credential harvesting forms
     - Benign mimicry detection
     - IP-based URIs
   - Update existing rule severity/confidence
2. Phase 2.2: Advanced heuristics (2 days) - partially done
   - Already have: tolerance logic, context-aware severity
   - Missing:
     - URI analysis heuristics (domain extraction, reputation checking, count-based risk)
     - Form field analysis (credential field detection, submit action validation)
     - Temporal validation (rapid update detection, timestamp analysis)
3. Phase 2.3: Rule validation (1 day) - not done
   - Validate new rules against 2024 corpus
   - Measure detection rates
   - False positive analysis on benign corpus

### Track 3: Threat intelligence (0% complete)

Duration: 1 week | Status: not started

1. Phase 3.1: Temporal trend report (2 days)
   - Executive summary of 2022 to 2024 evolution
   - Attack vector shift analysis (JS 81.7% to 22.8%, URI 1.4% to 47.8%)
   - IOC patterns and recommendations
   - 15-20 page technical report
2. Phase 3.2: IOC feed generation (2 days)
   - STIX 2.1 bundle (287K indicators)
   - MISP event export
   - Hash lists (MD5/SHA256 of 287K malicious files)
   - URI/domain extraction from findings
3. Phase 3.3: Detection signatures (1 day)
   - Snort/Suricata rules
   - Sigma SIEM rules
   - ClamAV signature updates
4. Phase 3.4: Playbook updates (2 days)
   - Updated incident response procedures
   - 2024-focused triage decision tree
   - Analyst training materials

## Quick priority assessment

Based on the plan's Tier 1 (critical) recommendations:

Done:
- Test case extraction
- Confidence level upgrades
- False positive reduction
- Object cycle detection
- Metadata analysis

High-priority open items:

1. Deploy URI analysis heuristics (2 days)
   - Addresses biggest 2024 threat (47.8% prevalence)
   - Low complexity, high impact
   - Extract from existing URI findings
2. Update YARA rules for phishing (2-3 days)
   - Credential harvesting patterns (29.5% prevalence)
   - Suspicious TLD detection
   - Form and URI combinations
3. Generate IOC feeds (1-2 days)
   - Network-level blocking capability
   - Hashes already available (287K samples)
   - STIX/MISP format generation
4. Train XGBoost classifier (5-7 days)
   - Highest accuracy potential
   - Foundation for ML-based detection
   - Addresses 60-70% detection gap on 2024 samples

## Estimated remaining work

- Track 1 (ML): 15-20 days (can start in parallel)
- Track 2 (rules): 3-5 days
- Track 3 (intel): 5-7 days

Total: about 3-4 weeks of focused work to complete the full plan.

## Recommendation

Most impactful next steps in priority order:

1. URI analysis heuristics (2 days) - biggest threat coverage gain
2. YARA rule updates (2 days) - quick deployment wins
3. ML model training (2 weeks) - highest long-term accuracy
4. IOC feed generation (2 days) - enables network defence
5. Threat intelligence report (3 days) - communicates findings

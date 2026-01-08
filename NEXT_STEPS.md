# Next Steps for ML Signals and Explainability

## Current Status

### ✅ Completed Phases (Phases 1-3)

**Phase 1: Extended Feature Vector with Attribution** ✅
- [x] Extended feature vector (35 → 333 features)
- [x] Feature extraction from findings
- [x] Permutation importance (SHAP-style attribution)
- [x] Benign baseline computation and comparison
- [x] Natural language explanation generation
- [x] Feature group aggregation
- [x] 38 tests passing

**Phase 2: Enhanced IR with Semantic Annotations** ✅
- [x] EnhancedPdfIrObject structure
- [x] Per-object risk scoring (severity + confidence weighted)
- [x] Per-object natural language explanations
- [x] Document-level summaries and aggregations
- [x] Multiple export formats (JSON, pretty JSON, text)
- [x] 17 tests passing

**Phase 3: Enhanced ORG with Graph Paths** ✅
- [x] Graph path structures (GraphPathExplanation, SuspiciousPath, PathNode)
- [x] Path extraction from action chains
- [x] Path risk scoring (automatic triggers, JS, external actions)
- [x] Attack pattern classification (7 patterns)
- [x] Natural language path explanations
- [x] ORG export integration (OrgExportWithPaths)
- [x] 23 tests passing (18 explainability + 5 org_export)

**Total Progress**: 78 tests passing across all new modules

---

## Remaining Phases (Phases 4-7)

### Phase 4: Document-Level Risk Profile with Calibration (2 weeks)

**Goal**: Aggregate all signals + calibrate risk scores + comparative explanations

**Components to Implement**:

1. **DocumentRiskProfile structure**
   ```rust
   pub struct DocumentRiskProfile {
       pub prediction: CalibratedPrediction,
       pub total_findings: usize,
       pub high_severity_count: usize,
       pub attack_surface_diversity: usize,

       // Category-specific risk profiles
       pub js_risk: JsRiskProfile,
       pub uri_risk: UriRiskProfile,
       pub structural_risk: StructuralRiskProfile,
       pub supply_chain_risk: SupplyChainRiskProfile,
       pub content_risk: ContentRiskProfile,
       pub crypto_risk: CryptoRiskProfile,

       // Comprehensive explanations
       pub explanation: MlExplanation,
       pub comparative_analysis: Vec<ComparativeFeature>,
       pub graph_paths: Option<GraphPathExplanation>,
       pub evidence_chains: Vec<EvidenceChain>,
   }
   ```

2. **Risk Score Calibration**
   - CalibrationModel enum (PlattScaling, IsotonicRegression)
   - `calibrate()` function for transforming raw scores
   - Confidence interval estimation
   - Human-readable interpretation strings
   - Save/load calibration models

3. **Category-Specific Risk Profiles**
   - JsRiskProfile: obfuscation, evasion, multi-stage
   - UriRiskProfile: suspicious domains, schemes, redirects
   - StructuralRiskProfile: spec violations, compression bombs
   - SupplyChainRiskProfile: author trust, signatures
   - ContentRiskProfile: phishing indicators, text anomalies
   - CryptoRiskProfile: weak algorithms, suspicious certificates

4. **Comparative Explanations**
   - Z-score computation vs benign baseline
   - Percentile ranking
   - Human-readable interpretations ("3.5σ above average - highly unusual")
   - Top-N most anomalous features

**Deliverables**:
- [ ] DocumentRiskProfile structure (explainability.rs)
- [ ] 6 category-specific risk profile structures
- [ ] CalibrationModel implementation with Platt scaling + isotonic regression
- [ ] Comparative explanation generation
- [ ] Integration function: `generate_document_risk_profile()`
- [ ] Tests for risk profiling and calibration
- [ ] Documentation

**Estimated Effort**: 2 weeks

---

### Phase 5: ML Training Pipeline Integration (2 weeks)

**Goal**: Update training scripts to use enhanced signals and train with explainability support

**Components to Implement**:

1. **Training Data Export Commands**
   ```bash
   # Export extended features
   sis export-features --path dataset/ --extended --format jsonl -o features.jsonl

   # Export enhanced IR with findings
   sis export-ir --path dataset/ --enhanced --with-summary --format jsonl -o ir.jsonl

   # Export ORG with paths
   sis export-org --path dataset/ --enhanced --with-paths --format jsonl -o org.jsonl
   ```

2. **Benign Baseline Computation Utility**
   ```bash
   sis compute-baseline --benign-samples benign_features.jsonl -o baseline.json
   ```
   - Compute means, stddevs, percentiles for all 333 features
   - Save to JSON for inference-time comparison

3. **Calibration Model Training**
   - Python script for Platt scaling
   - Python script for isotonic regression
   - Validation set evaluation
   - Calibration curve plotting
   - Save calibration model to JSON (compatible with Rust)

4. **Training Pipeline Documentation**
   - Feature extraction workflow
   - Baseline computation workflow
   - Model training with calibration
   - Example Jupyter notebooks

**Deliverables**:
- [ ] `sis export-features` command with `--extended` flag
- [ ] `sis export-ir` command with `--enhanced` flag
- [ ] `sis export-org` command with `--with-paths` flag
- [ ] `sis compute-baseline` command
- [ ] Python calibration training scripts
- [ ] Jupyter notebook examples
- [ ] Training pipeline documentation

**Estimated Effort**: 2 weeks

---

### Phase 6: Inference Integration with Comprehensive Explanations (2 weeks)

**Goal**: Use all enhanced signals during inference and generate complete explanations

**Components to Implement**:

1. **Unified Inference Pipeline**
   ```rust
   pub struct MlInferenceConfig {
       pub model_path: PathBuf,
       pub baseline_path: PathBuf,
       pub calibration_path: Option<PathBuf>,
       pub threshold: f32,
       pub explain: bool,
   }

   pub fn run_ml_inference(
       pdf_path: &Path,
       config: &MlInferenceConfig,
   ) -> Result<InferenceResult> {
       // 1. Extract extended features
       // 2. Run model prediction
       // 3. Calibrate score if calibration model provided
       // 4. Generate explanations if requested
       // 5. Build DocumentRiskProfile
   }
   ```

2. **InferenceResult Structure**
   ```rust
   pub struct InferenceResult {
       pub prediction: CalibratedPrediction,
       pub risk_profile: DocumentRiskProfile,
       pub explanation_text: String,
       pub evidence_summary: EvidenceSummary,
   }
   ```

3. **CLI Integration**
   ```bash
   # Run inference with full explanations
   sis predict sample.pdf \
     --model model.onnx \
     --baseline baseline.json \
     --calibration calibration.json \
     --explain \
     --format json \
     -o result.json
   ```

4. **Explanation Report Generation**
   - Markdown report format
   - HTML report format (optional)
   - SARIF format for security tools
   - Customizable report templates

**Deliverables**:
- [ ] MlInferenceConfig and run_ml_inference()
- [ ] InferenceResult structure with full explanations
- [ ] `sis predict` command with explanation flags
- [ ] Report generation in multiple formats
- [ ] Integration tests with real models
- [ ] Documentation and examples

**Estimated Effort**: 2 weeks

---

### Phase 7 (Optional): Advanced Explainability Features (2 weeks)

**Goal**: Additional explainability techniques for production use

**Components to Consider**:

1. **Counterfactual Explanations**
   - "If feature X was Y instead of Z, prediction would change from malicious to benign"
   - Minimal feature perturbations
   - Actionable insights for analysts

2. **Anchor Explanations**
   - Identify minimal sufficient conditions: "If js.eval_count > 3 AND obfuscation > 0.8, then malicious"
   - Rule-based explanations from black-box models

3. **LIME Integration**
   - Local interpretable model-agnostic explanations
   - Complement to SHAP for different perspectives

4. **Visualization Exports**
   - SHAP waterfall plots (JSON data for frontend)
   - Feature importance bar charts
   - Calibration curve plots
   - Decision boundary visualizations

5. **Explainability Benchmarks**
   - Fidelity: How well explanations match model behavior
   - Stability: Consistency of explanations for similar inputs
   - Comprehensibility: Human evaluation metrics

**Deliverables**:
- [ ] Counterfactual explanation generator
- [ ] Anchor explanation generator
- [ ] LIME integration
- [ ] Visualization data export formats
- [ ] Explainability evaluation metrics
- [ ] Research paper / technical report

**Estimated Effort**: 2 weeks (optional, research-oriented)

---

## Immediate Next Steps (Priority Order)

### Option A: Continue Sequential Implementation (Recommended)

**Next Phase: Phase 4 (Document-Level Risk Profile)**

1. **Week 1**:
   - Implement DocumentRiskProfile structure
   - Implement 6 category-specific risk profiles
   - Add CalibrationModel with Platt scaling + isotonic regression
   - Write tests for calibration

2. **Week 2**:
   - Implement comparative explanation generation
   - Add `generate_document_risk_profile()` integration function
   - Write comprehensive tests
   - Document usage and API

**Rationale**: Completes the core explainability infrastructure before moving to training/inference integration.

### Option B: Jump to Inference Integration

**Skip to Phase 6 for immediate production value**

**Rationale**: If you need inference with explanations ASAP, you can:
- Use existing Phase 1-3 components (attribution, enhanced IR, graph paths)
- Skip calibration and category profiles for now (simpler explanations)
- Return to Phase 4-5 later for advanced features

### Option C: Training Pipeline First

**Implement Phase 5 before Phase 4**

**Rationale**: If you need to train models with the new 333 features:
- Export extended features from dataset
- Train baseline models
- Add calibration later (Phase 4)

---

## Technical Debt and Polish

### Before Production Deployment

1. **CLI Integration**
   - Wire up all export commands (IR, ORG, features)
   - Add `--explain` flags to scan commands
   - Implement report generation

2. **Performance Optimization**
   - Benchmark feature extraction on large files
   - Optimize path finding for graphs with >10K objects
   - Add caching for repeated scans

3. **Error Handling**
   - Graceful degradation when explanations fail
   - Better error messages for missing models/baselines
   - Handle edge cases (empty PDFs, corrupted files)

4. **Documentation**
   - API documentation for all new modules
   - Usage examples for each export format
   - Tutorial notebooks for ML engineers
   - Analyst guide for interpreting explanations

5. **Testing**
   - Integration tests with real malicious samples
   - Fuzzing for feature extraction
   - Performance regression tests
   - Documentation tests

---

## Success Metrics

### Phase 4 Success Criteria
- [ ] DocumentRiskProfile generates for all test samples
- [ ] Calibration reduces Brier score by >15%
- [ ] Category profiles cover 95%+ of finding types
- [ ] Comparative explanations identify top anomalies
- [ ] All tests passing

### Phase 5 Success Criteria
- [ ] Can export features from 10K+ PDF dataset
- [ ] Baseline computation completes in <5 minutes
- [ ] Calibration models train successfully
- [ ] Documentation enables external ML engineers to train models

### Phase 6 Success Criteria
- [ ] Inference pipeline generates explanations in <2 seconds
- [ ] Explanations are actionable for analysts (human eval)
- [ ] SARIF output compatible with security tools
- [ ] Command-line interface is intuitive

---

## Resources Needed

### For Phase 4-6
- **Test data**: Labeled benign/malicious PDF dataset (>1000 samples each)
- **Calibration data**: Validation set with ground truth labels
- **Trained models**: ONNX models for inference testing
- **Human evaluation**: Analysts to validate explanation quality

### For Phase 7 (Optional)
- **Research time**: Experiment with advanced techniques
- **Visualization tools**: Frontend for interactive explanations
- **Academic collaboration**: Partner with explainability researchers

---

## Questions to Resolve

1. **Model Format**: Continue with ONNX, or support other formats (TorchScript, TensorFlow SavedModel)?
2. **Baseline Updates**: How often should benign baseline be recomputed? Automatic updates?
3. **Calibration Strategy**: Use isotonic regression (more flexible) or Platt scaling (simpler)?
4. **Report Format**: Prioritize Markdown, HTML, or SARIF for initial release?
5. **Performance Target**: What's acceptable latency for explanation generation? <1s? <5s?
6. **Deployment**: Package explanations in CLI tool, or provide as library for integration?

---

## Long-Term Vision

### Beyond Phase 7

1. **Interactive Explainability UI**
   - Web dashboard for exploring explanations
   - Click on features to see source evidence
   - Visualize ORG graphs with findings overlay

2. **Federated Learning Integration**
   - Privacy-preserving model updates
   - Aggregate explanations across organizations
   - Collaborative threat intelligence

3. **Adversarial Robustness**
   - Detect explanation attacks (model evasion)
   - Robust explanations under perturbations
   - Adversarial training with explanations

4. **Human-in-the-Loop**
   - Analyst feedback on explanation quality
   - Active learning from explanation interactions
   - Explanation-guided labeling

5. **Multi-Modal Explanations**
   - Combine PDF structure + content + metadata
   - Cross-reference with external threat feeds
   - Explain in context of attack campaigns

---

## Conclusion

**Current Achievement**: 3 out of 7 phases complete, with 78 tests passing and comprehensive documentation.

**Recommended Next Step**: Implement **Phase 4 (Document-Level Risk Profile with Calibration)** to complete the core explainability infrastructure.

**Timeline**: With current velocity (~1 week per phase), all core phases (1-6) can be completed in ~6-8 weeks total, with Phase 7 as optional research.

**Value Delivered So Far**:
- ✅ 333-feature ML signal extraction
- ✅ SHAP-style feature attribution
- ✅ Enhanced IR with risk scoring
- ✅ Graph path analysis with attack patterns
- ✅ Natural language explanations
- ✅ Multiple export formats for integration

**Ready for**: Model training with extended features, enhanced IR export for datasets, graph path analysis for threat intelligence.

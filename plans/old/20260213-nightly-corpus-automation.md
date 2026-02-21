# Nightly corpus evaluation automation plan (GitHub Actions + remote VM)

Date: 2026-02-13  
Status: Proposed  
Scope: nightly evaluation against latest corpus batch on a public VM, with automated reporting, investigation item capture, PR creation, and auto-merge.

## 1) Goals and non-goals

### Goals
1. Every night, run `sis` evaluation against the latest corpus batch available on the remote VM.
2. Persist daily performance and quality metrics in a CSV trend file (create if missing, append one row per day).
3. Auto-register scan errors/anomalies/investigation candidates and append them to `plans/corpus_investigation_items.md`.
4. Open a PR with generated updates and auto-merge to `main` when checks pass.
5. Keep the workflow deterministic, idempotent, and auditable.

### Non-goals
1. Replacing existing manual deep-dive investigation workflows.
2. Fully autonomous detector tuning in this phase.
3. Storing full corpus artefacts in Git.

## 2) High-level architecture

1. **GitHub Actions nightly workflow**
   - Scheduled trigger (`cron`) + manual trigger (`workflow_dispatch`).
   - Builds or downloads `sis` binary.
   - Executes a remote evaluation orchestration script over SSH.
2. **Remote VM batch discovery and scan execution**
   - Resolve “latest corpus batch” on VM (by date-stamped directory or latest manifest).
   - Run scans and produce structured artefacts (JSON/JSONL + summary JSON) on VM.
3. **Artefact pull-back to runner**
   - Fetch only summary artefacts and compact per-file anomaly records (not raw PDFs).
4. **Repo update step**
   - Update trend CSV in `reports/trends/` (or create).
   - Update `plans/corpus_investigation_items.md` with daily H2 + per-item H3 sections.
5. **PR + auto-merge**
   - Create PR via bot action.
   - Enable auto-merge (squash) after required checks.

## 3) Security model and controls (public VM + SSH)

1. Use a **dedicated deploy SSH key** with:
   - command restrictions where possible,
   - no interactive shell for general use,
   - no agent forwarding.
2. Store credentials in GitHub secrets:
   - `CORPUS_VM_HOST`, `CORPUS_VM_PORT`, `CORPUS_VM_USER`, `CORPUS_VM_SSH_KEY`.
3. Pin host key:
   - store trusted host fingerprint in secret/config,
   - enforce strict host key checking in workflow.
4. Run evaluation in a constrained directory/user on VM.
5. Pull back only sanitised outputs:
   - no raw payload bytes,
   - no sensitive paths beyond hashed filenames.
6. Harden auto-merge:
   - only merge bot-authored PRs from this workflow branch prefix,
   - require workflow checks to pass before merge,
   - disallow direct pushes to `main`.

## 4) Data contracts

### 4.1 Trend CSV (`reports/trends/nightly_corpus_metrics.csv`)

Create if missing with header:

`date,batch_id,files_total,files_scanned,scan_errors,scan_warnings,runtime_unknown_total,runtime_unknown_unique,timeout_count,p95_detection_ms,p99_detection_ms,total_findings,high_count,critical_count,parser_resource_exhaustion_count,notes`

Rules:
1. One row per date + batch_id.
2. Upsert semantics (replace existing row for same `date,batch_id`).
3. Numeric fields must be parseable.

### 4.2 Investigation plan file (`plans/corpus_investigation_items.md`)

Append/update structure:

1. `## YYYY-MM-DD`
2. For each item:
   - `### <short item title>`
   - `- date: YYYY-MM-DD`
   - `- filename: <hash>.pdf`
   - `- type: <error|anomaly|performance|coverage_gap>`
   - `- details: <concise finding summary>`
   - `- findings: <comma-separated top kinds>`
   - `- severity_profile: <Critical=X, High=Y, ...>`
   - `- source_batch: <batch_id>`
   - `- status: open`

Idempotency:
1. Item key = `date + filename + type + canonical_top_kind`.
2. Re-runs must not duplicate identical items.

### 4.3 Remote summary JSON

Expected keys (minimum):
1. `date`, `batch_id`
2. `files_total`, `files_scanned`
3. `scan_errors`, `scan_warnings`, `timeout_count`
4. `detection_duration_ms` distribution (`p50`, `p95`, `p99`, `max`)
5. `findings.by_kind`, `findings.by_severity`
6. `runtime_unknown_behaviour.total`, `.unique_names`, `.samples`
7. `investigation_candidates[]` (normalised records for markdown generation)

## 5) Workflow design (`.github/workflows/nightly-corpus-eval.yml`)

1. **Trigger**
   - nightly cron (off-peak UTC),
   - manual dispatch with optional date override.
2. **Permissions**
   - `contents: write`, `pull-requests: write`.
3. **Steps**
   - checkout,
   - install Rust + build `sis` (or download release),
   - configure SSH key + known_hosts,
   - remote command: run evaluation script on VM for latest batch,
   - pull back `summary.json` + `candidates.jsonl`,
   - run local updater script to:
     - upsert CSV row,
     - update investigation markdown,
   - create PR with deterministic branch name,
   - enable auto-merge.
4. **Branch naming**
   - `automation/nightly-corpus-YYYYMMDD`.
5. **PR title format**
   - `Nightly corpus evaluation: YYYY-MM-DD`.

## 6) Script implementation plan

### 6.1 New script: `scripts/nightly_corpus_eval.py`

Responsibilities:
1. Read pulled summary/candidates artefacts.
2. Upsert trend CSV row.
3. Update `plans/corpus_investigation_items.md`.
4. Emit concise run summary for GitHub job output.

Key functions:
1. `upsert_metrics_row(...)`
2. `normalise_candidate(...)`
3. `merge_investigation_items(...)`
4. `render_daily_section(...)`
5. `load_existing_plan(...)` / `write_plan(...)`

### 6.2 Remote runner script (on VM)

Responsibilities:
1. Resolve latest batch path deterministically.
2. Execute `sis` scan/query pipeline.
3. Produce:
   - `nightly_summary.json`
   - `nightly_candidates.jsonl`
4. Exit non-zero for infrastructure failures; zero for completed run with data.

## 7) Investigation candidate extraction rules

Generate candidates when any of:
1. File-level scan error/time-out.
2. `js_runtime_unknown_behaviour_pattern` observed.
3. `parser_resource_exhaustion` observed.
4. High-risk chains observed (e.g. launch + JS intent + automatic trigger).
5. Detection/runtime outliers:
   - detection duration > dynamic threshold (e.g. p95 * 1.5),
   - finding volume > dynamic threshold (e.g. top 5%).

Candidate priority:
1. `P0`: critical/high exploit chains or unknown runtime behaviours.
2. `P1`: parser/resource exhaustion with structural anomalies.
3. `P2`: noisy but performance-significant outliers.

## 8) Auto-merge policy

1. Auto-merge only when:
   - workflow succeeds,
   - changed files are limited to allow-list:
     - `reports/trends/nightly_corpus_metrics.csv`
     - `plans/corpus_investigation_items.md`
     - optional run metadata under `reports/trends/nightly/`.
2. If unexpected files changed, fail and require manual review.
3. Use squash merge for linear history.

## 9) Testing and validation

### Unit tests
1. CSV creation/upsert behaviour.
2. Markdown section generation and deduplication logic.
3. Candidate normalisation and priority mapping.

### Integration tests
1. Dry-run with fixture summary/candidates files.
2. Re-run idempotency test (no duplicate entries).
3. PR generation smoke test in a non-protected branch.

### Operational validation
1. Run nightly workflow in shadow mode for 3 nights (PR without auto-merge).
2. Verify:
   - row appended/upserted correctly,
   - investigation entries are actionable and non-duplicative,
   - no secret leakage in logs.
3. Enable auto-merge after shadow validation passes.

## 10) Rollout phases

### Phase 1: Foundation
1. Add workflow skeleton + secure SSH bootstrap.
2. Implement local updater script + tests.
3. Keep merge manual.

### Phase 2: Live nightly with PRs
1. Enable nightly schedule.
2. Generate PRs automatically.
3. Monitor for 1 week.

### Phase 3: Auto-merge enablement
1. Turn on guarded auto-merge policy.
2. Enforce changed-file allow-list gate.
3. Add on-call notification on failures.

## 11) Failure handling and observability

1. On SSH/connectivity failure:
   - workflow fails early,
   - create issue/comment optional hook.
2. On empty/latest batch missing:
   - record a metrics row with `notes=empty_batch`,
   - skip investigation items.
3. On parser/update script failure:
   - fail workflow, no PR.
4. Preserve run logs and pulled summary artefacts via workflow artefact upload.

## 12) Open decisions to resolve before implementation

1. Whether to run `sis` on VM or pull latest corpus subset to runner.
   - recommendation: run on VM, pull summary only.
2. Exact threshold policy for outlier candidate creation.
3. Whether weekly compaction of `plans/corpus_investigation_items.md` is needed to keep file size manageable.
4. Whether to also open GitHub Issues for `P0` items in addition to plan updates.

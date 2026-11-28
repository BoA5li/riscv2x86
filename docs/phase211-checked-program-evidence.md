# Phase211: checked subclaim consumption and original L2 planning

This revision repairs two production gaps without changing translation rules or
turning diagnostic observations into semantic approval:

* L1 now passes actual original source/target build receipts and optional machine
  inventory receipts to the claim consumer. Fresh original checkers validate the
  project, both build roles, artifact bytes, commands and inventory/build joins.
  Recorded builds and a bounded inventory can become checked subclaims; complete
  machine ABI, internal access, dependency effects and canonical coverage cannot.
* Independent original-evaluation readback replays the original process comparator
  and obligation consumption. Rehashing a modified assessment or approval marker
  cannot replace the expected result. This remains record checking, not independent
  program semantic proof.
* Every generated project request registers ORIGINAL requirement-driven L2 planning,
  even without a finite API runtime result. Its manifest is derived from the exact
  independently audited native report using the existing classifier. The native
  report's authority enrichment has its own original audit; it is not assigned an
  automatic-command staging receipt belonging to a different report.
* Existing automatic-command staging remains mandatory on other routes. Native
  request manifests are pinned, regenerated and checked against audited report
  identity. Source reports and the original attempt archive are never overwritten.
* The original resolver reports every missing dimension/provider before execution.
  An empty provider catalogue stays incomplete; it is not a substitute provider.
  An existing checked finite-API provider remains usable only within its own scope.

## Limits

This is not the implementation of all complete ABI/access/refinement/L3 proof
producers. For the current excluded instance, expect L1 to remain inconclusive.
The change is that checked build/inventory facts are consumed correctly and L2
is registered with explicit capability gaps instead of being absent. Never bypass
L1 or mark the excluded instance as covered. The default architectural plan still
requires L0/L1/L2; L3 needs an explicit applicable intent/property/environment
contract and a compatible original backend. Semantic approval remains false.

## Run blocks separately

Stop on an unexpected error. Use fresh outputs; retain Phase210 evidence.

### 1. Tooling

```bash
git -C "$REPO" fetch origin phase211-checked-program-evidence
```

```bash
export PHASE211_TOOLING="$(mktemp -d "$PREP_ROOT/tooling-phase211-XXXXXX")"
rmdir "$PHASE211_TOOLING"
git -C "$REPO" worktree add --detach "$PHASE211_TOOLING" origin/phase211-checked-program-evidence
```

```bash
export PHASE211_PARENT="$(mktemp -d "$PHASE210_PARENT/phase211-XXXXXX")"
export PYTHONPATH="$PHASE211_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE211_CLI="$PHASE211_TOOLING/experiment/automate_native_project.py"
git -C "$PHASE211_TOOLING" rev-parse HEAD
printf 'PHASE211_PARENT=%s\n' "$PHASE211_PARENT"
```

### 2. Regression

```bash
python3 -m pytest -q -rs "$PHASE211_TOOLING/pytools/tests/test_phase211_checked_program_evidence.py" "$PHASE211_TOOLING/pytools/tests/test_native_project_evaluation.py" "$PHASE211_TOOLING/pytools/tests/test_phase210_original_assessment.py" "$PHASE211_TOOLING/pytools/tests/test_program_claim_consumption.py" "$PHASE211_TOOLING/pytools/tests/test_project_obligation_assessment.py" > "$PHASE211_PARENT/regression.log" 2>&1
PHASE211_STATUS=$?
printf 'regression_status=%s\n' "$PHASE211_STATUS"
tail -n 30 "$PHASE211_PARENT/regression.log"
```

Require exit 0 and no unexpected skips. Tests require the existing pypcode and
GCC dependencies. They are host/fixture regression, not real corpus approval.

### 3. Fresh original translation and preflight

```bash
python3 "$PHASE211_CLI" api-replay --previous-result "$PHASE208_PARENT/api-campaign/result.json" --output "$PHASE211_PARENT/task" --stop-after preflight --profile-output "$PHASE211_PARENT/preflight-profile.json" > "$PHASE211_PARENT/preflight.log" 2>&1
PHASE211_STATUS=$?
printf 'preflight_status=%s\n' "$PHASE211_STATUS"
```

Expected 1 for completed preflight without acceptance. Current exclusion must
remain. Old campaign files are selectors only; the current verifier reaudits.

### 4. Invoke the original formal evaluator

```bash
python3 "$PHASE211_CLI" api-assess --preflight "$PHASE211_PARENT/task/preflight.json" --complete-api --output "$PHASE211_PARENT/assessment" --profile-output "$PHASE211_PARENT/assessment-profile.json" > "$PHASE211_PARENT/assessment.log" 2>&1
PHASE211_STATUS=$?
printf 'assessment_status=%s\n' "$PHASE211_STATUS"
tail -n 2 "$PHASE211_PARENT/assessment.log"
```

Expected may remain 1 for an original inconclusive/failed result. Exit 2 is an
acquisition error. Do not rerun a checked terminal verdict until it passes.

Inspect the checked result for:

* originalEvaluationInvoked=true; L0/L1 statuses and unexecuted L2 remain accurate.
* readiness.gaps no longer contains ORIGINAL_LAYER_RUNNER_NOT_DECLARED:L2.
* readiness.l2ProviderResolution lists actual required dimensions and unresolved
  providers/capabilities; it does not assert execution or semantic approval.
* L1 obligationAssessment.claimConsumption.claims includes recorded-project-builds
  and, when its checked receipt exists, bounded-machine-inventory.
* The corresponding missingProofFacts no longer lists those acquired subfacts;
  complete-machine-call-and-exit-contract and other genuine proof gaps remain.
* Finite API cases and official project cases remain separate scopes.

### 5. Independent checks

```bash
python3 "$PHASE211_CLI" check --input "$PHASE211_PARENT/assessment/result.json" --profile-output "$PHASE211_PARENT/check-cached-profile.json" > "$PHASE211_PARENT/check-cached.log" 2>&1
PHASE211_STATUS=$?
printf 'check_cached_status=%s\n' "$PHASE211_STATUS"
```

```bash
python3 "$PHASE211_CLI" check --input "$PHASE211_PARENT/assessment/result.json" --verification-cache-mib 0 --profile-output "$PHASE211_PARENT/check-no-cache-profile.json" > "$PHASE211_PARENT/check-no-cache.log" 2>&1
PHASE211_STATUS=$?
printf 'check_no_cache_status=%s\n' "$PHASE211_STATUS"
```

```bash
cmp "$PHASE211_PARENT/check-cached.log" "$PHASE211_PARENT/check-no-cache.log"
PHASE211_STATUS=$?
printf 'check_comparison_status=%s\n' "$PHASE211_STATUS"
```

Expected all 0. These check integrity and rederivation, not full program proof.

## Return these existing files

* regression.log
* assessment/result.json and assessment.log
* assessment/contracts/request.json and assessment/contracts/l2-requirements.json
* assessment/evaluations/000000/result.json
* assessment/evaluations/000000/evaluation-result.json
* preflight-profile.json, assessment-profile.json and both independent profiles
* check-cached.log and check-no-cache.log

No additional replay of Phase209/210 is needed. Measure comparable operations;
the extra evidence rederivation is required correctness work, not a measured
speedup claim. Other proof-producer extensions must be implemented and tested
within their declared supported scope; additional status flags cannot close them.

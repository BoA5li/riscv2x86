# Phase210: execute the original evaluation chain

## Changes and limits

* Original finite L2 findings are selected by compiler instance identity, not
  enclosing function spelling. Missing, duplicate and ambiguous subjects reject.
* `api-assess` invokes native_original_evaluation.acquire, which invokes the
  existing evaluation.run_evaluation. It checks the resulting original records.
  It does not implement translation rules, new layer validators or an approval
  shortcut. A checked failed/inconclusive verdict is terminal.
* `api-corpus --evaluate` freezes a v2 plan. Every task proceeds to original
  formal evaluation, including source-excluded tasks. Such tasks skip finite API
  execution, not the formal request/evaluation. Failed acquisitions retain the
  original API result and logs. Evaluation verdicts are distinct from acquisition
  errors. Resume cannot change between legacy and evaluation modes.
* `api-inventory` lists all findings in the registered checked contexts, including
  findings without an available entry or explicit finite domain. It does not
  claim to have discovered every upstream source/configuration.
* Intermediate corpus checkpoints avoid recursive all-task checking; final and
  independent checks rederive child evidence with original checkers.

Finite API inputs are NOT the official project test domain. Assessment receipts
report both scopes separately. The default architectural project request requires
L0/L1/L2. Missing runners, prerequisites or dimensions remain explicit; L3 is not
silently added, passed or declared inapplicable. Complete ABI, internal access,
dependency effects, canonical machine execution and independent program audit
are not implemented by this orchestration adapter. Existing supported proof and
L3 backends still require compatible bound contracts.

A record-integrity check is NOT an independent semantic audit. All top-level
semanticApproval and productionAcceptanceComplete flags remain false.
originalEvaluationInvoked indicates a real evaluator call; it does not mean all
required layers ran or passed. Inspect attempts/unexecutedRequiredLevels and
readiness.gaps, including unexecutedRequiredLevelsWithoutAttempts.

## Run instructions

Execute blocks separately in Bash. Stop on unexpected errors. Commands use new
directories; retain existing evidence and do not rerun into the same output.

### 1. Isolated tooling

```bash
git -C "$REPO" fetch origin phase210-original-evaluation-chain
```

```bash
export PHASE210_TOOLING="$(mktemp -d "$PREP_ROOT/tooling-phase210-XXXXXX")"
rmdir "$PHASE210_TOOLING"
git -C "$REPO" worktree add --detach "$PHASE210_TOOLING" origin/phase210-original-evaluation-chain
```

```bash
export PHASE210_PARENT="$(mktemp -d "$PHASE209_PARENT/phase210-XXXXXX")"
export PYTHONPATH="$PHASE210_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE210_CLI="$PHASE210_TOOLING/experiment/automate_native_project.py"
git -C "$PHASE210_TOOLING" rev-parse HEAD
printf 'PHASE210_PARENT=%s\n' "$PHASE210_PARENT"
```

### 2. Focused regression

```bash
python3 -m pytest -q -rs "$PHASE210_TOOLING/pytools/tests/test_phase210_original_assessment.py" "$PHASE210_TOOLING/pytools/tests/test_phase209_api_preflight.py" "$PHASE210_TOOLING/pytools/tests/test_native_api_campaign.py" "$PHASE210_TOOLING/pytools/tests/test_native_project_l2_entry.py" "$PHASE210_TOOLING/pytools/tests/test_native_project_evaluation.py" > "$PHASE210_PARENT/regression.log" 2>&1
PHASE210_STATUS=$?
printf 'regression_status=%s\n' "$PHASE210_STATUS"
tail -n 30 "$PHASE210_PARENT/regression.log"
```

Require 0 and no unexpected skips. CI additionally runs the wider previous
regression and original evaluator tests. Host fixtures do not prove real RV64
or GMP semantic equivalence.

### 3. Fresh original translation, audit and preflight

Do not consume Phase209 evidence as current authority after changing verifier
code. Replay its pinned selectors through the original pipeline:

```bash
python3 "$PHASE210_CLI" api-replay --previous-result "$PHASE208_PARENT/api-campaign/result.json" --output "$PHASE210_PARENT/task" --stop-after preflight --profile-output "$PHASE210_PARENT/preflight-profile.json" > "$PHASE210_PARENT/preflight.log" 2>&1
PHASE210_STATUS=$?
printf 'preflight_status=%s\n' "$PHASE210_STATUS"
tail -n 2 "$PHASE210_PARENT/preflight.log"
```

Expected exit 1 for a completed non-acceptance preflight; 2 is an error.
The unchanged source-excluded configuration must remain excluded.

### 4. Inventory ALL findings in this checked project context

```bash
python3 "$PHASE210_CLI" api-inventory --preflight "$PHASE210_PARENT/task/preflight.json" --output "$PHASE210_PARENT/instance-inventory.json" > "$PHASE210_PARENT/inventory.log" 2>&1
PHASE210_STATUS=$?
printf 'inventory_status=%s\n' "$PHASE210_STATUS"
```

Expected 0. Additional checked contexts may be supplied with repeated
`--preflight` arguments. Missing entry contracts must remain missing; no pointer
bounds, aliases, legal inputs or intent are guessed from function names.

### 5. Actually invoke original evaluation

```bash
python3 "$PHASE210_CLI" api-assess --preflight "$PHASE210_PARENT/task/preflight.json" --complete-api --output "$PHASE210_PARENT/assessment" --profile-output "$PHASE210_PARENT/assessment-profile.json" > "$PHASE210_PARENT/assessment.log" 2>&1
PHASE210_STATUS=$?
printf 'assessment_status=%s\n' "$PHASE210_STATUS"
tail -n 2 "$PHASE210_PARENT/assessment.log"
```

`--complete-api` resumes the SAME original task when runtime is required. For
the current excluded task it correctly skips finite API execution and invokes
the original project evaluator with its official case list. No alternate source
or translator is generated.

Expected status may remain 1 with failed/inconclusive original evaluation.
Exit 2 indicates an acquisition/contract error; retain all child logs.
A successful command execution is not the target by itself: check
originalEvaluationInvoked, requiredLevels, attempts, unexecutedRequiredLevels,
readiness.gaps and the original evaluation reason codes. If an early original
requirement stage stops execution, its missing obligations remain explicit.
Never keep retrying a checked failed/inconclusive verdict to obtain a pass.

### 6. Independent cached and no-cache record checks

Run only if assessment/result.json exists:

```bash
python3 "$PHASE210_CLI" check --input "$PHASE210_PARENT/assessment/result.json" --profile-output "$PHASE210_PARENT/check-cached-profile.json" > "$PHASE210_PARENT/check-cached.log" 2>&1
PHASE210_STATUS=$?
printf 'check_cached_status=%s\n' "$PHASE210_STATUS"
```

```bash
python3 "$PHASE210_CLI" check --input "$PHASE210_PARENT/assessment/result.json" --verification-cache-mib 0 --profile-output "$PHASE210_PARENT/check-no-cache-profile.json" > "$PHASE210_PARENT/check-no-cache.log" 2>&1
PHASE210_STATUS=$?
printf 'check_no_cache_status=%s\n' "$PHASE210_STATUS"
```

```bash
cmp "$PHASE210_PARENT/check-cached.log" "$PHASE210_PARENT/check-no-cache.log"
PHASE210_STATUS=$?
printf 'check_comparison_status=%s\n' "$PHASE210_STATUS"
```

All three expected 0, even when the independently checked evaluation verdict
is inconclusive or failed. No claim of independent semantic proof follows.

### Batch formal mode

For an explicit multi-task manifest (same schema as Phase209), use a NEW output:

```bash
python3 "$PHASE210_CLI" api-corpus --manifest "$PHASE209_PARENT/api-tasks.json" --output "$PHASE210_PARENT/corpus" --max-tasks 1 --evaluate --profile-output "$PHASE210_PARENT/corpus-profile.json" > "$PHASE210_PARENT/corpus.log" 2>&1
PHASE210_STATUS=$?
printf 'corpus_status=%s\n' "$PHASE210_STATUS"
```

This is an alternative to single-task steps 3-5, not a necessary duplicate.
The old manifest supplies selectors; all task preparation and verification use
current code. One excluded task should end as source-excluded-evaluated-STATUS,
with a referenced assessment, zero finite API runs and no semantic approval.
If acquisition fails, status is blocked, not an evaluation pass.
Exit 1 means all tasks have terminal accounting, 3 budget-limited pending work,
2 a top-level error. Resume must preserve `--evaluate`:

```bash
python3 "$PHASE210_CLI" api-corpus --manifest "$PHASE209_PARENT/api-tasks.json" --output "$PHASE210_PARENT/corpus" --max-tasks 1 --evaluate --resume > "$PHASE210_PARENT/corpus-resume.log" 2>&1
PHASE210_STATUS=$?
printf 'corpus_resume_status=%s\n' "$PHASE210_STATUS"
```

Check with the existing `check --input .../corpus/progress.json` command.
Use --retry-blocked for a genuinely resolved acquisition prerequisite; changed
selectors or verifier code require a fresh output. All older attempts remain.

## Feedback files

Return regression.log; preflight.log and preflight-profile.json;
instance-inventory.json; assessment.log and assessment/result.json;
assessment/contracts/request.json; assessment-profile.json; both check logs
and their profiles. If assessment acquisition fails, return its retained
evaluations/*/run-status.json and associated command logs instead of rerunning.
For batch mode additionally return corpus/progress.json and corpus-profile.json.

The next proof-producer changes should be driven by actual original evaluator
reason codes. This revision does not pretend to close complete ABI/access/L3
obligations without the corresponding production evidence.

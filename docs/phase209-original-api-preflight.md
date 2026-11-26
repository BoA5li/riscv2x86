# Phase209: original API preflight and bounded corpus scheduling

This revision adds orchestration, not a new translator or proof algorithm.
The existing original preparation, audit, compiler-bound API request, typed
L2 provider and independent checkers retain ownership of their decisions.

## What changes

* `api-campaign` and `api-replay` accept `--stop-after preflight`.
  They perform original preparation and input-contract validation and publish
  `preflight.json` without launching API build/run or original L2 acquisition.
* A nonempty, unique selection must join exactly to checked applicability
  instances AND report findings. A missing or ambiguous join rejects the
  preflight. Unknown or unstructured control flow cannot authorize a skip.
* `api-corpus` preserves every explicitly registered task. Only when ALL
  selected instances have checked source exclusions does it retain a
  `source-excluded` row and continue without runtime acquisition. Otherwise
  it resumes the same original campaign to execute and attempt original L2.
* Failed tasks retain diagnostics and do not block independent tasks.
  `--max-tasks` bounds work; `--resume` preserves the denominator;
  `--retry-blocked` starts a fresh attempt and retains the failed directory.
  Identical selector contents cannot be counted twice under different labels.
* Independent `check` reconstructs statuses from original child checkers.
  No source exclusion, erasure invariant, finite API agreement, or completed
  task count grants canonical coverage, program approval or L3 acceptance.

This does not close complete machine ABI, all internal accesses, dependency
effects, canonical execution events or L3 properties. Those require producers
and validators with the corresponding artifact-bound contracts. A new task
must use an independently captured configuration and an explicitly justified
domain; do not modify guards or invent pointer bounds to obtain execution.

## 1. Isolated setup

Run each code block separately in Bash. No existing evidence is overwritten.
The venv must have the same original pipeline dependencies as Phase208.

```bash
phase209_setup() {
  : "${REPO:?}" "${PREP_ROOT:?}" "${PHASE208_PARENT:?}" || return
  test -s "$PHASE208_PARENT/api-campaign/result.json" || return
  git -C "$REPO" fetch origin phase209-original-api-preflight || return
  PHASE209_TOOLING=$(mktemp -d "$PREP_ROOT/tooling-phase209-XXXXXX") || return
  rmdir "$PHASE209_TOOLING" || return
  git -C "$REPO" worktree add --detach "$PHASE209_TOOLING" origin/phase209-original-api-preflight || return
  PHASE209_PARENT=$(mktemp -d "$PHASE208_PARENT/phase209-XXXXXX") || return
  export PHASE209_TOOLING PHASE209_PARENT
  export PYTHONPATH="$PHASE209_TOOLING/pytools"
  export PYTHONDONTWRITEBYTECODE=1
  export PHASE209_CLI="$PHASE209_TOOLING/experiment/automate_native_project.py"
  git -C "$PHASE209_TOOLING" rev-parse HEAD || return
  printf 'PHASE209_PARENT=%s\n' "$PHASE209_PARENT"
}
phase209_setup
```

## 2. Regression

```bash
python3 -m pytest -q -rs "$PHASE209_TOOLING/pytools/tests/test_phase209_api_preflight.py" "$PHASE209_TOOLING/pytools/tests/test_native_api_campaign.py" "$PHASE209_TOOLING/pytools/tests/test_native_original_api.py" "$PHASE209_TOOLING/pytools/tests/test_phase208_instance_accounting.py" "$PHASE209_TOOLING/pytools/tests/test_native_instance_erasure.py" "$PHASE209_TOOLING/pytools/tests/test_native_project_l2_entry.py" "$PHASE209_TOOLING/pytools/tests/test_verification_session.py" > "$PHASE209_PARENT/regression.log" 2>&1
PHASE209_STATUS=$?
printf 'regression_status=%s\n' "$PHASE209_STATUS"
tail -n 30 "$PHASE209_PARENT/regression.log"
```

Require status 0 and no unexpected skips. The branch workflow runs the wider
Phase208-related regression set plus the new tests; host fixtures do not
establish real RV64 or corpus-wide semantic approval.

## 3. Real original-path preflight

```bash
python3 "$PHASE209_CLI" api-replay --previous-result "$PHASE208_PARENT/api-campaign/result.json" --output "$PHASE209_PARENT/preflight" --stop-after preflight --profile-output "$PHASE209_PARENT/preflight-profile.json" > "$PHASE209_PARENT/preflight.log" 2>&1
PHASE209_STATUS=$?
printf 'preflight_status=%s\n' "$PHASE209_STATUS"
tail -n 2 "$PHASE209_PARENT/preflight.log"
```

Expected exit 1 means the preparation/contract-only command completed without
claiming evaluation acceptance. Exit 2 indicates an actual error.
For the unchanged excluded seed expect
`selection.disposition=all-selected-instances-source-excluded`,
`runtimeAcquisitionRecommended=false`, no API `attempts` directory, and all
approval/coverage flags false. This is not a replacement L2 pass.

## 4. Cached and independent no-cache checks

```bash
python3 "$PHASE209_CLI" check --input "$PHASE209_PARENT/preflight/preflight.json" --profile-output "$PHASE209_PARENT/check-cached-profile.json" > "$PHASE209_PARENT/check-cached.log" 2>&1
PHASE209_STATUS=$?
printf 'check_cached_status=%s\n' "$PHASE209_STATUS"
```

```bash
python3 "$PHASE209_CLI" check --input "$PHASE209_PARENT/preflight/preflight.json" --verification-cache-mib 0 --profile-output "$PHASE209_PARENT/check-no-cache-profile.json" > "$PHASE209_PARENT/check-no-cache.log" 2>&1
PHASE209_STATUS=$?
printf 'check_no_cache_status=%s\n' "$PHASE209_STATUS"
```

Require both exit 0 and identical JSON output. Compare like operations only:
preflight timings and full Phase208 API campaign timings measure different work.

```bash
cmp "$PHASE209_PARENT/check-cached.log" "$PHASE209_PARENT/check-no-cache.log"
```

## 5. Register the actual corpus task denominator

Use the current checked campaign selectors to create a one-task scheduling
regression. This does not invent another executable configuration.

```bash
python3 - <<'PY'
import json
import os
from pathlib import Path
from riscv2x86_py import native_api_campaign as c
from riscv2x86_py import native_api_corpus as batch

root = Path(os.environ["PHASE209_PARENT"])
value = c.check_preflight(root / "preflight/preflight.json")
plan = c.check_plan(value["plan"]["path"])
task = {
    "taskId": "recorded-task-0",
    "configuration": plan["configuration"]["path"],
    "domain": plan["domain"]["path"],
    "functionAstPath": plan["functionAstPath"],
    "assumptionSources": [r["path"] for r in plan["assumptionSources"]],
}
with (root / "api-tasks.json").open("x") as stream:
    json.dump({"schemaVersion": batch.INPUT, "tasks": [task]}, stream, indent=2)
    stream.write("\n")
PY
```

Each additional task requires its own existing captured configuration, compiler
AST function path, explicit finite-domain file and precondition sources. Register
them together BEFORE running. Never reuse an AST path across different inputs
without inspecting its current declaration. Paths in the manifest are absolute.
After a run begins, changing the manifest or selector bytes must reject resume.

```bash
python3 "$PHASE209_CLI" api-corpus --manifest "$PHASE209_PARENT/api-tasks.json" --output "$PHASE209_PARENT/api-corpus" --max-tasks 1 --profile-output "$PHASE209_PARENT/corpus-profile.json" > "$PHASE209_PARENT/corpus.log" 2>&1
PHASE209_STATUS=$?
printf 'corpus_status=%s\n' "$PHASE209_STATUS"
tail -n 2 "$PHASE209_PARENT/corpus.log"
```

Exit 1 means all registered tasks are accounted for WITHOUT semantic acceptance;
exit 3 means budget-limited pending tasks remain; exit 2 is an orchestration
error. Inspect `taskStatuses` even on exit 1: blocked tasks remain blocked.
For the current one-task list expect one source-excluded row and zero runtime
observations. This confirms the scheduler avoids another unproductive API run;
it does not increase executable-instance coverage.

For a larger list, continue the same frozen list:

```bash
python3 "$PHASE209_CLI" api-corpus --manifest "$PHASE209_PARENT/api-tasks.json" --output "$PHASE209_PARENT/api-corpus" --max-tasks 1 --resume > "$PHASE209_PARENT/corpus-resume.log" 2>&1
PHASE209_STATUS=$?
printf 'corpus_resume_status=%s\n' "$PHASE209_STATUS"
```

Use `--retry-blocked` only after resolving a prerequisite without changing the
frozen selectors/verifier. Changed selectors or code require a fresh output.
Check the scheduler receipt independently:

```bash
python3 "$PHASE209_CLI" check --input "$PHASE209_PARENT/api-corpus/progress.json" > "$PHASE209_PARENT/corpus-check.log" 2>&1
PHASE209_STATUS=$?
printf 'corpus_check_status=%s\n' "$PHASE209_STATUS"
```

If an explicit full finite API replay is still needed, omit `--stop-after`.
The default original replay/campaign behavior is unchanged; this may correctly
remain inconclusive for source-excluded instances.

## Files to return

* regression.log
* preflight/preflight.json and preflight.log
* preflight-profile.json
* check-cached.log, check-no-cache.log and their profile JSON files
* api-tasks.json, api-corpus/progress.json, corpus.log and corpus-profile.json
* For any blocked task: the referenced failure.json and original child logs
* For any runtime task: its original result.json and l2-attempts result receipts

No additional binary upload is needed merely to diagnose the already proven
source exclusion. Canonical execution, ABI, accesses and L3 require the actual
corresponding checked evidence before their obligations can be discharged.

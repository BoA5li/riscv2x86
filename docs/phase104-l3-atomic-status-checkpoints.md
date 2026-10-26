# Phase104: atomic mutable status and fail-closed program backend preparation

Base: Phase103 commit `0b9db57a5f07be489d07210fabe884674fc638e5`.
Branch: `phase104-l3-atomic-status-checkpoints`.

## Change and evidence boundaries

Program backend preparation incorrectly used immutable `save()` for recurring
`build-status.json` checkpoints. The second checkpoint failed before calibration;
the exception checkpoint then masked the original failure with another conflict.

`l3_status.write_status_atomic` serializes first, writes a unique file in the same
directory, flushes/fsyncs the file and atomically replaces the diagnostic JSON.
It retains the old status on serialization/write/replace failure. It is a
single-owner fresh-run-directory contract, not a concurrent writer or power-loss
recovery protocol. `record_failure` retains the primary exception, records the
failed stage and reports secondary status failures to stderr.

Program backend binds the new status implementation in its files/digest set.
Preparation checkpoints identify each calibration item and its completed prefix,
validation, publication and final status. Failure never returns success. If backend
publication succeeded but the final checkpoint failed, `backendPublished` identifies
this situation when diagnostics can be written; consumers must still call the full
backend validator. Status files never grant semantic approval.

The program production driver uses the same atomic diagnostic writer. Immutable
command records, calibration evidence, backend publication, output directory
exclusivity, observer/parser, translation contracts, L3 comparison and independent
audit rules remain unchanged. Shared `l3_trace_support.save()` is unchanged.

Existing memory/control backend builders are intentionally unchanged in this
patch. Changing their fingerprinted implementations would invalidate calibrated
backends and require unnecessary rebuilds for this blocker. Their existing mutable
status writers do not have the exclusive-create defect; migrating their non-atomic
writers is a separate compatibility change. The new helper is reusable by future
routes, independent of source names and test inventory.

## Local validation

`test_l3_status.py`: 23 tests, including real atomic file writes and immutable
conflicts, injected serialization/fsync/replace failures, fresh-directory isolation,
full prepare lifecycle with fake external tool boundaries, all six negative
calibration failure positions, primary/secondary failure reporting, backend helper
fingerprint enforcement and program driver error propagation. These orchestration
fixtures are not real calibration or L3 semantic evidence.

Related L3 / automatic batch / validation tests: **520 passed, 19 skipped**.
The skipped tests are the opt-in real control, memory, scalar and program production
tests without selected calibrated backends. The final 23 status tests were also
run separately after adding three final dependency/isolation/initial-error checks;
these counts overlap and must not be added as independent test coverage.

Real source/target QEMU tools are unavailable in the editing environment. Host
calibration and production acceptance below are required before claiming the
program route has passed production acceptance.

## Host validation (Bash, no exit / errexit)

Run each block in order, inspect its result and proceed only when the stated
criteria hold. Preserve Phase103 failed directories. Do not modify old backend
hashes or remove validation checks.

### 1. Update and build

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase104-l3-atomic-status-checkpoints
git switch --track origin/phase104-l3-atomic-status-checkpoints
git rev-parse HEAD

export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
export CLANG10="/usr/lib/llvm-10/bin/clang"
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
export PHASE104_ROOT="$(mktemp -d "$REPO/experiment/results/phase104-XXXXXX")"
hash -r
printf 'PHASE104_ROOT=%s\n' "$PHASE104_ROOT"
cmake --build build > "$PHASE104_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE104_ROOT/build.log"
```

Check branch/SHA against the delivered commit. Build must return 0. Do not discard
local files to switch branches; report any switch conflict instead.

### 2. Focused tests

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_status.py \
  pytools/tests/test_l3_program_regions.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_l3_trace_driver.py \
  --junitxml="$PHASE104_ROOT/focused.xml" \
  > "$PHASE104_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$PHASE104_ROOT/focused.log"
```

Require return 0, no failures/errors/skips in these focused tests.

### 3. Prepare and validate a fresh program backend

```bash
python3 -m riscv2x86_py.l3_program_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$PHASE104_ROOT/program-backend" \
  > "$PHASE104_ROOT/program-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'program_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 100 "$PHASE104_ROOT/program-backend.log"
if [ -f "$PHASE104_ROOT/program-backend/build-status.json" ]; then
  python3 -m json.tool "$PHASE104_ROOT/program-backend/build-status.json"
fi
```

Require return 0, stage/status complete, complete true, semanticApproval false,
six `calibrationCompleted` entries, backendPublished true. Any failure: preserve
logs/status and report them before executing dependent steps. `semanticApproval`
false is expected for tool preparation.

```bash
export RV2X86_L3_PROGRAM_BACKEND="$PHASE104_ROOT/program-backend/backend.json"
python3 - <<'PY'
import os
from riscv2x86_py.l3_program_backend import validate
value = validate(os.environ['RV2X86_L3_PROGRAM_BACKEND'])
print('backend_validated:', value['backendIdentity'])
print('calibration_count:', len(value['calibration']))
PY
VALIDATE_STATUS=$?
printf 'backend_validation_status=%s\n' "$VALIDATE_STATUS"
```

Require return 0 and count 6.

### 4. Real renamed multi-region production

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_program_production.py \
  --junitxml="$PHASE104_ROOT/program-production.xml" \
  > "$PHASE104_ROOT/program-production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'program_production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 120 "$PHASE104_ROOT/program-production.log"
```

Require 2 passed, 0 skipped. Tests cover two/three regions, all L0-L3 layers,
shared whole-program capture and rejection of missing members/raw trace tampering.

### 5. Original018 complete route

```bash
python3 experiment/run_l3_program_trace.py \
  --input "$REPO/experiment/generated-suite/case_018_e8928cf372.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_PROGRAM_BACKEND" \
  --output "$PHASE104_ROOT/original-program" \
  > "$PHASE104_ROOT/original-program.log" 2>&1
PROGRAM_STATUS=$?
printf 'original_program_status=%s\n' "$PROGRAM_STATUS"
python3 - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ['PHASE104_ROOT']) / 'original-program'
p = root / 'run-status.json'
if not p.is_file():
    print('missing:', p)
else:
    d = json.loads(p.read_text())
    for k in ('currentStage','executionComplete','independentResultAuditComplete',
              'productionAcceptanceComplete','blockers','errorType','error'):
        print(k + ':', d.get(k))
    for a in d.get('acceptance', []):
        print('acceptance:', json.dumps(a, ensure_ascii=False))
    for c in d.get('caseDiagnostics', []):
        print('case:', c.get('caseId'), c.get('status'), c.get('reasonCodes'))
        for a in c.get('attempts', []):
            print('translation:', a.get('translationOutcome'))
            print('layers:', [(l.get('level'), l.get('status')) for l in a.get('layers', [])])
PY
```

Require return 0, complete execution/audit/acceptance, no blockers, both fragments
L0-L3 verified, captureGroupCount=1 and programExecutionUnitCount=1. This is a
paired source/target whole-program observation group; it is not one isolated
execution per fragment. Scope remains bounded architectural intent, not physical
cache/prediction/speculation/timing equivalence.

After these pass, proceed with the Phase103 common mechanism selection and targeted
compatibility regression. Do not repeat already-passed control production merely
because a diagnostic writer was fixed. Run the final selected no-skip regression
once the new route and dispatcher integration pass, with all required backends
explicitly selected. Future synchronization/atomic/controlled-environment L3
mechanism expansion remains separate work.

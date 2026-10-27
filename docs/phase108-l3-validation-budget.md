# Phase108: bounded intent production and operation-local backend validation

## Problem and correction

On Phase107 commit `8de1e41f6dfd199cbf034c8c291f517f4df01a14`, five
independent inputs reached emitted translation but stopped at
`l3_intent_production` with `l3.intent.producer-timed-out`. The mechanism selection
loaded correctly outside the producer. A program execution budget of 240 seconds
never changed the producer manifest's default 120 seconds.

The combined producer validates every explicitly selected backend before dispatch.
Previously one fence validation recursively validated the control backend 13 times:
one base check plus two per calibration record. Those validations rechecked the
shared QEMU source preparation, actual tools and calibration. The new implementation
passes the validated base into all six record checks and reconstructs their
commands without hidden recursive validation. No probe, file hash, ordering
obligation or semantic comparison is removed.

Combined selection loading now uses one local validation session for shared QEMU
and control dependencies. Only successful checks are reused; results are copied;
keys bind validator identity and actual manifest content, not path or mtime alone.
The wrapper roots are checked again, followed by **uncached full shared-validator
checks** before the selection returns. Closing results must equal the original
validated results. Selection and backend manifest digests are checked for changes.
No session is persisted or shared with later execution, capture or independent
audit. This is bounded duplicate-work elimination, not a lasting trust cache.

`--l3-producer-timeout-seconds` (integer 1..3600, default 120) is independent of
`--timeout-seconds`. It is recorded in the authenticated producer manifest and
used for both production and receipt replay. The enclosing translation command
gets execution budget + producer budget, so a producer with 600 seconds is not
killed by its enclosing 240-second translation deadline. Actual build/program
execution budgets stay unchanged. Other translation commands keep their budget.

Timeout failures retain the reason code, configured budget, elapsed time, producer
command and bounded stderr tail. The combined producer emits backend phase timing
on stderr. Successful intent transcripts retain that stderr and elapsed time;
evaluation command records retain their actual budget and elapsed time. None of
these diagnostic fields grants semantic approval. Failure remains inconclusive.
The launcher and producer now use one canonical pinned dependency set.

## Compatibility and scope

The QEMU base backend implementation and source preparation are unchanged. Keep
`phase95-92qksg/trace-backend/backend.json` and its files intact. Its current strict
validation must still pass. Control, scalar-program, fence and atomic wrappers pin
changed implementation files and must be freshly prepared with current code.
Never edit old manifests or replace their recorded hashes to suppress stale checks.
Calibration remains 10 control, 6 program, 6 fence and 42 atomic probes. Backend
publication has `semanticApproval: false`; it is not test-case acceptance.

This change does not implement CAS/bitwise RMW, compound mechanisms, concurrency,
physical memory-order measurement or new hardware microarchitecture properties.
It repairs combined-entry validation and budget handling. Host experiments below
are required before claiming the original production failure is resolved.

## Host verification

Run blocks separately; proceed only when the preceding stage passes. Use the
existing `.venv-l2` environment. No block enables errexit or closes the terminal.

### 1. Update, environment and focused tests

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase108-l3-validation-budget
git switch --track origin/phase108-l3-validation-budget
git rev-parse HEAD

export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
hash -r
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PHASE108_ROOT="$(mktemp -d "$REPO/experiment/results/phase108-XXXXXX")"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
printf 'PHASE108_ROOT=%s\n' "$PHASE108_ROOT"

cmake --build build > "$PHASE108_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 30 "$PHASE108_ROOT/build.log"
```

If the branch already exists locally, use `git switch phase108-l3-validation-budget`
and inspect its HEAD. Do not force checkout over local changes.

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_backend_validation.py \
  pytools/tests/test_l3_fence_trace.py \
  pytools/tests/test_l3_atomic_trace.py \
  pytools/tests/test_l3_program_regions.py \
  pytools/tests/test_l3_production_ingress.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  pytools/tests/test_evaluation_runner.py \
  --junitxml="$PHASE108_ROOT/focused.xml" \
  > "$PHASE108_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$PHASE108_ROOT/focused.log"
```

Expected build and test statuses 0, zero failures/errors. Check skip explanations;
these focused tests do not require real-production opt-in backends.

### 2. Reprepare wrappers, retaining the existing QEMU base

Each wrapper writes a fresh child directory. Stop the sequence on any failed
preparation; do not build a selection from incomplete outputs.

```bash
for KIND in control program fence atomic
do
  case "$KIND" in
    control|program)
      BASE_FLAG="--base-backend"
      BASE_PATH="$RV2X86_L3_TRACE_BACKEND"
      ;;
    fence|atomic)
      BASE_FLAG="--control-backend"
      BASE_PATH="$PHASE108_ROOT/control-backend/backend.json"
      ;;
  esac

  python3 -m "riscv2x86_py.l3_${KIND}_backend" \
    "$BASE_FLAG" "$BASE_PATH" \
    --output "$PHASE108_ROOT/$KIND-backend" \
    > "$PHASE108_ROOT/$KIND-backend.log" 2>&1
  PREPARE_STATUS=$?
  printf '%s_backend_status=%s\n' "$KIND" "$PREPARE_STATUS"
  tail -n 20 "$PHASE108_ROOT/$KIND-backend.log"
  if [ "$PREPARE_STATUS" -ne 0 ]; then
    printf 'Preparation stopped; preserve logs and inspect this failure.\n'
    break
  fi
done
```

If a path already exists because a prior attempt failed, keep it and use a fresh
PHASE108_ROOT or different output path. Do not delete evidence to rerun in place.

```bash
python3 - <<'PY_STATUS'
import json, os
from pathlib import Path
root = Path(os.environ['PHASE108_ROOT'])
complete = True
for kind in ('control', 'program', 'fence', 'atomic'):
    path = root / (kind + '-backend/build-status.json')
    if not path.is_file():
        print(kind, 'status missing'); complete = False; continue
    value = json.loads(path.read_text())
    print(kind, {k: value.get(k) for k in ('stage', 'complete', 'semanticApproval', 'error')})
    complete = complete and value.get('complete') is True and (path.parent/'backend.json').is_file()
assert complete, 'Do not continue until all four current wrappers are complete'
PY_STATUS
WRAPPER_STATUS=$?
printf 'wrapper_status=%s\n' "$WRAPPER_STATUS"
```

### 3. Create and time the five-mechanism selection

Only proceed if wrapper_status=0.

```bash
export SELECT_CONFIG="$PHASE108_ROOT/mechanisms.json"
python3 - <<'PY_SELECTION' > "$PHASE108_ROOT/selection.log" 2>&1
import json, os, time
from pathlib import Path
from riscv2x86_py.l3_mechanism_selection import SCHEMA, load
root = Path(os.environ['PHASE108_ROOT'])
backends = {'memory': os.environ['RV2X86_L3_TRACE_BACKEND']}
for name, directory in (('control','control'), ('scalar-program','program'),
                        ('fence','fence'), ('atomic','atomic')):
    backends[name] = str(root/(directory+'-backend/backend.json'))
path = Path(os.environ['SELECT_CONFIG'])
with path.open('x') as stream:
    json.dump({'schemaVersion':SCHEMA,'backends':backends}, stream, indent=2)
started = time.monotonic()
selected = load(path, progress=lambda event: print(json.dumps(event), flush=True))
print('selectionElapsedSeconds:', time.monotonic()-started)
for name, value in selected.items(): print(name, value['backendIdentity'])
PY_SELECTION
SELECTION_STATUS=$?
printf 'selection_status=%s\n' "$SELECTION_STATUS"
tail -n 100 "$PHASE108_ROOT/selection.log"
```

Expected status 0 and all five identities. The measured load time provides a
basis for the explicitly chosen 600-second producer budget below. If validation
alone approaches 600 seconds, preserve timings for analysis rather than repeatedly
raising limits. Cold-cache versus warm-cache measurements are not interchangeable.

### 4. Original030 through the combined entry

```bash
python3 -m riscv2x86_py.automatic_batch_cli \
  --input "$REPO/experiment/generated-suite/case_030_ea26615c60.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --output-directory "$PHASE108_ROOT/combined-030" \
  --jobs 1 --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --l3-mechanism-selections "$SELECT_CONFIG" --require-l3 \
  > "$PHASE108_ROOT/combined-030.log" 2>&1
CASE_STATUS=$?
printf 'combined_030_status=%s\n' "$CASE_STATUS"
tail -n 80 "$PHASE108_ROOT/combined-030.log"

python3 - <<'PY_AUDIT' > "$PHASE108_ROOT/combined-030-audit.log" 2>&1
import json, os
from pathlib import Path
from riscv2x86_py.l3_production_acceptance import audit_evaluation
root = Path(os.environ['PHASE108_ROOT'])/'combined-030'
paths = list(root.glob('cases/*/evaluation-result.json'))
assert len(paths)==1, paths
report = json.loads(paths[0].read_text())
print('status:', report.get('status'))
print('reasonCodes:', report.get('reasonCodes'))
print('requirementStagingFailure:', report.get('requirementStagingFailure'))
for command in report.get('commands', []):
    print('COMMAND_BUDGET:', command.get('phase'), command.get('timeoutSeconds'), command.get('elapsedSeconds'))
for attempt in report.get('attempts', []):
    print('translationOutcome:', attempt.get('translationOutcome'))
    print('LAYERS:', [(x.get('level'), x.get('status')) for x in (attempt.get('validation') or {}).get('layers', [])])
for path in root.rglob('*.l3-intent-production.json'):
    transcript = json.loads(path.read_text())
    print('PRODUCER_EXECUTION:', json.dumps(transcript.get('producerExecution'), ensure_ascii=False))
audit = audit_evaluation(report)
print('AUDIT:', json.dumps(audit, ensure_ascii=False, indent=2))
assert audit['status']=='verified'
PY_AUDIT
AUDIT_STATUS=$?
printf 'combined_030_audit_status=%s\n' "$AUDIT_STATUS"
cat "$PHASE108_ROOT/combined-030-audit.log"
```

Expected both statuses 0, emitted translation, L0-L3 verified and audit verified.
Translation command budget is 840 seconds; actual build/execution stays 240;
producer manifest/transcript records 600. Timings are diagnostics, not semantic
proof. A timeout or missing requirement artifact is a failure of this acceptance.

### 5. Existing-route compatibility, then independent audit

Run only after original030 passes. These are separate programs sharing one
selection, not evidence for compound mechanisms within one program.

```bash
printf 'caseId\texitCode\n' > "$PHASE108_ROOT/compatibility-status.tsv"
for INDEX in 006 000 002 018
do
  for SOURCE in "$REPO"/experiment/generated-suite/case_${INDEX}_*.c
  do
    if [ -f "$SOURCE" ]; then
      CASE_NAME="$(basename "$SOURCE" .c)"
      python3 -m riscv2x86_py.automatic_batch_cli \
        --input "$SOURCE" --frontend "$RISCV2X86_TEST_FRONTEND" \
        --output-directory "$PHASE108_ROOT/$CASE_NAME" \
        --jobs 1 --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
        --l3-mechanism-selections "$SELECT_CONFIG" --require-l3 \
        > "$PHASE108_ROOT/$CASE_NAME.log" 2>&1
      CASE_STATUS=$?
      printf '%s\t%s\n' "$CASE_NAME" "$CASE_STATUS" >> "$PHASE108_ROOT/compatibility-status.tsv"
      printf '%s status=%s\n' "$CASE_NAME" "$CASE_STATUS"
    else
      printf 'missing_source=%s\n' "$SOURCE"
    fi
  done
done

python3 - <<'PY_COMPAT' > "$PHASE108_ROOT/compatibility-audit.log" 2>&1
import json, os
from pathlib import Path
from riscv2x86_py.l3_production_acceptance import audit_evaluation
root = Path(os.environ['PHASE108_ROOT']); failures = []
for index in ('006','000','002','018'):
    paths = list(root.glob('case_'+index+'_*/cases/*/evaluation-result.json'))
    if len(paths)!=1:
        failures.append(index+': report count '+str(len(paths))); continue
    value = json.loads(paths[0].read_text())
    print(index, value.get('status'), value.get('reasonCodes'), flush=True)
    print('requirementStagingFailure:', value.get('requirementStagingFailure'), flush=True)
    for attempt in value.get('attempts', []):
        print('LAYERS:', [(x.get('level'), x.get('status')) for x in (attempt.get('validation') or {}).get('layers', [])], flush=True)
    try:
        audit = audit_evaluation(value)
        print('AUDIT:', audit['status'], flush=True)
        if audit['status']!='verified': failures.append(index+': audit not verified')
    except Exception as exc:
        failures.append(index+': '+type(exc).__name__+': '+str(exc))
print('FAILURES:', failures, flush=True)
assert not failures, failures
PY_COMPAT
COMPAT_STATUS=$?
printf 'compatibility_audit_status=%s\n' "$COMPAT_STATUS"
cat "$PHASE108_ROOT/compatibility-status.tsv"
cat "$PHASE108_ROOT/compatibility-audit.log"
```

Expected four exit codes 0, L0-L3 verified, all independent audits verified and
FAILURES empty. If all pass, combined-entry integration is accepted within its
existing domains. Do not infer all-32-case or all-atomic coverage. Preserve these
artifacts before proceeding to bitwise/CAS or other capability development.

## Development validation

The development environment has native GCC but no usable dual-ISA QEMU/cross-tool
production backend. Related L3, automatic/batch evaluation and validation tests:
**769 passed, 27 skipped** (51.85 seconds); real-production opt-in tests are skipped here, not represented as host
acceptance. New tests cover operation-local reuse, mandatory closing validation,
changed files/results, failed-cache exclusion, per-record fence mutation, the
five-backend dependency graph, actual producer budget wiring, outer deadline,
timeout diagnostics and command budget records. Host stages above remain required.

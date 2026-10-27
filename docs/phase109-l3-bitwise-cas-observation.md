# Phase109: bitwise RMW and attributed target CAS retry regions

## Goal and evidence basis

Build on accepted Phase108 commit `f4fa6a4cb7bd1e2157d641f63065a7737c2df503`.
Phase108 host original030 plus 006/000/002/018 all passed normal L0-L3 and independent
acceptance. That resolves the combined producer budget/duplicate-validation issue;
this stage preserves that design and adds atomic observation capability.

The host GCC7.5/binutils2.30 diagnostic contained 24 real function encodings:
AND/OR/XOR x 32/64 bits x returned/discarded old value, each at O0/O2. Discard uses
LOCK bitwise memory instructions. Returned-old uses CMPXCHG loops: O0 has
SETE/TEST/JE, O2 direct JNE. Diagnostic bytes are retained as decoder test fixtures,
not translation or QEMU evidence. Normal production still uses the existing O0
build contract. O2 forms are decoded/tested; an O2 production matrix is not claimed.

## Implementation

- `l3_atomic_semantics.py`: explicit modular add/and/or/xor/exchange semantics and
  renderer identities. Unknown operations reject; there is no exchange fallback.
- `l3_atomic_spec.py`: retain the proof gate, source/compiler/function scope,
  aligned single-object, RV64 32/64-bit memory, unsigned carriers, two-parameter,
  zero-offset, old-value/discarded-result requirements. Admit the three already
  registered and L2-supported bitwise contracts. Capability is versioned to
  `qemu-attributed-atomic-rmw-v2`.
- `l3_atomic_machine.py`: decode actual source AMO operation/aq/rl/width/registers
  and target LOCK AND/OR/XOR. A CAS-containing function needs the separate proof;
  a decoded CMPXCHG alone is never sufficient evidence for an RMW contract.
- `l3_atomic_retry.py`: bounded typed x86 decoding, ABI parameter and compiler-stack
  value flow, initial same-object load, one CAS and one failure backedge, desired
  value and old-value return projection. Two distinct symbolic old-value epochs
  prove desired is recomputed from the refreshed accumulator after failure.
  Register allocation and input parameter order are not fixed patterns. Low-word
  input spills and modular word projection are explicitly modeled. Unsupported
  memory accesses, helper calls, flags, control, side effects and encodings reject.
- Retry region starts before the loop head, at its initial load, and ends at the
  successful fallthrough. This avoids treating a retry backedge as a fresh plugin
  invocation. The static instruction limit is 256; the observer retains its
  existing 128-PC per-invocation and global 4096 record budgets. Maximum attempts
  are derived from the 128-PC budget (also bounded by 64). Exceeded or incomplete
  captures remain inconclusive; no termination/progress claim follows from samples.
- `l3_atomic_backend.py`: v2 backend, 138 exact required calibration cases: original
  42 + 48 source bitwise width/order/result cases + 12 target direct locked/unlocked
  bitwise cases + 36 target CAS cases. CAS covers both predicate forms, both widths,
  all three operations, immediate success, deliberately forced first failure and
  unlocked negative mechanisms. Exact raw callback vectors are calibrated separately
  for success/failure. A failed CAS may have no callback only if explicitly
  calibrated; no read or write is invented. Successful CAS requires callbacks.
- `l3_atomic_retry_observation.py`: preserve instruction-occurrence memory timeline,
  every retry, and compiler-input-stack reads. The abstract successful RMW count is
  one; raw failed-attempt callbacks are not called successful writes. Failure/success
  labels are attributed from the proved machine branch and actual PC path, not
  runtime register/value callbacks that the API does not provide. Stable address
  binding is proved statically and tied to actual successful object accesses;
  failed values are not claimed as measured.
- Deployment retains unchanged actual translated function bytes and full independent
  rebuild/image comparison. Route replay reconstructs the machine proof, reads raw
  captures/commands, recomputes per-side outcomes and cross-ISA comparison, and
  closes all four synchronization subproperties. Generic production acceptance
  continues to require prior L0-L2, requirements, receipts and invocation bindings.

No case filename selects a route. No prior requirement, approval gate or status
criterion is removed. Compiler stack accesses remain explicit internal evidence;
source/target PC or callback counts are not required to be equal. Comparison is
of the approved abstract operation, bound object footprint and measured outcomes.

## Scope

This implements target CAS loops for source single AMO RMW, not source LR/SC or
source compare-exchange sequence authority. It does not add mixed-mechanism
programs, multiple atomic fragments, arbitrary pointer offsets/qualifiers/types,
helper-based atomics, concurrent linearizability, measured physical memory order,
cache timing, prediction or speculation equivalence. Keep those refusals explicit.

The independent result remains `architectural_intent` with concurrentAtomicityMeasured,
physicalMemoryOrderMeasured and physicalMicroarchitectureClaimed false. Calibration
forced failure is a calibration program, not measured contention in the production
input. Boundary samples do not prove all-input equivalence.

## Host validation

Execute blocks sequentially and preserve failed outputs. No block enables errexit
or closes the terminal. Keep Phase108 wrappers/base and result directories intact.
Only the atomic wrapper must be newly prepared: its pinned code/capability changed.
Memory/control/program/fence implementations are unchanged and their current
validation still applies. Do not edit old hashes or reuse old atomic manifests.

### 1. Update and targeted regression

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase109-l3-bitwise-cas-observation
git switch --track origin/phase109-l3-bitwise-cas-observation
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
export PHASE108_ROOT="$REPO/experiment/results/phase108-VWL1Ko"
export PHASE109_ROOT="$(mktemp -d "$REPO/experiment/results/phase109-XXXXXX")"
printf 'PHASE109_ROOT=%s\n' "$PHASE109_ROOT"

cmake --build build > "$PHASE109_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 30 "$PHASE109_ROOT/build.log"
```

If the branch already exists locally, switch without --track and inspect HEAD.
Never force checkout over local work. After build_status=0:

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_atomic_retry.py \
  pytools/tests/test_l3_atomic_trace.py \
  pytools/tests/test_l3_atomic_eligibility.py \
  pytools/tests/test_l2_atomic_production.py \
  pytools/tests/test_atomic_native_observation.py \
  pytools/tests/test_l3_backend_validation.py \
  pytools/tests/test_l3_program_regions.py \
  pytools/tests/test_l3_production_ingress.py \
  --junitxml="$PHASE109_ROOT/focused.xml" \
  > "$PHASE109_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 100 "$PHASE109_ROOT/focused.log"
```

Expected 0, zero failures/errors; inspect any skips. The supplied host GCC7 bytes
and actual native compiler output are both covered. Real QEMU evidence is next.

### 2. Prepare the current atomic backend (138 probes)

```bash
python3 -m riscv2x86_py.l3_atomic_backend \
  --control-backend "$PHASE108_ROOT/control-backend/backend.json" \
  --output "$PHASE109_ROOT/atomic-backend" \
  > "$PHASE109_ROOT/atomic-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'atomic_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 100 "$PHASE109_ROOT/atomic-backend.log"

python3 - <<'PY_BACKEND'
import json, os
from pathlib import Path
from riscv2x86_py.l3_atomic_backend import CASES
root = Path(os.environ['PHASE109_ROOT'])/'atomic-backend'
status = json.loads((root/'build-status.json').read_text())
for key in ('stage','complete','semanticApproval','calibrationCurrent','error'):
    print(key+':',status.get(key))
print('calibrationCompleted:',len(status.get('calibrationCompleted',[])))
print('requiredCalibrationCount:',len(CASES))
if status.get('complete') is True:
    backend=json.loads((root/'backend.json').read_text())
    print('schemaVersion:',backend['schemaVersion'])
    print('backendIdentity:',backend['backendIdentity'])
    shapes=[{'case':r['case'],'callbacks':r['callbackAccessByOutcome']}
            for r in backend['calibration'] if 'callbackAccessByOutcome' in r]
    print('CAS_CALIBRATION:',json.dumps(shapes,ensure_ascii=False,indent=2))
assert status.get('complete') is True and len(status['calibrationCompleted'])==len(CASES)
PY_BACKEND
CALIBRATION_STATUS=$?
printf 'calibration_status=%s\n' "$CALIBRATION_STATUS"
```

Expected both statuses 0, 138 completed, v2 schema and semanticApproval false.
This stage can take considerable time because all contexts are independently
checked. Do not start it again in the same output directory. On failure report
calibrationCurrent, error and the log; do not remove a failed case to publish.

### 3. Clean combined-entry bitwise production

Use fresh inputs and fresh outputs. These clean runs are separate from pytest
production tests, which intentionally mutate evidence to test audit rejection.

```bash
export RV2X86_L3_ATOMIC_BACKEND="$PHASE109_ROOT/atomic-backend/backend.json"
export SELECT_CONFIG="$PHASE109_ROOT/mechanisms.json"
python3 - <<'PY_INPUTS' > "$PHASE109_ROOT/selection.log" 2>&1
import json,os,time
from pathlib import Path
from riscv2x86_py.l3_mechanism_selection import load
root=Path(os.environ['PHASE109_ROOT']);previous=Path(os.environ['PHASE108_ROOT'])/'mechanisms.json'
selection=json.loads(previous.read_text())
selection['backends']={k:str((Path(v) if Path(v).is_absolute() else previous.parent/v).resolve())
                       for k,v in selection['backends'].items()}
selection['backends']['atomic']=os.environ['RV2X86_L3_ATOMIC_BACKEND']
with Path(os.environ['SELECT_CONFIG']).open('x') as stream:json.dump(selection,stream,indent=2)
started=time.monotonic()
for name,value in load(os.environ['SELECT_CONFIG'],progress=lambda e:print(json.dumps(e),flush=True)).items():
    print(name,value['backendIdentity'])
print('selectionElapsedSeconds:',time.monotonic()-started)
inputs=root/'inputs';inputs.mkdir()
for name,operation,width,order,discard in (
    ('alpha','amoand',64,'',False),('beta','amoor',32,'.aqrl',False),
    ('gamma','amoxor',32,'.rl',True)):
    instruction=operation+('.d' if width==64 else '.w')+order
    body=('__asm__ volatile("'+instruction+' zero,%1,%0": "+A"(*address):"r"(value):"memory");') if discard else (
        'uint64_t old;__asm__ volatile("'+instruction+' %0,%2,%1":"=r"(old),"+A"(*address):"r"(value):"memory");return old;')
    (inputs/(name+'.c')).write_text('#include <stdint.h>\n'+('void' if discard else 'uint64_t')+' '+name+'(uint'+str(width)+'_t *address,uint64_t value){'+body+'}\n')
PY_INPUTS
SELECTION_STATUS=$?
printf 'selection_status=%s\n' "$SELECTION_STATUS"
tail -n 80 "$PHASE109_ROOT/selection.log"
```

Only after selection_status=0, run three original RISC-V inputs through the normal
translator and combined entry. Unsupported encodings are an incomplete acceptance,
not permission to rewrite the input or manually supply target assembly.

```bash
printf 'caseId\texitCode\n' > "$PHASE109_ROOT/bitwise-status.tsv"
for NAME in alpha beta gamma
do
  python3 -m riscv2x86_py.automatic_batch_cli \
    --input "$PHASE109_ROOT/inputs/$NAME.c" \
    --frontend "$RISCV2X86_TEST_FRONTEND" \
    --output-directory "$PHASE109_ROOT/clean-$NAME" \
    --jobs 1 --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
    --l3-mechanism-selections "$SELECT_CONFIG" --require-l3 \
    > "$PHASE109_ROOT/clean-$NAME.log" 2>&1
  CASE_STATUS=$?
  printf '%s\t%s\n' "$NAME" "$CASE_STATUS" >> "$PHASE109_ROOT/bitwise-status.tsv"
  printf '%s status=%s\n' "$NAME" "$CASE_STATUS"
done

python3 - <<'PY_AUDIT' > "$PHASE109_ROOT/bitwise-audit.log" 2>&1
import json,os
from pathlib import Path
from riscv2x86_py.l3_production_acceptance import audit_evaluation
root=Path(os.environ['PHASE109_ROOT']);failures=[]
for name in ('alpha','beta','gamma'):
    paths=list((root/('clean-'+name)).glob('cases/*/evaluation-result.json'))
    print('\nCASE:',name,'reportCount:',len(paths),flush=True)
    if len(paths)!=1:failures.append(name+': missing/duplicate report');continue
    report=json.loads(paths[0].read_text())
    print('status:',report.get('status'),'reasonCodes:',report.get('reasonCodes'))
    print('requirementStagingFailure:',report.get('requirementStagingFailure'))
    for attempt in report.get('attempts',[]):
        print('translationOutcome:',attempt.get('translationOutcome'))
        for layer in (attempt.get('validation') or {}).get('layers',[]):
            print('LAYER:',layer.get('level'),layer.get('status'))
            if layer.get('level')=='L3' and layer.get('status')=='verified':
                detail=layer['detail'];detail=json.loads(detail) if isinstance(detail,str) else detail
                if 'providerDetail' in detail:detail=json.loads(detail['providerDetail'])
                for side,value in detail['platformReports'].items():
                    print('MECHANISM:',side,value['mechanism']['instruction'])
                    print('FIRST_EVENT:',json.dumps(value['atomicEvents'][0],ensure_ascii=False))
            elif layer.get('status')!='verified':print('DETAIL:',layer.get('detail'))
    try:
        audit=audit_evaluation(report);print('AUDIT:',audit['status'],flush=True)
        if audit['status']!='verified':failures.append(name+': audit not verified')
    except Exception as exc:failures.append(name+': '+type(exc).__name__+': '+str(exc))
print('FAILURES:',failures,flush=True)
assert not failures,failures
PY_AUDIT
AUDIT_STATUS=$?
printf 'bitwise_audit_status=%s\n' "$AUDIT_STATUS"
cat "$PHASE109_ROOT/bitwise-status.tsv"
cat "$PHASE109_ROOT/bitwise-audit.log"
```

Expected all exit codes and audit status 0, emitted, L0-L3 verified, no failures.
alpha/beta target should be proved locked CAS loops, gamma a direct LOCK XOR.
Each completed sample has one abstract successful RMW. Preserve actual retry
counts/callbacks; do not require production contention or force fake failures.

### 4. Existing-route compatibility

Use this same selection for five representative existing inputs and fresh outputs:

```bash
printf 'caseId\texitCode\n' > "$PHASE109_ROOT/compatibility-status.tsv"
for INDEX in 030 006 000 002 018
do
  for SOURCE in "$REPO"/experiment/generated-suite/case_${INDEX}_*.c
  do
    if [ -f "$SOURCE" ]; then
      CASE_NAME="$(basename "$SOURCE" .c)"
      python3 -m riscv2x86_py.automatic_batch_cli \
        --input "$SOURCE" --frontend "$RISCV2X86_TEST_FRONTEND" \
        --output-directory "$PHASE109_ROOT/compat-$CASE_NAME" \
        --jobs 1 --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
        --l3-mechanism-selections "$SELECT_CONFIG" --require-l3 \
        > "$PHASE109_ROOT/compat-$CASE_NAME.log" 2>&1
      CASE_STATUS=$?
      printf '%s\t%s\n' "$CASE_NAME" "$CASE_STATUS" >> "$PHASE109_ROOT/compatibility-status.tsv"
      printf '%s status=%s\n' "$CASE_NAME" "$CASE_STATUS"
    else
      printf 'missing_source=%s\n' "$SOURCE"
    fi
  done
done

python3 - <<'PY_COMPAT' > "$PHASE109_ROOT/compatibility-audit.log" 2>&1
import json,os
from pathlib import Path
from riscv2x86_py.l3_production_acceptance import audit_evaluation
root=Path(os.environ['PHASE109_ROOT']);failures=[]
for index in ('030','006','000','002','018'):
    paths=list(root.glob('compat-case_'+index+'_*/cases/*/evaluation-result.json'))
    if len(paths)!=1:failures.append(index+': report count '+str(len(paths)));continue
    report=json.loads(paths[0].read_text())
    print(index,report.get('status'),report.get('reasonCodes'),flush=True)
    print('requirementStagingFailure:',report.get('requirementStagingFailure'),flush=True)
    for attempt in report.get('attempts',[]):
        print('LAYERS:',[(r.get('level'),r.get('status')) for r in (attempt.get('validation') or {}).get('layers',[])],flush=True)
    try:
        value=audit_evaluation(report);print('AUDIT:',value['status'],flush=True)
        if value['status']!='verified':failures.append(index+': audit not verified')
    except Exception as exc:failures.append(index+': '+type(exc).__name__+': '+str(exc))
print('FAILURES:',failures,flush=True)
assert not failures,failures
PY_COMPAT
COMPAT_STATUS=$?
printf 'compatibility_audit_status=%s\n' "$COMPAT_STATUS"
cat "$PHASE109_ROOT/compatibility-status.tsv"
cat "$PHASE109_ROOT/compatibility-audit.log"
```

Expected five exit codes 0, L0-L3 and independent acceptance verified, FAILURES
empty. Reuse no prior reports as current acceptance evidence.

### 5. Real production matrix (once)

After clean combined runs pass, execute the expanded matrix once. It includes the
six unchanged baseline nodes and twelve bitwise width/order/result nodes. This is
not the full Cartesian product; static/decode and calibration matrices cover the
other declared combinations. Read zero skips as a requirement here.

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_atomic_production.py \
  --junitxml="$PHASE109_ROOT/atomic-production.xml" \
  > "$PHASE109_ROOT/atomic-production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'atomic_production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 120 "$PHASE109_ROOT/atomic-production.log"
```

Expected 18 passed, zero skips/errors/failures, status 0. These tests deliberately
append/tamper evidence after successful audits to check rejection; use the clean
runs for later independent re-auditing, not these intentionally altered artifacts.
No repeated full 32-case or all-route regression is needed before any failed
stage has been diagnosed. After acceptance, next capability stages are source
LR/SC sequence authority and compound-program mechanisms, not dropping refusals.

## Development evidence

**1191 related tests passed, 39 real-production opt-in tests skipped** in 94.70 seconds.
The 39 skips include the expanded 18-case atomic production matrix; no host dual-ISA
acceptance is inferred from them. Uploaded GCC7 O0/O2 encodings are test fixtures only. Development has native GCC
but no real RISC-V/QEMU backend. Actual native compiled functions exercise widths,
returned/discarded results, parameter permutations, guards and word extension;
58 native calibration programs execute, including forced initial CAS failures.
All 138 lifecycle failure positions and rehashed failed-attempt erasure are tested
with clearly labeled external-tool fixtures. Production tests remain opt-in and
must be run on the host before claiming real dual-ISA acceptance.

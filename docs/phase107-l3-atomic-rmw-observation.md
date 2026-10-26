# Phase107: direct atomic RMW L3 observation

## Delivered scope

The new normal-production route observes real RV64 AMO and x86 direct RMW
mechanisms, actual invocation outcomes and object-relative raw callbacks, then
independently rebuilds and audits their evidence. It is selected by typed proof
and compiler authority, never a filename, case number or mnemonic text match.

This is stage C's first production domain, not complete atomic or whole-corpus
coverage. It supports fetch-add/exchange, 32/64-bit memory on RV64, unsigned
32/64-bit carriers, old-value return or discarded result, and relaxed/acquire/
release/acq_rel obligations. The function has two parameters (object pointer and
integer value), a compiler-proven standalone operation scope, one bound object,
zero object offset, sufficient alignment, and no other source effects. The
observed machine function must be straight-line with exactly one supported RMW.

Source AMOADD/AMOSWAP and target LOCK XADD, memory XCHG and result-discarding
LOCK ADD are decoded from actual ELF bytes. An unlocked XADD/ADD is a recognized
weakened mechanism. Returning bitwise operations lowered to CAS loops, LR/SC,
compare-exchange, helper calls, signed carriers, sequential-consistency claims,
compound effects and unsupported function shapes remain explicit capability
limits. No necessary synchronization obligation is erased on refusal.

The original 030 source is a 64-bit relaxed old-value fetch-add with complete
canonical facts and authority. Its saved objdump commands failed because old
Binutils does not support --disassemble=NAME. No translator fix is inferred from
that diagnostic failure. This route reads ELF bytes directly; it neither needs
that option nor assumes the actual compiler emits a preselected byte sequence.
Unknown actual encodings reject the route with a diagnostic and saved artifacts.

## Implementation and evidence

- `l3_atomic_spec.py`: replay existing atomic facts, authority and compiler scope;
  bind pointer/value/return roles; define Cartesian boundary-value samples and
  the real invocation harness. Allocate at least the authority's object extent
  and compare the entire allocated object including guards.
- `l3_atomic_machine.py`: bounded binary decoding and unique direct instruction
  attribution. Calls, branches, retry loops and unknown encodings reject.
- `l3_atomic_deployment.py`: compile unchanged source and approved builtin target;
  require L0/object/linked function bytes to agree. Locate actual atomic PC and
  its completion boundary within decoded functions. No source rewriting, forced
  inline-asm replacement, APP-marker assumption, or optimization change is used.
- `l3_atomic_backend.py`: immutable wrapper over the unchanged calibrated control
  PC/memory backend. Forty-two separate probes cover source operation x width x
  aq/rl order x return/discard, target direct mechanisms and unlocked negative
  mechanisms. Probes also check known old/new outcomes through process status.
  Every manifest validation replays calibration source, command, binary identity,
  decoded instruction/roles, raw trace, data address and callback shape.
- `l3_atomic_compare.py`: preserve raw callback kinds. Do not expand a store-only
  atomic callback into fabricated read/write records. Calibrated callback shape,
  actual PC, object base, offset, width, actual initializer/input, returned value,
  updated object and guard cells each participate in comparison.
- `l3_atomic_route.py`: close external obligations and bind current receipts,
  artifacts, prior evidence and execution context. Independently rebuild and
  recompute reports, comparison, property closure and reported status.
- `l3_atomic_intent.py`, normal CLI, mechanism selection, runtime registry and
  production acceptance integrate the route without bypassing L0-L2.
- `experiment/run_l3_atomic_trace.py`: normal production followed by independent
  audit; preserve the actual failing stage and child log when prerequisites fail.

The four synchronization subproperties remain separate: compiler contract,
executed atomic mechanism, actual atomic outcome, and ordering refinement.
Atomicity/order guarantees are supplied by approved contracts plus attributed
ISA mechanisms, not inferred from an absence of races in single-thread samples.
Hardware concurrency, physical ordering, timing, cache, prediction and speculation
are not measured. Boundary samples are not an exhaustive input-space proof.

Original memory/control/program/fence implementations and their backend/plugin
files remain unchanged. Old backends may be reused only if normal validation
passes. Do not edit their hashes. Updated producer dependencies require fresh
translation/observation receipts for the new runs.

## Host verification

Use the published Phase107 branch in the delivery message. All dependent stages
require the previous stage to succeed. Commands preserve failures and do not use
set -e, exit, forced checkout, destructive cleanup or evidence-hash rewriting.

### 1. Build and targeted tests

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
export CLANG10="/usr/lib/llvm-10/bin/clang"
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PHASE107_ROOT="$(mktemp -d "$REPO/experiment/results/phase107-XXXXXX")"
hash -r
printf 'PHASE107_ROOT=%s\n' "$PHASE107_ROOT"
git rev-parse HEAD
clang --version
cmake --build build > "$PHASE107_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE107_ROOT/build.log"
```

After status 0:

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_atomic_trace.py \
  pytools/tests/test_l3_program_regions.py \
  --junitxml="$PHASE107_ROOT/focused.xml" \
  > "$PHASE107_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$PHASE107_ROOT/focused.log"
```

Expected status 0, no failures/errors/skips. These checks include real native
builtin compilation and execution, real native calibration programs, synthetic
external-tool lifecycle/failure fixtures, strict sample parsing and independent
result-audit consumer mutations. Synthetic fixtures do not constitute QEMU proof.

### 2. Real dual-ISA calibration

```bash
python3 -m riscv2x86_py.l3_atomic_backend \
  --control-backend "$REPO/experiment/results/phase102-6NllZl/control-backend/backend.json" \
  --output "$PHASE107_ROOT/atomic-backend" \
  > "$PHASE107_ROOT/atomic-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'atomic_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 100 "$PHASE107_ROOT/atomic-backend.log"
python3 - <<'PY_STATUS'
import json, os
from pathlib import Path
p = Path(os.environ['PHASE107_ROOT']) / 'atomic-backend/build-status.json'
if p.is_file():
    d = json.loads(p.read_text())
    print({k: d.get(k) for k in ('stage', 'complete', 'semanticApproval',
                                'calibrationCurrent', 'error')})
    print('calibrationCompleted:', len(d.get('calibrationCompleted', [])))
else:
    print('build-status.json missing; inspect atomic-backend.log')
PY_STATUS
```

Expected: backend status 0, complete true, 42 completed probes, semanticApproval
false. Negative probes execute successfully but are not semantically accepted as
atomic translations. Missing/different raw callback shapes remain blockers; do
not invent callbacks, skip calibration or modify manifests to force acceptance.
Retain the failed probe's build/execute commands, binary and guest-trace.log.

### 3. One real production smoke test

After calibration success:

```bash
export RV2X86_L3_ATOMIC_BACKEND="$PHASE107_ROOT/atomic-backend/backend.json"
python3 -m pytest -vv -rs \
  'pytools/tests/test_l3_atomic_production.py::test_real_direct_atomic_renamed_production[64-fetch_add-relaxed-False]' \
  --junitxml="$PHASE107_ROOT/production-smoke.xml" \
  > "$PHASE107_ROOT/production-smoke.log" 2>&1
SMOKE_STATUS=$?
printf 'atomic_smoke_status=%s\n' "$SMOKE_STATUS"
tail -n 120 "$PHASE107_ROOT/production-smoke.log"
```

Expected: one passed, no skips, status 0. This uses unrelated names, the actual
frontend and builtin output, L0-L3, generic acceptance and negative evidence
checks. Fault injection modifies only that test's own temporary evidence; use
the separate original-030 run below as clean retained acceptance evidence.

### 4. Original 030 full chain

```bash
python3 experiment/run_l3_atomic_trace.py \
  --input "$REPO/experiment/generated-suite/case_030_ea26615c60.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_ATOMIC_BACKEND" \
  --output "$PHASE107_ROOT/original-030" \
  > "$PHASE107_ROOT/original-030.log" 2>&1
CASE_STATUS=$?
printf 'case_030_status=%s\n' "$CASE_STATUS"
python3 - <<'PY_RESULT'
import json, os
from pathlib import Path
p = Path(os.environ['PHASE107_ROOT']) / 'original-030/run-status.json'
if p.is_file():
    d = json.loads(p.read_text())
    print({k: d.get(k) for k in ('currentStage', 'executionComplete',
          'independentResultAuditComplete', 'productionAcceptanceComplete', 'blockers')})
    for c in d.get('caseDiagnostics', []):
        print('CASE:', c.get('caseId'), c.get('status'), c.get('reasonCodes'))
        for a in c.get('attempts', []):
            print('LAYERS:', [(l['level'], l['status']) for l in a.get('layers', [])])
            for l in a.get('layers', []):
                if l.get('status') != 'verified':
                    print('DETAIL:', l.get('detail'))
    for a in d.get('acceptance', []):
        print('AUDIT:', a.get('status'), a.get('comparison'))
else:
    print('run-status.json missing; inspect original-030.log')
PY_RESULT
```

Expected: case status 0, complete stage, L0-L3 verified, execution/independent
result audit/production acceptance true, empty blockers. All four synchronization
subproperties must be verified, with concurrentAtomicityMeasured and
physicalMemoryOrderMeasured false. Failure requires analysis of its preserved
stage; it does not justify removing an obligation or weakening a prerequisite.

### 5. Remaining production matrix

After smoke and original acceptance pass, run the five remaining cases without
repeating the successful smoke node:

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_atomic_production.py \
  --deselect='pytools/tests/test_l3_atomic_production.py::test_real_direct_atomic_renamed_production[64-fetch_add-relaxed-False]' \
  --junitxml="$PHASE107_ROOT/production-remaining.xml" \
  > "$PHASE107_ROOT/production-remaining.log" 2>&1
MATRIX_STATUS=$?
printf 'atomic_matrix_status=%s\n' "$MATRIX_STATUS"
tail -n 120 "$PHASE107_ROOT/production-remaining.log"
```

Expected: five passed, one deselected, zero skips, status 0. The full matrix
covers widths, add/exchange, ordering variants, word result extension and result
discard. It does not validate CAS-loop/bitwise or concurrency capability.

### 6. Combined dispatch and prior-route compatibility

Create a fresh mechanism selection by resolving the old paths to absolute paths
and adding the calibrated atomic backend. Include the already validated fence
wrapper; leave previous selection files intact.

```bash
python3 - <<'PY_SELECTION'
import json, os
from pathlib import Path
repo = Path(os.environ['REPO']); root = Path(os.environ['PHASE107_ROOT'])
p = repo / 'experiment/results/phase104-UqpwRG/selection-VCKufX/mechanisms.json'
v = json.loads(p.read_text())
v['backends'] = {k: str((Path(x) if Path(x).is_absolute() else p.parent/x).resolve())
                 for k, x in v['backends'].items()}
v['backends']['fence'] = str(repo / 'experiment/results/phase106-dzfDWh/fence-backend/backend.json')
v['backends']['atomic'] = os.environ['RV2X86_L3_ATOMIC_BACKEND']
out = root / 'mechanisms.json'
with out.open('x') as f:
    json.dump(v, f, indent=2)
from riscv2x86_py.l3_mechanism_selection import load
for name, b in load(out).items():
    print(name, b['backendIdentity'])
PY_SELECTION
SELECTION_STATUS=$?
printf 'selection_status=%s\n' "$SELECTION_STATUS"
```

If selection status is 0:

```bash
python3 -m riscv2x86_py.automatic_batch_cli \
  --input "$REPO/experiment/generated-suite/case_030_ea26615c60.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --output-directory "$PHASE107_ROOT/combined-030" \
  --jobs 1 --timeout-seconds 240 \
  --l3-mechanism-selections "$PHASE107_ROOT/mechanisms.json" \
  --require-l3 > "$PHASE107_ROOT/combined-030.log" 2>&1
COMBINED_STATUS=$?
printf 'combined_status=%s\n' "$COMBINED_STATUS"
tail -n 80 "$PHASE107_ROOT/combined-030.log"
python3 - <<'PY_AUDIT'
import json, os
from pathlib import Path
from riscv2x86_py.l3_production_acceptance import audit_evaluation
root = Path(os.environ['PHASE107_ROOT']) / 'combined-030'
reports = list(root.glob('cases/*/evaluation-result.json'))
assert len(reports) == 1, reports
print(json.dumps(audit_evaluation(json.loads(reports[0].read_text())), indent=2))
PY_AUDIT
AUDIT_STATUS=$?
printf 'combined_audit_status=%s\n' "$AUDIT_STATUS"
```

Expected both statuses 0 and independent acceptance verified. Then check 006 and
representative prior 000/002/018 routes with this same selection and separate
fresh output directories before scheduling an expensive corpus or no-skip
regression. The regression driver now includes atomic production tests: export
RV2X86_L3_ATOMIC_BACKEND when requesting a no-skip run. No exhaustive corpus
acceptance or unsupported atomic property is claimed by this commit.

## Development checks recorded

Related L3, batch/configuration/regression-runner, existing atomic authority and
fence tests: **778 passed, 27 skipped**. The 27 skips are explicit real-production
backend opt-ins, including six new atomic production cases. Native GCC builtin
and standalone calibration programs execute in the development container; no
real RISC-V/QEMU calibration or original 030 acceptance was claimed there.
The targeted two-module command above collects 147 tests. Python source parsing,
shell-example syntax and patch whitespace checks also passed.

After host acceptance, the next extension is independently calibrated bitwise
RMW/CAS-loop attribution, followed by compound mechanism execution. Do not treat
this commit as completion of all atomic or all L3 coverage requirements.

# Phase106: executed fence observation and independent audit

This completes the implementation of stage B's first real fence route. It does
not complete the atomic route (stage C), all synchronization mechanisms, or
whole-corpus L3 coverage. Real dual-ISA production acceptance must be run on the
host; no RISC-V compiler or calibrated QEMU is installed in the development
container.

## Guarantees and limits

The new route is selected by proof obligations and compiler authority, never by
case ID, filename, source text pattern, or an expected output. Its supported
production domain is a compiler-bound, single standalone full ordinary-memory
fence in a `void(void)` function with the already supported L2 function scope.
It rejects missing authority, extra effects, unknown instruction encodings,
multiple fragments, incomplete captures, and unsupported signatures.

It closes three synchronization subproperties separately:

- `sync.compiler-contract`: approved compiler-ordering contract, validated against
  the current proof, compiler snapshot, authority sidecar and replacement.
- `sync.fence-mechanism`: actual ELF bytes and executed region PCs on both ISAs,
  complete region exit, and successful function-call completion.
- `sync.ordering-contract`: explicit source/target ordering refinement, restricted
  to ordinary coherent memory R/W pairs. This is static contract evidence.

The RV64 instruction must be normal `FENCE rw,rw`; the target must be the approved
MFENCE ordinary-R/W mechanism. MFENCE is not equated with global C sequential
consistency. Proof-context read/write anchors are not fabricated dynamic memory
accesses. The observed assembly region must contain no data accesses. Prologue,
epilogue, caller and harness accesses are outside the observation boundary.

Three invocations repeat the same zero-argument input. They establish three
observed successful calls, not three distinct input values or concurrency cases.
No physical cache, timing, speculation, cross-hart publication, or hardware
reordering measurement is claimed.

## Implementation

- `l3_fence_spec.py`: replay obligations, authority and compiler scope; construct
  the completion harness and strict sample protocol.
- `l3_fence_machine.py`: decode actual RV64/x86 region bytes. Partial fences and
  NOPs are recognized negative mechanisms; unknown encodings remain unproved.
- `l3_fence_backend.py`: wrap the immutable control PC/memory observer; add six
  fence-specific probes (full/partial/missing on each ISA). Every probe is
  replayed against its binary, command and raw capture before publication.
- `l3_fence_deployment.py`: label the actual approved compiler assembly without
  adding instructions. Require original object, deployment object and linked
  function bytes to match. Independently rebuild executable load images.
- `l3_fence_compare.py`: compare real event attribution and explicit contracts;
  retain the distinction between measured execution and static ordering evidence.
- `l3_fence_route.py`: bind artifacts, requirements, receipts, prior layers,
  execution context and raw observations; independently replay the result.
- `l3_fence_intent.py`, the normal batch CLI and mechanism selection: expose the
  explicit fence backend and dispatch only complete supported obligations.
- `experiment/run_l3_fence_trace.py`: run normal production plus independent
  result audit. Preserve the child log and its actual stage if no batch report
  is produced. Exit 0 means verified acceptance, 1 an independently audited
  supported counterexample, 2 incomplete or rejected prerequisites.

The old memory/control/program backends and their plugin files are unchanged.
Do not edit their saved hashes. The fence wrapper has its own dependency binding
and calibration records. New code changes invalidate its own manifest normally.
Mutable progress checkpoints use atomic status replacement; evidence files keep
exclusive creation.

## Host validation

Use the Phase106 branch named in the delivery message. Do not reuse an existing
output directory. These commands do not use `set -e` or `exit`; inspect each
stage's status before starting the dependent stage.

### 1. Environment and targeted verification

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export CLANG10="/usr/lib/llvm-10/bin/clang"
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PHASE106_ROOT="$(mktemp -d "$REPO/experiment/results/phase106-XXXXXX")"
hash -r
printf 'PHASE106_ROOT=%s\n' "$PHASE106_ROOT"
git rev-parse HEAD
clang --version
cmake --build build > "$PHASE106_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE106_ROOT/build.log"
```

Continue if build status is 0:

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_fence_trace.py \
  pytools/tests/test_l3_sync_semantics.py \
  pytools/tests/test_l3_program_regions.py \
  pytools/tests/test_l3_production_acceptance.py \
  --junitxml="$PHASE106_ROOT/focused.xml" \
  > "$PHASE106_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$PHASE106_ROOT/focused.log"
```

Expected: status 0. The new fence unit tests include actual native GCC function
byte preservation and completion, six-probe lifecycle/error paths, mechanism
counterexamples, strict sample parsing, independent-audit consumer mutations and
primary-failure diagnostics. Mocked external-tool fixtures exercise lifecycle
only; they do not substitute for the following real production stage.

### 2. Fence-specific calibration

```bash
python3 -m riscv2x86_py.l3_fence_backend \
  --control-backend "$REPO/experiment/results/phase102-6NllZl/control-backend/backend.json" \
  --output "$PHASE106_ROOT/fence-backend" \
  > "$PHASE106_ROOT/fence-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'fence_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 100 "$PHASE106_ROOT/fence-backend.log"
if [ -f "$PHASE106_ROOT/fence-backend/build-status.json" ]; then
  cat "$PHASE106_ROOT/fence-backend/build-status.json"
fi
```

Expected: status 0, complete true, six calibrationCompleted entries,
semanticApproval false. Existing control calibration is also validated. Full,
partial and missing mechanism probes are all observed successfully; observing a
negative probe is not accepting it as a semantically valid fence translation.

If rejected, retain build-status.json and the failing probe build/capture records;
do not rewrite manifests, bypass checks, or rerun into this directory.

### 3. Real production with unrelated names and negative audits

After successful calibration:

```bash
export RV2X86_L3_FENCE_BACKEND="$PHASE106_ROOT/fence-backend/backend.json"
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_fence_production.py \
  --junitxml="$PHASE106_ROOT/fence-production.xml" \
  > "$PHASE106_ROOT/fence-production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'fence_production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 130 "$PHASE106_ROOT/fence-production.log"
```

Expected: two passed, zero skipped, status 0. Both use normal production,
L0-L3 closure, independent acceptance and report/raw-evidence tampering checks.

### 4. Original 006 acceptance

```bash
python3 experiment/run_l3_fence_trace.py \
  --input "$REPO/experiment/generated-suite/case_006_61dfdddddc.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_FENCE_BACKEND" \
  --output "$PHASE106_ROOT/original-006" \
  > "$PHASE106_ROOT/original-006.log" 2>&1
CASE_STATUS=$?
printf 'case_006_status=%s\n' "$CASE_STATUS"
tail -n 100 "$PHASE106_ROOT/original-006.log"
if [ -f "$PHASE106_ROOT/original-006/run-status.json" ]; then
  python3 -m json.tool "$PHASE106_ROOT/original-006/run-status.json"
fi
```

Expected: status 0, executionComplete/independentResultAuditComplete/
productionAcceptanceComplete true, blockers empty, L0-L3 verified. Inspect the
synchronization subproperty results: mechanism execution is observed, whereas
ordering refinement retains its static-contract verification method.

### 5. Combined mechanism selection

Create a new selection without changing the old one:

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
repo = Path(os.environ['REPO'])
root = Path(os.environ['PHASE106_ROOT'])
p = repo / 'experiment/results/phase104-UqpwRG/selection-VCKufX/mechanisms.json'
v = json.loads(p.read_text())
v['backends'] = {k: str((Path(x) if Path(x).is_absolute() else p.parent / x).resolve())
                 for k, x in v['backends'].items()}
v['backends']['fence'] = os.environ['RV2X86_L3_FENCE_BACKEND']
out = root / 'mechanisms.json'
with out.open('x') as f:
    json.dump(v, f, indent=2)
from riscv2x86_py.l3_mechanism_selection import load
for name, backend in load(out).items():
    print(name, backend['backendIdentity'])
PY
SELECTION_STATUS=$?
printf 'selection_status=%s\n' "$SELECTION_STATUS"
```

If status is 0:

```bash
python3 -m riscv2x86_py.automatic_batch_cli \
  --input "$REPO/experiment/generated-suite/case_006_61dfdddddc.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --output-directory "$PHASE106_ROOT/combined-006" \
  --jobs 1 --timeout-seconds 240 \
  --l3-mechanism-selections "$PHASE106_ROOT/mechanisms.json" \
  --require-l3 > "$PHASE106_ROOT/combined-006.log" 2>&1
COMBINED_STATUS=$?
printf 'combined_status=%s\n' "$COMBINED_STATUS"
tail -n 80 "$PHASE106_ROOT/combined-006.log"
python3 - <<'PY_AUDIT'
import json, os
from pathlib import Path
from riscv2x86_py.l3_production_acceptance import audit_evaluation
root = Path(os.environ['PHASE106_ROOT']) / 'combined-006'
reports = list(root.glob('cases/*/evaluation-result.json'))
assert len(reports) == 1, reports
print(json.dumps(audit_evaluation(json.loads(reports[0].read_text())), indent=2))
PY_AUDIT
AUDIT_STATUS=$?
printf 'combined_audit_status=%s\n' "$AUDIT_STATUS"
```

Expected: both statuses 0, L0-L3 verified and independent audit verified. Existing
memory/control/scalar-program compatibility can then be checked on 000/002/018
with this new selection before an expensive corpus run. Keep output directories
fresh; do not interpret selection loading alone as production acceptance.

## Remaining stage C

030 is atomic RMW, not a fence-only operation. It must retain atomic-mechanism,
atomic-outcome, compiler-contract and ordering-contract obligations. This change
must not turn 030 into verified. Next implement actual atomic machine-region
attribution, memory/RMW outcome observation, compiler-generated target-region
binding (including out-of-line helper refusal/handling), positive and weakened
mechanism calibration, and independent audit. Single-thread final values alone
cannot prove atomicity or inter-thread ordering. No broad 32-case success is
claimed by this commit.

## Development validation recorded

- Targeted fence/sync/program/acceptance checks: 120 passed, no skips.
- Broader related L3, batch, configuration and regression-runner checks:
  615 passed, 21 skipped. The skips are opt-in real-production tests without
  calibrated host backends, including the two new fence production tests.
- Existing fence proof/ordering/execution-closure checks: 30 passed.
- Native GCC execution and byte-preservation test passed.
- Real dual-ISA fence calibration and original 006 acceptance remain host checks;
  they have not been reported as successful development-container executions.

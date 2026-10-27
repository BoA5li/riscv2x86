# Phase115: LR/SC target proof and L2 integration

This change follows Phase114 (744e344a38ded356b42284dd3e440b5f78f489a7).
Phase114 closes compiler/source sequence bindings; it does not approve a target.
An approvalArtifact containing boundary/graph/decision fields is not an approved
translation. Only proofStatus=approved and its bound proof establish approval.

## Implemented scope

A dedicated typed target contract enters the existing Phase6B candidate,
Phase6C constraints, Phase6D proof, Phase6E selection and Phase6F renderer gates.
It accepts the byte-owned RV64 LR–ALU–SC–retry domain from Phase114: aligned
32/64-bit objects, ADD/AND/OR/XOR, three distinct 64-bit early-clobber outputs,
explicit address/value inputs, and an exact read/write memory operand. ADDW is
also supported in the 32-bit object domain. GNU operand indexes are not fixed.
The target is a registered locked CMPXCHG retry sequence with a fixed accumulator,
not a C signed-arithmetic expression or a replacement selected by source name.
It computes and preserves old, next, status=0 and the updated memory word.
For LR.W the old register is sign extended. A 64-bit ADD retains its full next
register even when the SC stores only its low 32 bits. ADDW sign extends next.

Symbolic bitvector terms check every input bit pattern on completion, together
with the registered locked-CAS retry invariant: failed CAS updates the expected
word; the next iteration recomputes desired; successful CAS linearizes the RMW.
This is a completion-state refinement. It does not equate retry counts or
reservation histories, prove individual termination, or measure physical order.
Explicit microarchitecture/retry-sensitive requests remain outside the domain.
The normal compiler, operand, shell, capability and selection gates still apply.

L2 has dedicated sequence proof facts. The consumer replays current machine and
compiler evidence, verifies target/effect proof bindings, and builds all six
operand authorities and the bounded memory object. It never fills the single-AMO
source model with invented facts. Corruption does not fall back to scalar/AMO.
The invocation observer compares actual return and object values. next/status
must be compiler-proven dead/discarded for this observer; live additional output
sinks require separate instrumentation and remain inconclusive.

## Remaining work: full L3 is NOT complete

The direct-AMO L3 observer now explicitly rejects a sequence with
L3_LRSC_SOURCE_OBSERVATION_BACKEND_REQUIRED. It must not reinterpret LR/SC as an
AMO event. Next work must implement real LR and SC instruction attribution,
reservation/failure/success path capture, complete retry-path checking,
source/target abstraction comparison, calibration and independent audit.
Until that work is validated, --require-l3 for these inputs must not be reported
as successful. Neither source reference calculations nor L2 native tests are L3
execution evidence. Existing AMO L3 behavior is retained.

## Local validation and limits

The new tests exercise common proof/selection/rendering, source/target replay,
public authority materialization, stale/rehashed authority rejection, missing
capabilities, sensitive intents, output-observation limits and explicit L3
refusal. Native GCC tests run both optimization levels, both widths, four ALU
operations, ADDW and permuted slots; they check all three outputs, memory results
and adjacent-memory sentinels. This development environment has no usable
RISC-V compiler/QEMU/Clang10 production toolchain, so host source execution and
end-to-end L2 acceptance remain required. Validation: 692 related tests passed without skips; after tightening common
constraint invariants, all 59 target-route tests passed again. These counts
do not imply full corpus or L3 coverage.

## Host verification (Bash, keeps terminal open)

Do not delete old evidence or restore tracked build products. This is Python
code, so no C++ rebuild is required for this change.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase115-lrsc-target-proof-l2
git switch --track origin/phase115-lrsc-target-proof-l2
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PATH="/usr/lib/llvm-10/bin:$PATH"
hash -r
export PHASE115_ROOT="$(mktemp -d "$REPO/experiment/results/phase115-XXXXXX")"
printf 'PHASE115_ROOT=%s\n' "$PHASE115_ROOT"
git rev-parse HEAD > "$PHASE115_ROOT/git-head.txt"
python3 -m pytest -q -rs \
  pytools/tests/test_lrsc_target.py \
  pytools/tests/test_lrsc_source.py \
  pytools/tests/test_lrsc_compiler_binding.py \
  pytools/tests/test_lrsc_sequence_contract.py \
  pytools/tests/test_l2_atomic_production.py \
  pytools/tests/test_automatic_l2_authority.py \
  pytools/tests/test_l2_materialization_closure.py \
  --junitxml="$PHASE115_ROOT/focused.xml" \
  > "$PHASE115_ROOT/focused.log" 2>&1
TEST_STATUS=$?
printf 'focused_status=%s\n' "$TEST_STATUS"
tail -n 80 "$PHASE115_ROOT/focused.log"
```

Then test target/L2 through the ordinary production entry. These commands
intentionally request architectural evaluation, without --require-l3 or a
mechanism selection. They do not disable any L0/L1/L2 checks.

```bash
printf 'caseId\texitCode\n' > "$PHASE115_ROOT/exit-status.tsv"
for NAME in lrsc_add_32 lrsc_add_64
do
  SOURCE="$REPO/experiment/results/phase112-yHGqbt/inputs/$NAME.c"
  if [ -f "$SOURCE" ]; then
    python3 -m riscv2x86_py.automatic_batch_cli \
      --input "$SOURCE" --frontend "$RISCV2X86_TEST_FRONTEND" \
      --output-directory "$PHASE115_ROOT/$NAME" \
      --jobs 1 --timeout-seconds 240 \
      > "$PHASE115_ROOT/$NAME.log" 2>&1
    CASE_STATUS=$?
    printf '%s\t%s\n' "$NAME" "$CASE_STATUS" >> "$PHASE115_ROOT/exit-status.tsv"
    printf '%s status=%s\n' "$NAME" "$CASE_STATUS"
  else
    printf 'missing_source=%s\n' "$SOURCE"
  fi
done
python3 experiment/inspect_lrsc_source.py \
  --root "$PHASE115_ROOT" --output "$PHASE115_ROOT/source-target-summary.json" \
  > "$PHASE115_ROOT/source-target-summary.log" 2>&1
python3 experiment/inspect_lrsc_evaluation.py --root "$PHASE115_ROOT" \
  > "$PHASE115_ROOT/evaluation-summary.txt" 2>&1
cat "$PHASE115_ROOT/exit-status.tsv"
cat "$PHASE115_ROOT/evaluation-summary.txt"
```

Expected: translation emitted; proofStatus approved; registered LRSC contract;
six operands; sidecar present; materialization executable; L0/L1/L2 verified.
Do not treat these as observed host results before running them. If any fails,
return evaluation-summary.txt and source-target-summary.json. The collector
includes build failures and L2 preconditions and does not assert/exit the shell.

## Previously calibrated L3 backend manifests

l3_atomic_spec.py and l3_sync_obligations.py changed. Existing atomic backend
manifests bind these file digests, so loading an old manifest must reject it.
Do not edit its hashes. Before AMO L3 regression, build a fresh backend from a
still-valid control backend into a new directory:

```bash
python3 -m riscv2x86_py.l3_atomic_backend \
  --control-backend "$REPO/experiment/results/phase108-VWL1Ko/control-backend/backend.json" \
  --output "$PHASE115_ROOT/atomic-backend" \
  > "$PHASE115_ROOT/atomic-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'atomic_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 80 "$PHASE115_ROOT/atomic-backend.log"
```

Only after successful calibration export RV2X86_L3_ATOMIC_BACKEND to the new
backend.json and run the prior AMO production regression. Copy an existing
mechanism selection to a new file and change only its atomic backend path;
preserve its other paths and schema. This backend refresh preserves existing
AMO coverage; it does not add LR/SC L3 coverage.

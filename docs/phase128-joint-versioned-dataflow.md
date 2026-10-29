# Phase128: single-pointer harness and versioned operand-backed dataflow

Base remote commit: `bfdb8fb6255c7f50e03247723d55aa65425b60f7`.
Branch: `phase128-joint-versioned-dataflow`.

## Changes and scope

1. `l3_joint_observation.harness` emits an integer argument table only when
   integer arguments exist. Pointer-only calls still initialize, invoke and
   observe the actual object and return value; strict warning flags remain.
2. `source_versioned_program` adds a temporal canonical-p-code adapter after
   the existing adapter. Each read names its current definition; COPY captures
   the current value. Each arithmetic result must reach exactly one bound
   output slot before the next arithmetic instruction. Unavailable old values,
   uninitialized reads, mixed widths and unbound operations are rejected.
   New schema version 2 has immutable definition history checked against the
   ordered instructions and complete external input/output coverage. Version 1
   retains its original single-definition contract. This is an operand-backed
   finite dataflow extension, not an arbitrary scratch-register SSA allocator.
3. Existing candidate/constraint/proof/renderer stages consume the authoritative
   versioned program. Version 2 outputs require early-clobber constraints; the
   proof gate rejects their absence. If an old destination is the RHS, rendering
   preserves that value: commutative operations use the destination directly;
   modular subtraction uses negation followed by addition. No input register is
   overwritten, no scratch register or C output is invented, CC is declared.
4. Program evaluation retains partial candidates but does not send them to the
   target compiler if any required member is unsupported, needs_route, failed
   or not_attempted. It returns `evaluation.program-translation-incomplete`,
   retains individual outcomes, and leaves target/L0-L3 acceptance unclaimed.
   KEEP behavior and explicit single-candidate mode are unchanged.
5. Coverage diagnostics recognize unresolved translation members before absent
   target/L3 evidence. Joint L2 failures distinguish source/target build stages
   from execution, retaining the actual exception and non-execution disposition.
6. Pure versioned COMPOSITE regions enter the joint registry only with a
   proof-bound, type-sensitive external-boundary projection contract. Source
   profile multi-operation/internal-value flags are retained; they are not
   relabeled as single operations. The provider observes actual pre/post values
   and replays the complete pure arithmetic definition graph to check final
   outputs. Intermediate values are explicitly **not measured**. No after-asm
   snapshot is labeled as the old overwritten intermediate value. Memory,
   ordering/control, non-pure operations and unavailable versions remain
   rejected. Composite/joint capability declarations and exact dimension
   matching are required. Persistence replays both source and target results.

Version 2 currently admits uniform 32/64-bit register add/sub/and/or/xor, with
all required values available in bound operands at use time. Other operations,
scratch allocation, memory/control and M2-M8 domains are not implicitly approved.
No source-text or test-name matching, suppressed warning, relaxed proof gate,
fabricated observation or physical/concurrent equivalence claim is introduced.

## Validation

New tests use canonical p-code and the real proof/render chain, then real GCC
O0/O2/O3 executables for wraparound, commutative combinations and reversed-RHS
subtraction, both 32/64 bits and direct/COPY-mediated definitions. Rejection
tests cover stale/undefined values, unknown operations, mixed widths, altered
history, boolean schema versions and legacy redefinitions. JSON round-trip
preserves exact program identity. Shared harness tests compile and execute all
1-4 parameter/pointer-position shapes. Partial-program tests retain upstream
outcomes and require absence of target compilation.

Focused regression: **181 passed, 4 skipped** (real Clang AST unavailable).
No real RISC-V compiler/QEMU was available locally. Native executions establish
target behavior of proof-bound renderings, not dual-ISA production acceptance.

Broader regression: **432 passed, 13 skipped, 6 failed**. All six failures were
reproduced unchanged in a detached Phase127 baseline: five obsolete lifted-CFG/
PIC API tests in `test_phase6_pytest.py`, and the functional CSR time fallback
expectation in `test_phase6_rv64_add_contract.py`. They remain outstanding,
are not marked passed or suppressed, and are outside this joint-path patch.

## Host validation (preserve historical results)

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase128-joint-versioned-dataflow
git switch --track origin/phase128-joint-versioned-dataflow
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
hash -r
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase128-XXXXXX")"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
```

### Focused checks

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_joint_harness_call_shapes.py \
  pytools/tests/test_versioned_gpr_program.py \
  pytools/tests/test_versioned_joint_closure.py \
  pytools/tests/test_partial_program_evaluation.py \
  pytools/tests/test_l2_joint_registry.py \
  pytools/tests/test_l3_joint_program.py \
  pytools/tests/test_l3_joint_production_layout.py \
  pytools/tests/test_phase6_add_shift_early_clobber_contract.py \
  pytools/tests/test_evaluation_runner.py \
  pytools/tests/test_l3_coverage_inventory.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  pytools/tests/test_candidate_materialization.py \
  pytools/tests/test_l3_production_acceptance.py \
  --junitxml="$CHECK_ROOT/focused.xml" > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 100 "$CHECK_ROOT/focused.log"
```

With real Clang/native GCC, expected 185 passed, zero failures/errors/skips.
Continue only after passing; retain any failure logs.

### Fresh backend and complete production matrix

The shared harness changed. Prepare a fresh wrapper; do not edit old backend
identities or reuse old evidence as newly approved v2 evidence.

```bash
python3 -m riscv2x86_py.l3_joint_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$CHECK_ROOT/joint-backend" > "$CHECK_ROOT/backend.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 80 "$CHECK_ROOT/backend.log"
if [ -f "$CHECK_ROOT/joint-backend/build-status.json" ]; then
  cat "$CHECK_ROOT/joint-backend/build-status.json"
fi
```

After status 0 and complete preparation (backend semanticApproval=false is
normal; only actual program evidence can establish program acceptance):

```bash
export RV2X86_L3_JOINT_BACKEND="$CHECK_ROOT/joint-backend/backend.json"
export MATRIX_ROOT="$(mktemp -d "$CHECK_ROOT/matrix-XXXXXX")"
printf 'MATRIX_ROOT=%s\n' "$MATRIX_ROOT"
python3 -m pytest -vv -rs pytools/tests/test_l3_joint_production.py \
  --basetemp="$MATRIX_ROOT/pytest" --junitxml="$MATRIX_ROOT/production.xml" \
  > "$MATRIX_ROOT/production.log" 2>&1
MATRIX_STATUS=$?
printf 'matrix_status=%s\n' "$MATRIX_STATUS"
tail -n 140 "$MATRIX_ROOT/production.log"
```

Expected 12 passed without skips. Keep the original source parameterizations,
including repeated assignments and early-clobber; do not simplify them. The
eight operation cases deliberately corrupt temporary negative evidence at the
end, so do not bulk-audit their resulting directories as positive archives.

After a passing matrix, retain a fresh unmodified positive smoke:

```bash
python3 experiment/run_l3_joint_trace.py \
  --input "$REPO/experiment/inputs/l3-joint-load-add-store.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" --backend "$RV2X86_L3_JOINT_BACKEND" \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --output "$CHECK_ROOT/joint-smoke" > "$CHECK_ROOT/smoke.log" 2>&1
SMOKE_STATUS=$?
printf 'smoke_status=%s\n' "$SMOKE_STATUS"
tail -n 20 "$CHECK_ROOT/smoke.log"
```

Expected status 0, all completion flags true, blockers empty. Independently
re-read its evidence with the single-line audit command (no heredoc needed):

```bash
python3 -c 'import json,os,sys;from pathlib import Path;from riscv2x86_py.l3_production_acceptance import audit_evaluation;p,=(Path(os.environ["CHECK_ROOT"])/"joint-smoke").glob("batch/cases/*/evaluation-result.json");r=audit_evaluation(json.loads(p.read_text()));print(json.dumps(r,ensure_ascii=False,indent=2));sys.exit(0 if r["status"]=="verified" else 1)' > "$CHECK_ROOT/audit.log" 2>&1
AUDIT_STATUS=$?
printf 'audit_status=%s\n' "$AUDIT_STATUS"
cat "$CHECK_ROOT/audit.log"
```

After joint acceptance, follow Phase127's ordinary typed load/store compatibility
section using a fresh typed-memory backend/output directory under CHECK_ROOT.
Expected 35 passed. A complete new M0/M1 acceptance requires these host results;
local native tests alone are insufficient. Broader legacy failures above remain
separate tracked work and no claim of a globally green repository is made.

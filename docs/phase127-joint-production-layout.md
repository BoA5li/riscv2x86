# Phase127: joint production input/work isolation

Base: Phase126 `c0800cb5169e24b3844afe5c3944b7cfd994db8e`.
Branch: `phase127-joint-production-layout`.

## Cause and scope

The four declared-call/region production cases wrote `boundary.c` directly
under `tmp_path` and placed production output below the same directory.
For a single-file input, automatic_batch_cli uses the parent as sourceRoot.
The evaluator correctly rejected the nested work directory before translation.
These were orchestration failures, not observed semantic counterexamples.

Use `tmp_path/inputs/boundary.c`, with `tmp_path/production` as its sibling.
Preserve all generated C/asm, compiler flags, parameterizations, assertions,
independent audits and the central evaluator's overlap rejection unchanged.
Do not move or rewrite historical evidence.

`test_l3_joint_production_layout.py` invokes setup of all 12 actual production
test instances and stops at the subprocess boundary. It verifies disjoint
resolved input/work paths without running any compiler or observer. It does
not grant semantic acceptance. Before the fix it reproduced 4 failed/8 passed;
after the fix all 12 passed. Along with evaluation runner, trace driver and
coverage inventory regressions: **48 passed**. Dual-ISA production was not
available locally and remains a required host check.

Related automatic L3 production launch sites (scalar, memory, typed memory,
control, program, fence, atomic, LR/SC, controlled time/system) already place
sources in inputs subdirectories. Direct native helper/compiler unit fixtures
do not invoke this evaluation source-root contract and need no layout change.

## Host acceptance

Run in the existing Python environment. Preserve local build outputs; do not
reset or clean the checkout. This patch changes tests/documentation only, so
the Phase126 frontend and backend need no rebuild or recalibration solely for
this patch. Backend validation remains mandatory during actual runs.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase127-joint-production-layout
git switch --track origin/phase127-joint-production-layout
git rev-parse HEAD

export REPO="$PWD"
export PHASE126_ROOT="$REPO/experiment/results/phase126-9cv0CE"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
export RV2X86_L3_JOINT_BACKEND="$PHASE126_ROOT/joint-backend/backend.json"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
hash -r
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase127-XXXXXX")"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
```

### Fast regressions

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_joint_production_layout.py \
  pytools/tests/test_evaluation_runner.py \
  pytools/tests/test_l3_trace_driver.py \
  pytools/tests/test_l3_coverage_inventory.py \
  --junitxml="$CHECK_ROOT/focused.xml" \
  > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$CHECK_ROOT/focused.log"
```

Expected 48 passed, no skips. Continue only after successful completion.

### Rerun the four blocked cases

```bash
export BOUNDARY_ROOT="$(mktemp -d "$CHECK_ROOT/boundaries-XXXXXX")"
printf 'BOUNDARY_ROOT=%s\n' "$BOUNDARY_ROOT"
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_joint_production.py \
  -k declared_call_and_region_boundaries \
  --basetemp="$BOUNDARY_ROOT/pytest" \
  --junitxml="$BOUNDARY_ROOT/production.xml" \
  > "$BOUNDARY_ROOT/production.log" 2>&1
BOUNDARY_STATUS=$?
printf 'joint_boundary_status=%s\n' "$BOUNDARY_STATUS"
tail -n 140 "$BOUNDARY_ROOT/production.log"
```

Expected 4 passed, 8 deselected, no skips. Each selected case must complete
real L0-L3 and independent acceptance. Deselection is intentional: the other
eight cases already passed in `phase126-9cv0CE/joint-matrix-mZMM00` and their
test bodies and implementation are unchanged. Preserve both runs and their
commit identities; this is not a claim that one new 12-case run was executed.

If any selected case fails, retain its fresh run-status/evaluation records and
production.log. Do not change proof or observation gates to force acceptance.

### Previously pending ordinary load/store compatibility

If this compatibility suite has already passed with current implementation
and calibrated backend, retain that evidence rather than rerunning. Otherwise:

```bash
export COMPAT_ROOT="$(mktemp -d "$CHECK_ROOT/compatibility-XXXXXX")"
printf 'COMPAT_ROOT=%s\n' "$COMPAT_ROOT"
python3 -m riscv2x86_py.l3_memory_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" --include-loads \
  --output "$COMPAT_ROOT/typed-memory-backend" \
  > "$COMPAT_ROOT/backend.log" 2>&1
TYPED_STATUS=$?
printf 'typed_backend_status=%s\n' "$TYPED_STATUS"
tail -n 80 "$COMPAT_ROOT/backend.log"
if [ -f "$COMPAT_ROOT/typed-memory-backend/build-status.json" ]; then
  cat "$COMPAT_ROOT/typed-memory-backend/build-status.json"
fi
```

Only after status 0 and completed preparation:

```bash
export RV2X86_L3_TYPED_LOAD_BACKEND="$COMPAT_ROOT/typed-memory-backend/backend.json"
export RV2X86_L3_TYPED_MEMORY_BACKEND="$RV2X86_L3_TYPED_LOAD_BACKEND"
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_typed_load_production.py \
  pytools/tests/test_l3_typed_store_production.py \
  --junitxml="$COMPAT_ROOT/compatibility.xml" \
  > "$COMPAT_ROOT/compatibility.log" 2>&1
COMPAT_STATUS=$?
printf 'compatibility_status=%s\n' "$COMPAT_STATUS"
tail -n 140 "$COMPAT_ROOT/compatibility.log"
```

Expected 35 passed, no skips. No shell exit or strict-shell declaration is
needed. A Python/pytest nonzero status does not close this interactive shell.

M0/M1 acceptance still requires the retained smoke/audit/ledger and completed
production and compatibility checks. This patch expands no M2-M8 support and
makes no physical microarchitecture or concurrent atomicity claim.

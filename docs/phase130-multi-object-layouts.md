# Phase130: explicit typed object layouts and alias-coherent joint execution

Base remote commit: `513fbb253065573630c11725d13fd677c0b1c7b4`.
Branch: `phase130-m2-m3-memory-contracts`.

## Status — this is not completion of all M2/M3

Implemented in this checkpoint: multiple compiler-bound pointer views in direct
joint programs; explicit per-invocation allocations; separated, same-address
and aligned partially overlapping views of identical unqualified integer types;
actual typed L1/L2/L3 calls and complete object snapshots; cross-view memory-state
continuity; per-layout overlap dependencies; strict actual alias/disjoint address
checks; independent deployment and L2/L3 replay. Ordinary approved rw/rw fences
remain available in these programs.

Still unimplemented: a single asm with multiple memory effects and its complete
source/target proof/renderer; general address/value expression consumption;
other fence contracts and environment-specific L3 routes. Compiler downstream
use enumeration also has a pre-existing limitation for outputs redefined by
later asm: it can misclassify a write-only output as an input consumer. Its
completeness checks are not bypassed here. The new store-then-reload tests use a
separate compiler-bound output declaration; same-declaration redefinition remains
an explicit gap requiring reaching-definition-aware compiler use facts.

The requested overall M2/M3 task remains incomplete. No registry or catalog is
marked fully complete, and host acceptance of this new checkpoint is pending.

## What changed

- `object_layout_contract`: compiler/type/object bindings, actual allocation/view
  layouts, alias-coherent byte reconstruction and projection. Different object
  IDs never imply noalias. The automatic 32-byte object remains a harness input
  contract, not a claim about arbitrary incoming pointers.
- `compiler_joint_scope` v3: multiple pointer parameters, existing direct-acyclic
  grammar and unsigned64 scalar carriers/results. Existing v1/v2 remain separate.
- L1: multiple-pointer wrappers use the same layout construction, observe every
  view and omit absolute addresses from cross-ISA stdout comparison. Old single
  object wrappers/parsers retain their previous protocol. Arbitrary braces in
  legacy stdout are not reinterpreted as the new protocol.
- Joint spec v2: binds all views, proofs and per-layout object dependency graphs.
  Single-pointer specs keep their previous route and schema.
- `l3_multi_object_observation`: real typed allocations and arguments; source/
  target each allocate the declared layouts. Object views sharing an allocation
  really share storage. Boundary replay updates that shared allocation once,
  then projects every view, catching alias-state inconsistencies and writes
  outside the approved interval. Actual sampled addresses must realize exactly
  the declared alias/disjoint relationships.
- Event comparison checks object-relative addresses, widths, directions and all
  final objects. Whole-program fence sequence checks apply to the new route.
- Existing independent audits rebuild fresh specs and plans and reread actual
  command records and traces; version changes are hash-bound. No L3 value is
  synthesized from expected callback values.
- JSON sample decoding rejects duplicate keys and boolean sample indices. Entry
  symbols use a unique GNU asm linkage alias, so legal function names cannot be
  shadowed by local harness names such as allocation0, returned or argc.

Input scope remains 1-4 parameters, 2-16 regions, Linux LP64, valid aligned
ordinary private objects, and listed finite samples. Shared automatic views are
only generated for identical unqualified pointee types. Cross-type character/
integer views, restrict, volatile/atomic objects, arbitrary allocation contracts
and exhaustive alias partitions are not silently approved. Layouts are selected
round-robin over the listed samples; this is not an exhaustive value/layout proof.
Source/target static proofs and runtime evidence retain their distinct scopes.

## Validation scope

Local native fixtures use synthetic compiler/proof records and explicit native
compiler/executor adapters only inside tests. They are not dual-ISA approval.
They compile with normal warning/error flags, run real GCC code, exercise
central L2 registration/persistence/rebuild, check separated/equal/overlap actual
addresses, store-to-alias reload state, and adverse event/object evidence.

Local focused regression: **376 passed, 4 skipped** (real Clang unavailable).
After the additional multi-object fence comparison cases, the final targeted
multi-object run was **39 passed**. These runs overlap and are not added as a
single test count. The six real production cases were collected and skipped
locally because no calibrated real dual-ISA backend was supplied.

Six opt-in real frontend/dual-ISA tests have been added in
`test_l3_multi_object_production.py`. They include 8/16/32/64-bit objects,
signedness, pointer positions, fences, store then alias reload, standalone audit,
and refusal of altered raw traces. The editing environment cannot run them
because the real RISC-V/Clang/QEMU toolchain is not installed.

## Host validation — preserve existing Phase129 results

Run blocks separately. Do not continue dependent stages if a command fails.
Do not reuse output subdirectories. `set +e` keeps failures from closing the
interactive shell; no `exit` command is used below.

### 1. Update, environment and build

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase130-m2-m3-memory-contracts
git switch --track origin/phase130-m2-m3-memory-contracts
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
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase130-XXXXXX")"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
cmake --build build > "$CHECK_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$CHECK_ROOT/build.log"
```

### 2. Focused integration and previous proof/observer regression

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_multi_object_joint.py \
  pytools/tests/test_l3_joint_typed_access.py \
  pytools/tests/test_l3_joint_fence_context.py \
  pytools/tests/test_l3_joint_program.py \
  pytools/tests/test_l2_joint_registry.py \
  pytools/tests/test_l3_coverage_inventory.py \
  pytools/tests/test_joint_harness_call_shapes.py \
  pytools/tests/test_versioned_joint_closure.py \
  pytools/tests/test_l3_fence_trace.py \
  pytools/tests/test_l2_fence_ordering_relations.py \
  pytools/tests/test_phase6_full_memory_fence_contract.py \
  pytools/tests/test_fence_execution_closure.py \
  pytools/tests/test_phase6_direct_memory_contract.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  pytools/tests/test_l2_memory_object_observation.py \
  pytools/tests/test_l2_fragment_execution_authority.py \
  pytools/tests/test_compiler_expression_contracts.py \
  pytools/tests/test_compiler_expression_evaluation.py \
  --junitxml="$CHECK_ROOT/focused.xml" \
  > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 100 "$CHECK_ROOT/focused.log"
```

Expected exit 0; inspect all skips. Real Clang tests must not be declared passed
because a fixture-only test passed. Stop on a failure and retain diagnostics.

### 3. Fresh joint backend

```bash
python3 -m riscv2x86_py.l3_joint_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$CHECK_ROOT/joint-backend" \
  > "$CHECK_ROOT/joint-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 80 "$CHECK_ROOT/joint-backend.log"
cat "$CHECK_ROOT/joint-backend/build-status.json"
export RV2X86_L3_JOINT_BACKEND="$CHECK_ROOT/joint-backend/backend.json"
```

Expected complete true, stage complete, 12 calibration records. A fresh wrapper
is required because implementations are pinned; semanticApproval false remains
correct for backend preparation.

### 4. Ordinary production smoke and standalone independent audit

```bash
python3 experiment/run_l3_joint_trace.py \
  --input "$REPO/experiment/inputs/l3-joint-multi-object-alias.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_JOINT_BACKEND" \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --output "$CHECK_ROOT/multi-smoke" \
  > "$CHECK_ROOT/multi-smoke.log" 2>&1
SMOKE_STATUS=$?
printf 'smoke_status=%s\n' "$SMOKE_STATUS"
tail -n 50 "$CHECK_ROOT/multi-smoke.log"
python3 experiment/inspect_joint_acceptance.py \
  --root "$CHECK_ROOT/multi-smoke" \
  > "$CHECK_ROOT/multi-audit.log" 2>&1
AUDIT_STATUS=$?
printf 'audit_status=%s\n' "$AUDIT_STATUS"
cat "$CHECK_ROOT/multi-audit.log"
```

Expected both statuses 0, five emitted members with L0-L3 verified, all completion
flags true, no blockers, one capture/program execution unit. Each side has eight
samples and 32 events (three memory accesses and one fence per sample). Layouts
include two distinct allocations, identical views and partially overlapping views.

### 5. New real production matrix

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_multi_object_production.py \
  --basetemp="$CHECK_ROOT/multi-pytest" \
  --junitxml="$CHECK_ROOT/multi-production.xml" \
  > "$CHECK_ROOT/multi-production.log" 2>&1
MULTI_STATUS=$?
printf 'multi_status=%s\n' "$MULTI_STATUS"
tail -n 120 "$CHECK_ROOT/multi-production.log"
```

Expected six passed, no failures/errors/skips. Successful tests deliberately
alter some test traces for negative audit assertions. Preserve the separate
ordinary smoke as the clean positive evidence archive.

### 6. Previous joint compatibility matrices

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_joint_context_production.py \
  pytools/tests/test_l3_joint_production.py \
  --basetemp="$CHECK_ROOT/compat-pytest" \
  --junitxml="$CHECK_ROOT/compat-production.xml" \
  > "$CHECK_ROOT/compat-production.log" 2>&1
COMPAT_STATUS=$?
printf 'compat_status=%s\n' "$COMPAT_STATUS"
tail -n 120 "$CHECK_ROOT/compat-production.log"
```

Expected 20 passed, no failures/errors/skips. These real matrices take hours;
redirected logs need not emit progress to the terminal.

### 7. Coverage ledger

```bash
export LEDGER_ROOT="$(mktemp -d "$CHECK_ROOT/ledger-XXXXXX")"
python3 -m riscv2x86_py.l3_coverage_inventory \
  --sources "$REPO/experiment/inputs" \
  --results "$CHECK_ROOT/multi-smoke" \
  --capability joint \
  --output "$LEDGER_ROOT/multi-smoke.json" \
  > "$LEDGER_ROOT/multi-smoke.log" 2>&1
LEDGER_STATUS=$?
printf 'ledger_status=%s\n' "$LEDGER_STATUS"
cat "$LEDGER_ROOT/multi-smoke.log"
```

Expected accepted for this smoke only, unrelated inputs not_run, errors empty.
Aggregate productionAcceptanceComplete stays false while other inputs are not
accepted in that ledger. Do not infer all M2/M3 completion from process exit 0.

## Remaining implementation gates

Next code work: compiler-owned multi-effect memory program, matching candidate/
constraint/proof/renderer, full effect observation and audit; expression-aware
address/value/return contracts; specific ordinary-fence domain refinements;
reaching-definition-aware downstream compiler use facts. Existing single-effect
and direct-declaration gates remain, rather than being disabled.

Before environment-specific fence production can be completed, specify the
actual intended contract: local or multi-hart instruction publication, runtime/
page permissions/completion confirmation, or I/O device/model and MMIO domain.
QEMU user-mode ordinary memory callbacks cannot substitute for device or physical
I-cache evidence. These missing environment facts do not explain away the
remaining unimplemented ordinary-memory code.

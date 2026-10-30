# Phase129: typed joint accesses and ordinary fence context

Base: Phase128 remote commit `9228e113f1a18d9acfaf59f239f50d630fc72cf0`.
Branch: `phase129-m2-m3-program-contracts`.

## Delivery and boundaries

This is **partial M2 and bounded M3**, not completion of all M2/M3 requirements.

- Joint memory regions consume their existing approved width, carrier and value
  projection facts. Reads of 8/16/32 bits require approved sign/zero extension
  to a 64-bit carrier; stores require an approved identity/low-bit relation.
  Bounds, alignment, object binding and exact effect/proof checks remain.
- Compiler joint scope v2 permits one signed/unsigned integer object with
  8/16/32/64-bit elements. Scalar inputs, local carriers and result remain
  unsigned 64-bit direct declarations. Legacy unsigned64-object scope v1 remains.
  The harness uses the compiler pointee width for its actual typed allocation.
- Instrumented L2 checks actual pre/post operands and byte object states for
  every region, including continuity. Width-specific reads, sign extension and
  low-bit stores are checked against the approved relation, not inferred from
  source names. Intermediate L3 register values remain unmeasured.
- An identity-bound object access graph retains each region/effect/authority,
  access interval and write-dependent overlap. Equal compiler object identities
  establish the shared object. Different identities are never assumed disjoint.
- Approved ordinary `fence rw,rw`/`mfence` members can coexist with memory and
  scalar members. Their original proof, ordering relation, compiler context,
  central provider resolution and shell checks remain mandatory.
- L3 executes the original function code. A fence witness requires actual region
  entry and completion callbacks and an exact single-instruction machine-byte
  classification reconstructed from the executable. Callback line positions are
  retained. The memory callback sequence counter/footer still counts memory
  callbacks only; the extra fence witnesses do not alter the raw plugin protocol.
- Each fence compares the entire same-invocation ordered access/fence sequence.
  Independent audit rebuilds the deployment, reclassifies machine bytes and
  rereads raw execution records before reconstructing results for every member.
  Compiler/ordering guarantees come from the approved static contract; no
  physical memory-order or concurrent-atomicity measurement is claimed.
- Fresh joint backend calibration now has **12 records**: each ISA executes
  empty/read/write/skip/fence/nop-fence probes. The NOP is a negative mechanism
  control. Existing prepared backends must not be reused after source changes.
- The coverage catalog explicitly retains partial/pending statuses.

Still not implemented: multiple pointer objects and a proved shared-allocation/
alias-layout contract; multiple memory effects inside one asm; general compiler
address/value expressions; signed scalar carriers and arbitrary outputs; control,
calls or loops in this joint route; other fence domains such as I/O, instruction
visibility or environment-specific observation. These need upstream proof,
invocation, observation, comparison and audit changes together. No claim of
"all M2 complete" follows from passing the tests below.

## Local verification

Native tests use explicit synthetic compiler/proof fixtures and native tool
adapters only inside tests. They check actual GCC executions, central registry
resolution, persistence and adverse evidence. They do not establish dual-ISA
production acceptance. No real RISC-V GCC/QEMU/Clang toolchain is available in
the editing environment. The production matrix is deliberately opt-in.

Focused local regression: **275 passed, 4 skipped** (real Clang AST unavailable).
The eight new real production cases were collected and skipped locally because
no explicitly prepared real joint backend was supplied. They remain pending
host acceptance; this is not recorded as production success.

## Host verification

Run each block separately; preserve the printed root and do not reuse output
subdirectories. `set +e` keeps test failures from closing the shell. No warning
flag, semantic gate or assertion should be removed to obtain a pass.

### 1. Update and build

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase129-m2-m3-program-contracts
git switch --track origin/phase129-m2-m3-program-contracts
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
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase129-XXXXXX")"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
cmake --build build > "$CHECK_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$CHECK_ROOT/build.log"
```

### 2. Focused proof/consumer/native checks

```bash
python3 -m pytest -q -rs \
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
  --junitxml="$CHECK_ROOT/focused.xml" \
  > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$CHECK_ROOT/focused.log"
```

Expected: exit 0; host real Clang tests should execute. Review every skip.
Do not proceed on a failure; retain the log and JUnit report.

### 3. Fresh backend

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

Expected: stage complete, complete true, 12 calibrationCompleted entries;
semanticApproval false is intentional. Calibration is not program acceptance.
Only continue when preparation succeeds.

### 4. Normal joint fence smoke and fresh independent audit

```bash
python3 experiment/run_l3_joint_trace.py \
  --input "$REPO/experiment/inputs/l3-joint-load-fence-add-store.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_JOINT_BACKEND" \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --output "$CHECK_ROOT/fenced-smoke" \
  > "$CHECK_ROOT/fenced-smoke.log" 2>&1
SMOKE_STATUS=$?
printf 'smoke_status=%s\n' "$SMOKE_STATUS"
tail -n 40 "$CHECK_ROOT/fenced-smoke.log"
python3 experiment/inspect_joint_acceptance.py \
  --root "$CHECK_ROOT/fenced-smoke" \
  > "$CHECK_ROOT/fenced-audit.log" 2>&1
AUDIT_STATUS=$?
printf 'audit_status=%s\n' "$AUDIT_STATUS"
cat "$CHECK_ROOT/fenced-audit.log"
```

Expected: both statuses 0, all completion flags true, no blockers, four emitted
members each L0-L3 verified, one shared capture and one program execution unit.
Each ISA: eight samples, 24 events including eight actual fence witnesses.

### 5. New production matrix, then previous M1 compatibility matrix

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_joint_context_production.py \
  --basetemp="$CHECK_ROOT/context-pytest" \
  --junitxml="$CHECK_ROOT/context-production.xml" \
  > "$CHECK_ROOT/context-production.log" 2>&1
CONTEXT_STATUS=$?
printf 'context_status=%s\n' "$CONTEXT_STATUS"
tail -n 100 "$CHECK_ROOT/context-production.log"
```

Expected **8 passed**, no skip/error/failure. These test actual frontend/proof,
L0-L3, independent audit and refusal of altered retained raw traces. They cover
narrow typed signed/unsigned objects and zero/one/two fence contexts.

After that succeeds:

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_joint_production.py \
  --basetemp="$CHECK_ROOT/m1-pytest" \
  --junitxml="$CHECK_ROOT/m1-production.xml" \
  > "$CHECK_ROOT/m1-production.log" 2>&1
M1_STATUS=$?
printf 'm1_status=%s\n' "$M1_STATUS"
tail -n 100 "$CHECK_ROOT/m1-production.log"
```

Expected **12 passed**, no skip/error/failure. This preserves the previous
1-4 parameter, pointer-position, scalar-operation and 16-region boundaries.
These real matrices are slow; they do not indicate a hung shell merely because
output is redirected. Avoid editing source files during calibrated execution.

### 6. M0 ledger

Use a fresh ledger directory and the smoke's generated selection/evaluation.
Inventory entries never grant semantic approval merely because a mechanism is
configured. Unrelated/unexecuted sources must remain not_run.

```bash
export LEDGER_ROOT="$(mktemp -d "$CHECK_ROOT/ledger-XXXXXX")"
python3 -m riscv2x86_py.l3_coverage_inventory \
  --sources "$REPO/experiment/inputs" \
  --results "$CHECK_ROOT/fenced-smoke" \
  --capability joint \
  --output "$LEDGER_ROOT/fenced-smoke.json" \
  > "$LEDGER_ROOT/fenced-smoke.log" 2>&1
LEDGER_STATUS=$?
printf 'ledger_status=%s\n' "$LEDGER_STATUS"
cat "$LEDGER_ROOT/fenced-smoke.log"
```

Expected: the fenced input accepted; unrelated inputs not_run; errors empty.
The aggregate productionAcceptanceComplete remains false if any input was not
accepted. Do not interpret the ledger's process exit 0 as all inputs accepted.

Send focused.log, backend build-status.json, fenced-audit.log, both matrix logs
and ledger log. If any stage fails, preserve its existing artifacts; do not
rerun into the same output directory or bypass the failing requirement.

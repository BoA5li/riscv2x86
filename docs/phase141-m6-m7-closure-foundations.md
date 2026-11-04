# Phase141: M6 entry fix, compiler call-target facts and M7 host basis

Baseline: Phase140 `147489845649ca20eac86388c878cb4cd0339a2e`.
Branch: `phase141-m6-m7-closure-foundations`.

## Delivery and claims

This is a bounded foundation revision, NOT completion of M6/M7 and NOT a new
performance optimization. Phase140's checks, observation counts, first/closing
epochs, and separate-process audits remain unchanged. No measured speedup is
claimed. Compiler target resolution and host collection never authorize execution.

| Item | Delivered | What remains |
| --- | --- | --- |
| Joint extra exported C functions | Fix both L2 provider registration and L3 entry selection; keep every finding, scope and proof gate | Only existing direct no-call joint domain; arbitrary unrelated asm still subject to construction/region checks |
| Internal callees | Compiler AST inventory includes static primary-file definitions and direct call sites | Not connected as an executable caller/callee translation route |
| Reachability | Root identity, repeated static sites, target resolution, recursion/indirect/external/header/macro/startup blockers | Effect summaries, object/alias state substitution, ABI/link closure, dynamic call instances, whole-program audit |
| M7 | Read-only fingerprints and actual retained layer/schema inventory | New L3 policy, intent, backend, comparator and independent replay for each environment domain |

The joint change removes file function count as a rejection criterion. It does
NOT permit calls in the selected entry: the old compilerJointScope grammar still
excludes them. Findings from different functions, duplicate entry identities and
unproved shells still fail. The complete function list remains bound in the
compiler snapshot/rebuild; no unrelated functions or findings are silently deleted.
Selecting a joint provider still means candidate availability, not semantic approval.

`compiler_call_inventory` is a separate diagnostic path. It does not change the
legacy compiler snapshots or the meaning of their existing identities. Function
identities use source digest, symbol/type and AST range, not Clang process-local
IDs. Prototypes can bind to definitions. Header bodies remain explicit external
prerequisites; macros require additional provenance. Function pointer expressions
are not guessed from names. Constructor effects require startup closure, even
when the constructor is not directly called by the root. An inventory is not an
effect proof: `effectClosureStatus` and `abiClosureStatus` stay `not_proved`, while
execution and audit stay `not_run`, even if `staticCallTargetsResolved=true`.
This flag concerns C CallExpr targets only, not hidden calls in asm, runtime or
linker effects. `notStaticallyReachedFunctions` is not a proof of unreachability.
Header/dependency closure is explicitly not verified by this diagnostic.

The supplied M6 seed intentionally still requires a new call route. Do not report
it as a translation success because target inspection succeeds. This revision
does not remove `L3_SYNC_VISIBILITY_ROUTE_REQUIRED`,
`L3_SYNC_ENVIRONMENT_ROUTE_REQUIRED`, or change the existing L3 fetch exclusions.
Existing controlled time/system production can finish L0-L2 with L3 not_run;
that is NOT M7 acceptance.

## Local validation

- Focused 24-file regression: 411 passed, 6 skipped in 68.84 seconds. Skips:
  five real-Clang tests and one real source-ISA instruction-visibility test.
- Final entry-registration/collector/inventory/batch regression: 60 passed,
  3 skipped in 1.33 seconds. Skips: one real-Clang inventory test and two
  calibrated dual-ISA production cases. This overlaps the focused run.
- 32 production cases collected (2 new + 30 compatibility), not executed here.
- Eight Python files parse with Python 3.10 grammar; eight Bash blocks pass
  `bash -n`. `git diff --check` passes. Collector ran read-only with errors=[].
- No local real dual-ISA or M7 L3 acceptance and no new performance claim.

## 1. Update (preserve old results and build modifications)

Stop active experiments before changing branches.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase141-m6-m7-closure-foundations
git switch --track origin/phase141-m6-m7-closure-foundations
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RV2X86_TEST_RISCV_CC="/usr/bin/riscv64-linux-gnu-gcc-7"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase141-XXXXXX")"
hash -r
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
```

If the branch already exists, switch to it then merge the origin branch with
`git merge --ff-only origin/phase141-m6-m7-closure-foundations`. No frontend C++
changes are included; do not rebuild just for this Python revision.

## 2. Focused regression (includes unchanged environment and audit gates)

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_compiler_call_inventory.py \
  pytools/tests/test_m6_joint_entry.py \
  pytools/tests/test_m6_m7_host_basis.py \
  pytools/tests/test_l3_joint_program.py \
  pytools/tests/test_l2_joint_registry.py \
  pytools/tests/test_multi_object_joint.py \
  pytools/tests/test_l3_joint_typed_access.py \
  pytools/tests/test_l3_joint_fence_context.py \
  pytools/tests/test_versioned_joint_closure.py \
  pytools/tests/test_joint_definitions_layout_coverage.py \
  pytools/tests/test_joint_operation_replay.py \
  pytools/tests/test_joint_validation_performance.py \
  pytools/tests/test_joint_provenance_performance.py \
  pytools/tests/test_atomic_validation_operation.py \
  pytools/tests/test_l3_lrsc_direct_entry.py \
  pytools/tests/test_instruction_visibility_production.py \
  pytools/tests/test_instruction_visibility_execution.py \
  pytools/tests/test_controlled_time.py \
  pytools/tests/test_controlled_system.py \
  pytools/tests/test_execution_environment_closure.py \
  pytools/tests/test_configured_environment_suite.py \
  pytools/tests/test_experiment_environment.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  pytools/tests/test_l3_production_acceptance.py \
  --junitxml="$CHECK_ROOT/focused.xml" > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 100 "$CHECK_ROOT/focused.log"
```

Require no failed/errors. Inspect each skip: host Clang/compiler tests should run
when the actual tools are present. Fixtures and native target tests are not
source/target production. Production tests are separate below.

## 3. Actual compiler inspection of a static helper

```bash
python3 -m riscv2x86_py.compiler_call_inventory \
  --source "$REPO/experiment/inputs/m6-static-helper-basis.c" \
  --clang "$RV2X86_SYSTEM_CLANG" --target riscv64 \
  --compile-arg=-march=rv64gc --compile-arg=-mabi=lp64d \
  --root-function m6_entry --output "$CHECK_ROOT/call-basis.json" \
  > "$CHECK_ROOT/call-basis.log" 2>&1
CALL_STATUS=$?
printf 'call_inventory_status=%s\n' "$CALL_STATUS"
cat "$CHECK_ROOT/call-basis.log"
cat "$CHECK_ROOT/call-basis.json"
```

Expected: 3 primary-file definitions, 2 statically reached functions (including
the static update helper), 1 not-statically-reached function. Target resolution
true is expected; semanticApproval and productionAcceptanceComplete remain false.
No runtime was performed. Do not count this diagnostic as a verified M6 program.
For real seeds use the real build's include/define/sysroot flags as repeated
`--compile-arg=...` arguments. A compiler error is collection failure, not an
unsupported translation result. Existing output paths are not overwritten.

## 4. Fresh joint backend and two actual extra-entry production cases

The Python implementation dependency set changed. Rebuild the outer wrapper;
reuse the immutable Phase95 base and never edit its recorded digests.

```bash
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
python3 -m riscv2x86_py.l3_joint_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$CHECK_ROOT/joint-backend" > "$CHECK_ROOT/joint-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'joint_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 60 "$CHECK_ROOT/joint-backend.log"
cat "$CHECK_ROOT/joint-backend/build-status.json"
export RV2X86_L3_JOINT_BACKEND="$CHECK_ROOT/joint-backend/backend.json"
```

Continue only on exit 0 and complete build status (12 calibration records). Then:

```bash
python3 -m pytest -vv -rs --durations=0 \
  pytools/tests/test_l3_m6_entry_production.py \
  --basetemp="$CHECK_ROOT/entry-pytest" \
  --junitxml="$CHECK_ROOT/entry-production.xml" \
  > "$CHECK_ROOT/entry-production.log" 2>&1
ENTRY_STATUS=$?
printf 'entry_production_status=%s\n' "$ENTRY_STATUS"
tail -n 120 "$CHECK_ROOT/entry-production.log"
```

Require 2 passed, no skips/errors. Each case retains full L0-L3, whole-call group
audit, a fresh-process audit, missing-member rejection and raw-trace corruption
rejection. The deliberate corruption at the end means these pytest directories
must not be used later for clean performance audits.

## 5. Existing joint production compatibility (30 cases)

```bash
python3 -m pytest -vv -rs --durations=0 \
  pytools/tests/test_l3_joint_production.py \
  pytools/tests/test_l3_joint_context_production.py \
  pytools/tests/test_l3_joint_definitions_production.py \
  pytools/tests/test_l3_multi_object_production.py \
  --basetemp="$CHECK_ROOT/compat-pytest" \
  --junitxml="$CHECK_ROOT/compat-production.xml" \
  > "$CHECK_ROOT/compat-production.log" 2>&1
COMPAT_STATUS=$?
printf 'compat_production_status=%s\n' "$COMPAT_STATUS"
tail -n 120 "$CHECK_ROOT/compat-production.log"
```

Require 30 passed, no skips/errors. For AMO/LRSC performance continuity, follow
the Phase140 guide with NEW control/atomic/lrsc wrappers and new output paths.
No change here is expected to improve Phase140 speedups; compare workload-equal
wall times separately if rerunning, and do not count skipped checks as speedups.

## 6. Read-only M7 host basis (no environment approval)

This command inventories tool versions, hashes, CPU affinity and source changes.
It does not run a backend or scan all result files. It does not dump the shell
environment. Existing files are never modified.

```bash
python3 experiment/collect_m6_m7_basis.py \
  --repository "$REPO" \
  --backend "$RV2X86_L3_TRACE_BACKEND" \
  --backend "$RV2X86_L3_JOINT_BACKEND" \
  --output "$CHECK_ROOT/m6-m7-host-basis.json" \
  > "$CHECK_ROOT/m6-m7-host-basis.log" 2>&1
BASIS_STATUS=$?
printf 'host_basis_status=%s\n' "$BASIS_STATUS"
cat "$CHECK_ROOT/m6-m7-host-basis.log"
cat "$CHECK_ROOT/m6-m7-host-basis.json"
```

To locate already existing environment artifacts, first list names only:

```bash
rg --files --hidden \
  -g 'backend.json' -g '*manifest*.json' -g 'run-status.json' \
  "$REPO/experiment/results" \
  | rg 'local-sync|controlled|system|visibility|time|mechanism' \
  > "$CHECK_ROOT/environment-paths.txt"
cat "$CHECK_ROOT/environment-paths.txt"
```

Return that text and the host basis. If environment paths are known, rerun the
collector with additional repeated `--backend /actual/path.json` and
`--evaluation /actual/evaluation-result.json`, using a NEW output filename.
Do not guess paths or rewrite backend hashes. Recorded verified labels are
reported as data: `formalBackendValidationPerformed` and
`independentAuditPerformed` remain false.

Needed before implementing the real M7 route: existing local-sync reviewed
mechanism/domain/provider files, controlled-time backend/runner contract, and
SYSTEM backend/scope with raw source/target execution records. Clarify whether
the intended domain extends to cross-hart publication, MMIO or external interrupts;
the current shipped domain does not cover them. Missing hardware observations
cannot be replaced by a software label or a finite expected-state table.

## Remaining implementation order

1. Compiler call graph integrated with build/TU/header provenance and root choice.
2. Approved C/asm function effect summaries and argument/object/alias substitution.
3. Final-link callee/ABI/stack closure, including external/indirect/recursive rules.
4. Dynamic call/return/region instance protocol; independent whole-program replay.
5. Versioned L3 instruction-visibility policy and backend/probe provenance, with
   explicit separation of protocol annotations from actual fetched values.
6. Controlled-time/SYSTEM/CSR L3 contracts, independent comparison and audits.
7. M5 CFG/loop and M6/M7 cross-function environment integration.

Every item needs actual positive and negative execution in its declared domain.
Do not delete existing call/scope/synchronization blockers until the replacement
proof and observer discharge the obligations. A missing-sync mutation need not
produce a stale-code value under QEMU: keep mechanism rejection separate from
whether the executor can expose that particular physical behavior.

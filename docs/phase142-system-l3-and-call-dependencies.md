# Phase142: bounded SYSTEM L3 and compiler call dependency acquisition

Baseline: Phase141 `59c37afd7fa02288be1620957eaa43758cba8a73`.
Branch: `phase142-system-l3-and-call-dependencies`.

## Delivery boundaries

This revision does NOT complete all M6/M7. It implements one explicit bounded
SYSTEM L3 route, compiler dependency acquisition/replay, and unrelated-export
scope fixes. General interprocedural effect/ABI composition, dynamic calls,
visibility L3, arbitrary environments and cross-function environment operations
are still code gaps, not merely missing host tests. No speedup is claimed.
Unrelated plain C exports are supported by the entry fix. Additional asm findings
are not silently ignored: this bounded production route still requires one finding.

| Item | Delivered | Remaining |
| --- | --- | --- |
| Compiler call facts | Opt-in compiler-emitted header dependencies, content checks surrounding AST acquisition, independent command/inventory replay | Immutable build snapshots, full header function summaries, link and effect closure |
| SYSTEM entry scope | Select the bound entry despite unrelated definitions; reject startup constructors/destructors | The selected entry is still a sole no-operand volatile SYSTEM asm; no caller/callee permission |
| SYSTEM L3 | Explicit policy, pinned intent producer, eligible staged requirements, receipt replay, full build matrix replay, final machine attribution, new actual state-protocol execution and independent audit | Only ECALL trap-return or already-pending-MTIP WFI in the reviewed one-hart M-mode environment |
| Visibility | Existing code and old L2 checks preserved | New visibility L3 deployment/comparison/audit and actual host acceptance |
| Performance | New timing spans; removed an unnecessary outer proof-replay call by deriving the callee from freshly replayed intent | No reduced validation standard, no cache or measured performance optimization |

`dependencyClosureVerified=false` intentionally remains. The new dependency
manifest establishes acquisition consistency of compiler-emitted files, NOT a
complete semantic/build/link closure or an adversarial concurrent-write guarantee.
Headers remain explicit prerequisites in the old call-target inventory. The
dependency validator repeats the compiler acquisition, rather than trusting a
rehashed manifest. Restricted preprocessing/ISA flags are supported; response
files, compiler plugins and output-redirection flags require a future recipe.

## SYSTEM policy and acceptance

The new policy is `bounded-controlled-system-intent.v1`; it is NOT an expansion
or reinterpretation of the old compiler-region policy that excludes fetch and
outside-fragment effects. The existing global visibility/environment blockers
are unchanged for routes that do not possess the new explicit evidence.

The normal automatic batch can select `--system-l3` only with the existing
explicit controlled SYSTEM L2 provider and its approved environment. It prepares
a pinned SYSTEM intent producer and ordinary staged L3 requirements/receipt.
The L3 result must match and independently replay those requirements. Candidate
availability or an eligible requirement is never execution acceptance.

The L3 runner requires all L0/L1/L2 results and the actual execution context.
It independently rebuilds and checks all six source/target O0/O2/O3 products,
attributes a single source SYSTEM instruction in the entire decoded straight
entry, and binds the target entry's one decoded direct call to the approved
runtime symbol. Unknown encodings/control transfers do not pass.

It then performs a NEW reviewed kernel/native-adapter execution. It does not
promote a recorded L2 result into L3. Kernel/adapter event IDs are protocol
observations, not a hardware PC trace. The target library is a reviewed logical
adapter, not native RISC-V privilege execution on x86. Full native machine state,
arbitrary services, future-event liveness, physical timing and microarchitecture
equivalence are not claimed. Test-program MMIO/cross-hart/external interrupts
remain out of scope; private observer transport and MTIP setup are environment
implementation, not translated-program MMIO coverage.

Independent acceptance replays compiler/proof/intent, typed provider artifacts,
the six builds, final machine attribution, raw protocol/state comparison,
environment, program and invocation bindings. Booleans cannot stand for integer
states/exit codes; duplicate JSON keys/nonfinite values reject. Missing members,
wrong policies, changed executables and stale package identities reject.

Legacy `run_controlled_system_routes.py` without `--require-l3` remains L0-L2
with `L3Equivalent=false`. With the flag it emits v2 status with requiredLevels
L0-L3, `boundedSystemL3Complete`, execution/audit flags and an explicit bounded
claim; the ambiguous legacy `L3Equivalent` field is absent. Physical equivalence
and original Linux-user equivalence remain false. A passing v2 run still does
NOT mean M6/M7 as a whole are complete.

## 1. Update and fresh outputs

Stop active experiments before changing code. Preserve build modifications and
all old results. No C++ frontend or reviewed kernel/runtime source changed.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase142-system-l3-and-call-dependencies
git switch --track origin/phase142-system-l3-and-call-dependencies
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RV2X86_TEST_RISCV_CC="/usr/bin/riscv64-linux-gnu-gcc-7"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase142-XXXXXX")"
hash -r
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
```

If the local branch exists: switch to it and use
`git merge --ff-only origin/phase142-system-l3-and-call-dependencies`.

## 2. Focused tests

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_system_route.py \
  pytools/tests/test_system_entry_scope.py \
  pytools/tests/test_compiler_call_dependencies.py \
  pytools/tests/test_compiler_call_inventory.py \
  pytools/tests/test_controlled_system.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  pytools/tests/test_l3_production_acceptance.py \
  pytools/tests/test_execution_environment_closure.py \
  pytools/tests/test_configured_environment_suite.py \
  pytools/tests/test_experiment_environment.py \
  pytools/tests/test_l3_coverage_inventory.py \
  --junitxml="$CHECK_ROOT/focused.xml" \
  > "$CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 100 "$CHECK_ROOT/focused.log"
```

Require no failures/errors. Real Clang tests should execute with the configured
host compiler. Simulated source-protocol unit fixtures are not production proof.

## 3. Compiler dependency acquisition and fresh-process replay

```bash
python3 -m riscv2x86_py.compiler_call_inventory \
  --source "$REPO/experiment/inputs/m6-static-helper-basis.c" \
  --clang "$RV2X86_SYSTEM_CLANG" --target riscv64 \
  --compile-arg=-march=rv64gc --compile-arg=-mabi=lp64d \
  --root-function m6_entry --bind-dependencies \
  --output "$CHECK_ROOT/call-basis.json" \
  > "$CHECK_ROOT/call-basis.log" 2>&1
CALL_STATUS=$?
printf 'call_basis_status=%s\n' "$CALL_STATUS"
cat "$CHECK_ROOT/call-basis.log"
python3 -m riscv2x86_py.compiler_call_dependencies \
  --inventory "$CHECK_ROOT/call-basis.json" \
  > "$CHECK_ROOT/call-replay.log" 2>&1
REPLAY_STATUS=$?
printf 'call_replay_status=%s\n' "$REPLAY_STATUS"
cat "$CHECK_ROOT/call-replay.log"
```

Both statuses must be zero. Acquisition replay is not semantic acceptance;
effect/ABI remain unproved and execution/audit not_run. Do not count the seed as
a successfully translated M6 caller/callee production program.

## 4. Reprobe the existing SYSTEM backend under the current environment

The following old backend path was provided by the user's actual inventory.
It is an INPUT to validation, not a backend selected by phase number as proof.
No old files are rewritten and no QEMU rebuild is silently substituted.

```bash
export OLD_SYSTEM_BACKEND="$REPO/experiment/results/phase100-jkM4fJ/compatibility-fY3ROl/system-reprobe-cMpzM3/backend/backend.json"
python3 -m riscv2x86_py.controlled_system_backend upgrade-backend \
  --backend "$OLD_SYSTEM_BACKEND" \
  --output "$CHECK_ROOT/system-backend" \
  > "$CHECK_ROOT/system-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'system_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 100 "$CHECK_ROOT/system-backend.log"
```

Proceed only if status=0. A changed runtime/QEMU/implementation rejects; do not
edit stored hashes. Upgrade probes the supported build profile; it is not L3
acceptance. Keep PATH and compiler-search environment stable afterwards.

## 5. New real SYSTEM L3 matrix (2 cases)

Use Bash time; `/usr/bin/time` is not required. The backend must have passed step4.

```bash
export RV2X86_CONTROLLED_SYSTEM_BACKEND="$CHECK_ROOT/system-backend/backend.json"
export RV2X86_VALIDATION_TIMING="$CHECK_ROOT/system-l3-timing.jsonl"
TIMEFORMAT='wall_seconds=%R user_seconds=%U system_seconds=%S'
{ time python3 -m pytest -vv -rs --durations=0 \
  pytools/tests/test_l3_system_production.py \
  --basetemp="$CHECK_ROOT/system-l3-pytest" \
  --junitxml="$CHECK_ROOT/system-l3-production.xml"; } \
  > "$CHECK_ROOT/system-l3-production.log" 2>&1
SYSTEM_L3_STATUS=$?
unset RV2X86_VALIDATION_TIMING
printf 'system_l3_status=%s\n' "$SYSTEM_L3_STATUS"
tail -n 140 "$CHECK_ROOT/system-l3-production.log"
python3 experiment/inspect_validation_timing.py \
  --input "$CHECK_ROOT/system-l3-timing.jsonl" \
  > "$CHECK_ROOT/system-l3-timing-summary.json"
cat "$CHECK_ROOT/system-l3-timing-summary.json"
```

Require 2 passed, no skips/failures/errors. Each case uses a renamed source with
an unrelated export, the ordinary frontend/proof/renderer/batch, actual source
and target execution, central L2 audit and a separate-process L3 audit. Tampered
program evidence must reject. The test restores its temporary mutation afterward.
If this fails, return the log and run-status; do not proceed to long regressions.

## 6. Preserve the existing L0-L2 SYSTEM route

```bash
python3 -m pytest -vv -rs --durations=0 \
  pytools/tests/test_controlled_system_production.py \
  --basetemp="$CHECK_ROOT/system-legacy-pytest" \
  --junitxml="$CHECK_ROOT/system-legacy.xml" \
  > "$CHECK_ROOT/system-legacy.log" 2>&1
LEGACY_STATUS=$?
printf 'legacy_system_status=%s\n' "$LEGACY_STATUS"
tail -n 100 "$CHECK_ROOT/system-legacy.log"
```

Require 2 passed. Its L3 remains not_run: that is intentional and different from
step5, not a regression or a basis for treating the two routes as identical work.

## 7. Previous supported domains and timing interpretation

The local broad regression includes joint, atomic operation reuse, LRSC direct
entry, controlled time, visibility and environment closure. For a host release
regression, follow Phase141's freshly calibrated joint-backend instructions,
then execute the existing 30 joint/context/definition/multi-object production
cases. Old joint/atomic/LRSC wrappers pin package content and must not be rehashed
or reused after a package revision; rebuild them with their existing commands.

Return focused.log, call-basis.log, call-replay.log, system-backend.log,
system-l3-production.log, system-l3-timing-summary.json and system-legacy.log.
No archive upload is necessary; text can be pasted in parts.

Timing spans are instrumented work, not acceptance. Inclusive nested and
cross-process spans cannot be summed as wall time. The new L3 work is stricter
than legacy L0-L2, so their elapsed times do not constitute a speedup comparison.
Profile one case/audit only after correctness passes; compare performance only
with identical policy, inputs, builds, observations, audit work and environment.

## Remaining M6/M7 implementation

1. Integrate call graph with complete build/TU/header provenance and entry choice.
2. Compose proved C/asm function effects with argument/object/alias substitution.
3. Prove final-link callee/ABI/stack closure; handle approved external targets,
   indirect target sets and recursion only with corresponding proof support.
4. Observe dynamic call/return/region instances and independently audit them.
5. Add visibility L3 policy/backend/probe attribution/comparison/replay, preserving
   the difference between returned probe values and hardware fetch observations.
6. Integrate environment operations into callee summaries and whole-program
   execution, rather than stitching separate invocations together.
7. Clear the coverage ledger only on actual declared-domain acceptance, with
   positive/negative tests and archived artifacts. Controlled time is optional
   for the user's current scope and must never be substituted for native time.

## Local validation before publication

- Broad 25-file regression: 398 passed, 11 skipped in 46.71 seconds.
- Final targeted four-file regression: 69 passed, 1 skipped (overlaps the broad run).
- Skips are real Clang/source-ISA/explicit SYSTEM backend requirements, not passes.
- Real 2-case new L3 and 2-case legacy SYSTEM production matrices collected, not executed locally.
- Modified Python files parse with Python 3.10 grammar; all six Bash blocks pass `bash -n`; `git diff --check` passes.
- Actual native GCC/runtime and P-code/proof tests ran. Simulated source records are labelled unit fixtures.
- No local real dual-ISA SYSTEM L3 acceptance, complete M6/M7 acceptance or measured speedup is claimed.

# Phase155: stable compiler type inventories and strict replay diagnostics

Base: Phase154, `4b0fdd653959187d476c9dfcf2769fcd3b489292`.
Branch: `phase155-stable-compiler-type-replay`.

## Evidence and cause

Independent inspection can succeed while replay fails on
`functionTypeInventory` when a function parameter uses a typedef. Clang emits
`parameterTypes[*].compilerType.typeAliasDeclId` as a process-local AST node
reference. A different reference changes derived function and inventory
identities even when all other recorded type fields remain identical. No
project name, address, source offset, path or expected output is used by the
repair. The regression fixtures use synthetic source names and identifiers.

`compiler_function_types.describe()` previously copied the complete Clang type
dictionary into the hashed inventory. The function-level type record was also
copied directly. Strict independent comparison then treated allocation IDs as
semantic differences. The comparison correctly prevented false completion,
but the persisted representation incorrectly blocked unchanged programs.

## Representation and gate

- Inventory schema is now `riscv2x86.compiler-function-types.v2` with an explicit
  type projection policy and `typedefDeclarationClosureVerified: false`.
- Project only one Clang type dictionary at a time. Remove the documented
  process-local `typeAliasDeclId` field after checking its expected ID shape.
  Preserve every other field, including unknown future metadata. Never erase
  arbitrary `id` fields, hexadecimal strings or references inside other AST data.
- Apply the same rule to parameter and function-level types. Do not mutate raw
  compiler AST evidence. Continue to bind dependency and target identities.
- This is a descriptive type inventory, not typedef declaration resolution or
  proof of a call ABI. Spelling and desugaring remain exact; unclassified types,
  floating-point prerequisites, internal entry adapters and all approval flags
  retain their conservative meaning.
- Replaying v1 inspections explicitly requires reacquisition. Do not strip IDs
  from old files, rewrite hashes or convert a failed historical run into success.
- Strict comparison remains in place for all original replay components. New
  diagnostics identify source/context, component and first differing field.
  Underlying fields precede derived identity fields in diagnostics only.
- Captured build actions, dependency bytes, compiler identities, environments,
  include-search ordering and exact pilot membership are still independently
  checked. This is not a cache or a waiver of a failed comparison.

## Fixed contexts, not randomized configurations

Contexts come from observed native build actions: compiler, source, working
directory, original arguments, include/macro environment, dependencies and
variant. Clang inspection is an explicitly checked projection of that context;
it is not a randomly chosen build. A source-path pilot can select deterministically by sorted source path,
with all captured variants for those paths. Random-looking temporary directory names isolate results;
Clang allocation IDs are process-local implementation details. Neither is a
random change to the declared test configuration.

## Host verification: reuse captures, reacquire inspections

Do not repeat native configure/make or change upstream sources. Run from
the existing virtual environment. Add the new worktree once; output directories
must be fresh. Preserve the failed Phase154 batch and its plan unchanged.

```bash
# Set these to your existing repository, preparation, capture and pilot roots.
: "${REPO:?}" "${PREP_ROOT:?}" "${VERIFY_ROOT:?}" "${CORPUS_CHECK_ROOT:?}" "${ACTIVE_ROOT:?}"
: "${RV2X86_SYSTEM_CLANG:?}" "${RV2X86_TEST_RISCV_CC:?}"
cd "$REPO"
export TOOLING="$PREP_ROOT/tooling-phase155"
git fetch origin phase155-stable-compiler-type-replay
git worktree add --detach "$TOOLING" origin/phase155-stable-compiler-type-replay
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$TOOLING/pytools${PYTHONPATH:+:$PYTHONPATH}"
export CHECK_ROOT="$(mktemp -d "$CORPUS_CHECK_ROOT/phase155-XXXXXX")"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git -C "$TOOLING" rev-parse HEAD
```

Run the following as one gated block. On a failing stage it stops before the
next experiment. Repeating the block requires a new `CHECK_ROOT`.

```bash
bash -e <<'STAGES'
: "${TOOLING:?}" "${CHECK_ROOT:?}" "${VERIFY_ROOT:?}" "${ACTIVE_ROOT:?}"
python3 -m pytest -q -rs \
  "$TOOLING/pytools/tests/test_project_type_replay.py" \
  "$TOOLING/pytools/tests/test_compiler_function_types.py" \
  "$TOOLING/pytools/tests/test_project_build_records.py" \
  "$TOOLING/pytools/tests/test_project_build_capture.py" \
  "$TOOLING/pytools/tests/test_project_header_search.py" \
  "$TOOLING/pytools/tests/test_compiler_call_dependencies.py" \
  "$TOOLING/pytools/tests/test_project_inspection_pilot.py" \
  --junitxml="$CHECK_ROOT/focused.xml" \
  > "$CHECK_ROOT/focused.log" 2>&1
python3 "$TOOLING/experiment/run_project_inspection_pilot.py" \
  --tooling "$TOOLING" \
  --records "$VERIFY_ROOT/gmp-native/records.json" \
  --plan "$ACTIVE_ROOT/batch-plan.json" \
  --clang "$RV2X86_SYSTEM_CLANG" \
  --output "$CHECK_ROOT/eight-source-pilot" \
  > "$CHECK_ROOT/eight-source-driver.log" 2>&1
STAGES
STATUS=$?
printf 'verification_status=%s\n' "$STATUS"
cat "$CHECK_ROOT/focused.log"
if test -f "$CHECK_ROOT/eight-source-driver.log"; then
  cat "$CHECK_ROOT/eight-source-driver.log"
fi
if test -f "$CHECK_ROOT/eight-source-pilot/run-status.json"; then
  cat "$CHECK_ROOT/eight-source-pilot/run-status.json"
fi
```

Expected: tests pass, including real Clang integration when installed; pilot has
exactly the planned number of inspected contexts, `status/currentStage: complete`, both inspection/replay
completion flags true, and no primary failure. Read `summary.json` and
`replay.log` after success. If it fails, preserve and return the failed stage
log and status; new replay mismatches include `replayDifference` details.

For an additional independent process check, use a NEW log filename:

```bash
python3 "$TOOLING/experiment/prepare_real_project_experiment.py" replay \
  --report "$CHECK_ROOT/eight-source-pilot/contexts.json" \
  > "$CHECK_ROOT/second-replay.log" 2>&1
REPLAY_STATUS=$?
printf 'second_replay_status=%s\n' "$REPLAY_STATUS"
cat "$CHECK_ROOT/second-replay.log"
```

## Experiment status after this repair

The native source paths and compile contexts remain the captured build
denominator, not counts of activated asm instances. Reinspect additional sources
under their captured variants only after this same frozen batch closes. Preserve
uninspected, blocked and failed rows; do not select by successful translation.
Do not feed old v1 inspection results directly to new replay.

Successful compiler acquisition still reports `asmInstanceInventoryComplete:
false`, `endToEndEligibilityAssessed: false`, `semanticApproval: false` and
`productionAcceptanceComplete: false`. Complete macro/header expansion
provenance, activation-instance enumeration and call/object/environment contracts
are separate remaining work; this repair does not implement general macros,
general ABI, floating-point translation or full kernel execution. It does not
establish L0--L3 acceptance, even if primary functions have zero asm syntax.

## Local verification

The new regressions exercise changing process IDs, retained semantic and unknown
type fields, qualifiers, function properties, dependency/target identity binding,
v1 rejection, rehashed tampering, CLI failure diagnostics and optional real Clang
invocations in separate processes. Host Clang integration is necessary; simulated
ASTs establish serialization behavior, not native compiler equivalence.

Results: project/type/dependency regressions 204 passed, 5 skipped (real Clang
and/or RISC-V GCC unavailable locally); immutable corpus regressions 92 passed.
Frozen corpus policies, source archives, native captures and translation rules
are unchanged. Local tests are not the host's full corpus production experiment.

# Phase165: compiler-explicit dependency tests and accurate backend diagnostics

Base: Phase164, `435a0432ca96fad61109b5f7a2eeb76f4c25221e`.

## Confirmed host failure and scope

The host ran GCC 7.5. Its default-compiled root.o declares an undefined
_GLOBAL_OFFSET_TABLE_, while the displayed .rela.text only references leaf
through R_X86_64_PLT32. Phase164 conservatively follows *all* undefined nonlocal
symbols. Its test nevertheless asserted that this default compiler invocation
could have no unresolved references. This is an invalid test precondition, not
an observed GMP semantic mistranslation. The experiment stopped at pytest;
GMP dependency inventory and replay did not execute.

The host backend inventory had 70 diagnostic rows over 24 paths: 68 binding rows
over 23 bound-file paths, plus one missing base manifest reported twice as missing
and mismatch. Replaying that blocked inventory succeeded, but the CLI incorrectly
printed blockerCount=0 because replay's result had no blockers field.

This revision repairs those errors. It does not implement the remaining complete
GMP target library, call/object/effect contracts or program-level L0--L3 route.
No source/target acceptance or compiler flag of a production candidate is changed.
No symbol name is whitelisted, no backend hash is refreshed to force validation,
and no historical evidence is overwritten.

## Changes

### Dependency regression domain

The business-only native GCC/ar test fixture explicitly requests -fno-pic and
-fno-pie. These options apply only to that fixture, never the actual corpus.
Additional real default/PIC/PIE cases validate the three-object business dependency
graph while retaining extra compiler-generated unresolved references. Independent
nm output checks their presence in diagnostics. Name-independent negative cases
require that arbitrary unresolved symbols (including _GLOBAL_OFFSET_TABLE_) remain
obligations without a link contract. The conservative object-symbol policy remains
unchanged. It does not claim symbol declarations equal relocation demand or that
absence of a direct relocation proves linker-synthesized infrastructure safe.

A future relocation-aware precision extension needs separate versioned evidence
for symbol declarations, explicit and implicit relocation requirements, supported
relocation semantics and actual link provenance. This revision does not simulate
a linker or silently remove unreferenced declarations.

### Backend observation v2

New acquisitions use riscv2x86.native-backend-inventory.v2:

* Missing, nonregular, unreadable and content-mismatched files have distinct
  reason codes. Expected/actual digests and observation state are explicit.
* A base manifest is observed once, and every owner's expected digest remains in
  baseReferences. Missing/unreadable manifests are never labeled digest mismatch.
  Readable content is compared separately against every owner's expectation.
* diagnosticSummary contains row count, unique affected-path count, reason counts
  and path/owner relationships. Repeated bindings remain evidence; only the display
  groups paths. No obligation is deleted by deduplication.
* File observations are rechecked at closing, including missing/nonregular/
  unreadable paths and resolved paths, not only successful hashes.
* status=blocked describes diagnostic blockers even when staticInventoryComplete
  is true. Backend schema-specific validation/calibration and program observation
  capability remain false.

The previous v1 projection is frozen in native_backend_inventory_v1.py solely for
historical independent replay. A valid old report is reconstructed exactly; its old
reasons are not rewritten. Rehashed changed diagnostics or approval flags fail.
A new v2 acquisition uses a new output root and identity.

### Replay and command status

Both dependency and backend replays return replayedInventoryIdentity,
replayedBlockerCount and an explicit diagnostic status. CLI summaries require this
count rather than treating a missing list as empty. New backend inventories and
replays additionally report affectedPathCount. Inventory completion and replay
completion are distinct fields. Outer run-status.status=complete means the command
finished; inventoryStatus=blocked preserves the diagnostic result. Semantic and
production completion flags remain false in every successful diagnostic operation.

Exit zero means successful inventory/reconstruction, including consistent blocked
results. A malformed input or changed closing observation is a failed operation.
Neither exit zero nor zero static blockers validates a backend for an experiment.

## Host verification

Keep all existing worktrees/captures/candidates and the failed Phase164 run. No
GMP reconfigure, rebuild, download or repeat of the successful native baseline is
needed. Do not restore stale backend hashes or copy unrelated QEMU headers.

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE163_ROOT:?}"
git -C "$REPO" fetch origin phase165-backend-diagnostic-replay
export PHASE165_TOOLING="$PREP_ROOT/tooling-phase165"
git -C "$REPO" worktree add --detach "$PHASE165_TOOLING" origin/phase165-backend-diagnostic-replay
export PHASE165_ROOT="$(mktemp -d "$PHASE163_ROOT/phase165-XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
printf 'PHASE165_ROOT=%s\n' "$PHASE165_ROOT"
```

If tooling-phase165 already exists, inspect its HEAD or choose a fresh path; do not
delete a worktree referenced by old captures. Preserve the existing
RV2X86_SYSTEM_CLANG, RV2X86_TEST_RISCV_CC and RISCV2X86_TEST_FRONTEND values so real
integration tests run. A skip is not verification of that integration.

### 1. Focused tests, then the previously unexecuted real GMP inventory

```bash
bash -e <<'VERIFY'
: "${PHASE165_TOOLING:?}" "${PHASE165_ROOT:?}" "${PHASE162_ROOT:?}" "${GMP_ACQUISITION:?}" "${GMP_BUILD:?}"
export PYTHONPATH="$PHASE165_TOOLING/pytools"
python3 -m pytest -q -rs \
  "$PHASE165_TOOLING/pytools/tests/test_native_dependency_inventory.py" \
  "$PHASE165_TOOLING/pytools/tests/test_project_build_capture.py" \
  "$PHASE165_TOOLING/pytools/tests/test_native_audit_evidence.py" \
  "$PHASE165_TOOLING/pytools/tests/test_native_integer_translation.py" \
  "$PHASE165_TOOLING/pytools/tests/test_native_test_entry.py" \
  --basetemp="$PHASE165_ROOT/pytest" --junitxml="$PHASE165_ROOT/focused.xml" \
  > "$PHASE165_ROOT/focused.log" 2>&1
python3 "$PHASE165_TOOLING/experiment/inspect_native_dependencies.py" inventory \
  --candidate "$PHASE162_ROOT/candidate/candidate.json" \
  --records "$GMP_ACQUISITION/records.json" \
  --archive "$GMP_BUILD/.libs/libgmp.a" --output "$PHASE165_ROOT/dependencies" \
  > "$PHASE165_ROOT/dependencies.log" 2>&1
python3 "$PHASE165_TOOLING/experiment/inspect_native_dependencies.py" replay \
  --input "$PHASE165_ROOT/dependencies/result.json" --output "$PHASE165_ROOT/dependency-replay" \
  > "$PHASE165_ROOT/dependency-replay.log" 2>&1
VERIFY
VERIFY_STATUS=$?
printf 'phase165_status=%s\n' "$VERIFY_STATUS"
for NAME in focused.log dependencies.log dependency-replay.log; do
  if test -f "$PHASE165_ROOT/$NAME"; then cat "$PHASE165_ROOT/$NAME"; fi
done
```

Use original records.json, not build-actions.json. Expected: focused tests pass,
GMP dependency inventory and reconstruction run, external/variant obligations
remain visible. Their count is not hardcoded and is not an acceptance criterion.
Initial/replay blocker counts must agree when inputs remain unchanged.

### 2. New backend diagnosis and independent replay

Run independently of step 1 so a dependency-stage failure cannot suppress diagnosis.

```bash
bash -e <<'BACKENDS'
: "${PHASE165_TOOLING:?}" "${PHASE165_ROOT:?}" "${BASIS_ROOT:?}"
python3 "$PHASE165_TOOLING/experiment/inspect_native_dependencies.py" backends \
  --paths-file "$BASIS_ROOT/available-backend-paths.txt" --output "$PHASE165_ROOT/backends" \
  > "$PHASE165_ROOT/backends.log" 2>&1
python3 "$PHASE165_TOOLING/experiment/inspect_native_dependencies.py" replay-backends \
  --input "$PHASE165_ROOT/backends/result.json" --output "$PHASE165_ROOT/backend-replay" \
  > "$PHASE165_ROOT/backend-replay.log" 2>&1
BACKENDS
BACKEND_STATUS=$?
printf 'phase165_backend_status=%s\n' "$BACKEND_STATUS"
cat "$PHASE165_ROOT/backends.log" "$PHASE165_ROOT/backend-replay.log"
```

Expected with stale files: both commands exit zero, both show the same nonzero
blockerCount/affectedPathCount and status=blocked. Missing base manifests have
unavailable baseReferences, no spurious digest-mismatch diagnostic. A readable
base with wrong bytes remains a real mismatch. Do not expect old 70 to become zero;
changes in count due to more precise diagnostics do not restore backend validity.

### 3. Optional unchanged historical v1 replay

```bash
: "${PHASE164_ROOT:?}" "${PHASE165_TOOLING:?}" "${PHASE165_ROOT:?}"
python3 "$PHASE165_TOOLING/experiment/inspect_native_dependencies.py" replay-backends \
  --input "$PHASE164_ROOT/backends/result.json" --output "$PHASE165_ROOT/historical-backend-replay" \
  > "$PHASE165_ROOT/historical-backend-replay.log" 2>&1
HISTORICAL_STATUS=$?
printf 'historical_replay_status=%s\n' "$HISTORICAL_STATUS"
cat "$PHASE165_ROOT/historical-backend-replay.log"
```

Only run this if the host inputs bound by the old inventory are unchanged. For the
reported old case, successful replay still reports 70 blockers, not zero. Changed
inputs must fail rather than being reinterpreted under the v2 projection.

Return focused.log, dependencies/result.json, backends/result.json, both replay
logs and any failing run-status.json. These reports replace the need for further
manual repeated path searches or large mixed terminal transcripts.

## Backend recovery and next program milestones

Missing historical runtime artifacts are not repairable by changing diagnostic
code or refreshing hashes. Preserve old manifests and their results. With the v2
file/owner detail, prepare only capabilities required by the selected program route
in new exclusive directories under the current implementation. Use the actual
matching QEMU source/header/toolchain provenance, rebuild plugins where required,
and run the registered positive/negative calibration. Bound implementation changes
require new preparation; unrelated host headers or stale labels are not evidence.
Do not rebuild every historical atomic/system backend merely to make this inventory
empty. This command intentionally cannot run arbitrary recipes from JSON.

After the repair passes, continue selecting exact build variants and target
providers, establish compatible target data/runtime ABI and dependency builds,
authorize actual translated symbol linkage, and connect call/object/effect evidence
and actual instance execution to program-level comparison and independent audit.
Those are separate remaining features, not completed by this diagnostic repair.
The existing native baseline and local candidate proof remain bounded evidence;
they do not grant whole-program or physical-microarchitecture equivalence.

## Local validation

The dependency/backend focused suite passed 41 tests. The broader native/project,
operand-relation, function-type and call-inventory/dependency regression passed
427 tests with 10 explicit integration skips in 30.94 seconds. The skipped tests
require real Clang, RISC-V GCC and/or the built frontend, which are unavailable
in this editing environment. They must run on the user's provisioned host before
claiming host integration success. Python compilation and git diff --check passed.

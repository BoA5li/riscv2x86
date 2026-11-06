# Phase164: replayable dependency evidence for native project candidates

Base: `fc3e92da7ad66ffdea4b977e10b7c99779cc989a` (Phase163).

## What this revision implements

This is a source provenance/dependency and backend availability revision. It does
not complete the GMP program translation/evaluation route. No legacy acceptance,
translation, semantic proof, or backend calibration gate is relaxed. Existing
Phase162 candidates and original build records remain unchanged.

The host evidence identifies a successful official RV64 test baseline and a
locally proved x86 integer candidate. It does not identify a linked translated
x86 test, a complete call/object/effect contract, or observed translated execution.
The dependency-source diagnostic had skipped `assemble` actions. Matching only
member basenames also cannot distinguish renamed members or PIC variants.

New `experiment/inspect_native_dependencies.py` operations:

* `inventory`: validate the original records identity, independently replay the
  capture, check the candidate artifact identities, parse the actual regular ar
  archive and ELF64-LE objects, bind member bytes to successful captured outputs,
  and traverse conservative object-level symbol dependencies from source.o.
* `replay`: reconstruct and compare the entire inventory from its live inputs.
* `backends`: read the explicitly listed JSON manifests, diagnose missing or
  malformed input, follow registered baseBackendPath references, and check bound
  file hashes. It never runs a command from a backend document.
* `replay-backends`: repeat that static inspection and compare the result.

A completed inventory may contain blockers. Exit zero means the inventory was
produced, not that the program is eligible, linked, observed or accepted. Result
and outer run status always retain false semanticApproval/productionAcceptanceComplete.
Errors retain a failed outer status and emit no result.json success artifact.
Outputs are exclusive new directories; existing results are never overwritten.

## Evidence policy

Regular GNU/BSD ar names are decoded as data, never extracted into paths. Thin
archives, malformed ranges/name tables and unsupported ELF forms fail. Members
with equal names or content retain their physical offset identity. Content matches
retain *all* captured build actions; multiple matches remain a variant-selection
obligation. compile/assemble/copy outputs are considered, including differently
named objects. All inspected provider files and principal inputs are rechecked
at closing. A replayed historical capture does not establish complete process-tree
observation or historical archive membership that was never captured.

Object symbol reachability is deliberately conservative. It is not the GNU ld
archive selection algorithm. Weak/common/unique symbols, ambiguous providers,
external references, unbound selected members and architecture/ABI-flag differences
remain visible obligations. Source/target exported symbol signatures are compared;
this is **not** a compiler-type, calling-convention or object-domain proof.

Future captures additionally observe output path/content for an explicit narrow
regular-ar write grammar (r/q with supported modifiers). Unsupported options,
response-file forms and thin archives remain unknown. Existing captures are not
rewritten to invent missing archive observations. Replay continues to consume
what each old capture actually recorded.

The latest uploaded backend text begins mid-JSON and contains system build-profile
fragments, not eight complete backend manifests. It is not admissible calibration
evidence. The new command reads the original host files directly. A static hash
match still does not validate a backend's schema-specific mechanism or calibration.

## Host validation

Keep the old worktrees, candidates, captures and baseline directories in place.
The real cross-compiler integration tests need the same RV2X86_SYSTEM_CLANG,
RV2X86_TEST_RISCV_CC and RISCV2X86_TEST_FRONTEND as Phase163. Use a new worktree path
if the proposed one already exists; do not delete a bound old worktree.

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE163_ROOT:?}" "${GMP_BUILD:?}" "${GMP_ACQUISITION:?}" "${BASIS_ROOT:?}"
git -C "$REPO" fetch origin phase164-native-dependency-evidence
export PHASE164_TOOLING="$PREP_ROOT/tooling-phase164"
git -C "$REPO" worktree add --detach "$PHASE164_TOOLING" origin/phase164-native-dependency-evidence
export PHASE164_ROOT="$(mktemp -d "$PHASE163_ROOT/phase164-XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
printf 'PHASE164_ROOT=%s\n' "$PHASE164_ROOT"
```

Run checks, inventory and independent reconstruction. Use the original records.json,
not build-actions.json (the latter is only an analysis projection without capture
closure). The inventory reads files and capture records; it does not configure,
compile, link or run GMP, and does not repeat the official baseline.

```bash
bash -e <<'VERIFY'
: "${PHASE164_TOOLING:?}" "${PHASE164_ROOT:?}" "${PHASE162_ROOT:?}" "${GMP_ACQUISITION:?}" "${GMP_BUILD:?}"
export PYTHONPATH="$PHASE164_TOOLING/pytools"
python3 -m pytest -q -rs \
  "$PHASE164_TOOLING/pytools/tests/test_native_dependency_inventory.py" \
  "$PHASE164_TOOLING/pytools/tests/test_project_build_capture.py" \
  "$PHASE164_TOOLING/pytools/tests/test_native_audit_evidence.py" \
  "$PHASE164_TOOLING/pytools/tests/test_native_integer_translation.py" \
  "$PHASE164_TOOLING/pytools/tests/test_native_test_entry.py" \
  --basetemp="$PHASE164_ROOT/pytest" --junitxml="$PHASE164_ROOT/focused.xml" \
  > "$PHASE164_ROOT/focused.log" 2>&1
python3 "$PHASE164_TOOLING/experiment/inspect_native_dependencies.py" inventory \
  --candidate "$PHASE162_ROOT/candidate/candidate.json" \
  --records "$GMP_ACQUISITION/records.json" \
  --archive "$GMP_BUILD/.libs/libgmp.a" --output "$PHASE164_ROOT/dependencies" \
  > "$PHASE164_ROOT/dependencies.log" 2>&1
python3 "$PHASE164_TOOLING/experiment/inspect_native_dependencies.py" replay \
  --input "$PHASE164_ROOT/dependencies/result.json" --output "$PHASE164_ROOT/dependency-replay" \
  > "$PHASE164_ROOT/dependency-replay.log" 2>&1
VERIFY
VERIFY_STATUS=$?
printf 'phase164_status=%s\n' "$VERIFY_STATUS"
for NAME in focused.log dependencies.log dependency-replay.log; do
  if test -f "$PHASE164_ROOT/$NAME"; then cat "$PHASE164_ROOT/$NAME"; fi
done
```

Inspect backends independently (a dependency error should not suppress its diagnosis):

```bash
bash -e <<'BACKENDS'
: "${PHASE164_TOOLING:?}" "${PHASE164_ROOT:?}" "${BASIS_ROOT:?}"
python3 "$PHASE164_TOOLING/experiment/inspect_native_dependencies.py" backends \
  --paths-file "$BASIS_ROOT/available-backend-paths.txt" --output "$PHASE164_ROOT/backends" \
  > "$PHASE164_ROOT/backends.log" 2>&1
python3 "$PHASE164_TOOLING/experiment/inspect_native_dependencies.py" replay-backends \
  --input "$PHASE164_ROOT/backends/result.json" --output "$PHASE164_ROOT/backend-replay" \
  > "$PHASE164_ROOT/backend-replay.log" 2>&1
BACKENDS
BACKEND_STATUS=$?
printf 'phase164_backend_status=%s\n' "$BACKEND_STATUS"
cat "$PHASE164_ROOT/backends.log" "$PHASE164_ROOT/backend-replay.log"
```

Return both result.json files and logs. If a stage fails, return that directory's
run-status.json; never change stored hashes or recapture old builds to erase it.
The GMP inventory is expected to retain external/variant/link obligations. Source
object traversal may select approximately the earlier 19 members, but this count
is not an acceptance threshold and is never hardcoded in the implementation.

## Remaining implementation and order

1. Select exact archive/build variants and generated-source provenance using
   the action graph, rather than equal-name/equal-byte guessing.
2. Build target dependencies under an explicit compatibility contract: integer
   model, limb/nail data, public/internal layouts and platform runtime ABI.
   Resolve source libc-specific declarations, fortify and stack-protector symbols
   through contracts; do not copy RV config.h or delete protective checks.
3. Choose static versus shared target experiment explicitly. A PIC variant must
   be generated and independently bound if needed, rather than silently mutating
   the already audited object. Keep source and target build plans separate.
4. Extend typed call/object/effect evidence from the official public entry to
   the translated internal implementation: array bounds, scratch via itch,
   alias/lifetime, normalization and result propagation. Shared C syntax alone
   is not a whole-function proof. Unsupported behavior remains blocked.
5. Authorize final target links and verify actual symbol provenance and runtime
   library selection. Auxiliary native x86 dependencies are declared assumptions,
   never counted as translator-produced coverage.
6. Extend/calibrate the observation route for actual library code, dynamic calls,
   instance coverage and required object outputs. Old atomic/control/system backend
   labels do not substitute for this capability.
7. Integrate program-level L0--L3 and independent audit. Official test return zero
   is supporting evidence, not sole equivalence authority. Include negative cases
   for substituted providers, wrong ABI/layout, changed artifacts, missing events,
   skipped regions, failed executions and rehashed false completion claims.

Original-header macro rewriting remains a separate provenance/authorization task.
Frozen derived-input translation does not grant permission to edit longlong.h.
These remaining features are not implemented by this revision and no report
marks them complete. The user need not collect more baseline logs to start that
work; real target build/observation evidence must be obtained during its implementation.

## Validation performed

Scoped existing native/project/compiler regression: **410 passed, 10 skipped**.
Focused new dependency/backend plus existing capture regression: **43 passed**.
Real native GCC/ar tests cover transitive providers, assemble classification,
PIC/action identity ambiguity, stale outputs, long/duplicate/BSD archive names,
malformed archives/ELF, weak/common symbols, and actual new archive output capture.
Backend tests cover missing/truncated/forged manifests, base references, file
changes and replay. CLI tests check failed outer state and missing-manifest replay.
One receipt-plumbing test changes native ELF machine header values synthetically;
it is explicitly not cross-ISA execution evidence. The skipped integrations need
real Clang, RV64 GCC and the built frontend on the user's host.

# Phase161: native callee resolution and reproducible development evidence

Base: `phase160-native-instance-and-call-context-binding`,
`e2de99ed6e71ba9f1a4d01b8bec3e8d6d64425d5` (tree
`cc481918eec789310a617274c901b35d3880c22a`).

## Implemented behavior

* Native call-context v2 recognizes the compiler's `BuiltinFnToFnPtr` conversion.
  A `FunctionDecl` reference is still required. Parentheses and modeled NoOp
  conversions preserve evidence; arbitrary casts, function-pointer variables and
  malformed callees do not become direct calls. Reserved-looking names without
  builtin conversion evidence do not grant builtin authority.
* Builtins have their own `builtin-contract-required` class, never an invented
  external symbol or an automatically approved in-TU implementation. Every
  argument AST, result type, conversion chain and declaration reference is kept.
  The constant-query and branch-expectation contracts enumerate outstanding
  obligations; they do not replace GCC's constant evaluation with Clang's.
  Unknown builtins remain explicit obligations.
* Existing v1 bundles validate/replay using the original v1 classification and
  identities. New acquisitions default to v2. Unknown schemas fail closed.
* `development-basis` validates the frozen bundle and captured build records,
  rederives v2 contexts, exports every reachable unresolved call with argument,
  parent-expression and declaration ASTs, and records object/control syntax.
  All instances and global-effect candidates remain accounted for. It does not
  assume that a local temporary's initializer is memory-free or an output dead.
* Every captured link is reported, not just a print limit. Explicit output paths
  are resolved relative to each action cwd. Available output ELF machine/type,
  defined-main presence and content digest are recorded. Tool names do not
  establish artifact architecture. A main symbol, ET_DYN or successful link is
  not test-entry authority, legal input evidence or a full link closure. Missing
  files, ambiguous output options and response files stay diagnostic blockers.
  The current ELF snapshot is explicitly not historical output binding.
* `replay-development-basis` rederives and strictly compares every field from
  validated stored evidence and current link artifacts. It is NOT a fresh
  compiler replay; use `replay-bindings` for that. Rehashing edited flags,
  arguments, omitted calls or requirement lists cannot approve a result.

## Remaining work (not claimed complete)

This revision repairs a demonstrated classification defect and automates the
next evidence acquisition. It does not implement composition proof, original
macro rewrite/provenance, target edit authorization, a general eight-parameter
object harness, or native-input production L0--L3 integration. Existing
production gates are unchanged. All semantic, edit and production flags stay
false. A derived-TU route may be implemented before original macro rewriting,
but must explicitly label its input domain and preserve/prove the surrounding C.

The current GMP experiment has one selected native asm occurrence; successful
binding does not certify all 344 recorded occurrences. Its 25 formerly
unclassified callees are 24 constant queries and one branch-expectation call.
They must become builtin obligations, not disappear. Existing external-call
obligations and recursion/effect/ABI obligations remain.

Original captures have seven host code generators and one RISC-V shared-library
link. These are not eight target tests. The remaining entry evidence must come
from a selected official test driver, legal inputs/objects, source and target
builds, and actual execution. Do not replace pointer contracts with guessed
buffers or label native x86 GMP fallback code as translated code.

## Host validation: isolated tooling and guarded variables

Run in the existing venv. Keep old receipt paths: copying/moving hash-bound
artifacts is not a repair. These scripts never delete prior results. If a
worktree already exists, inspect its HEAD before reusing it instead of running
worktree add again.

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${BIND_ROOT:?}" "${GMP_BUILD_RECORDS:?}"
git -C "$REPO" fetch origin phase161-native-call-obligations-and-entry-basis
export NEXT_TOOLING="$PREP_ROOT/tooling-phase161"
git -C "$REPO" worktree add --detach "$NEXT_TOOLING" origin/phase161-native-call-obligations-and-entry-basis
export PYTHONDONTWRITEBYTECODE=1
export PHASE161_ROOT="$(mktemp -d "$BIND_ROOT/phase161-XXXXXX")"
```

Execute the following as one block. A nonzero exit stops later stages; logs are
inside the new directory. Do not read `/focused.log` or another old root log.

```bash
bash -e <<'RUN'
: "${NEXT_TOOLING:?}" "${PHASE161_ROOT:?}" "${BIND_ROOT:?}" "${GMP_BUILD_RECORDS:?}"
export PYTHONPATH="$NEXT_TOOLING/pytools"
test -f "$BIND_ROOT/first/binding-bundle.json"
test -f "$GMP_BUILD_RECORDS"
python3 -m pytest -q -rs \
  "$NEXT_TOOLING/pytools/tests/test_native_call_obligations.py" \
  "$NEXT_TOOLING/pytools/tests/test_native_instance_binding.py" \
  "$NEXT_TOOLING/pytools/tests/test_project_native_input.py" \
  "$NEXT_TOOLING/pytools/tests/test_project_macro_preflight.py" \
  "$NEXT_TOOLING/pytools/tests/test_project_build_contract.py" \
  "$NEXT_TOOLING/pytools/tests/test_project_type_replay.py" \
  --basetemp="$PHASE161_ROOT/pytest" \
  --junitxml="$PHASE161_ROOT/focused.xml" > "$PHASE161_ROOT/focused.log" 2>&1
python3 "$NEXT_TOOLING/experiment/preflight_project_macros.py" development-basis \
  --bundle "$BIND_ROOT/first/binding-bundle.json" --records "$GMP_BUILD_RECORDS" \
  --output "$PHASE161_ROOT/development.json" > "$PHASE161_ROOT/development.log" 2>&1
python3 "$NEXT_TOOLING/experiment/preflight_project_macros.py" replay-development-basis \
  --input "$PHASE161_ROOT/development.json" > "$PHASE161_ROOT/development-replay.log" 2>&1
RUN
PHASE161_STATUS=$?
printf 'phase161_status=%s\nroot=%s\n' "$PHASE161_STATUS" "$PHASE161_ROOT"
cat "$PHASE161_ROOT/focused.log" "$PHASE161_ROOT/development.log" "$PHASE161_ROOT/development-replay.log"
```

The real compiler test requires RV2X86_SYSTEM_CLANG,
RV2X86_TEST_RISCV_CC and RISCV2X86_TEST_FRONTEND. It now tests real builtin
classification as well as asm binding. A skip is not a pass for that integration.
For the known GMP context, expect 25 builtin obligations instead of the former
25 indirect-call obligations; retain all external obligations. Zero exit on the
development report means acquisition success, not semantic acceptance.

For a fresh v2 compiler export, set NATIVE_INPUT_RECEIPT to the existing receipt
and run both commands sequentially (use the already built frontend):

```bash
bash -e <<'FRESH'
: "${NEXT_TOOLING:?}" "${PHASE161_ROOT:?}" "${NATIVE_INPUT_RECEIPT:?}" "${RISCV2X86_TEST_FRONTEND:?}"
export PYTHONPATH="$NEXT_TOOLING/pytools"
python3 "$NEXT_TOOLING/experiment/preflight_project_macros.py" bind-native \
  --native-input-receipt "$NATIVE_INPUT_RECEIPT" --frontend "$RISCV2X86_TEST_FRONTEND" \
  --output "$PHASE161_ROOT/fresh" --timeout-seconds 300 > "$PHASE161_ROOT/fresh.log" 2>&1
python3 "$NEXT_TOOLING/experiment/preflight_project_macros.py" replay-bindings \
  --bundle "$PHASE161_ROOT/fresh/binding-bundle.json" \
  --output "$PHASE161_ROOT/fresh-replay" --timeout-seconds 300 > "$PHASE161_ROOT/fresh-replay.log" 2>&1
FRESH
```

## Acquire an official test build before declaring a formal entry

Inspection of the pinned, unmodified GMP 6.3.0 release shows
`tests/mpz/t-powm.c` calls `mpz_powm_sec` and performs reference-result checks;
its `Makefile.am` links `tests/libtests.la` and `libgmp.la`. This makes it an entry
CANDIDATE, not proof that a run reaches this exact internal asm or satisfies its
complete input and observation contract. Verify actual linkage/path later.
No test source changes, reduced repetitions or relaxed comparisons are proposed.

Use the existing successful GMP acquisition directory (not the translator's
own build directory). The following only builds this official candidate and
captures its commands. It does not run the RISC-V executable or claim translation
success. Stage names must be new. Building it may also build its test support
library. Existing objects can result in zero new compiler invocations: retain
that outcome; do not manufacture records or delete the old build to hide it.

```bash
export GMP_ACQUISITION="$(dirname "$GMP_BUILD_RECORDS")"
bash -e <<'ENTRY'
: "${NEXT_TOOLING:?}" "${PHASE161_ROOT:?}" "${GMP_ACQUISITION:?}"
export PYTHONPATH="$NEXT_TOOLING/pytools"
test -f "$GMP_ACQUISITION/capture/capture.json"
test -f "$GMP_ACQUISITION/source.json"
test -f "$GMP_ACQUISITION/build/tests/mpz/Makefile"
python3 "$NEXT_TOOLING/experiment/capture_project_build.py" run \
  --capture "$GMP_ACQUISITION/capture/capture.json" \
  --stage official-test-entry-phase161 --cwd "$GMP_ACQUISITION/build" \
  --source-proof "$GMP_ACQUISITION/source.json" \
  --input "$GMP_ACQUISITION/build/config.h" \
  --input "$GMP_ACQUISITION/build/gmp.h" \
  --input "$GMP_ACQUISITION/build/Makefile" \
  --input "$GMP_ACQUISITION/build/tests/Makefile" \
  --input "$GMP_ACQUISITION/build/tests/mpz/Makefile" -- \
  make -C "$GMP_ACQUISITION/build/tests/mpz" -j1 V=1 t-powm \
  > "$PHASE161_ROOT/official-test-build.log" 2>&1
python3 "$NEXT_TOOLING/experiment/capture_project_build.py" import \
  --capture "$GMP_ACQUISITION/capture/capture.json" \
  --stage official-test-entry-phase161 --output "$PHASE161_ROOT/official-test-records.json" \
  > "$PHASE161_ROOT/official-test-import.log" 2>&1
ENTRY
ENTRY_STATUS=$?
printf 'official_test_capture_status=%s\n' "$ENTRY_STATUS"
cat "$PHASE161_ROOT/official-test-build.log" "$PHASE161_ROOT/official-test-import.log"
```

If building fails, preserve the failure and import that stage separately to
retain partial records; do not proceed to semantic acceptance. Supply
`development.log`, `development-replay.log`, `official-test-build.log`,
`official-test-import.log` and all link actions from official-test-records.json.
The official test's own result check alone is not L0--L3 or independent audit.

## Validation performed in the implementation environment

* Native binding + call-obligation tests: 52 passed, 1 skipped.
* Native/project acquisition regression: 273 passed, 7 skipped.
* GNU relations, compiler types and call dependency contracts: 67 passed,
  6 skipped.
* Skips are explicit missing Clang, cross GCC/frontend integrations, not accepted
  target executions. The native GCC ELF-inspection integration ran.
* Negative tests cover unknown casts, variable callees, unknown builtins, arity,
  apparent builtin definitions, name-only spoofing, v1 compatibility, edited or
  omitted obligation evidence, false approval claims, ambiguous/response-file
  output paths, and misleading compiler names versus actual ELF machine.

# Phase147: reproducible real-project acquisition and build contexts

Base: remote Phase146 `bd8b3942f438db75d7990c3b78bbccf87f18f18e`.
The Phase146 corpus and its filtering policy are unchanged. This branch adds an
opt-in experimental preparation interface; it does **not** assert that real musl,
GMP or Linux entries now have end-to-end translation coverage.

## Delivered behavior

- POSIX backslash-newline reconstruction before tokenization, with physical line
  ranges and the input log digest. The musl shared-library link spanning physical
  lines 2779–2780 is a link action, not a missing compile action.
- Separate compile, assembly, preprocessing, link, archive, ranlib and copy
  observations. Unknown progress/diagnostic lines are retained. Recipes needing
  shell expansion, cwd transitions or wrappers are unresolved. A recovered
  command has no observed exit status: a successful import does not certify a
  successful native build.
- Compilation database `arguments` are preferred to command strings. Relative
  working directories are rejected. Native argv, cwd, source/driver bytes,
  environment and output variants are retained. Unsupported semantic flags stay
  explicit blockers; response files and plugins are not executed implicitly.
- Clang inspection keeps semantic flags, their order, relative include paths and
  cwd. Excluded output/diagnostic options are recorded. This is an explicit
  inspection projection, **not** GCC/Clang semantic equivalence. If the installed
  Clang cannot consume an option, inspection fails with its actual diagnostic.
- Existing dependency scans surround AST acquisition. Dependency content and
  tool/environment bindings are replayed. New project function identities include
  compile context and dependency identities; old source-only identities are not
  reinterpreted as project proof identities.
- Optional compiler type discovery retains primary-file floating, static and
  unclassified functions rather than treating integer harness eligibility as the
  source-function denominator. Header definitions require real TU inclusion and
  entry adapters, not standalone header compilation.
- Native compilation replay retains original native semantic/optimization flags,
  redirects object/dependency outputs into a fresh directory and checks dependency
  consistency. It does not link, translate or certify L0–L3. Original build objects
  and logs are not overwritten.
- The new download command catches interrupted HTTP reads, retries/falls back
  only to locked URLs, hashes complete bytes before atomically publishing, checks
  cached archives, and preserves per-project failures. It never accepts truncated
  archives or overwrites a corrupt cache entry.

## Required distinctions / remaining implementation

| State | Meaning |
|---|---|
| `context_ready` | A known inspection recipe can be constructed. No compiler execution has been certified. |
| `inspected` | Contextual Clang AST/dependency acquisition completed. No equivalence approval. |
| `blocked` | A required context component/argument is unsupported or missing. |
| `inspection_failed` | The actual compiler invocation failed. Read its stderr before attributing a translator semantic error. |
| `nativeCompileReplayed` | The source compiled with the recorded native recipe into a fresh object. No translated object or link proof. |

The legacy automatic runner still constructs its own default compilation and
execution profiles. Feeding a context-inspected project source to that runner
would not establish verification of the original project configuration.
`PROJECT_END_TO_END_CONTEXT_ROUTE_REQUIRED` therefore remains explicit on every
new instance. Context plumbing through frontend candidate extraction, source and
target builds, L0/L1/L2/L3 obligations, actual-symbol execution and independent
acceptance still needs implementation and validation before this gap is closed.

The four musl `fabs/fabsf/sqrt/sqrtf` entries expose a separate absent capability:
compiler floating types are now visible, but this branch supplies no floating
translation proof, floating ABI bridge, `frm`/`fflags` observation, FSQRT rounding
refinement or floating L3 acceptance route. The source FSQRT words have dynamic
rounding; ignoring RMM, sticky exception state or NaN behavior is not a valid
repair. A successful native or AST scan must not count as successful translation.
Similarly CAS, TLS, syscalls and relocation/control entries retain their own
semantic and environment prerequisites. No original source is changed to fit an
existing fetch-add or integer-only route.

## Verification on the user host

Run each block separately in Bash. Set `MUSL_RUN_ROOT` to the existing native
build directory, not a newly extracted tree. No earlier output is overwritten.

```bash
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG=/usr/lib/llvm-10/bin/clang
export MUSL_RUN_ROOT="$REPO/experiment/results/real-project-eval-HloKpA/musl-native-IEqkaH"
export MUSL_SRC="$MUSL_RUN_ROOT/upstream/musl-1.2.5"
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase147-XXXXXX")"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
```

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_project_build_records.py \
  pytools/tests/test_compiler_function_types.py \
  pytools/tests/test_project_archive_acquisition.py \
  pytools/tests/test_compiler_call_dependencies.py \
  pytools/tests/test_compiler_call_inventory.py \
  pytools/tests/test_real_project_corpus.py \
  pytools/tests/test_whole_project_corpus.py \
  pytools/tests/test_filter_rv64_c_corpus.py \
  --junitxml="$CHECK_ROOT/focused.xml" > "$CHECK_ROOT/focused.log" 2>&1
TEST_STATUS=$?
printf 'focused_status=%s\n' "$TEST_STATUS"
tail -n 80 "$CHECK_ROOT/focused.log"
```

```bash
python3 experiment/prepare_real_project_experiment.py import-log \
  --log "$MUSL_RUN_ROOT/build.log" \
  --working-directory "$MUSL_RUN_ROOT/build" \
  --output "$CHECK_ROOT/build-records.json" \
  > "$CHECK_ROOT/import.log" 2>&1
IMPORT_STATUS=$?
printf 'import_status=%s\n' "$IMPORT_STATUS"
cat "$CHECK_ROOT/import.log"
```

Inspect `unresolved` and `unclassifiedLines` in the JSON, even if exit status is
zero. The previous 2699-record extractor counted all compiler `-c` actions;
compare `compile + assemble`, not just `compile`. Exact counts must follow the
actual full log. A successful importer does not prove the full build log is
complete or that every command succeeded.

```bash
python3 experiment/prepare_real_project_experiment.py inspect \
  --records "$CHECK_ROOT/build-records.json" \
  --source "$MUSL_SRC/src/math/riscv64/fabs.c" \
  --source "$MUSL_SRC/src/math/riscv64/fabsf.c" \
  --source "$MUSL_SRC/src/math/riscv64/sqrt.c" \
  --source "$MUSL_SRC/src/math/riscv64/sqrtf.c" \
  --output "$CHECK_ROOT/contexts.json" \
  > "$CHECK_ROOT/contexts.log" 2>&1
CONTEXT_STATUS=$?
printf 'context_status=%s\n' "$CONTEXT_STATUS"
cat "$CHECK_ROOT/contexts.log"
```

For this native build, expect four distinct sources and eight `.o`/`.lo` build
variants, provided all eight commands exist in the full log. These are not eight
independent source functions or eight verified translations.

```bash
python3 experiment/prepare_real_project_experiment.py native-build \
  --report "$CHECK_ROOT/contexts.json" \
  --output "$CHECK_ROOT/native-replay" \
  > "$CHECK_ROOT/native-replay.log" 2>&1
NATIVE_STATUS=$?
printf 'native_status=%s\n' "$NATIVE_STATUS"
cat "$CHECK_ROOT/native-replay.log"
```

Then request contextual Clang acquisition explicitly. This may expose a GCC-only
option or an ABI/header compatibility gap; preserve the resulting diagnostic.
Do not delete options until inspection succeeds.

```bash
python3 experiment/prepare_real_project_experiment.py inspect \
  --records "$CHECK_ROOT/build-records.json" \
  --source "$MUSL_SRC/src/math/riscv64/fabs.c" \
  --source "$MUSL_SRC/src/math/riscv64/fabsf.c" \
  --source "$MUSL_SRC/src/math/riscv64/sqrt.c" \
  --source "$MUSL_SRC/src/math/riscv64/sqrtf.c" \
  --clang "$RV2X86_SYSTEM_CLANG" \
  --output "$CHECK_ROOT/inspections.json" \
  > "$CHECK_ROOT/inspections.log" 2>&1
INSPECT_STATUS=$?
printf 'inspection_status=%s\n' "$INSPECT_STATUS"
cat "$CHECK_ROOT/inspections.log"
```

If inspection succeeds, independently reacquire the dependencies and derived
facts; raw Clang AST allocation IDs are not stable and are not used for equality.

```bash
python3 experiment/prepare_real_project_experiment.py replay \
  --report "$CHECK_ROOT/inspections.json" \
  > "$CHECK_ROOT/context-replay.log" 2>&1
REPLAY_STATUS=$?
printf 'context_replay_status=%s\n' "$REPLAY_STATUS"
cat "$CHECK_ROOT/context-replay.log"
```

For missing archives, the new acquisition path is:

```bash
python3 experiment/prepare_real_project_experiment.py download \
  --lock "$REPO/experiment/corpora/real-projects-v1/sources.lock.json" \
  --directory "$REPO/experiment/results/real-project-archives" \
  --project gmp --attempts 2
```

Do not run a long production matrix or report corpus translation rates from these
preflight states. Return the import summary, unresolved records, contexts and
inspection failures first; these distinguish ingestion/context bugs from genuine
translation/verification capability gaps.

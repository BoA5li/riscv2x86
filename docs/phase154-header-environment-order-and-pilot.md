# Phase154: include-environment ordering and a closed compiler pilot

Base: `5cfc01afd7a8bdb3b593ea0ef055f456432d83f4` (Phase153).

## Continued repair

Phase153's header projection retained `C_INCLUDE_PATH` as an automatic compiler
environment entry while adding builtin paths with explicit `-isystem`. GCC puts
automatic C include paths after explicit system paths, so this could move a
legitimate environment path behind builtin headers and trigger a conservative
order mismatch. A real native GCC reproduction confirmed this before the fix.

Keep `CPATH` in its non-system environment role. Mirror compiler-reported
`C_INCLUDE_PATH` positions explicitly in the ordered system chain, before builtin
paths. The unchanged environment's duplicate is deduplicated by the compiler.
No guessed path, environment mutation, search-order relaxation or CPP tolerance
is introduced. Existing strict effective-order comparison and independent replay
remain. Real GCC regression covers an environment-only and a mixed explicit
`-I`/`-iquote`/`-isystem`/`CPATH`/`C_INCLUDE_PATH` layout. Clang/RISC-V checks still
require the host toolchain; native GCC comparison is not Clang acceptance.

The new `run_project_inspection_pilot.py` entry consumes the SAME saved pilot
plan, records its bytes and the build inventory/tool identities, runs contextual
inspection, verifies the exact context/source set (no omissions or duplicates),
and invokes independent context replay in a separate process. First failure
stops the workflow and persists a stage status/log. A parser returning zero is
insufficient if members were lost. Zero primary-function asm syntax is not a
complete macro/asm inventory. Even completion retains:

- `semanticApproval: false`
- `productionAcceptanceComplete: false`
- `asmInstanceInventoryComplete: false`
- `endToEndEligibilityAssessed: false`

This remains compiler acquisition, not L0–L3, general macro/ABI/FP support or
Linux environment acceptance. Linux option/probe classification gaps remain.

## Host workflow: no native rebuild

The branch includes Phase153; do not create/rebuild old worktrees again.

```bash
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PREP_ROOT="$REPO/experiment/results/gmp-linux-prepare-Q0FqGS"
export TOOLING="$PREP_ROOT/tooling-phase154"
export VERIFY_ROOT="$REPO/experiment/results/project-build-phase152-CtODca/verification-TCA4lE"
export CORPUS_CHECK_ROOT="$VERIFY_ROOT/corpus-analysis-fzAdqI"
git fetch origin phase154-header-environment-order-and-pilot
git worktree add --detach "$TOOLING" origin/phase154-header-environment-order-and-pilot
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$TOOLING/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG=/usr/lib/llvm-10/bin/clang
export RV2X86_TEST_RISCV_CC=/usr/bin/riscv64-linux-gnu-gcc-7
export PILOT_CHECK_ROOT="$(mktemp -d "$CORPUS_CHECK_ROOT/phase154-XXXXXX")"
printf 'PILOT_CHECK_ROOT=%s\n' "$PILOT_CHECK_ROOT"
```

Only add the worktree on first setup. Existing result directories are protected;
never remove old receipts or overwrite prior failed experiment output.

### 1. Focused tests

```bash
python3 -m pytest -q -rs \
  "$TOOLING/pytools/tests/test_project_header_search.py" \
  "$TOOLING/pytools/tests/test_project_inspection_pilot.py" \
  "$TOOLING/pytools/tests/test_compiler_call_dependencies.py" \
  "$TOOLING/pytools/tests/test_project_build_contract.py" \
  "$TOOLING/pytools/tests/test_project_build_records.py" \
  --junitxml="$PILOT_CHECK_ROOT/focused.xml" > "$PILOT_CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$PILOT_CHECK_ROOT/focused.log"
```

Proceed only if tests pass. The real RISC-V/Clang stdio test must run when the
reported compilers are present; do not hide a failed integration test with a skip.

### 2. Original four-context pilot plus member closure and independent replay

Do not resample by successful outcomes or run all 1008 contexts at this point.
Use the original plan generated before inspection failed:

```bash
python3 "$TOOLING/experiment/run_project_inspection_pilot.py" \
  --tooling "$TOOLING" \
  --records "$VERIFY_ROOT/gmp-native/records.json" \
  --plan "$CORPUS_CHECK_ROOT/gmp-pilot-plan.json" \
  --clang "$RV2X86_SYSTEM_CLANG" \
  --output "$PILOT_CHECK_ROOT/gmp-pilot" \
  > "$PILOT_CHECK_ROOT/gmp-pilot-driver.log" 2>&1
PILOT_STATUS=$?
printf 'pilot_status=%s\n' "$PILOT_STATUS"
cat "$PILOT_CHECK_ROOT/gmp-pilot-driver.log"
cat "$PILOT_CHECK_ROOT/gmp-pilot/run-status.json"
```

`gmp-pilot` must not exist before invocation. The saved plan's context IDs must
match the captured variants exactly. On failure return `run-status.json` and the
specified failing log tail; actual inspection failures remain in `contexts.json`.
If parsing failed, function/asm counts are unknown, not zero.

On success read `summary.json`, `contexts.json`, and `replay.log`. Only
`compilerInspectionComplete=true` and `independentContextReplayComplete=true`
close this diagnostic. No further native make/configure or separate manual
replay is needed. Actual activated asm/macros/call scopes and their semantic,
ABI, environment, machine-observation and production-audit contracts are still
required before a formal translation plan can run.

## Scope and evidence

A changed projection may invalidate old projected commands in environments with
`C_INCLUDE_PATH`; regenerate inspection evidence instead of rewriting its hashes.
No frozen corpus policy or source archive changed. Existing Phase152 native
build captures remain reusable and independently checked. The guarded pilot
checks acquisition and member closure, not the compiler implementation itself
or full input/path-space equivalence.

## Local verification

- Project/header/dependency/type regressions: 250 passed, 7 skipped (real Clang,
  RISC-V GCC or rebuilt frontend unavailable locally).
- Frozen corpus regressions: 92 passed.
- Native GCC reproduced the pre-fix environment-order mismatch and confirmed
  matched effective search order after the fix in both regression layouts.
- Pilot tests execute real child processes for failure/exit handling and reject
  missing/duplicate members, malformed plans and boolean replay counts. Mocked
  compiler reports are not production acceptance evidence.

# Phase152: original-project recipes, dependency checks and persistent stage failures

Base: `182db40fee7d53ddcdc7568b4e51f30557d228c0` (Phase151).

## Delivered scope and strict boundaries

This branch fixes the observed GMP configure error, Linux missing-build-tool
preflight, and missing top-level error summaries. It does **not** implement all
remaining macro, ABI, floating-point or native Linux-kernel translation routes.
Those gaps remain explicitly below; no blocked instance is marked supported.
Sources, frozen corpus policies, and L0–L3 acceptance standards are unchanged.

Verified source evidence from pinned GMP 6.3.0: `configure` initializes
`abilist="standard"`; the riscv64 branch does not replace that selector.
`ABI=64` was an acquisition recipe error, not a synonym for GCC LP64D. The new
argv uses `env -u ABI`, retains `-march=rv64gc -mabi=lp64d` and lets the original
configure choose its supported default. It does not force a different target or
disable assembly. Old manual Phase150 instructions have also been corrected.

Linux 6.6 `Kbuild` invokes `bc` to generate `include/generated/timeconst.h`.
Check selected tools before source scans/builds, recording resolved paths,
digests and safe version queries. No automatic package installation or claim of
all headers/libraries being available. Actual native commands remain decisive.

The Bash entry is now a thin compatibility wrapper. Python executes every stage
without a shell and persists `run-status.json` before and after the command.
Status binds commands, working directories, log paths, actual return codes and
implementation identity. Top-level stderr always names a failed stage and its
log. Signal termination is retained as the negative child status in evidence,
with conventional CLI exit mapping. This removes reliance on Bash ERR inheritance.

On native configure/prepare/build failure, export the existing capture under the
**failed stage**, even when no compiler invocation occurred. This diagnostic is
separate from normal successful-stage import/inspection. Its failure cannot
replace the original failure code. Do not label unexecuted diagnostic builds as
successful, applicable corpus instances or a completed production workflow.

Output directories remain exclusive. Existing results are never overwritten;
failed prerequisite checks preserve a status file and the dependency report.

## Host verification

Keep the old main checkout and its build/cache changes. New tools use a detached
worktree; reuse the verified original upstream/archives without modifying them.

```bash
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PREP_ROOT="$REPO/experiment/results/gmp-linux-prepare-Q0FqGS"
export ARCHIVE_ROOT="$REPO/experiment/results/real-project-archives"
export TOOLING="$PREP_ROOT/tooling-phase152"
git fetch origin phase152-project-acquisition-stage-contracts
git worktree add --detach "$TOOLING" origin/phase152-project-acquisition-stage-contracts
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$TOOLING/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG=/usr/lib/llvm-10/bin/clang
export PATH="/usr/lib/llvm-10/bin:$PATH"
export BUILD_BASIS="$(mktemp -d "$REPO/experiment/results/project-build-phase152-XXXXXX")"
printf 'BUILD_BASIS=%s\n' "$BUILD_BASIS"
```

Only use `git worktree add` on the first setup. If its path exists, verify its
commit and status rather than deleting it or mixing versions.

### 1. Short regression and dependency reports

```bash
python3 -m pytest -q -rs \
  "$TOOLING/pytools/tests/test_project_acquisition_driver.py" \
  "$TOOLING/pytools/tests/test_project_archive_stream.py" \
  "$TOOLING/pytools/tests/test_project_source_release.py" \
  "$TOOLING/pytools/tests/test_project_build_capture.py" \
  --junitxml="$BUILD_BASIS/focused.xml" > "$BUILD_BASIS/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 60 "$BUILD_BASIS/focused.log"
python3 "$TOOLING/experiment/check_project_build_dependencies.py" \
  --project gmp --project linux --output "$BUILD_BASIS/dependencies.json" \
  > "$BUILD_BASIS/dependencies.log" 2>&1
DEPENDENCY_STATUS=$?
printf 'dependency_status=%s\n' "$DEPENDENCY_STATUS"
cat "$BUILD_BASIS/dependencies.log"
```

Do not start acquisition until the required regressions and dependency checks
succeed. The reported host lacks `bc`. Install the genuine package through the
host's package manager (Ubuntu: `apt-get update` then `apt-get install bc`),
retaining that environment change; do not supply a dummy executable or a copied
`timeconst.h`. Rerun the report with a **new filename** after installation.
Source proof and full archive checks still run inside each acquisition.

### 2. GMP original build and Linux diagnostic (separate runs)

```bash
bash "$TOOLING/experiment/acquire_real_project_builds.sh" \
  "$TOOLING" "$PREP_ROOT" "$ARCHIVE_ROOT" "$BUILD_BASIS/gmp-native" gmp \
  > "$BUILD_BASIS/gmp-driver.log" 2>&1
GMP_STATUS=$?
printf 'gmp_acquisition_status=%s\n' "$GMP_STATUS"
cat "$BUILD_BASIS/gmp-driver.log"
cat "$BUILD_BASIS/gmp-native/run-status.json"
```

```bash
bash "$TOOLING/experiment/acquire_real_project_builds.sh" \
  "$TOOLING" "$PREP_ROOT" "$ARCHIVE_ROOT" "$BUILD_BASIS/linux-native" linux \
  > "$BUILD_BASIS/linux-driver.log" 2>&1
LINUX_STATUS=$?
printf 'linux_acquisition_status=%s\n' "$LINUX_STATUS"
cat "$BUILD_BASIS/linux-driver.log"
cat "$BUILD_BASIS/linux-native/run-status.json"
```

A new attempt needs a new result directory. Never reuse old capture manifests
because they bind implementation/tool versions. Linux still performs only
`defconfig -> prepare -> init/main.o`, preserving Kbuild LP64 and all its actual
options. This is not `vmlinux` execution or an experiment denominator.

### 3. Read the first actual failure; don't rerun blindly

Each project directory contains `prerequisites.json`, `run-status.json` and
stage logs. Native failures additionally produce `failure-capture.log` and, if
export is possible, `failure-records.json`. Parent/tool receipts remain in
`capture/`; incomplete or nonzero records are never discarded.

Return the status JSON and the failing stage log tail. On import/inspect
failures, include `import.log`, `inspect.log`, `records.json` unresolved reasons
and the context blockers. Unknown semantic compiler flags stay blocked; do not
remove them to force an AST or change Kbuild to LP64D. The native build may
succeed while contextual inspection still fails; these are separate outcomes.

Only `status=complete` and `acquisitionComplete=true` mean these acquisition
stages completed. `semanticApproval` and `productionAcceptanceComplete` remain
false in every case. Real project translation still requires an explicit
project plan, closed semantics/call/environment contracts, L0–L3 and independent
production audit. Do not run a recursive source-directory sweep as a substitute.

## Remaining coverage work, not delivered capabilities

| Work package | Concrete consumers | Required closed evidence |
| --- | --- | --- |
| Macro source graph and safe edits | `Classifier.cpp`, `compiler_call_inventory`, candidate application | PP callback expansion/definition/argument graph, all affected instances, compiler-bound staging edits and unchanged unrelated tokens |
| GNU commutative constraints | `gnu_operand_contract`, candidate/target/L2 consumers | Adjacent-input relation and allowed permutations; do not strip `%` or grant approval from parsing |
| Typed ABI and reachable function effects | `compiler_function_types`, `register_call_abi`, scalar/memory/atomic deployments, project linking | Compiler structural types, location/stack/hidden-return contract, objects/aliases, all reachable body and library effects, machine attribution |
| Floating-point semantics and state | `compiler_floating_type`, proof/renderer/runtime/observation/audit consumers | ISA-version/format/rounding/flags/NaN contracts, target refinement, actual bit/state observation and independent replay |
| Kernel execution domains | `system_build_profile`, `controlled_system_scope`, `l3_system_route`, L0 profiles | Per-domain privilege/address-space/link/runtime contract; bounded M-mode route is not Linux S-mode or full kernel equivalence |
| Corpus activation and final accounting | project captured variants, immutable corpus source positions, evaluation ledger | Actual configuration/TU/expansion/call closure binding, no success-based denominator, all failures retained |

Current host logs establish the two recipe/dependency failures, not the missing
semantic proofs above. Generic code design can proceed, but completing these
work packages requires real activation/type/call evidence and reviewed source/
target semantic/environment contracts. Adding names, broad flag allowlists or
asserting absent effects would be unsound. No capability flag was relaxed here.

## Local checks

- Project/context and associated compiler tests: 224 passed, 6 skipped for real
  Clang or rebuilt frontend, unavailable locally.
- Native subprocess failures, missing dependencies, stale result protection,
  actual `env -u ABI`, original failure vs diagnostic failure, and signals tested.
- Immutable corpus regressions: 92 passed.
- Real cross-project builds/QEMU production acceptance remain host experiments.

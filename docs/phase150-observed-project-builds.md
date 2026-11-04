# Phase150: observed native builds and release-source integrity

Base: Phase149 remote commit `1869c787428692fb32e7f6e7cf3f6593d3febbca`.

**This branch does not complete the entire requested corpus translation plan.**
It implements build acquisition and provenance repairs, not macro lowering,
commutative operand proofs, additional calling conventions, floating execution,
or arbitrary kernel environments. Do not report a whole-project translation
rate from these preparation checks. Original corpus decisions and sources are
unchanged. Outstanding implementation is listed at the end.

## Code changes

- `project_build_capture`: generate wrappers for explicitly selected real tools;
  execute argv without reconstructing or evaluating shell-log text; preserve
  stdout/stderr, stdin and observed exit status. Every parallel invocation has
  unique, atomically published start/finish records. Missing records, changed
  tools, wrappers or configured inputs are unresolved. Signals remain signals.
- Parent build commands have separate run receipts. Configure probes, host
  generators, compilation, assembly, archive and link actions are retained.
  Stage selection retains unselected actions rather than deleting failures.
  A failed parent command is recorded without erasing successful child actions.
  Receipt completeness does not prove that every process was intercepted.
- `project_tool_resolution`: tools and relative PATH entries resolve in the
  action working directory, not the caller's directory.
- `project_compile_context`: a captured failed compilation cannot become a
  ready context. Source/tool/environment changes from capture time block the
  context. Supported section/common options are retained. Explicit common
  linkage options must match across body profiles.
- `project_compile_arguments`: a shared finite grammar handles separated and
  joined action/dependency options. Native replay redirects all recognized
  dependency outputs to fresh files, including `-MFpath` and `-Wp,-MMD,path`.
  Other `-Wp` forms remain blocked. Compiler profiles cannot inject these action
  outputs into body recipes.
- `project_source_release`: stream a digest-checked official archive once and
  compare all regular-file bytes, entry types, symlink spellings and executable
  bits with the complete source tree. Reject extra, missing or changed files.
  Do not follow a symlink parent when reading a regular member. This command
  does not extract or repair anything, verify publisher signatures, freeze the
  filesystem or grant translation acceptance.
- A capture run may bind a release proof. Full release comparison before and
  after the parent command catches source mutations; a command returning zero
  with inconsistent closing evidence is an acquisition failure. The command's
  actual return code remains in its receipt.
- `prepare_real_project_experiment`: import and independently reread captured
  records; classify an observed incompatible ELF target separately from a ready
  matching context. Known good captured actions are not discarded merely
  because another capture is incomplete. The aggregate unresolved count remains
  visible. Legacy logs with ambiguous working directories remain blocked.
  The old unconditional end-to-end-route marker is replaced by an explicit
  requirement for a build contract and route assessment, not by a ready label.

## Local verification

- Context, source, capture and existing route regressions: 499 passed, 10
  skipped. Skips require real Clang or the rebuilt frontend, which are absent
  locally. No RV64/QEMU production execution is claimed.
- Actual native GCC and nested parallel make are exercised; tests cover failed
  probes, failed parent builds, malformed receipts, source/config/tool changes,
  argv literals, signals, independent replay and dependency-output redirection.
- Complete official GMP 6.3.0 and Linux 6.6 source-tree comparisons succeeded.
  The Linux extraction copy initially lacked the official
  `arch/powerpc/configs/kvm_guest.config` symlink; verification correctly failed.
  Restoring precisely that archive entry in the scratch copy allowed the full
  comparison to pass. No verifier rule or original archive was relaxed.
- Immutable corpus checks: 92 passed. All 395 package Python files parse and
  patch whitespace checks pass. These checks do not establish
  macro activation, calling-convention validity, whole-library execution,
  translation rates, L2 proofs or L3 acceptance.

## Host setup

Reuse the already verified archives and extracted sources. Do not rerun
configure in an existing build directory under altered flags to force success.
The examples below establish explicit initial configurations, not all possible
GMP/Linux configurations. Record additional configurations separately.

```bash
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PREP_ROOT="$REPO/experiment/results/gmp-linux-prepare-Q0FqGS"
export ARCHIVE_ROOT="$REPO/experiment/results/real-project-archives"
export TOOLING="$PREP_ROOT/tooling-phase150"
export PYTHONDONTWRITEBYTECODE=1
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"

git fetch origin phase150-observed-project-builds
```

After fetch succeeds, create a new detached worktree (do not overwrite old one):

```bash
git worktree add --detach "$TOOLING" origin/phase150-observed-project-builds
export PYTHONPATH="$TOOLING/pytools${PYTHONPATH:+:$PYTHONPATH}"
export BUILD_BASIS="$(mktemp -d "$REPO/experiment/results/project-build-basis-XXXXXX")"
git -C "$TOOLING" rev-parse HEAD > "$BUILD_BASIS/git-head.txt"
```

Run focused acquisition checks before using the recorder:

```bash
python3 -m pytest -q -rs \
  "$TOOLING/pytools/tests/test_project_build_capture.py" \
  "$TOOLING/pytools/tests/test_project_tool_resolution.py" \
  "$TOOLING/pytools/tests/test_project_compile_arguments.py" \
  "$TOOLING/pytools/tests/test_project_source_release.py" \
  "$TOOLING/pytools/tests/test_project_build_records.py" \
  "$TOOLING/pytools/tests/test_project_build_contract.py" \
  --junitxml="$BUILD_BASIS/acquisition.xml" \
  > "$BUILD_BASIS/acquisition.log" 2>&1
ACQUISITION_STATUS=$?
printf 'acquisition_status=%s\n' "$ACQUISITION_STATUS"
tail -n 60 "$BUILD_BASIS/acquisition.log"
```

Proceed only after checking the status and any skips. Preserve failed evidence.

## Verify the extracted source trees

```bash
python3 "$TOOLING/experiment/prepare_real_project_experiment.py" verify-source \
  --lock "$TOOLING/experiment/corpora/real-projects-v2/sources.lock.json" \
  --project gmp --archive "$ARCHIVE_ROOT/gmp-6.3.0.tar.xz" \
  --source "$PREP_ROOT/upstream/gmp-6.3.0" \
  --output "$BUILD_BASIS/gmp-source.json" \
  > "$BUILD_BASIS/gmp-source.log" 2>&1
GMP_SOURCE_STATUS=$?
printf 'gmp_source_status=%s\n' "$GMP_SOURCE_STATUS"
cat "$BUILD_BASIS/gmp-source.log"

python3 "$TOOLING/experiment/prepare_real_project_experiment.py" verify-source \
  --lock "$TOOLING/experiment/corpora/real-projects-v2/sources.lock.json" \
  --project linux --archive "$ARCHIVE_ROOT/linux-6.6.tar.xz" \
  --source "$PREP_ROOT/upstream/linux-6.6" \
  --output "$BUILD_BASIS/linux-source.json" \
  > "$BUILD_BASIS/linux-source.log" 2>&1
LINUX_SOURCE_STATUS=$?
printf 'linux_source_status=%s\n' "$LINUX_SOURCE_STATUS"
cat "$BUILD_BASIS/linux-source.log"
```

Both must succeed. A missing/modified file is a source-acquisition issue, not a
reason to change the locked digest or ignore the entry. Generated configuration
and object files belong in separate build directories.

## GMP native build observation

Require the actual cross compiler, native generator compiler, cross ar and
ranlib. If a selected executable is unavailable, stop and retain that error.

```bash
export GMP_SRC="$PREP_ROOT/upstream/gmp-6.3.0"
export GMP_BUILD="$BUILD_BASIS/gmp-build"
mkdir "$GMP_BUILD"
python3 "$TOOLING/experiment/capture_project_build.py" create \
  --output "$BUILD_BASIS/gmp-capture" \
  --tool cc=/usr/bin/riscv64-linux-gnu-gcc-7 \
  --tool hostcc=/usr/bin/x86_64-linux-gnu-gcc-7 \
  --tool ar=/usr/bin/riscv64-linux-gnu-ar \
  --tool ld=/usr/bin/riscv64-linux-gnu-ld \
  --tool ranlib=/usr/bin/riscv64-linux-gnu-ranlib \
  --input "$TOOLING/experiment/corpora/real-projects-v2/sources.lock.json"
export GMP_CAPTURE="$BUILD_BASIS/gmp-capture/capture.json"
export GMP_BIN="$BUILD_BASIS/gmp-capture/bin"
export BUILD_TRIPLE="$("$GMP_SRC/config.guess")"
```

After successful recorder creation and a nonempty build triple:

```bash
python3 "$TOOLING/experiment/capture_project_build.py" run \
  --capture "$GMP_CAPTURE" --stage configure --cwd "$GMP_BUILD" \
  --source-proof "$BUILD_BASIS/gmp-source.json" -- \
  /usr/bin/env CC="$GMP_BIN/cc" CC_FOR_BUILD="$GMP_BIN/hostcc" \
  AR="$GMP_BIN/ar" RANLIB="$GMP_BIN/ranlib" LD="$GMP_BIN/ld" \
  CFLAGS="-O2 -march=rv64gc -mabi=lp64d" ABI=64 \
  /bin/sh "$GMP_SRC/configure" \
  --build="$BUILD_TRIPLE" --host=riscv64-linux-gnu \
  --enable-assembly --enable-static --enable-shared \
  --prefix="$BUILD_BASIS/gmp-install" \
  > "$BUILD_BASIS/gmp-configure.log" 2>&1
GMP_CONFIGURE_STATUS=$?
printf 'gmp_configure_status=%s\n' "$GMP_CONFIGURE_STATUS"
tail -n 60 "$BUILD_BASIS/gmp-configure.log"
```

After configure succeeds, the same configured wrappers remain in the Makefiles:

```bash
python3 "$TOOLING/experiment/capture_project_build.py" run \
  --capture "$GMP_CAPTURE" --stage build --cwd "$GMP_BUILD" \
  --input "$GMP_BUILD/config.h" --input "$GMP_BUILD/gmp.h" \
  --input "$GMP_BUILD/gmp-mparam.h" --input "$GMP_BUILD/Makefile" \
  --input "$GMP_BUILD/config.status" --input "$GMP_BUILD/libtool" \
  --source-proof "$BUILD_BASIS/gmp-source.json" -- \
  make -j4 V=1 \
  > "$BUILD_BASIS/gmp-build.log" 2>&1
GMP_BUILD_STATUS=$?
printf 'gmp_build_status=%s\n' "$GMP_BUILD_STATUS"
tail -n 80 "$BUILD_BASIS/gmp-build.log"
```

Regardless of build success, import completed observations, retaining failures:

```bash
python3 "$TOOLING/experiment/prepare_real_project_experiment.py" import-capture \
  --capture "$GMP_CAPTURE" --stage build \
  --output "$BUILD_BASIS/gmp-records.json"
python3 "$TOOLING/experiment/prepare_real_project_experiment.py" inspect \
  --records "$BUILD_BASIS/gmp-records.json" \
  --output "$BUILD_BASIS/gmp-contexts.json"
```

This initial inspect derives contexts without Clang. Unknown flags remain
concrete blockers. Host-generator objects are not RV64 experiment entries.
Do not run the legacy source-directory automatic runner on all extracted files.

## Linux native configuration and preparation

Linux kernel and tools/selftests are separate build domains. This initial kernel
configuration does not cover `tools/`, BPF or every configuration-dependent site.
Use the same `create` command shape to create `$BUILD_BASIS/linux-capture`, with
`cc`, `hostcc`, `ar`, `ranlib` mapped to the same actual tools above.

```bash
export LINUX_SRC="$PREP_ROOT/upstream/linux-6.6"
export LINUX_BUILD="$BUILD_BASIS/linux-build"
mkdir "$LINUX_BUILD"
python3 "$TOOLING/experiment/capture_project_build.py" create \
  --output "$BUILD_BASIS/linux-capture" \
  --tool cc=/usr/bin/riscv64-linux-gnu-gcc-7 \
  --tool hostcc=/usr/bin/x86_64-linux-gnu-gcc-7 \
  --tool ar=/usr/bin/riscv64-linux-gnu-ar \
  --tool ld=/usr/bin/riscv64-linux-gnu-ld \
  --tool ranlib=/usr/bin/riscv64-linux-gnu-ranlib \
  --input "$TOOLING/experiment/corpora/real-projects-v2/sources.lock.json"
export LINUX_CAPTURE="$BUILD_BASIS/linux-capture/capture.json"
export LINUX_BIN="$BUILD_BASIS/linux-capture/bin"

python3 "$TOOLING/experiment/capture_project_build.py" run \
  --capture "$LINUX_CAPTURE" --stage configure --cwd "$LINUX_BUILD" \
  --source-proof "$BUILD_BASIS/linux-source.json" -- \
  make -C "$LINUX_SRC" O="$LINUX_BUILD" ARCH=riscv \
  CROSS_COMPILE=riscv64-linux-gnu- CC="$LINUX_BIN/cc" \
  HOSTCC="$LINUX_BIN/hostcc" AR="$LINUX_BIN/ar" RANLIB="$LINUX_BIN/ranlib" \
  LD="$LINUX_BIN/ld" \
  V=1 defconfig > "$BUILD_BASIS/linux-configure.log" 2>&1
LINUX_CONFIGURE_STATUS=$?
printf 'linux_configure_status=%s\n' "$LINUX_CONFIGURE_STATUS"
tail -n 80 "$BUILD_BASIS/linux-configure.log"
```

After successful configuration, confirm `CONFIG_64BIT=y` in `.config`. Keep
this initial configuration; do not select alternatives based on translator
success. Preparation and compilation are separate observed stages:

```bash
python3 "$TOOLING/experiment/capture_project_build.py" run \
  --capture "$LINUX_CAPTURE" --stage prepare --cwd "$LINUX_BUILD" \
  --source-proof "$BUILD_BASIS/linux-source.json" \
  --input "$LINUX_BUILD/.config" -- \
  make -C "$LINUX_SRC" O="$LINUX_BUILD" ARCH=riscv \
  CROSS_COMPILE=riscv64-linux-gnu- CC="$LINUX_BIN/cc" \
  HOSTCC="$LINUX_BIN/hostcc" AR="$LINUX_BIN/ar" RANLIB="$LINUX_BIN/ranlib" \
  LD="$LINUX_BIN/ld" \
  V=1 prepare > "$BUILD_BASIS/linux-prepare.log" 2>&1
LINUX_PREPARE_STATUS=$?
printf 'linux_prepare_status=%s\n' "$LINUX_PREPARE_STATUS"
tail -n 80 "$BUILD_BASIS/linux-prepare.log"
```

Only after preparation succeeds:

```bash
python3 "$TOOLING/experiment/capture_project_build.py" run \
  --capture "$LINUX_CAPTURE" --stage build --cwd "$LINUX_BUILD" \
  --source-proof "$BUILD_BASIS/linux-source.json" \
  --input "$LINUX_BUILD/.config" \
  --input "$LINUX_BUILD/include/config/auto.conf" \
  --input "$LINUX_BUILD/include/generated/autoconf.h" -- \
  make -C "$LINUX_SRC" O="$LINUX_BUILD" ARCH=riscv \
  CROSS_COMPILE=riscv64-linux-gnu- CC="$LINUX_BIN/cc" \
  HOSTCC="$LINUX_BIN/hostcc" AR="$LINUX_BIN/ar" RANLIB="$LINUX_BIN/ranlib" \
  LD="$LINUX_BIN/ld" \
  -j4 V=1 vmlinux > "$BUILD_BASIS/linux-build.log" 2>&1
LINUX_BUILD_STATUS=$?
printf 'linux_build_status=%s\n' "$LINUX_BUILD_STATUS"
tail -n 80 "$BUILD_BASIS/linux-build.log"

python3 "$TOOLING/experiment/prepare_real_project_experiment.py" import-capture \
  --capture "$LINUX_CAPTURE" --stage build \
  --output "$BUILD_BASIS/linux-records.json"
python3 "$TOOLING/experiment/prepare_real_project_experiment.py" inspect \
  --records "$BUILD_BASIS/linux-records.json" \
  --output "$BUILD_BASIS/linux-contexts.json"
```

Preserve all native failures; do not remove assembly or manually override
Kbuild ISA choices to force a successful build. Compiler/GNU-as versions may
require compatibility work independently of translator correctness. Per-run
configuration files are checked before and after the command and before each
wrapped tool; a changed configuration cannot reuse that run's context.

## Formal translation boundary and remaining implementation

Acquisition is not L0. Native make returning zero is not a translation result.
Captured commands and observed ELF headers do not prove that every relevant
source position was instantiated, that every compiler process was wrapped, or
that an ISA/memory/ABI contract holds. `processTreeCompletenessVerified`,
`buildSuccessVerified`, semantic approval and production acceptance stay false.

The following remain **unimplemented by this branch**, not completed coverage:

1. Full compiler macro spelling/expansion authority, header/static entry adapters
   and safe macro rewriting, including every affected instance.
2. GNU commutative input-pair proof and its complete downstream consumption.
   `%r` is still rejected by the existing semantic consumer. Do not strip `%`.
3. General typed multi-output calls and ordinary-C/callee effect closure needed
   by actual GMP macro consumers and broader Linux entry functions.
4. Build-derived activation-to-site accounting and a fully reconciled formal
   experiment denominator. No arbitrary source globs or success-based filtering.
5. Further legitimate compiler/header compatibility and code-generation option
   families; current unknown options fail rather than being discarded.
6. Additional floating, privileged/kernel or controlled-environment production
   routes and all their proof/observation/audit obligations.

Consequently, do not start a whole-GMP/Linux translation-rate experiment yet.
For an entry already within the proved and observable domain, use the formal
Phase148 `make-contract` and project-aware automatic invocation with its exact
context, explicit target/driver profiles, harness and calibrated mechanism
selection. Existing L0--L3 and independent acceptance gates remain required.
The raw build log, capture directory, source proofs, generated configuration,
records, contexts and exact tooling worktree must be retained together. New
code revisions do not silently validate an older recorder implementation.

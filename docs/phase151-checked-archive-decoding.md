# Phase151: checked archive decoding and acquisition stage gates

Base: `afb3606f3f4311ac90973f122733bdf57c9c62d0` (Phase150).

This repair addresses missing Python archive codecs and cascading acquisition
failures. It does not add macro translation, `%r` proofs, floating-point routes,
new ABIs or kernel execution environments. Source and immutable corpus policies
are unchanged. Acquisition, successful native builds and decoder availability
never grant L0–L3 or production acceptance.

## Implementation and evidence

- Identify XZ/gzip/bzip2 archive magic and check the required Python codec before
  source scanning. Report unavailable decoders separately from malformed tar.
- If Python lacks `lzma`, resolve and hash an executable `xz`; stream its output
  into the same tar/member verifier. Do not retry corrupt native decoding with a
  different backend. No shell invocation, extraction or source repair occurs.
- Drain decoded input through EOF; tar end markers alone do not validate the
  compression trailer. Require external decoder exit zero and unchanged tool
  bytes. Store stderr in a temporary file, bound diagnostic output, close pipes
  and reap/terminate children even if member verification raises.
- Native and fallback decoding produce the same release proof for identical
  archives/source trees. Tool identity is reported separately by the capability
  probe and checked during fallback decoding; it does not alter source identity.
- Missing source proof blocks the build command before execution with an explicit
  reason. Empty captures distinguish no completed run, stage not run and no
  selected tool invocation; these remain unresolved, never successful evidence.
- Use whole stage blocks below. A nonzero prerequisite must stop the block;
  do not paste later commands after a failed prerequisite. Retain failed output.

## 1. Isolated tooling and fresh result paths

Reuse the existing upstream and archives. Do not recreate the Phase150 worktree,
reset the user's main checkout, replace the active Python or edit source files.
Run this initialization in the current shell:

```bash
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PREP_ROOT="$REPO/experiment/results/gmp-linux-prepare-Q0FqGS"
export ARCHIVE_ROOT="$REPO/experiment/results/real-project-archives"
export TOOLING="$PREP_ROOT/tooling-phase151"
git fetch origin phase151-checked-archive-decoding
# Only on first setup; an existing path must be inspected, not overwritten.
git worktree add --detach "$TOOLING" origin/phase151-checked-archive-decoding
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$TOOLING/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG=/usr/lib/llvm-10/bin/clang
export PATH="/usr/lib/llvm-10/bin:$PATH"
export BUILD_BASIS="$(mktemp -d "$REPO/experiment/results/project-build-phase151-XXXXXX")"
printf 'BUILD_BASIS=%s\n' "$BUILD_BASIS"
```

## 2. Required tests and source proofs (one stop-on-error block)

```bash
bash -e <<'STAGES'
: "${TOOLING:?}" "${BUILD_BASIS:?}" "${ARCHIVE_ROOT:?}" "${PREP_ROOT:?}"
python3 -m pytest -q -rs \
  "$TOOLING/pytools/tests/test_project_archive_stream.py" \
  "$TOOLING/pytools/tests/test_project_acquisition_driver.py" \
  "$TOOLING/pytools/tests/test_project_source_release.py" \
  "$TOOLING/pytools/tests/test_project_build_capture.py" \
  "$TOOLING/pytools/tests/test_project_tool_resolution.py" \
  "$TOOLING/pytools/tests/test_project_compile_arguments.py" \
  "$TOOLING/pytools/tests/test_project_build_records.py" \
  "$TOOLING/pytools/tests/test_project_build_contract.py" \
  --junitxml="$BUILD_BASIS/acquisition.xml" > "$BUILD_BASIS/acquisition.log" 2>&1
python3 "$TOOLING/experiment/check_project_acquisition.py" \
  --archive "$ARCHIVE_ROOT/gmp-6.3.0.tar.xz" \
  --archive "$ARCHIVE_ROOT/linux-6.6.tar.xz" \
  > "$BUILD_BASIS/decoder-capabilities.json"
for PROJECT in gmp linux; do
  case "$PROJECT" in
    gmp) RELEASE=gmp-6.3.0 ;;
    linux) RELEASE=linux-6.6 ;;
  esac
  python3 "$TOOLING/experiment/prepare_real_project_experiment.py" verify-source \
    --lock "$TOOLING/experiment/corpora/real-projects-v2/sources.lock.json" \
    --project "$PROJECT" --archive "$ARCHIVE_ROOT/$RELEASE.tar.xz" \
    --source "$PREP_ROOT/upstream/$RELEASE" \
    --output "$BUILD_BASIS/$PROJECT-source.json" \
    > "$BUILD_BASIS/$PROJECT-source.log" 2>&1
done
STAGES
SOURCE_STAGE_STATUS=$?
printf 'source_stage_status=%s\n' "$SOURCE_STAGE_STATUS"
cat "$BUILD_BASIS/acquisition.log"
cat "$BUILD_BASIS/decoder-capabilities.json"
cat "$BUILD_BASIS/gmp-source.log" "$BUILD_BASIS/linux-source.log"
```

On the reported host the decoder should be `external-xz`; native Python with
`_lzma` should report `python-tarfile`. Both require full source comparison.
Do not continue unless the block returns zero and both source checks report
`sourceTreeMatchesRelease: true`. This is not semantic approval. Missing files in
this display mean the preceding stage stopped; inspect its error instead of
running downstream commands. Preserve this directory; retries use fresh paths.

## 3. Native project acquisition

After step 2 succeeds, follow the Phase150 sections "GMP native build observation" and "Linux native configuration and preparation" using the
new `TOOLING` and `BUILD_BASIS`. The capture entry inserts its own package path;
all generated wrappers must therefore be created by Phase151. Do not reuse old
capture manifests whose implementation digests bind Phase150.

Run GMP initialization/configure/build/import/inspect in a `bash -e` block.
An inspect blocker ends acquisition for analysis; do not remove compiler flags
or assembly, change the corpus, or treat `context_ready` as acceptance.

For Linux perform initialization, `defconfig` and `prepare` first, in order,
with the same guarded block. Keep the actual Kbuild ABI; RV64 kernel LP64 is
not the user-mode LP64D contract. Replace the expensive Phase150 `vmlinux` step
with this diagnostic, inside that same shell after initialization:

```bash
python3 "$TOOLING/experiment/capture_project_build.py" run \
  --capture "$LINUX_CAPTURE" --stage diagnostic-build --cwd "$LINUX_BUILD" \
  --source-proof "$BUILD_BASIS/linux-source.json" \
  --input "$LINUX_BUILD/.config" \
  --input "$LINUX_BUILD/include/config/auto.conf" \
  --input "$LINUX_BUILD/include/generated/autoconf.h" -- \
  make -C "$LINUX_SRC" O="$LINUX_BUILD" ARCH=riscv \
  CROSS_COMPILE=riscv64-linux-gnu- CC="$LINUX_BIN/cc" \
  HOSTCC="$LINUX_BIN/hostcc" AR="$LINUX_BIN/ar" \
  RANLIB="$LINUX_BIN/ranlib" LD="$LINUX_BIN/ld" \
  -j1 V=1 init/main.o > "$BUILD_BASIS/linux-diagnostic.log" 2>&1
python3 "$TOOLING/experiment/prepare_real_project_experiment.py" import-capture \
  --capture "$LINUX_CAPTURE" --stage diagnostic-build \
  --output "$BUILD_BASIS/linux-diagnostic-records.json"
python3 "$TOOLING/experiment/prepare_real_project_experiment.py" inspect \
  --records "$BUILD_BASIS/linux-diagnostic-records.json" \
  --output "$BUILD_BASIS/linux-diagnostic-contexts.json"
```

`init/main.o` is a toolchain diagnostic, not a representative corpus denominator.
Return the first failed stage, full reason codes, and its log tail. No real
RV64/QEMU translation acceptance is claimed by these preparation procedures.

## Single-entry native acquisition (preferred)

Instead of manually concatenating Phase150 stages, the supplied Bash driver
encodes their prerequisite order. Pass an output directory that does not yet
exist. It stops on the first nonzero stage, preserves its log and returns its
status. It never changes the source tree or installs packages. Capture manifests
are created only after source verification. Actual tool executables can be set
through the explicit `RV2X86_TEST_RISCV_{CC,AR,LD,RANLIB}` and
`RV2X86_TEST_HOST_CC` environment variables; defaults match the reported host.
No timeout, failed source check or missing compiler becomes acceptance.

After the tests/source stage above succeeds:

```bash
bash "$TOOLING/experiment/acquire_real_project_builds.sh" \
  "$TOOLING" "$PREP_ROOT" "$ARCHIVE_ROOT" "$BUILD_BASIS/gmp-native" gmp \
  > "$BUILD_BASIS/gmp-native-driver.log" 2>&1
GMP_STATUS=$?
printf 'gmp_acquisition_status=%s\n' "$GMP_STATUS"
cat "$BUILD_BASIS/gmp-native-driver.log"
```

Run the Linux diagnostic separately, not a full kernel production matrix:

```bash
bash "$TOOLING/experiment/acquire_real_project_builds.sh" \
  "$TOOLING" "$PREP_ROOT" "$ARCHIVE_ROOT" "$BUILD_BASIS/linux-native" linux \
  > "$BUILD_BASIS/linux-native-driver.log" 2>&1
LINUX_STATUS=$?
printf 'linux_acquisition_status=%s\n' "$LINUX_STATUS"
cat "$BUILD_BASIS/linux-native-driver.log"
```

If a build fails after starting, import its recorded observations separately for
diagnosis (GMP stage `build`, Linux `diagnostic-build`); retain failed actions and
parent receipts. Do not continue translation automatically. `inspect` may itself
return nonzero for unsupported contexts; its JSON and blockers are analysis
inputs, not reasons to suppress compiler options or exclude difficult corpus
instances. This driver is a pinned acquisition recipe, not a claim of general
project translation or all Linux configurations.

## Local validation results

- Project acquisition/context and associated compiler regressions: 215 passed,
  6 skipped (real Clang/rebuilt frontend unavailable).
- Immutable corpus regressions: 92 passed.
- Complete official GMP and Linux archives were streamed through both native
  and forced external-XZ routes. Member names/types and all regular member bytes
  agreed: 2,343 and 87,083 members including release root, respectively. This is
  an archive-decoder comparison, not a new source-tree or translation acceptance.
- Shell syntax and the failed-source dependency gate were checked. Real
  cross-project configure/build and RV64/QEMU acceptance still require the host.

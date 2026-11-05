#!/usr/bin/env bash
# Original-project acquisition only. Never grants translation acceptance.
set -euo pipefail
if [ "$#" -ne 5 ]; then
  echo 'usage: bash acquire_real_project_builds.sh TOOLING PREP_ROOT ARCHIVE_ROOT NEW_OUTPUT gmp|linux' >&2
  exit 2
fi
TOOLING=$(realpath "$1")
PREP_ROOT=$(realpath "$2")
ARCHIVE_ROOT=$(realpath "$3")
OUTPUT=$4
PROJECT=$5
case "$PROJECT" in
  gmp) RELEASE=gmp-6.3.0 ;;
  linux) RELEASE=linux-6.6 ;;
  *) echo 'project must be gmp or linux' >&2; exit 2 ;;
esac
# Never overwrite old evidence or capture manifests.
mkdir "$OUTPUT"
OUTPUT=$(realpath "$OUTPUT")
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$TOOLING/pytools${PYTHONPATH:+:$PYTHONPATH}"
trap 'code=$?; printf "acquisition_failed line=%s status=%s\n" "$LINENO" "$code" >&2; exit "$code"' ERR
SOURCE="$PREP_ROOT/upstream/$RELEASE"
PROOF="$OUTPUT/source.json"
CAPTURE="$OUTPUT/capture/capture.json"
BIN="$OUTPUT/capture/bin"
BUILD="$OUTPUT/build"
python3 "$TOOLING/experiment/check_project_acquisition.py" \
  --archive "$ARCHIVE_ROOT/$RELEASE.tar.xz" > "$OUTPUT/decoder.json"
python3 "$TOOLING/experiment/prepare_real_project_experiment.py" verify-source \
  --lock "$TOOLING/experiment/corpora/real-projects-v2/sources.lock.json" \
  --project "$PROJECT" --archive "$ARCHIVE_ROOT/$RELEASE.tar.xz" \
  --source "$SOURCE" --output "$PROOF" > "$OUTPUT/source.log" 2>&1
mkdir "$BUILD"
python3 "$TOOLING/experiment/capture_project_build.py" create \
  --output "$OUTPUT/capture" \
  --tool "cc=${RV2X86_TEST_RISCV_CC:-/usr/bin/riscv64-linux-gnu-gcc-7}" \
  --tool "hostcc=${RV2X86_TEST_HOST_CC:-/usr/bin/x86_64-linux-gnu-gcc-7}" \
  --tool "ar=${RV2X86_TEST_RISCV_AR:-/usr/bin/riscv64-linux-gnu-ar}" \
  --tool "ld=${RV2X86_TEST_RISCV_LD:-/usr/bin/riscv64-linux-gnu-ld}" \
  --tool "ranlib=${RV2X86_TEST_RISCV_RANLIB:-/usr/bin/riscv64-linux-gnu-ranlib}" \
  --input "$TOOLING/experiment/corpora/real-projects-v2/sources.lock.json" > "$OUTPUT/create.log" 2>&1
capture_run() {
  python3 "$TOOLING/experiment/capture_project_build.py" run \
    --capture "$CAPTURE" --cwd "$BUILD" --source-proof "$PROOF" "$@"
}
if [ "$PROJECT" = gmp ]; then
  BUILD_TRIPLE=$("$SOURCE/config.guess")
  test -n "$BUILD_TRIPLE"
  capture_run --stage configure -- \
    /usr/bin/env CC="$BIN/cc" CC_FOR_BUILD="$BIN/hostcc" \
    AR="$BIN/ar" RANLIB="$BIN/ranlib" LD="$BIN/ld" \
    CFLAGS='-O2 -march=rv64gc -mabi=lp64d' ABI=64 \
    /bin/sh "$SOURCE/configure" --build="$BUILD_TRIPLE" --host=riscv64-linux-gnu \
    --enable-assembly --enable-static --enable-shared --prefix="$OUTPUT/install" \
    > "$OUTPUT/configure.log" 2>&1
  capture_run --stage build \
    --input "$BUILD/config.h" --input "$BUILD/gmp.h" \
    --input "$BUILD/gmp-mparam.h" --input "$BUILD/Makefile" \
    --input "$BUILD/config.status" --input "$BUILD/libtool" -- \
    make -j4 V=1 > "$OUTPUT/build.log" 2>&1
  STAGE=build
else
  KMAKE=(make -C "$SOURCE" "O=$BUILD" ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
    "CC=$BIN/cc" "HOSTCC=$BIN/hostcc" "AR=$BIN/ar" "RANLIB=$BIN/ranlib" "LD=$BIN/ld" V=1)
  capture_run --stage configure -- "${KMAKE[@]}" defconfig > "$OUTPUT/configure.log" 2>&1
  grep -qx CONFIG_64BIT=y "$BUILD/.config"
  capture_run --stage prepare --input "$BUILD/.config" -- \
    "${KMAKE[@]}" prepare > "$OUTPUT/prepare.log" 2>&1
  STAGE=diagnostic-build
  capture_run --stage "$STAGE" --input "$BUILD/.config" \
    --input "$BUILD/include/config/auto.conf" --input "$BUILD/include/generated/autoconf.h" -- \
    "${KMAKE[@]}" -j1 init/main.o > "$OUTPUT/build.log" 2>&1
fi
python3 "$TOOLING/experiment/prepare_real_project_experiment.py" import-capture \
  --capture "$CAPTURE" --stage "$STAGE" --output "$OUTPUT/records.json" > "$OUTPUT/import.log" 2>&1
python3 "$TOOLING/experiment/prepare_real_project_experiment.py" inspect \
  --records "$OUTPUT/records.json" --output "$OUTPUT/contexts.json" > "$OUTPUT/inspect.log" 2>&1
printf 'acquisition_complete project=%s output=%s semanticApproval=false\n' "$PROJECT" "$OUTPUT"

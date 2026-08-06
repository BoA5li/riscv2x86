#!/usr/bin/env bash
set -euo pipefail

ROOT=$(pwd)
SRC=test/input
OUT=test/out_phase2

rm -rf "$OUT"
mkdir -p "$OUT"

cat > "$SRC/compile_commands.json" <<EOF
[
  {"directory":"$ROOT/$SRC","command":"clang-10 --target=riscv64 -march=rv64gc -c sample_atomic_basic.c","file":"sample_atomic_basic.c"},
  {"directory":"$ROOT/$SRC","command":"clang-10 --target=riscv64 -march=rv64gc -c sample_atomic_cas.c","file":"sample_atomic_cas.c"},
  {"directory":"$ROOT/$SRC","command":"clang-10 --target=riscv64 -march=rv64gc -c sample_pure.c","file":"sample_pure.c"},
  {"directory":"$ROOT/$SRC","command":"clang-10 --target=riscv64 -march=rv64gc -c sample_phase2_negative.c","file":"sample_phase2_negative.c"},
  {"directory":"$ROOT/$SRC","command":"clang-10 --target=riscv64 -march=rv64gc -c sample_inline_asm.c","file":"sample_inline_asm.c"}
]
EOF

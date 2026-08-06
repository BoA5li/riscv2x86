#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$ROOT"

SRC=pytools/tests/e2e
OUT=pytools/tests/e2e_out

mkdir -p "$SRC"

cat > "$SRC/compile_commands.json" <<EOF
[{"directory":"$ROOT/$SRC","command":"clang --target=riscv64 -march=rv64gc -c $ROOT/$SRC/sample.c","file":"$ROOT/$SRC/sample.c"}]
EOF

if [ ! -x ./build/riscv2x86 ]; then
    echo "error: ./build/riscv2x86 not found"
    exit 1
fi

rm -rf "$OUT" && mkdir -p "$OUT"

# Step 1: 分类 + 内置规则改写
./build/riscv2x86 -p "$SRC" --src-root="$SRC" -o "$OUT" \
    --report-json="$OUT/report.json" \
    "$SRC/sample.c"

# Step 2: Python 翻译/校验（这里只验证 Python 管线，不回填）
PYTHONPATH="$ROOT/pytools${PYTHONPATH:+:$PYTHONPATH}" \
python3 -m riscv2x86_py.cli \
    --in "$OUT/report.json" \
    --out "$OUT/translated.json" \
    --xlen 64

# Step 3: 展示当前版本在 Step 1 直接产出的 rewrite 结果
echo "=== rewritten sample.c ==="
cat "$OUT/sample.c"

# Step 4: 用 x86 clang 编译验证改写结果
clang --target=x86_64-pc-linux-gnu -O2 -c "$OUT/sample.c" -o "$OUT/sample.o"
echo "=== build OK ==="

# Step 5: 汇总 Python 阶段状态
python3 - <<PY
import json
with open("$OUT/translated.json") as f:
    r = json.load(f)
for x in r.get("findings", []):
    print(x.get("verificationStatus"), x.get("ruleName"), "|", x.get("suggestedReplacement"))
PY
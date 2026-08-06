# test/e2e/run.sh
#!/usr/bin/env bash
set -e
ROOT=$(pwd)
SRC=test/e2e
OUT=test/e2e_out
mkdir -p $SRC
cat > $SRC/compile_commands.json <<EOF
[{"directory":"$ROOT/$SRC","command":"clang --target=riscv64 -march=rv64gc -c sample.c","file":"sample.c"}]
EOF

# Step 1: 分类（不启用 C++ 内置规则，让 Python 全权处理）
rm -rf $OUT && mkdir -p $OUT
./build/riscv2x86 -p $SRC --src-root=$SRC -o $OUT \
    --report-json=$OUT/report.json --no-builtin-rules \
    $SRC/sample.c

# Step 2: Python 翻译 + 校验
python3 -m riscv2x86_py.cli --in $OUT/report.json --out $OUT/translated.json --xlen 64

# Step 3: 回填
./build/riscv2x86 --apply --report=$OUT/translated.json \
                  --src-root=$SRC -o $OUT \
                  $SRC/sample.c

echo "=== rewritten sample.c ==="
cat $OUT/sample.c

# Step 4: 用 x86 clang 编译看是否成立
clang --target=x86_64-pc-linux-gnu -O2 -c $OUT/sample.c -o $OUT/sample.o
echo "=== build OK ==="

# Step 5: 验证状态汇总
python3 -c "
import json
with open('$OUT/translated.json') as f:
    r = json.load(f)
for x in r['findings']:
    print(x.get('verificationStatus'), x.get('ruleName'), '|', x.get('suggestedReplacement'))
"
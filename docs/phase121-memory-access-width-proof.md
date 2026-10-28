# Phase121：按实际访存宽度建立翻译与验证证明

本轮解决 Phase120 的 `memory proof alignment is invalid` 及其相邻错误链，
不宣称完成全部 L3 覆盖扩展。原始示例是 64 位指针和输入，通过 `sw` 在
偏移 12 处写 4 字节。64 位 GNU 输入载体应当保留，访问宽度不能从它推断。

## 实现

* Phase6A 从规范化 LOAD 输出 / STORE 值 varnode 的字节大小取得实际访问宽度。
  STORE 的值来源必须追溯到有 assembler/compiler 绑定的输入，允许透明 COPY
  和零起始 SUBPIECE；拒绝未知来源、高位截取、算术结果及此前覆盖输入寄存器的情况。
  数据库提供的低位寄存器视图必须与 varnode 坐标相符。不从助记符、参数名字、
  测试编号或指针类型猜测访问宽度。
* 源模型单独保留访问宽度、值操作数编号和 identity/low_bits 投影。
  候选、Phase6C、Phase6D 均核对它们；普通访存的源证明身份也绑定这些事实和操作数。
* 注册 8/16 位 store 合同；原有 32/64 位合同同样按实际访问宽度选择。
  输入约束保留载体宽度，store 用 `%b/%w/%k/%q` 指定实际寄存器视图。
  不允许用宽度更大的 mov 替代窄访问。
* L2 memory proof v3 身份覆盖 `carrierWidthBits` 和 `valueProjection`。
  读取旧 v2 时仍要求原来的等宽关系，不允许旧记录携带或隐式推导截断权限。
  实际对象、声明、范围、基址对齐、生命周期、效应关系和外壳检查仍须完成；
  非负偏移等结构坐标本身不能提供完整对象权威。
  不对齐或未知结构不能构造有效证明事实，也不能因此抛出本次构造异常。
* L2 值权威要求声明宽度与已证明载体精确一致，再验证实际访问投影，
  没有将原来的宽度相等检查简单替换为“大于等于”。
* L2 普通访存 harness 按已确认整数 pointee 类型分配真实对象，通过字符别名观察字节。
  这避免将字符数组转为整数指针后解引用造成 C effective-type 问题。
* 后端异常保留原始类型、消息和 traceback；外层记录实际命令、源码摘要、退出码、
  stdout/stderr 摘要和报告/归档存在性。缺归档仍失败，诊断损坏也失败。
  已执行的后端错误与未执行后端的 preflight 拒绝分开；不会伪造成功或 unsupported 归档。

## 验证范围

新增测试从 typed IR 走候选、约束、证明、渲染及 L2 权威，覆盖原始
4 字节 / 偏移 12 / 64 位输入组合；8/16/32/64 位 store 的原生编译、
逐字节执行结果、周边字节保持、低位截取、错误值来源、错误目标合同、
寄存器覆盖、持久化及诊断绑定。L2 harness 使用 `-O2 -fstrict-aliasing -Werror`
编译执行。原生执行不是 RISC-V/QEMU 双端验收。

本地没有可用的完整 RISC-V/Clang/QEMU 生产工具链，因此下列生产步骤必须在
原实验环境完成。既有 17 项 typed-store 生产矩阵保留，包括错误 raw capture
必须被独立审计拒绝的反例。不能将仅收集测试或 wrapper 校准当作最终 L3 验收。

窄 load 的扩展语义、一般表达式、多对象、混合机制、多区域控制和其它已列出
覆盖扩展不在本轮新增支持范围内；对应能力必须继续逐项证明与实现。

## 本地核验记录

跨路线回归：1,596 passed，零失败/错误/跳过；最后一轮直接相关检查：
208 passed，零失败/错误/跳过（包含最终补充的 load 输出覆盖反例）。
17 项真实生产测试已收集，未在此执行。Python 语法与文档 shell 块语法检查通过。

## 1. 更新与本地针对性检查

以下块均使用 `set +e`，不会关闭交互 shell；每一步检查结果后再继续。
输出必须使用新目录，保留旧实验。不要修改旧校准记录、身份或证明以绕过拒绝。

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase121-memory-access-width-proof
git switch --track origin/phase121-memory-access-width-proof
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PHASE121_ROOT="$(mktemp -d "$REPO/experiment/results/phase121-XXXXXX")"
hash -r
printf 'PHASE121_ROOT=%s\n' "$PHASE121_ROOT"
git rev-parse HEAD > "$PHASE121_ROOT/git-head.txt"
cmake --build build > "$PHASE121_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE121_ROOT/build.log"
```

构建通过后：

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_memory_access_width_proof.py \
  pytools/tests/test_translation_backend_failure.py \
  pytools/tests/test_phase6_direct_memory_contract.py \
  pytools/tests/test_l2_memory_object_observation.py \
  pytools/tests/test_automatic_l2_authority.py \
  pytools/tests/test_automatic_l2_effect.py \
  pytools/tests/test_translation_preflight.py \
  pytools/tests/test_l3_typed_memory.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_evaluation_runner.py \
  --junitxml="$PHASE121_ROOT/focused.xml" \
  > "$PHASE121_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$PHASE121_ROOT/focused.log"
```

要求无失败、无错误、无跳过。若失败，先保留以上日志，不启动长矩阵。

## 2. 重新校准 typed-store wrapper

Python 实现发生变化，旧 wrapper 的实现摘要不能继续作为新代码证据。
底层 reviewed QEMU base 未被修改，但仍由 wrapper 校验。

```bash
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
python3 -m riscv2x86_py.l3_memory_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$PHASE121_ROOT/typed-memory-backend" \
  > "$PHASE121_ROOT/typed-memory-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'typed_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 80 "$PHASE121_ROOT/typed-memory-backend.log"
cat "$PHASE121_ROOT/typed-memory-backend/build-status.json"
```

要求退出 0、准备完成、8 项双端宽度探针完成。`semanticApproval:false` 正确：
校准不等于翻译结果批准。通过后再设置：

```bash
export RV2X86_L3_TYPED_MEMORY_BACKEND="$PHASE121_ROOT/typed-memory-backend/backend.json"
```

## 3. 原始失败输入的完整验收

复制旧输入，保持字节不变。旧路径不存在时应恢复实际路径，不另造更简单输入替代。

```bash
mkdir -p "$PHASE121_ROOT/inputs"
cp "$REPO/experiment/results/phase120-syMjBe/inputs/narrow-store.c" \
  "$PHASE121_ROOT/inputs/narrow-store.c"
python3 experiment/run_l3_memory_trace.py \
  --input "$PHASE121_ROOT/inputs/narrow-store.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_TYPED_MEMORY_BACKEND" \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --output "$PHASE121_ROOT/narrow-store" \
  > "$PHASE121_ROOT/narrow-store.log" 2>&1
CASE_STATUS=$?
printf 'narrow_store_status=%s\n' "$CASE_STATUS"
tail -n 80 "$PHASE121_ROOT/narrow-store.log"
```

独立审计并核对真实访问宽度：

```bash
python3 - <<'PY' > "$PHASE121_ROOT/original-audit.log" 2>&1
import json, os
from pathlib import Path
from riscv2x86_py.l3_production_acceptance import audit_evaluation
root = Path(os.environ['PHASE121_ROOT'])/'narrow-store'
state = json.loads((root/'run-status.json').read_text())
for key in ('currentStage','productionAcceptanceComplete','blockers'):
    print(key, state.get(key), flush=True)
paths = list(root.glob('batch/cases/*/evaluation-result.json'))
if len(paths) != 1:
    raise ValueError('expected exactly one evaluation report')
report = json.loads(paths[0].read_text())
print('evaluation', report.get('status'), report.get('reasonCodes'), flush=True)
for attempt in report.get('attempts', []):
    for layer in (attempt.get('validation') or {}).get('layers', []):
        print('LAYER', layer.get('level'), layer.get('status'), flush=True)
        if layer.get('status') != 'verified':
            print('DETAIL', layer.get('detail'), flush=True)
for path in root.rglob('translated_report.json'):
    for finding in json.loads(path.read_text()).get('findings', []):
        print('MEMORY_FACTS', (finding.get('approvalArtifact') or {}).get('l2MemoryProofFacts'), flush=True)
if (state.get('currentStage') != 'complete' or state.get('productionAcceptanceComplete') is not True
        or state.get('blockers') or report.get('status') != 'verified'):
    raise ValueError('production workflow not complete')
audit = audit_evaluation(report)
print('INDEPENDENT_AUDIT', json.dumps(audit, ensure_ascii=False, indent=2), flush=True)
if audit.get('status') != 'verified':
    raise ValueError('independent audit not verified')
PY
AUDIT_STATUS=$?
printf 'original_audit_status=%s\n' "$AUDIT_STATUS"
cat "$PHASE121_ROOT/original-audit.log"
```

该输入的预期事实为 `widthBytes:4`、`byteOffset:12`、`requiredAlignment:4`、
`carrierWidthBits:64`、`valueProjection:low_bits`。要求 L0–L3 全部 verified，
且独立审计 verified。若出现新的失败，保留完整结果，不能仅凭原异常消失判定完成。
后端失败时额外读取 `*.pipeline-failure.json`、`*.backend-failure.json` 和
`evaluation-result.json` 的 `translationEvaluationLink.backendFailure`。

## 4. 通过原始验收后执行既有 17 项生产矩阵

```bash
export MATRIX_ROOT="$(mktemp -d "$PHASE121_ROOT/production-matrix-XXXXXX")"
printf 'MATRIX_ROOT=%s\n' "$MATRIX_ROOT"
python3 -m pytest -vv -rs pytools/tests/test_l3_typed_store_production.py \
  --basetemp="$MATRIX_ROOT/pytest" \
  --junitxml="$MATRIX_ROOT/production.xml" \
  > "$MATRIX_ROOT/production.log" 2>&1
MATRIX_STATUS=$?
printf 'typed_store_matrix_status=%s\n' "$MATRIX_STATUS"
tail -n 120 "$MATRIX_ROOT/production.log"
```

要求 17 passed，零失败/错误/跳过。测试在成功验收后故意篡改 raw capture，
验证独立审计拒绝伪造证据；因此不要再把该 pytest 输出目录当作未篡改的正例全量审计。
原始 narrow-store 验收目录未被这些反例修改，可用于正例归档。
